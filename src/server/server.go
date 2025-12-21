/*
This package implements the REST server for the Weft control plane.
*/
package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aquaduct-dev/weft/src/crypto"
	"github.com/aquaduct-dev/weft/src/dns"
	"github.com/aquaduct-dev/weft/src/internal/constants"
	"github.com/aquaduct-dev/weft/types"
	"github.com/aquaduct-dev/weft/wireguard"
	"github.com/golang-jwt/jwt/v4"
	"github.com/rs/zerolog/log"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Server implements the Weft control plane, managing tunnel registration,
// authentication, and proxy orchestration.
type Server struct {
	*http.Server

	// Store manages the persistence and state of tunnel peers.
	Store     TunnelStore
	// Dataplane manages the underlying networking (WireGuard/Proxies).
	Dataplane Dataplane

	// mu protects access to mutable fields (closing, challenges).
	mu sync.Mutex

	// closing indicates the server is shutting down and prevents new mutations.
	closing bool

	// ConnectionSecret is the shared secret used for the login challenge and JWT signing.
	ConnectionSecret string

	// bindIP constrains all server listeners (HTTP and proxy listeners) when set.
	bindIP string

	// UsageReportingURL is the destination for periodic usage statistics reports.
	UsageReportingURL string

	// CloudflareToken is used for automated DNS updates when new tunnels are established.
	CloudflareToken string

	// DNSUpdater is the strategy used to update external DNS records.
	DNSUpdater func(token, hostname, ip string) error

	// apiTLSConfig is the TLS configuration for the server's control plane API.
	apiTLSConfig *tls.Config

	// challenges maps remote client addresses to their active login challenges.
	challenges map[string]string
}

// CreateDevice initializes a new userspace WireGuard device on the specified port.
// It returns the device, the generated private key, and the actual port used.
func CreateDevice(port int, bindIP string) (*wireguard.UserspaceDevice, wgtypes.Key, int, error) {
	privateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return nil, wgtypes.Key{}, 0, fmt.Errorf("failed to generate private key: %w", err)
	}

	subnet := constants.DefaultSubnet

	cfg := wgtypes.Config{
		PrivateKey: &privateKey,
		ListenPort: &port,
	}
	conf, err := wireguard.ConfigToString(cfg)
	if err != nil {
		return nil, wgtypes.Key{}, 0, fmt.Errorf("failed to marshal wireguard config: %w", err)
	}
	device, err := wireguard.NewUserspaceDevice(conf, []netip.Addr{subnet.Addr()}, bindIP)
	if err != nil {
		return nil, wgtypes.Key{}, 0, fmt.Errorf("failed to create wireguard device: %w", err)
	}

	ipc, err := device.Device.IpcGet()
	if err != nil {
		return nil, wgtypes.Key{}, 0, fmt.Errorf("failed to get IPC info: %w", err)
	}
	var actualPort int
	for _, line := range strings.Split(ipc, "\n") {
		portStr, ok := strings.CutPrefix(line, "listen_port=")
		if !ok {
			continue
		}
		actualPort, err = strconv.Atoi(portStr)
		if err != nil {
			return nil, wgtypes.Key{}, 0, fmt.Errorf("failed to parse listen port: %w", err)
		}
	}

	log.Debug().Int("port", actualPort).Msg("CreateDevice: created server WireGuard device")
	return device, privateKey, actualPort, nil
}

// NewServer creates and initializes a new Weft control plane server.
func NewServer(port int, bindIP string, connectionSecret string, usageReportingURL string, cloudflareToken string) *Server {
	mux := http.NewServeMux()

	certPEM, keyPEM, certGenErr := crypto.GenerateCert("weft-server", []string{})
	if certGenErr != nil {
		log.Fatal().Err(certGenErr).Msg("failed to generate self-signed certificate")
	}

	cert, certPairErr := tls.X509KeyPair(certPEM, keyPEM)
	if certPairErr != nil {
		log.Fatal().Err(certPairErr).Msg("failed to load generated certificate")
	}

	apiTLSCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	if connectionSecret == "" {
		s, err := generateRandomSecret(10)
		if err != nil {
			log.Fatal().Err(err).Msg("failed to generate connection secret")
		}
		connectionSecret = s
	}

	addr := fmt.Sprintf(":%d", port)
	if bindIP != "" {
		addr = fmt.Sprintf("%s:%d", bindIP, port)
	}
	s := &Server{
		Server: &http.Server{
			Addr:      addr,
			Handler:   mux,
			TLSConfig: apiTLSCfg,
		},
		Store:             NewInMemoryTunnelStore(),
		ConnectionSecret:  connectionSecret,
		apiTLSConfig:      apiTLSCfg,
		challenges:        make(map[string]string),
		bindIP:            bindIP,
		UsageReportingURL: usageReportingURL,
		CloudflareToken:   cloudflareToken,
		DNSUpdater:        dns.UpdateRecord,
	}

	dp, err := NewTunnelDataplane(0, bindIP, s.RemoveTunnel, s.isShuttingDown)
	if err != nil {
		panic(err)
	}
	s.Dataplane = dp

	mux.HandleFunc("/connect", s.ConnectHandler)
	mux.HandleFunc("/healthcheck", s.HealthcheckHandler)
	mux.HandleFunc("/shutdown", s.ShutdownHandler)
	mux.HandleFunc("/login", s.LoginHandler)
	mux.HandleFunc("/list", s.ListHandler)
	mux.HandleFunc("/metrics", s.MetricsHandler)
	go s.startJanitor(11 * time.Second)
	go s.startUsageReporter(1 * time.Minute)

	return s
}

// MetricsHandler serves Prometheus-formatted usage metrics for all active tunnels.
func (s *Server) MetricsHandler(w http.ResponseWriter, r *http.Request) {
	user, _, ok := r.BasicAuth()
	if !ok || user != s.ConnectionSecret {
		w.Header().Set("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	proxies := s.Dataplane.GetProxyCounters()
	tunnels := s.Store.GetAllPeers()

	var b strings.Builder
	for name, peer := range tunnels {
		if counters, ok := proxies[name]; ok {
			b.WriteString(fmt.Sprintf("weft_tunnel_bytes_transmitted_total{tunnel_id=\"%%s\",src=\"%%s\",dst=\"%%s\"} %%d\n", name, peer.ProxiedUpstream, peer.DstURL, counters.Tx))
			b.WriteString(fmt.Sprintf("weft_tunnel_bytes_received_total{tunnel_id=\"%%s\",src=\"%%s\",dst=\"%%s\"} %%d\n", name, peer.ProxiedUpstream, peer.DstURL, counters.Rx))
		}
	}

	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	w.Write([]byte(b.String()))
}

func generateRandomSecret(length int) (string, error) {
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		return "", fmt.Errorf("failed to read random bytes: %w", err)
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// ConnectHandler processes requests from clients to establish a new tunnel connection.
func (s *Server) ConnectHandler(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, "Authorization header required", http.StatusUnauthorized)
		return
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		http.Error(w, "Invalid Authorization header", http.StatusUnauthorized)
		return
	}

	tokenString := parts[1]
	_, err := s.ValidateJWT(tokenString)
	if err != nil {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req types.ConnectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request body: %%v", err), http.StatusBadRequest)
		return
	}

	resp, err := s.Serve(&req)
	if err != nil {
		if err.Error() == "invalid connection secret" {
			http.Error(w, fmt.Sprintf("Invalid connection secret: %%v", err), http.StatusUnauthorized)
			return
		}
		if strings.Contains(err.Error(), "already exists") || strings.Contains(err.Error(), "conflict") {
			http.Error(w, fmt.Sprintf("Conflict: %%v", err), http.StatusConflict)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	log.Debug().Any("response", resp).Msg("ConnectHandler: sending response")
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

// Serve processes a connection request, allocates resources, and returns the tunnel configuration.
func (s *Server) Serve(req *types.ConnectRequest) (*types.ConnectResponse, error) {
	clientPublicKey, err := wgtypes.ParseKey(req.ClientPublicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid client public key")
	}

	p, created, err := s.getOrCreateTunnelPeer(req, clientPublicKey)
	if err != nil {
		return nil, err
	}

	if err := s.Dataplane.UpdateWireGuardConfig(s.Store.GetAllPeers()); err != nil {
		if created {
			s.RemoveTunnel(req.TunnelName)
		}
		return nil, err
	}

	tunnelProxyPort, err := s.Dataplane.StartProxy(req, p.IP)
	if err != nil {
		if created {
			s.RemoveTunnel(req.TunnelName)
		}
		return nil, err
	}

	pubKey := s.Dataplane.GetPrivateKey().PublicKey()
	
	// Update Peer with the assigned TunnelProxyPort
	p.TunnelProxyPort = tunnelProxyPort
	s.Store.SetPeer(req.TunnelName, p)

	return &types.ConnectResponse{
		ServerPublicKey: pubKey.String(),
		ClientAddress:   p.IP.String(),
		ServerWGPort:    s.Dataplane.GetWgListenPort(),
		TunnelProxyPort: tunnelProxyPort,
	}, nil
}

// getOrCreateTunnelPeer retrieves an existing peer or creates a new one, including IP allocation.
func (s *Server) getOrCreateTunnelPeer(req *types.ConnectRequest, clientPublicKey wgtypes.Key) (Peer, bool, error) {
	if p, ok := s.Store.GetPeer(req.TunnelName); ok {
		s.Store.SetLastSeen(req.TunnelName, time.Now())
		return p, false, nil
	}

	ip, err := s.Store.GetFreeIP()
	if err != nil {
		return Peer{}, false, err
	}

	p := Peer{
		IP:              ip,
		PublicKey:       clientPublicKey,
		ProxiedUpstream: req.ProxiedUpstream,
		DstURL:          fmt.Sprintf("%s://%s:%d", req.Protocol, req.Hostname, req.RemotePort),
	}
	s.Store.SetPeer(req.TunnelName, p)
	s.Store.SetLastSeen(req.TunnelName, time.Now())

	if s.CloudflareToken != "" && req.Hostname != "" && (req.Protocol == "http" || req.Protocol == "https") {
		if s.bindIP != "" && s.bindIP != "0.0.0.0" {
			updater := s.DNSUpdater
			go func(hostname, ip string) {
				if err := updater(s.CloudflareToken, hostname, ip); err != nil {
					log.Error().Err(err).Str("hostname", hostname).Msg("Failed to update Cloudflare DNS")
				}
			}(req.Hostname, s.bindIP)
		} else {
			log.Warn().Str("hostname", req.Hostname).Msg("Cloudflare token set but bindIP is invalid/empty, skipping DNS update")
		}
	}

	return p, true, nil
}

// HealthcheckHandler provides an endpoint for clients to report their health status.
func (s *Server) HealthcheckHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req types.HealthcheckRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && err != io.EOF {
		http.Error(w, fmt.Sprintf("Invalid request body: %%v", err), http.StatusBadRequest)
		return
	}

	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, "Authorization header required", http.StatusUnauthorized)
		return
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		http.Error(w, "Invalid Authorization header", http.StatusUnauthorized)
		return
	}

	tokenString := parts[1]
	token, err := s.ValidateJWT(tokenString)
	if err != nil {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		http.Error(w, "Invalid token claims", http.StatusUnauthorized)
		return
	}

	proxyName, ok := claims["sub"].(string)
	if !ok || proxyName == "" {
		http.Error(w, "Missing proxy name in token", http.StatusBadRequest)
		return
	}

	p, exists := s.Store.GetPeer(proxyName)
	if !exists {
		http.Error(w, fmt.Sprintf("Proxy '%%s' not found", proxyName), http.StatusNotFound)
		return
	}

	s.Store.SetLastSeen(proxyName, time.Now())

	resp := types.HealthcheckResponse{
		Status:  "healthy",
		Message: fmt.Sprintf("Proxy '%%s' is healthy. IP: %%s. Request message: '%%s'", proxyName, p.IP.String(), req.Message),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

func (s *Server) startJanitor(interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			if s.isShuttingDown() {
				return
			}
			cutoff := time.Now().Add(-2 * interval)
			lastSeen := s.Store.GetAllLastSeen()
			var staleTunnels []string
			for k, last := range lastSeen {
				if last.Before(cutoff) {
					staleTunnels = append(staleTunnels, k)
				}
			}

			if len(staleTunnels) > 0 {
				s.reportUsage(context.Background(), staleTunnels)
			}

			for _, k := range staleTunnels {
				if last, ok := s.Store.GetLastSeen(k); ok && last.Before(cutoff) {
					s.RemoveTunnel(k)
					log.Info().Str("peer", k).Msg("Janitor: removed stale tunnel")
				}
			}
		}
	}()
}

func (s *Server) startUsageReporter(interval time.Duration) {
	if s.UsageReportingURL == "" {
		return
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			s.reportUsage(context.Background(), nil)
		}
	}()
}

func (s *Server) reportUsage(ctx context.Context, tunnels []string) {
	if s.UsageReportingURL == "" {
		return
	}
	if s.isShuttingDown() {
		return
	}

	proxies := s.Dataplane.GetProxyCounters()
	peers := s.Store.GetAllPeers()
	var report UsageReport

	if tunnels == nil {
		for name, p := range peers {
			if counters, ok := proxies[name]; ok {
				report.Tunnels = append(report.Tunnels, TunnelUsage{
					TunnelName:  name,
					InstanceId:  counters.InstanceId,
					BytesTx:     counters.Tx,
					BytesRx:     counters.Rx,
					Source:      p.ProxiedUpstream,
					Destination: p.DstURL,
				})
			}
		}
	} else {
		for _, name := range tunnels {
			if counters, ok := proxies[name]; ok {
				if p, ok := s.Store.GetPeer(name); ok {
					report.Tunnels = append(report.Tunnels, TunnelUsage{
						TunnelName:  name,
						InstanceId:  counters.InstanceId,
						BytesTx:     counters.Tx,
						BytesRx:     counters.Rx,
						Source:      p.ProxiedUpstream,
						Destination: p.DstURL,
					})
				}
			}
		}
	}

	if len(report.Tunnels) == 0 {
		return
	}

	body, err := json.Marshal(report)
	if err != nil {
		log.Error().Err(err).Msg("failed to marshal usage report")
		return
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.UsageReportingURL, bytes.NewReader(body))
	if err != nil {
		log.Error().Err(err).Msg("failed to create usage report request")
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Error().Err(err).Msg("failed to send usage report")
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		log.Warn().Int("status", resp.StatusCode).Str("body", string(bodyBytes)).Msg("usage report failed")
	} else {
		log.Debug().Int("count", len(report.Tunnels)).Msg("usage report sent")
	}
}

func (s *Server) isShuttingDown() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closing
}

func (s *Server) ShutdownHandler(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, "Authorization header required", http.StatusUnauthorized)
		return
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		http.Error(w, "Invalid Authorization header", http.StatusUnauthorized)
		return
	}

	tokenString := parts[1]
	token, err := s.ValidateJWT(tokenString)
	if err != nil {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	tunnelName := token.Claims.(jwt.MapClaims)["sub"].(string)
	s.reportUsage(r.Context(), []string{tunnelName})
	s.RemoveTunnel(tunnelName)
	w.WriteHeader(http.StatusOK)
}

// RemoveTunnel cleans up all resources associated with a tunnel name.
func (s *Server) RemoveTunnel(tunnelName string) {
	if p, ok := s.Store.GetPeer(tunnelName); ok {
		s.Dataplane.CloseProxy(tunnelName)
		s.Store.ReleaseIP(p.IP)
		s.Store.DeletePeer(tunnelName)
		s.Store.DeleteLastSeen(tunnelName)
	}
}

// LoginHandler manages the multi-step challenge-response authentication for proxies.
func (s *Server) LoginHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.getChallenge(w, r)
	case http.MethodPost:
		s.verifyChallenge(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) getChallenge(w http.ResponseWriter, r *http.Request) {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		http.Error(w, "Failed to generate challenge", http.StatusInternalServerError)
		return
	}
	challenge := hex.EncodeToString(b)
	s.mu.Lock()
	s.challenges[r.RemoteAddr] = challenge
	s.mu.Unlock()

	encrypted, err := crypto.Encrypt(s.ConnectionSecret, "server-"+challenge)
	if err != nil {
		http.Error(w, "Failed to encrypt challenge", http.StatusInternalServerError)
		return
	}
	w.Write(encrypted)
	log.Debug().Str("client", r.RemoteAddr).Msg("getChallenge: Generated login challenge")
}

func (s *Server) verifyChallenge(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusInternalServerError)
		return
	}

	var encrypted []byte
	var proxyName string

	if r.Header.Get("Content-Type") == "application/json" {
		var loginReq map[string]any
		if err := json.Unmarshal(body, &loginReq); err != nil {
			http.Error(w, "Failed to parse JSON body", http.StatusBadRequest)
			return
		}

		challengeData, ok := loginReq["challenge"]
		if !ok {
			http.Error(w, "Missing challenge in JSON body", http.StatusBadRequest)
			return
		}

		proxyData, ok := loginReq["proxy_name"]
		proxyName, _ = proxyData.(string)
		if proxyName == "" {
			http.Error(w, "Missing proxy_name in JSON body", http.StatusBadRequest)
			return
		}

		if challengeStr, ok := challengeData.(string); ok {
			var err error
			encrypted, err = base64.StdEncoding.DecodeString(challengeStr)
			if err != nil {
				http.Error(w, "Invalid challenge format", http.StatusBadRequest)
				return
			}
		} else {
			http.Error(w, "Invalid challenge format", http.StatusBadRequest)
			return
		}
	}

	decrypted, err := crypto.Decrypt(s.ConnectionSecret, encrypted)
	if err != nil {
		http.Error(w, "Failed to decrypt challenge", http.StatusUnauthorized)
		return
	}

	s.mu.Lock()
	challenge, ok := s.challenges[r.RemoteAddr]
	delete(s.challenges, r.RemoteAddr)
	s.mu.Unlock()

	if !ok {
		http.Error(w, "No challenge found for this address", http.StatusUnauthorized)
		return
	}

	if string(decrypted) != challenge {
		http.Error(w, "Invalid challenge", http.StatusUnauthorized)
		return
	}

	claims := jwt.MapClaims{
		"nbf": time.Now().Unix(),
		"exp": time.Now().Add(30 * time.Minute).Unix(),
		"aud": r.RemoteAddr,
		"sub": proxyName,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(s.ConnectionSecret))
	if err != nil {
		http.Error(w, "Failed to sign token", http.StatusInternalServerError)
		return
	}

	w.Write([]byte(tokenString))
	log.Debug().Str("client", r.RemoteAddr).Msg("verifyChallenge: Client passed challenge")
}

// ValidateJWT parses and validates a JSON Web Token against the server's connection secret.
func (s *Server) ValidateJWT(tokenString string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %%v", token.Header["alg"])
		}
		return []byte(s.ConnectionSecret), nil
	})

	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("token is not valid")
	}

	return token, nil
}

// ListHandler returns a list of all active tunnels and their current usage statistics.
func (s *Server) ListHandler(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, "Authorization header required", http.StatusUnauthorized)
		return
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		http.Error(w, "Invalid Authorization header", http.StatusUnauthorized)
		return
	}

	tokenString := parts[1]
	_, err := s.ValidateJWT(tokenString)
	if err != nil {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	proxies := s.Dataplane.GetProxyCounters()
	peers := s.Store.GetAllPeers()

	type tunnelInfo struct {
		Tx     uint64 `json:"tx"`
		Rx     uint64 `json:"rx"`
		SrcURL string `json:"src"`
		DstURL string `json:"dst"`
	}

	response := make(map[string]tunnelInfo)
	for name, peer := range peers {
		info := tunnelInfo{
			SrcURL: peer.ProxiedUpstream,
			DstURL: peer.DstURL,
		}
		if counters, ok := proxies[name]; ok {
			info.Tx = counters.Tx
			info.Rx = counters.Rx
		}
		response[name] = info
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
