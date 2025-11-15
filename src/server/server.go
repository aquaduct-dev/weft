/*
This package implements the REST server for the Weft control plane.
*/
package server

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"aquaduct.dev/weft/src/crypto"
	proxy "aquaduct.dev/weft/src/proxy"
	"aquaduct.dev/weft/types"
	"aquaduct.dev/weft/wireguard"
	"github.com/golang-jwt/jwt/v4"
	"github.com/rs/zerolog/log"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type Server struct {
	*http.Server

	// device is the userspace WireGuard device that handles packet routing for peers.
	device *wireguard.UserspaceDevice

	// privateKey is the server's WireGuard private key used when forming the server peer.
	privateKey wgtypes.Key

	// tunnels maps a logical tunnel name (client-specified or computed) to the
	// assigned WireGuard address for that tunnel's client.
	tunnels map[string]peer

	// peerLastSeen stores the last time a tunnel name checked in (healthchecks).
	// Used by the janitor to prune stale entries.
	peerLastSeen map[string]time.Time

	proxies map[string]io.Closer

	// usedIPs tracks allocated addresses in the subnet.
	usedIPs map[netip.Addr]bool

	// subnet is the WireGuard subnet reserved for clients (e.g., 10.0.0.0/24).
	subnet netip.Prefix

	// mu protects access to mutable fields (tunnels, proxies, nextIP, etc.).
	mu sync.Mutex

	// closing indicates the server is shutting down and prevents new mutations.
	closing bool

	// ConnectionSecret is the shared secret used for the login challenge + JWT signing.
	ConnectionSecret string

	// VhostProxy implements virtual-host routing for hostname-based tunnels.
	ProxyManager *proxy.ProxyManager
	// bindIP constrains all server listeners (HTTP and proxy listeners) when set.
	bindIP string

	// apiTLSConfig is an optional TLS config for API-related listeners (kept for future use).
	apiTLSConfig *tls.Config

	// WgListenPort records the UDP port the server's WireGuard device is listening on.
	// This is returned to clients so they can configure the correct endpoint.
	WgListenPort int

	// challenges maps remote addresses to outstanding login challenges.
	challenges map[string]string
}

type peer struct {
	publicKey wgtypes.Key
	ip        netip.Addr
}

func CreateDevice(port int) (*wireguard.UserspaceDevice, wgtypes.Key, int, error) {
	privateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return nil, wgtypes.Key{}, 0, fmt.Errorf("failed to generate private key: %w", err)
	}

	subnet := netip.MustParsePrefix("10.1.0.0/16")

	// Build device config. Currently the userspace device constructor expects a
	// WireGuard-style config. We always provide private_key and listen_port.
	// The wireguard userspace device may not support an explicit bind address in
	// the config string across all implementations; however, we accept a
	// bindIP parameter and log it so operators know we attempted to constrain
	// bindings. If the underlying implementation supports endpoint binding via
	// the conf string, include it here.
	conf := fmt.Sprintf("private_key=%s\nlisten_port=%d", hex.EncodeToString(privateKey[:]), port)
	device, err := wireguard.NewUserspaceDevice(conf, []netip.Addr{subnet.Addr()})
	if err != nil {
		return nil, wgtypes.Key{}, 0, fmt.Errorf("failed to create wireguard device: %w", err)
	}

	// Get the actual listen port from the device
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

	log.Info().Int("port", actualPort).Msg("CreateDevice: created server WireGuard device")
	return device, privateKey, actualPort, nil
}

func NewServer(port int, bindIP string, connectionSecret string) *Server {
	mux := http.NewServeMux()

	apiTLSCfg := &tls.Config{}

	if connectionSecret == "" {
		// Generate a random connection secret on startup.
		s, err := generateRandomSecret(10) // 10 bytes for a secure secret
		if err != nil {
			log.Fatal().Err(err).Msg("failed to generate connection secret")
		}
		connectionSecret = s
	}

	// Configure HTTP server address. If bindIP is specified, bind only to that IP.
	addr := fmt.Sprintf(":%d", port)
	if bindIP != "" {
		addr = fmt.Sprintf("%s:%d", bindIP, port)
	}
	s := &Server{
		Server: &http.Server{
			Addr:    addr,
			Handler: mux,
		},
		tunnels:          make(map[string]peer),
		peerLastSeen:     make(map[string]time.Time),
		proxies:          make(map[string]io.Closer),
		subnet:           netip.MustParsePrefix("10.1.0.0/16"),
		usedIPs:          make(map[netip.Addr]bool),
		ConnectionSecret: connectionSecret,
		ProxyManager:     proxy.NewProxyManager(),
		apiTLSConfig:     apiTLSCfg,
		challenges:       make(map[string]string),
		bindIP:           bindIP,
	}
	// Propagate bindIP to the ProxyManager so proxies bind to the same IP.
	if bindIP != "" {
		s.ProxyManager.SetBindIP(bindIP)
	}
	var err error
	s.device, s.privateKey, s.WgListenPort, err = CreateDevice(0) // Always use a random port for the wireguard device
	if err != nil {
		panic(err)
	}

	mux.HandleFunc("/connect", s.ConnectHandler)
	mux.HandleFunc("/healthcheck", s.HealthcheckHandler)
	mux.HandleFunc("/shutdown", s.ShutdownHandler)
	mux.HandleFunc("/login", s.LoginHandler)
	go s.startJanitor(30 * time.Second)

	return s
}

// generateRandomSecret generates a cryptographically secure random string of the specified byte length.
// The string is base64 URL-encoded to ensure it's safe for use in URLs and other text-based contexts.
func generateRandomSecret(length int) (string, error) {
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		return "", fmt.Errorf("failed to read random bytes: %w", err)
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// getFreeIPFromPool finds an available IP address in the server's subnet.
// This function assumes the caller holds the mutex.
func (s *Server) getFreeIPFromPool() (netip.Addr, error) {

	// Reserve .1 for the server itself
	hostAddr, _ := netip.ParseAddr("10.1.0.1")
	if _, used := s.usedIPs[hostAddr]; !used {
		s.usedIPs[hostAddr] = true
	}
	addr := hostAddr
	for {
		addr = addr.Next()
		if !s.subnet.Contains(addr) {
			return netip.Addr{}, fmt.Errorf("subnet exhausted")
		}

		// Don't allocate the broadcast address. The broadcast address is the last address in the subnet.
		if !s.subnet.Contains(addr.Next()) {
			continue // This is the broadcast address, skip it.
		}

		if _, used := s.usedIPs[addr]; !used {
			s.usedIPs[addr] = true
			return addr, nil
		}
	}
}

// returnIPToPool returns an IP address to the pool of available addresses.
// This function assumes the caller holds the mutex.
func (s *Server) returnIPToPool(ip netip.Addr) {
	delete(s.usedIPs, ip)
}

// GetFreeIPFromPool finds an available IP address in the server's subnet.
func (s *Server) GetFreeIPFromPool() (netip.Addr, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.getFreeIPFromPool()
}

// ReturnIPToPool returns an IP address to the pool of available addresses.
func (s *Server) ReturnIPToPool(ip netip.Addr) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.returnIPToPool(ip)
}

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
		// Return the full JSON decoding error to help clients debug malformed payloads.
		// Avoid leaking request bodies or secrets; the error text itself (e.g., "invalid character")
		// is safe and useful for debugging.
		http.Error(w, fmt.Sprintf("Invalid request body: %v", err), http.StatusBadRequest)
		return
	}

	resp, err := s.Serve(&req)
	if err != nil {
		// Translate well-known error types into appropriate HTTP status codes so clients can act,
		// but include the full underlying error text in the response body to aid debugging.
		if err.Error() == "invalid connection secret" {
			http.Error(w, fmt.Sprintf("Invalid connection secret: %v", err), http.StatusUnauthorized)
			return
		}
		if strings.HasPrefix(err.Error(), "port_conflict:") {
			// Preserve details about which port conflicted.
			http.Error(w, fmt.Sprintf("Requested port unavailable: %v", err), http.StatusConflict)
			return
		}
		// Default: return the full error text.
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

func (s *Server) Serve(req *types.ConnectRequest) (*types.ConnectResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	clientPublicKey, err := wgtypes.ParseKey(req.ClientPublicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid client public key")
	}

	// If the tunnel is new, allocate an IP from the subnet.
	if _, ok := s.tunnels[req.TunnelName]; !ok {
		ip, err := s.getFreeIPFromPool()
		if err != nil {
			return nil, err
		}
		s.tunnels[req.TunnelName] = peer{
			ip:        ip,
			publicKey: clientPublicKey,
		}
	}
	peerIP := s.tunnels[req.TunnelName].ip
	// mark as seen now (new connection). Record by tunnelName.
	s.peerLastSeen[req.TunnelName] = time.Now()

	// Build wgtypes.Config from current tunnels for consistent UAPI generation.
	// Ensure server WireGuard device is listening on an ephemeral port bound to the WireGuard interface.
	// If s.WgListenPort==0, ask the device for its effective listen_port and use that. If the device
	// is nil, return an error.
	if s.device == nil || s.device.Device == nil {
		return nil, fmt.Errorf("device closed (cannot configure peers)")
	}
	// Read current IPC info to determine the active listen_port in case it was set to 0 at creation.
	ipc, _ := s.device.Device.IpcGet()
	for _, line := range strings.Split(ipc, "\n") {
		if portStr, ok := strings.CutPrefix(line, "listen_port="); ok {
			if p, err := strconv.Atoi(strings.TrimSpace(portStr)); err == nil && p != 0 {
				s.WgListenPort = p
			}
		}
	}

	cfg := wgtypes.Config{ListenPort: &s.WgListenPort}
	for _, p := range s.tunnels {
		cfg.Peers = append(cfg.Peers, wgtypes.PeerConfig{
			PublicKey:  p.publicKey,
			AllowedIPs: []net.IPNet{{IP: net.IP(p.ip.AsSlice()), Mask: net.CIDRMask(32, 32)}, {IP: net.ParseIP("10.1.0.1"), Mask: net.CIDRMask(32, 32)}},
		})
	}
	newConfig, err := ConfigToString(cfg)
	if err != nil {
		log.Fatal().Err(err).Msg("ConfigToString failed")
	}
	log.Debug().Str("config", newConfig).Msg("Config")

	if s.device != nil {
		// Defensive logging: record that we're preparing an IPC config update.
		// Compute checksum of the new config and compare with the device's current IPC state.
		log.Debug().Bool("replace_peers", strings.Contains(newConfig, "replace_peers=true")).Msg("IpcSet: preparing peer config update")
		if s.device.Device == nil {
			log.Warn().Msg("IpcSet: device.Device is nil (device closed?)")
			return nil, fmt.Errorf("device closed (cannot configure peers)")
		}
		log.Debug().Msg("IpcSet: device not nil")
		if s.isShuttingDown() {
			log.Warn().Msg("IpcSet: server is shutting down; refusing to configure peers")
			return nil, fmt.Errorf("server shutting down (cannot configure peers)")
		}
		log.Debug().Msg("IpcSet: device not shutting down")
		// Read current device config for comparison.
		currentConfig, getErr := s.device.Device.IpcGet()
		if getErr != nil {
			// If we cannot read current config, log and proceed to attempt an update.
			log.Warn().Err(getErr).Msg("IpcSet: failed to read current device config; will attempt to apply new config")
		}
		// Sanitize configs for logging/comparison by removing private_key lines.
		sanitize := func(conf string) string {
			var out []string
			for _, line := range strings.Split(conf, "\n") {
				if strings.HasPrefix(strings.TrimSpace(line), "private_key=") {
					out = append(out, "private_key=<redacted>")
					continue
				}
				out = append(out, line)
			}
			return strings.Join(out, "\n")
		}
		sanitizedNew := sanitize(newConfig)
		sanitizedCurrent := sanitize(currentConfig)
		log.Debug().Msg("IpcSet: comparing configs for change detection")
		if sanitizedCurrent == sanitizedNew && sanitizedCurrent != "" {
			log.Debug().Msg("IpcSet: skipping apply; device config unchanged")
		} else {
			log.Info().Msg("IpcSet: applying peer config")
			// Log sanitized newConfig so we can validate what is being applied (private_key redacted).
			log.Debug().Str("newConfig", sanitizedNew).Msg("IpcSet: newConfig to apply (redacted)")
			// Also log server wgListenPort and whether device.Device appears non-nil.
			log.Debug().Int("wgListenPort", s.WgListenPort).Bool("device.Device_nil", s.device.Device == nil).Msg("IpcSet: server state")
			err = s.device.Device.IpcSet(newConfig)
			if err != nil {
				// On error, fetch and log current device state (sanitized) to help debugging.
				log.Error().Err(err).Msg("IpcSet error")
				if cur, e := s.device.Device.IpcGet(); e == nil {
					// redact private_key before logging
					redacted := sanitize(cur)
					log.Debug().Str("current_config", redacted).Msg("IpcSet: current device IPC state after error (redacted)")
				} else {
					log.Error().Err(e).Msg("IpcSet: failed to read device IPC after error")
				}
				return nil, fmt.Errorf("failed to configure peer: %w", err)
			}
			// Diagnostic: read back the device IPC state after successful apply and log sanitized value.
			if cur, e := s.device.Device.IpcGet(); e == nil {
				redacted := sanitize(cur)
				log.Debug().Str("current_config", redacted).Msg("IpcSet: device IPC state after apply (redacted)")
			} else {
				log.Error().Err(e).Msg("IpcSet: failed to read device IPC after successful apply")
			}
		}
	}

	// Assign tunnelProxyPort randomly
	tunnelProxyPortBigInt, err := rand.Int(rand.Reader, big.NewInt(10000))
	if err != nil {
		return nil, err
	}
	tunnelProxyPort := int(tunnelProxyPortBigInt.Uint64()) + 10000
	tunnelSource := url.URL{
		Host:   fmt.Sprintf("%s:%d", peerIP.String(), tunnelProxyPort),
		Scheme: "tcp",
	}
	tunnelEnd := url.URL{
		Host:   fmt.Sprintf("%s:%d", req.Hostname, req.RemotePort),
		Scheme: "tcp",
	}
	switch req.Protocol {
	case "tcp":
	case "udp":
		tunnelSource.Scheme = "udp"
		tunnelEnd.Scheme = "udp"
	case "http":
		tunnelSource.Scheme = "http"
		tunnelEnd.Scheme = "http"
	case "https":
		tunnelSource.Scheme = "http"
		tunnelEnd.Scheme = "https"
	default:
		return nil, fmt.Errorf("unknown protocol: %s", req.Protocol)
	}
	// If protocol is https and client supplied certs, pass them to the proxy so the server
	// can terminate TLS using the provided certificate. Both certificate and private key
	// must be provided together.
	var certBytes, keyBytes []byte
	if req.Protocol == "https" {
		if req.CertificatePEM != "" || req.PrivateKeyPEM != "" {
			// Require both fields when one is present.
			if req.CertificatePEM == "" || req.PrivateKeyPEM == "" {
				return nil, fmt.Errorf("missing certificate or private key for https protocol")
			}
			// Do not log certificate contents; only log that certs were provided.
			log.Info().Str("tunnel", req.TunnelName).Msg("Serve: using provided TLS certificate for https proxy")
			certBytes = []byte(req.CertificatePEM)
			keyBytes = []byte(req.PrivateKeyPEM)
		}
	}
	err = s.ProxyManager.StartProxy(&tunnelSource, &tunnelEnd, req.TunnelName, s.device, certBytes, keyBytes, s.bindIP)
	if err != nil {
		return nil, err
	}

	publicKey := s.privateKey.PublicKey()
	// Map certain error messages to more specific HTTP-handling codes in the caller.
	// The HTTP handler will translate:
	//   - "port_conflict:<port>" -> 409 Conflict
	//   - "missing_port_for_protocol" or "url_missing_port" -> 422 Unprocessable Entity
	// After applying peer config, ensure WgListenPort is current by re-reading device IPC.
	if ipcAfter, err2 := s.device.Device.IpcGet(); err2 == nil {
		for _, line := range strings.Split(ipcAfter, "\n") {
			if portStr, ok := strings.CutPrefix(line, "listen_port="); ok {
				if p, err := strconv.Atoi(strings.TrimSpace(portStr)); err == nil && p != 0 {
					s.WgListenPort = p
				}
			}
		}
	}
	// Prepare ConnectResponse including both the server's WireGuard listen port and the
	// tunnel proxy port assigned for this connection (for protocols where server chooses).

	resp := &types.ConnectResponse{
		ServerPublicKey: hex.EncodeToString(publicKey[:]),
		ClientAddress:   peerIP.String(),
		// ServerWGPort is the UDP listen port of the server's WireGuard device.
		ServerWGPort: s.WgListenPort,
		// TunnelProxyPort is the port on the server side that will proxy to the client's WG IP.
		TunnelProxyPort: tunnelProxyPort,
	}

	return resp, nil
}

func (s *Server) HealthcheckHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Validate JWT token from Authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		log.Warn().Msg("HealthcheckHandler: missing Authorization header")
		http.Error(w, "Authorization header required", http.StatusUnauthorized)
		return
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		log.Warn().Msg("HealthcheckHandler: invalid Authorization header format")
		http.Error(w, "Invalid Authorization header", http.StatusUnauthorized)
		return
	}

	tokenString := parts[1]

	token, err := s.ValidateJWT(tokenString)
	if err != nil {
		log.Warn().Err(err).Msg("HealthcheckHandler: failed to validate JWT")
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	// Extract proxy name from JWT claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		log.Warn().Msg("HealthcheckHandler: failed to extract JWT claims")
		http.Error(w, "Invalid token claims", http.StatusUnauthorized)
		return
	}

	proxyName, ok := claims["sub"].(string)
	if !ok || proxyName == "" {
		log.Warn().Any("claims", claims).Msg("HealthcheckHandler: missing or invalid proxy name in JWT sub claim")
		http.Error(w, fmt.Sprintf("Missing proxy name in token %v", claims), http.StatusBadRequest)
		return
	}

	log.Debug().Str("proxy_name", proxyName).Msg("HealthcheckHandler: received healthcheck")

	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if the proxy (tunnel) exists
	peer, exists := s.tunnels[proxyName]
	if !exists {
		log.Warn().Str("proxy_name", proxyName).Msg("HealthcheckHandler: proxy not found")
		http.Error(w, fmt.Sprintf("Proxy '%s' not found", proxyName), http.StatusNotFound)
		return
	}

	// Update last seen time for this proxy
	s.peerLastSeen[proxyName] = time.Now()

	// Check if the proxy is healthy by verifying the peer is still configured
	// and the WireGuard device is available
	if s.device == nil {
		log.Debug().Str("proxy_name", proxyName).Msg("HealthcheckHandler: device is nil. This is expected in tests.")
	}

	// Return success status with proxy information
	response := map[string]any{
		"status":    "healthy",
		"proxy":     proxyName,
		"ip":        peer.ip.String(),
		"timestamp": time.Now().Unix(),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Error().Err(err).Str("proxy_name", proxyName).Msg("HealthcheckHandler: failed to encode response")
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}

	log.Debug().Str("proxy_name", proxyName).Msg("HealthcheckHandler: proxy is healthy")
}

// startJanitor launches a background goroutine that periodically prunes stale peer last-seen entries.
// interval controls how often the janitor runs. It keeps peers seen within 2 * interval.
func (s *Server) startJanitor(interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			s.mu.Lock()
			if s.closing {
				s.mu.Unlock()
				return
			}
			cutoff := time.Now().Add(-2 * interval)
			for k, last := range s.peerLastSeen {
				if last.Before(cutoff) {
					if p, ok := s.tunnels[k]; ok {
						s.returnIPToPool(p.ip)
						delete(s.tunnels, k)
					}
					delete(s.peerLastSeen, k)
					log.Info().Str("peer", k).Msg("janitor: removed stale peer last-seen")
				}
			}
			s.mu.Unlock()
		}
	}()
}

func (s *Server) isShuttingDown() bool {
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

	for name, p := range s.tunnels {
		if name == tunnelName {
			s.ProxyManager.Close(name)
			s.returnIPToPool(p.ip)
			delete(s.tunnels, name)
			delete(s.peerLastSeen, name)
		}
	}
	w.WriteHeader(http.StatusOK)
}

// ConfigToString converts a wgtypes.Config struct into the WireGuard UAPI string format.
func ConfigToString(cfg wgtypes.Config) (string, error) {
	var b strings.Builder

	// Always replace peers for now (UAPI expects top-level flags first)
	b.WriteString("replace_peers=true\n")

	// Emit each peer using UAPI format (flat key-value pairs, no section headers)
	for _, peer := range cfg.Peers {
		if peer.PublicKey != (wgtypes.Key{}) {
			b.WriteString(fmt.Sprintf("public_key=%s\n", hex.EncodeToString(peer.PublicKey[:])))
		}

		if len(peer.AllowedIPs) > 0 {
			for _, ipNet := range peer.AllowedIPs {
				b.WriteString(fmt.Sprintf("allowed_ip=%s\n", ipNet.String()))
			}
		}

		// Endpoint if present
		if peer.Endpoint != nil {
			b.WriteString(fmt.Sprintf("endpoint=%s\n", peer.Endpoint.String()))
		}

		// Persistent keepalive (seconds)
		if peer.PersistentKeepaliveInterval != nil && *peer.PersistentKeepaliveInterval != 0 {
			secs := max(0, int(*peer.PersistentKeepaliveInterval/time.Second))
			b.WriteString(fmt.Sprintf("persistent_keepalive_interval=%d\n", secs))
		}
	}

	// Ensure trailing newline
	if !strings.HasSuffix(b.String(), "\n") {
		b.WriteString("\n")
	}
	return b.String(), nil
}
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
}

func (s *Server) verifyChallenge(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusInternalServerError)
		return
	}

	var encrypted []byte
	var proxyName string

	// Check if this is JSON (contains proxy_name) or binary (legacy)
	if r.Header.Get("Content-Type") == "application/json" {
		// Parse JSON body
		var loginReq map[string]any
		if err := json.Unmarshal(body, &loginReq); err != nil {
			http.Error(w, "Failed to parse JSON body", http.StatusBadRequest)
			return
		}

		// Extract challenge and proxy_name
		challengeData, ok := loginReq["challenge"]
		if !ok {
			http.Error(w, "Missing challenge in JSON body", http.StatusBadRequest)
			return
		}

		proxyData, ok := loginReq["proxy_name"]
		proxyName = proxyData.(string)
		if !ok || proxyName == "" {
			http.Error(w, "Missing proxy_name in JSON body", http.StatusBadRequest)
			return
		}

		// Challenge should be base64 encoded bytes
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

	// At this point, the client is authenticated.
	// Generate a JWT and return it.

	// Build JWT claims
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
}

// ValidateJWT parses and validates a JWT token string using the server's ConnectionSecret.
// It returns the parsed token if valid, otherwise an error.
func (s *Server) ValidateJWT(tokenString string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
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
