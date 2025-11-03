/*
This package implements the REST server for the Weft control plane.
*/
package server

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"aquaduct.dev/weft/types"
	"aquaduct.dev/weft/wireguard"
	"github.com/golang-jwt/jwt/v4"
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

	// proxies maps a public port to the listener/closer that forwards traffic into the WG network.
	proxies map[int]io.Closer

	// nextIP is the next IP address to allocate inside s.subnet for newly created tunnels.
	nextIP netip.Addr

	// subnet is the WireGuard subnet reserved for clients (e.g., 10.0.0.0/24).
	subnet netip.Prefix

	// mu protects access to mutable fields (tunnels, proxies, nextIP, etc.).
	mu sync.Mutex

	// closing indicates the server is shutting down and prevents new mutations.
	closing bool

	// ConnectionSecret is the shared secret used for the login challenge + JWT signing.
	ConnectionSecret string

	// VhostProxy implements virtual-host routing for hostname-based tunnels.
	VhostProxy *VHostProxy

	// apiTLSConfig is an optional TLS config for API-related listeners (kept for future use).
	apiTLSConfig *tls.Config

	// challenges maps remote addresses to outstanding login challenges.
	challenges map[string]string
}

type peer struct {
	publicKey wgtypes.Key
	ip        netip.Addr
}

func CreateDevice(port int) (*wireguard.UserspaceDevice, wgtypes.Key, error) {
	privateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return nil, wgtypes.Key{}, fmt.Errorf("failed to generate private key: %w", err)
	}

	subnet := netip.MustParsePrefix("10.0.0.0/24")

	conf := fmt.Sprintf(`private_key=%s
listen_port=%d`, hex.EncodeToString(privateKey[:]), port)

	device, err := wireguard.NewUserspaceDevice(conf, []netip.Addr{subnet.Addr()})
	if err != nil {
		return nil, wgtypes.Key{}, fmt.Errorf("failed to create wireguard device: %w", err)
	}
	return device, privateKey, nil
}

func NewServer(device *wireguard.UserspaceDevice, privateKey wgtypes.Key) *Server {
	mux := http.NewServeMux()

	apiTLSCfg := &tls.Config{}

	s := &Server{
		Server: &http.Server{
			Addr:    ":9092",
			Handler: mux,
		},
		device:       device,
		privateKey:   privateKey,
		tunnels:      make(map[string]peer),
		peerLastSeen: make(map[string]time.Time),
		proxies:      make(map[int]io.Closer),
		subnet:       netip.MustParsePrefix("10.0.0.0/24"),
		nextIP:       netip.MustParsePrefix("10.0.0.0/24").Addr().Next(),
		// nextPort removed — no dynamic port allocation
		ConnectionSecret: "test-secret",
		VhostProxy:       NewVHostProxy(device),
		apiTLSConfig:     apiTLSCfg,
		challenges:       make(map[string]string),
	}

	mux.HandleFunc("/connect", s.handleConnect)
	mux.HandleFunc("/healthcheck", s.handleHealthcheck)
	mux.HandleFunc("/shutdown", s.handleShutdown)
	mux.HandleFunc("/login", s.handleLogin)
	go s.startJanitor(30 * time.Second)

	return s
}

func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
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

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(s.ConnectionSecret), nil
	})

	if err != nil {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	if !token.Valid {
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

	// Determine tunnel identifier: prefer provided tunnel name, otherwise fall back to client public key hex.
	tunnelName := req.TunnelName
	if tunnelName == "" {
		// fallback to client public key as identifier (legacy behavior)
		tunnelName = hex.EncodeToString(clientPublicKey[:])
	}
	// If the tunnel is new, allocate an IP from the subnet.
	if _, ok := s.tunnels[tunnelName]; !ok {
		if !s.subnet.Contains(s.nextIP) {
			return nil, fmt.Errorf("subnet exhausted")
		}
		s.tunnels[tunnelName] = peer{
			ip:        s.nextIP,
			publicKey: clientPublicKey,
		}
		s.nextIP = s.nextIP.Next()
	}
	peerIP := s.tunnels[tunnelName].ip
	// mark as seen now (new connection). Record by tunnelName.
	s.peerLastSeen[tunnelName] = time.Now()

	// Build wgtypes.Config from current tunnels for consistent UAPI generation.
	cfg := wgtypes.Config{}
	for _, p := range s.tunnels {
		cfg.Peers = append(cfg.Peers, wgtypes.PeerConfig{
			PublicKey:  p.publicKey,
			AllowedIPs: []net.IPNet{{IP: net.IP(p.ip.AsSlice()), Mask: net.CIDRMask(32, 32)}},
		})
	}
	newConfig, err := ConfigToString(cfg)
	if err != nil {
		log.Printf("ConfigToString failed: %v; exiting server", err)
		os.Exit(1)
	}

	if s.device != nil {
		// Defensive logging: record that we're preparing an IPC config update.
		// Compute checksum of the new config and compare with the device's current IPC state.
		log.Printf("IpcSet: preparing peer config update (replace_peers=%t)", strings.Contains(newConfig, "replace_peers=true"))
		if s.device.Device == nil {
			log.Printf("IpcSet: device.Device is nil (device closed?)")
			return nil, fmt.Errorf("device closed (cannot configure peers)")
		}
		log.Printf("IpcSet: device not nil")
		if s.isShuttingDown() {
			log.Printf("IpcSet: server is shutting down; refusing to configure peers")
			return nil, fmt.Errorf("server shutting down (cannot configure peers)")
		}
		log.Printf("IpcSet: device not shutting down")
		// Read current device config for comparison.
		currentConfig, getErr := s.device.Device.IpcGet()
		if getErr != nil {
			// If we cannot read current config, log and proceed to attempt an update.
			log.Printf("IpcSet: failed to read current device config: %v; will attempt to apply new config", getErr)
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
		log.Printf("IpcSet: comparing configs for change detection")
		if sanitizedCurrent == sanitizedNew && sanitizedCurrent != "" {
			log.Printf("IpcSet: skipping apply; device config unchanged")
		} else {
			log.Printf("IpcSet: applying peer config")
			err = s.device.Device.IpcSet(newConfig)
			if err != nil {
				// On error, fetch and log current device state (sanitized) to help debugging.
				log.Printf("IpcSet error: %v", err)
				if cur, e := s.device.Device.IpcGet(); e == nil {
					// redact private_key before logging
					redacted := sanitize(cur)
					log.Printf("IpcSet: current device IPC state after error (redacted):\n%s", redacted)
				} else {
					log.Printf("IpcSet: failed to read device IPC after error: %v", e)
				}
				return nil, fmt.Errorf("failed to configure peer: %w", err)
			}
		}
	}

	serverPort := 0
	if req.Hostname != "" {
		target, err := url.Parse(fmt.Sprintf("http://%s:%d", peerIP.String(), req.RemotePort))
		if err != nil {
			return nil, fmt.Errorf("failed to parse target url: %w", err)
		}
		// If certificate PEM/key provided, register TLS vhost
		if req.CertificatePEM != "" && req.PrivateKeyPEM != "" {
			if err := s.VhostProxy.AddHostWithTLS(req.Hostname, target, req.CertificatePEM, req.PrivateKeyPEM); err != nil {
				return nil, fmt.Errorf("failed to add TLS vhost: %w", err)
			}
			// Mount the TLS handler onto a listener on the public port only when required.
			// Defer binding to well-known ports (80/443, or configured public ports) until this point to avoid
			// occupying them unnecessarily.
			handler := s.VhostProxy.GetTLSHandler(req.Hostname)
			tlsCfg := s.VhostProxy.GetTLSConfig(req.Hostname)
			if handler == nil || tlsCfg == nil {
				return nil, fmt.Errorf("tls handler or config missing for host %s", req.Hostname)
			}
			publicPort := 443
			// If a specific RemotePort is provided, prefer it for tests or non-standard setups.
			if req.RemotePort != 0 {
				publicPort = req.RemotePort
			}
			// Only create the listener when needed (deferred bind).
			if _, exists := s.proxies[publicPort]; !exists {
				log.Printf("Bind: attempting to listen on public port %d for host %s", publicPort, req.Hostname)
				bindStart := time.Now()
				ln, err := net.Listen("tcp", fmt.Sprintf(":%d", publicPort))
				bindElapsed := time.Since(bindStart)
				log.Printf("Bind: net.Listen returned in %s (err: %v)", bindElapsed, err)
				if err != nil {
					return nil, fmt.Errorf("failed to listen on public port %d: %w", publicPort, err)
				}
				tlsLn := tls.NewListener(ln, tlsCfg)
				s.proxies[publicPort] = tlsLn
				log.Printf("Bind: created TLS listener on port %d for host %s", publicPort, req.Hostname)
				go func() {
					if err := http.Serve(tlsLn, handler); err != nil && err != http.ErrServerClosed {
						log.Printf("TLS vhost serve error: %v", err)
					}
				}()
			}
		} else {
			s.VhostProxy.AddHost(req.Hostname, target)
		}
		// Decide serverPort for hostname (vhost) requests.
		if req.CertificatePEM != "" && req.PrivateKeyPEM != "" {
			// TLS vhost: honor requested RemotePort when provided, otherwise default to 443
			if req.RemotePort != 0 {
				serverPort = req.RemotePort
			} else {
				serverPort = 443
			}
		} else {
			// Non-TLS hostname vhost:
			// - If client requested a specific RemotePort, attempt to reserve it and validate availability.
			// - If it's not available, return port_conflict so the HTTP handler maps it to HTTP 409.
			// - If no RemotePort requested, allocate from nextPort (same behavior as direct tunnels).
			if req.RemotePort != 0 {
				if _, exists := s.proxies[req.RemotePort]; exists {
					log.Printf("Serve: hostname non-TLS requested port %d already reserved", req.RemotePort)
					return nil, fmt.Errorf("port_conflict:%d", req.RemotePort)
				}
				// Try binding to ensure the port is free at the OS level.
				log.Printf("Serve: hostname non-TLS attempting to bind requested port %d for host %s", req.RemotePort, req.Hostname)
				ln, err := net.Listen("tcp", fmt.Sprintf(":%d", req.RemotePort))
				if err != nil {
					log.Printf("Serve: failed to bind requested port %d for host %s: %v", req.RemotePort, req.Hostname, err)
					return nil, fmt.Errorf("port_conflict: %d", req.RemotePort)
				}
				// Close immediately; we only needed to verify availability.
				ln.Close()
				serverPort = req.RemotePort
				// Note: For non-TLS vhost, we don't create a listener here since it's handled by VhostProxy
				// We don't reserve the port in s.proxies since VhostProxy handles the listener
				log.Printf("Serve: non-TLS vhost port %d will be handled by VhostProxy for host %s", serverPort, req.Hostname)
			} else {
				// dynamic allocation removed — this code path should no longer be reachable.
				return nil, fmt.Errorf("missing_port_for_protocol")
			}
		}
	} else {
		// For non-vhost (direct) tunnels, prefer the requested RemotePort when provided.
		// If the client specified a RemotePort, attempt to reserve that public port.
		// If it's unavailable, return an error so the HTTP handler can translate it into a 409 Conflict.
		if req.RemotePort != 0 {
			// Check if requested port is already reserved by our proxies map.
			if _, exists := s.proxies[req.RemotePort]; exists {
				return nil, fmt.Errorf("port_conflict:%d", req.RemotePort)
			}
			serverPort = req.RemotePort
			// Note: Port reservation moved to after successful listener creation to avoid nil entries
		} else {
			// dynamic allocation removed
			return nil, fmt.Errorf("missing_port_for_protocol")
		}
	}
	protocol := "tcp"
	if req.Protocol != "" {
		protocol = req.Protocol
	}

	if s.device != nil {
		if protocol == "tcp" {
			// ONLY LISTEN IF NOT VHOST
			if req.Hostname == "" {
				listener, err := net.Listen("tcp", fmt.Sprintf(":%d", serverPort))
				if err != nil {
					return nil, fmt.Errorf("failed to listen on public port %d: %w", serverPort, err)
				}
				// Reserve the port only after successfully creating the listener
				s.proxies[serverPort] = listener

				go func() {
					for {
						conn, err := listener.Accept()
						if err != nil {
							log.Printf("Failed to accept new connection on public port: %v", err)
							return
						}

						clientAddrStr := fmt.Sprintf("%s:%d", peerIP.String(), req.RemotePort)
						log.Printf("Accept: new public connection from %s, dialing client at %s", conn.RemoteAddr(), clientAddrStr)
						dialStart := time.Now()
						ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
						targetConn, err := s.device.NetStack.DialContext(ctx, "tcp", clientAddrStr)
						cancel()
						dialElapsed := time.Since(dialStart)
						if err != nil {
							log.Printf("Failed to dial to client (took %s): %v", dialElapsed, err)
							conn.Close()
							continue
						}
						log.Printf("Dial to client succeeded (took %s), starting TCPProxy", dialElapsed)
						go TCPProxy(conn, targetConn)
					}
				}()
			}
		} else if protocol == "udp" {
			addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", serverPort))
			if err != nil {
				return nil, fmt.Errorf("failed to resolve public udp addr %d: %w", serverPort, err)
			}
			publicConn, err := net.ListenUDP("udp", addr)
			if err != nil {
				return nil, fmt.Errorf("failed to listen on public udp port %d: %w", serverPort, err)
			}
			// Reserve the port only after successfully creating the listener
			s.proxies[serverPort] = publicConn

			clientAddrStr := fmt.Sprintf("%s:%d", peerIP.String(), req.RemotePort)
			targetConn, err := s.device.NetStack.Dial("udp", clientAddrStr)
			if err != nil {
				publicConn.Close()
				return nil, fmt.Errorf("failed to dial to client: %w", err)
			}

			go UDPProxy(publicConn, targetConn)
		}
	}

	publicKey := s.privateKey.PublicKey()
	// Map certain error messages to more specific HTTP-handling codes in the caller.
	// The HTTP handler will translate:
	//   - "port_conflict:<port>" -> 409 Conflict
	//   - "missing_port_for_protocol" or "url_missing_port" -> 422 Unprocessable Entity
	resp := &types.ConnectResponse{
		ServerPublicKey: hex.EncodeToString(publicKey[:]),
		ClientAddress:   peerIP.String(),
		AllowedIPs:      s.subnet.String(),
		ServerPort:      serverPort,
	}

	return resp, nil
}

func Tunnel(resp *types.ConnectResponse, privateKey wgtypes.Key) (*wireguard.UserspaceDevice, error) {
	clientAddress, err := netip.ParseAddr(resp.ClientAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to parse client address: %w", err)
	}

	conf := fmt.Sprintf(`private_key=%s
public_key=%s
allowed_ip=%s
endpoint=%s
persistent_keepalive_interval=1`,
		hex.EncodeToString(privateKey[:]),
		resp.ServerPublicKey,
		resp.AllowedIPs,
		"127.0.0.1:9092",
	)

	device, err := wireguard.NewUserspaceDevice(conf, []netip.Addr{clientAddress})
	if err != nil {
		return nil, fmt.Errorf("failed to create wireguard device: %w", err)
	}

	return device, nil
}

func (s *Server) handleHealthcheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Validate JWT token from Authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		log.Printf("handleHealthcheck: missing Authorization header")
		http.Error(w, "Authorization header required", http.StatusUnauthorized)
		return
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		log.Printf("handleHealthcheck: invalid Authorization header format")
		http.Error(w, "Invalid Authorization header", http.StatusUnauthorized)
		return
	}

	tokenString := parts[1]

	// Parse and validate JWT token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(s.ConnectionSecret), nil
	})

	if err != nil {
		log.Printf("handleHealthcheck: failed to parse JWT: %v", err)
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	if !token.Valid {
		log.Printf("handleHealthcheck: invalid JWT token")
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	// Extract proxy name from JWT claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		log.Printf("handleHealthcheck: failed to extract JWT claims")
		http.Error(w, "Invalid token claims", http.StatusUnauthorized)
		return
	}

	proxyName, ok := claims["sub"].(string)
	if !ok || proxyName == "" {
		log.Printf("handleHealthcheck: missing or invalid proxy name in JWT sub claim")
		http.Error(w, fmt.Sprintf("Missing proxy name in token %v", claims), http.StatusBadRequest)
		return
	}

	log.Printf("handleHealthcheck: received healthcheck for proxy '%s'", proxyName)

	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if the proxy (tunnel) exists
	peer, exists := s.tunnels[proxyName]
	if !exists {
		log.Printf("handleHealthcheck: proxy '%s' not found", proxyName)
		http.Error(w, fmt.Sprintf("Proxy '%s' not found", proxyName), http.StatusNotFound)
		return
	}

	// Update last seen time for this proxy
	s.peerLastSeen[proxyName] = time.Now()

	// Check if the proxy is healthy by verifying the peer is still configured
	// and the WireGuard device is available
	if s.device == nil {
		log.Printf("handleHealthcheck: device is nil for proxy '%s' -- triggering shutdown", proxyName)
		// If the device is unavailable, trigger shutdown so the tunnel process exits.
		// Set closing so other handlers stop mutating state, then close device if present and exit process.
		s.closing = true
		// Attempt to close any proxy listeners.
		for _, listener := range s.proxies {
			if listener != nil {
				log.Printf("handleHealthcheck: closing proxy listener due to unhealthy device: %T", listener)
				listener.Close()
			}
		}
		// If device exists, close underlying device handle.
		if s.device != nil {
			log.Printf("handleHealthcheck: closing wireguard device due to unhealthy device")
			// Close underlying device handle if present. UserspaceDevice embeds a Device field with Close method.
			if s.device.Device != nil {
				// Call Close() and ignore its (non-existent) return value if it's declared as func() in this type,
				// otherwise log any error returned. Use a type assertion to check for an interface with Close() error.
				type closer interface {
					Close() error
				}
				if c, ok := any(s.device.Device).(closer); ok {
					if err := c.Close(); err != nil {
						log.Printf("handleHealthcheck: error closing device: %v", err)
					}
				} else {
					// If the device has a Close method with no return value, call it via reflection-free direct call.
					// We assume device.Device has a Close method; if it does not, skip.
					// (This branch is defensive and should rarely be taken.)
					log.Printf("handleHealthcheck: device does not implement Close() error; skipping explicit close")
				}
			}
			s.device = nil
		}
		// Exit the process to ensure the tunnel runner stops.
		go func() {
			// give the HTTP response a moment to be written before exit
			time.Sleep(100 * time.Millisecond)
			log.Printf("handleHealthcheck: exiting process due to failed healthcheck for proxy '%s'", proxyName)
			os.Exit(1)
		}()
		http.Error(w, "Server device unavailable - shutting down", http.StatusServiceUnavailable)
		return
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
		log.Printf("handleHealthcheck: failed to encode response for proxy '%s': %v", proxyName, err)
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}

	log.Printf("handleHealthcheck: proxy '%s' is healthy", proxyName)
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
					delete(s.peerLastSeen, k)
					log.Printf("janitor: removed stale peer last-seen for %s", k)
				}
			}
			s.mu.Unlock()
		}
	}()
}

func (s *Server) isShuttingDown() bool {
	return s.closing
}

func (s *Server) handleShutdown(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	// mark as closing first to prevent races where Serve tries to IpcSet concurrently.
	s.closing = true
	defer s.mu.Unlock()

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// Optional: allow client to request cleanup for a specific peer using header
	if pk := r.Header.Get("X-Client-Pubkey"); pk != "" {
		// remove tunnel by name (support legacy pk header where possible)
		// If the header contains exactly a tunnel name, treat it as such; otherwise remove matching tunnel by public-key-hex.
		for name := range s.tunnels {
			if name == pk {
				delete(s.tunnels, name)
				delete(s.peerLastSeen, name)
				// best-effort: close any proxies associated (proxies keyed by port)
			}
		}
		// Also support legacy public-key-hex removal: if header matches a hex public key, remove tunnels whose
		// fallback identifier equals that hex. (This loop is intentionally the same as above
		// but kept for clarity for future migration paths.)
		for name := range s.tunnels {
			if name == pk {
				delete(s.tunnels, name)
				delete(s.peerLastSeen, name)
			}
		}
		w.WriteHeader(http.StatusOK)
		return
	}
	for _, listener := range s.proxies {
		if listener != nil {
			log.Printf("handleShutdown: closing proxy listener: %T", listener)
			listener.Close()
		} else {
			log.Printf("handleShutdown: skipping nil proxy listener (port reservation)")
		}
	}
	if s.device != nil {
		// Instrument device.Close so we can trace when the device is being closed.
		log.Printf("handleShutdown: closing wireguard device")
		s.device.Device.Close()
		log.Printf("handleShutdown: wireguard device closed")
		// Set device to nil so other goroutines see it's closed without racing on s.device.Device.
		s.device = nil
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
			var parts []string
			for _, ipNet := range peer.AllowedIPs {
				parts = append(parts, ipNet.String())
			}
			b.WriteString(fmt.Sprintf("allowed_ip=%s\n", strings.Join(parts, ",")))
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
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
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

	encrypted, err := encrypt(s.ConnectionSecret, "server-"+challenge)
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

	decrypted, err := decrypt(s.ConnectionSecret, encrypted)
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
