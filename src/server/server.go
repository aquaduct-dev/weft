/*
This package implements the REST server for the Weft control plane.
*/
package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aquaduct-dev/weft/src/crypto"
	"github.com/aquaduct-dev/weft/src/dns"
	"github.com/aquaduct-dev/weft/src/internal/constants"
	"github.com/aquaduct-dev/weft/wireguard"
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

	// certPEM is the PEM-encoded server certificate, sent encrypted during login
	// to prevent MITM attacks.
	certPEM []byte

	// certFingerprintHex is the lowercase hex sha256 of the leaf certificate
	// DER bytes, suitable for out-of-band pinning by clients (F-10).
	certFingerprintHex string

	// challenges maps remote client addresses to their active login challenges.
	// Entries expire after challengeTTL; the map is bounded by
	// maxOutstandingChallenges to prevent unauthenticated memory exhaustion.
	challenges map[string]challengeEntry

	// janitor handles periodic cleanup of stale tunnels.
	janitor *Janitor

	// UsageReporter handles periodic usage reporting to external services.
	UsageReporter *HTTPUsageReporter
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

	// Compute the leaf cert sha256 fingerprint for operator-side pinning (F-10).
	var fingerprintHex string
	if len(cert.Certificate) > 0 {
		sum := sha256.Sum256(cert.Certificate[0])
		fingerprintHex = hex.EncodeToString(sum[:])
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
		Store:              NewInMemoryTunnelStore(),
		ConnectionSecret:   connectionSecret,
		apiTLSConfig:       apiTLSCfg,
		certPEM:            certPEM,
		certFingerprintHex: fingerprintHex,
		challenges:         make(map[string]challengeEntry),
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

	mux.HandleFunc("/connect", s.requireJWT(s.ConnectHandler))
	mux.HandleFunc("/healthcheck", s.requireJWT(s.HealthcheckHandler))
	mux.HandleFunc("/shutdown", s.requireJWT(s.ShutdownHandler))
	mux.HandleFunc("/login", s.LoginHandler)
	mux.HandleFunc("/list", s.requireJWT(s.ListHandler))
	mux.HandleFunc("/metrics", s.MetricsHandler)
	mux.HandleFunc("/version", s.VersionHandler)

	s.UsageReporter = NewHTTPUsageReporter(
		usageReportingURL,
		1*time.Minute,
		s.Dataplane.GetProxyCounters,
		s.Store.GetAllPeers,
		s.isShuttingDown,
	)
	s.UsageReporter.Start()

	s.janitor = NewJanitor(
		5*time.Second,
		s.Store,
		s.RemoveTunnel,
		s.UsageReporter.ReportUsage,
		s.isShuttingDown,
	)
	s.janitor.Start()

	return s
}

// MetricsHandler serves Prometheus-formatted usage metrics for all active tunnels.


func generateRandomSecret(length int) (string, error) {
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		return "", fmt.Errorf("failed to read random bytes: %w", err)
	}
	return base64.URLEncoding.EncodeToString(b), nil
}



// HealthcheckHandler provides an endpoint for clients to report their health status.


// reportUsage delegates to the usage reporter for on-demand reporting.
func (s *Server) reportUsage(ctx context.Context, tunnels []string) {
	if s.UsageReporter != nil {
		s.UsageReporter.ReportUsage(ctx, tunnels)
	}
}



func (s *Server) isShuttingDown() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closing
}

// CertFingerprint returns the lowercase hex sha256 fingerprint of the server's
// TLS leaf certificate. It's intended for operator-side display so clients can
// pin against it via the auth.PinnedFingerprint mechanism (F-10).
func (s *Server) CertFingerprint() string {
	return s.certFingerprintHex
}


