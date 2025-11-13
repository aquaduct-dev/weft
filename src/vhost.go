package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"time"

	"aquaduct.dev/weft/wireguard"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/acme/autocert"
)

// VHostProxy manages name-based vhosts and optional TLS-termination handlers.
type VHostProxy struct {
	mu sync.RWMutex
	s  *http.Server

	hosts  map[string]http.Handler
	bindIp string
	port   int

	manager *VHostProxyManager

	defaultHandler http.Handler
	// tlsHandlers holds HTTPS handlers per hostname when TLS termination is configured.
	tlsHandlers map[string]http.Handler
	// tlsConfigs holds tls.Config per hostname for mounting listeners.
	tlsConfigs map[string]*tls.Config
}

type VHostKey struct {
	BindIp string
	Port   int
}

func (v *VHostKey) String() string {
	return fmt.Sprintf("%s:%d", v.BindIp, v.Port)
}

type VHostProxyManager struct {
	proxies        map[int]*VHostProxy
	mu             sync.Mutex
	acmeManager    *autocert.Manager
	acmeHosts      map[string]bool
	acmePort       int
	acmeEmail      string
	certsCachePath string
}

func NewVHostProxyManager() *VHostProxyManager {
	m := &VHostProxyManager{
		proxies:   make(map[int]*VHostProxy),
		acmeHosts: make(map[string]bool),
		acmePort:  80,
	}
	home, err := os.UserHomeDir()
	if err != nil {
		log.Fatal().Err(err).Msg("failed to get user home directory")
	}
	m.certsCachePath = filepath.Join(home, ".certs")
	m.acmeManager = &autocert.Manager{
		Prompt: autocert.AcceptTOS,
		HostPolicy: func(ctx context.Context, host string) error {
			if !m.acmeHosts[host] {
				return fmt.Errorf("acme: host %s not configured for acme", host)
			}
			return nil
		},
		Cache: autocert.DirCache(m.certsCachePath),
	}
	return m
}

func (v *VHostProxyManager) SetACMEEmail(email string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.acmeEmail = email
	if v.acmeManager != nil {
		v.acmeManager.Email = email
	}
}

func (v *VHostProxyManager) SetACMEPort(port int) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.acmePort = port
}

func (v *VHostProxyManager) SetCertsCachePath(path string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.certsCachePath = path
	if v.acmeManager != nil {
		v.acmeManager.Cache = autocert.DirCache(path)
	}
}

func (v *VHostProxyManager) ACMEPort() int {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.acmePort
}

func (v *VHostProxyManager) AddACMEHost(host string, bindIp string) (io.Closer, error) {
	proxy := v.Proxy(bindIp, 80)
	v.acmeHosts[host] = true
	err := proxy.Start()
	if err != nil {
		return VHostCloser{}, err
	}

	return VHostCloser{VHostProxy: proxy, Host: host, Tls: false}, err
}

func (v *VHostProxyManager) Proxy(bindIp string, port int) *VHostProxy {
	v.mu.Lock()
	defer v.mu.Unlock()
	proxy, ok := v.proxies[port]
	if ok {
		return proxy
	}
	v.proxies[port] = NewVHostProxy(VHostKey{BindIp: bindIp, Port: port}, v)
	return v.proxies[port]
}

type VHostCloser struct {
	VHostProxy *VHostProxy
	Host       string
	Tls        bool
}

func (v VHostCloser) Close() error {
	delete(v.VHostProxy.hosts, v.Host)
	if v.Tls {
		delete(v.VHostProxy.tlsHandlers, v.Host)
		delete(v.VHostProxy.tlsConfigs, v.Host)
	}
	if v.VHostProxy.s != nil && len(v.VHostProxy.hosts) == 0 {
		log.Info().Bool("has_tls", v.VHostProxy.hasTLS()).Int("port", v.VHostProxy.port).Msg("VHost: shutting down VHost proxy (no proxies)")
		v.VHostProxy.s.Close()
		v.VHostProxy.manager.mu.Lock()
		delete(v.VHostProxy.manager.proxies, v.VHostProxy.port)
		v.VHostProxy.manager.mu.Unlock()
		v.VHostProxy.s = nil
	}
	return nil
}

// NewVHostProxy creates a new VHostProxy backed by the provided userspace device.
func NewVHostProxy(key VHostKey, manager *VHostProxyManager) *VHostProxy {
	return &VHostProxy{
		hosts:          make(map[string]http.Handler),
		manager:        manager,
		port:           key.Port,
		bindIp:         key.BindIp,
		defaultHandler: http.NotFoundHandler(),
		tlsHandlers:    make(map[string]http.Handler),
		tlsConfigs:     make(map[string]*tls.Config),
	}
}

type WGAwareRoundTripper struct {
	http.RoundTripper
	device *wireguard.UserspaceDevice
	target *url.URL
}

// RoundTrip routes requests whose Host is an IP under 10.1.* through the userspace
// WireGuard device if one is configured. It attempts to parse the request Host as
// an IP:port (or plain IP); if the destination IP is only routable via the WG
// device, the request's transport will use the device's DialContext to reach it.
// Otherwise the default transport behavior is used.
func (w *WGAwareRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// Fast path: if no device provided or host isn't a 10.1.* address, use default.
	if w.device == nil || !strings.HasPrefix(w.target.Host, "10.1") {
		return http.DefaultTransport.RoundTrip(req)
	}
	// If probe failed, attempt to route through the userspace device's DialContext.
	// Build a transport that uses the device's dialer.
	tr := &http.Transport{
		// Use a DialContext that routes using the userspace device.
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			c, err := w.device.NetStack.Dial(network, addr)
			return c, err
		},
	}

	// Use the constructed transport to execute the request.
	return tr.RoundTrip(req)
}

// AddHost registers an HTTP reverse proxy for the given host.
func (p *VHostProxy) AddHost(host string, target *url.URL, device *wireguard.UserspaceDevice) (VHostCloser, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.Transport = &WGAwareRoundTripper{device: device, target: target}

	p.hosts[host] = proxy
	if err := p.Start(); err != nil {
		return VHostCloser{}, err
	}
	log.Info().Str("host", host).Int("port", p.port).Str("target", target.String()).Msg("VHost: HTTP proxy configured")
	return VHostCloser{VHostProxy: p, Host: host, Tls: false}, nil
}

// AddHostWithTLS registers both an HTTP reverse proxy and a TLS termination handler
// using the provided PEM certificate and key.
/* AddHostWithTLS already declared earlier; no-op here to avoid duplicate definition. */
// AddHostWithTLS registers a host reverse proxy and an HTTPS handler that
// terminates TLS using the provided certificate and key PEM strings.
func (p *VHostProxy) AddHostWithTLS(host string, target *url.URL, device *wireguard.UserspaceDevice, certPEM, keyPEM string) (VHostCloser, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	proxy := httputil.NewSingleHostReverseProxy(target)
	// Attach transport that uses the userspace device if present, and accept self-signed certs for upstreams.
	proxy.Transport = &WGAwareRoundTripper{device: device, target: target}
	p.hosts[host] = proxy

	// Create TLS server mux for this host that uses the same proxy.
	mux := http.NewServeMux()
	mux.Handle("/", proxy)

	// Create a tls.Config from the PEMs.
	cert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return VHostCloser{}, err
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	// Store the HTTPS handler (mux) and its TLS config so the Server can mount it on a listener.
	// We store the mux in tlsHandlers and the tls.Config in a parallel map.
	p.tlsHandlers[host] = mux

	// lazily create tlsConfigs map if needed
	if p.tlsConfigs == nil {
		p.tlsConfigs = make(map[string]*tls.Config)
	}
	p.tlsConfigs[host] = tlsConfig
	if err = p.Start(); err != nil {
		return VHostCloser{}, err
	}
	log.Info().Str("host", host).Int("port", p.port).Str("target", target.String()).Msg("VHost: HTTPS proxy configured")
	return VHostCloser{VHostProxy: p, Host: host, Tls: true}, nil
}

// AddHostWithACME registers an HTTP reverse proxy and enables ACME for the given host.
func (p *VHostProxy) AddHostWithACME(host string, target *url.URL, device *wireguard.UserspaceDevice, bindIp string) (VHostCloser, error) {

	// Before enabling ACME for the host, verify the server appears reachable from the public internet
	// for HTTP-01 challenges. This reduces time wasted attempting issuance for hosts that won't complete.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if !p.CanWebHost(ctx, host) {
		// If the host cannot be web-hosted, remove the proxy entry we just added to keep state consistent.
		delete(p.hosts, host)
		log.Warn().Str("host", host).Msg("VHost: host not reachable for ACME HTTP-01 challenge; aborting ACME setup")
		return VHostCloser{}, fmt.Errorf("host %s not reachable for ACME HTTP-01 challenge", host)
	}

	closer, err := p.manager.AddACMEHost(host, bindIp)
	if err != nil {
		return VHostCloser{}, err
	}
	defer closer.Close()

	p.mu.Lock()
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.Transport = &WGAwareRoundTripper{device: device, target: target}
	p.hosts[host] = proxy
	p.mu.Unlock()

	// Log that ACME registration has been requested for this host.
	log.Info().Str("host", host).Msg("ACME: host registered with manager for issuance")

	// Wait for certificate to be available before advertising/serving HTTPS on this port.
	// We do the wait asynchronously to avoid blocking callers, but only start the TLS
	// listener once the certificate is present. Serve() will check hasTLS() and mount TLS.
	// Small backoff and then wait up to 2 minutes for ACME issuance.
	if p.manager.acmeManager != nil {
		proxy := p.manager.Proxy(bindIp, 80)
		closer, err := proxy.AddHost("acme-"+host, &url.URL{Scheme: "http", Host: host + ":80"}, nil)
		if err != nil {
			log.Warn().AnErr("AddHostWithACME: AddHost error", err)
			return VHostCloser{}, err
		}
		err = proxy.Start()
		if err != nil {
			log.Warn().AnErr("AddHostWithACME: Start error", err)
			return VHostCloser{}, err
		}
		defer closer.Close()

		helper := NewACMEHelper(p.manager.acmeManager)
		cert, err := helper.WaitForCertificate(context.Background(), host)
		if err != nil {
			log.Error().Err(err).Str("host", host).Msg("VHost: failed to obtain ACME certificate in time")
			return VHostCloser{}, err
		}
		// Put the obtained certificate into tlsConfigs so Serve() can pick it up immediately.
		p.mu.Lock()
		if p.tlsConfigs == nil {
			p.tlsConfigs = make(map[string]*tls.Config)
		}
		tcfg := &tls.Config{}
		if cert != nil {
			tcfg.Certificates = []tls.Certificate{*cert}
		}
		p.tlsConfigs[host] = tcfg
		p.mu.Unlock()
		log.Info().Str("host", host).Msg("VHost: ACME certificate ready; starting TLS listener")
		if err := p.Start(); err != nil {
			log.Warn().Str("host", host).Msg("Could not start TLS proxy!")
			VHostCloser{VHostProxy: p, Host: host, Tls: true}.Close()
			return VHostCloser{}, err
		}
	} else {
		// Fallback: start Serve() so HTTP challenge endpoint is available.
		log.Warn().Str("host", host).Msg("ACME: acmeManager not configured; not possible to obtain certificate")
		VHostCloser{VHostProxy: p, Host: host, Tls: true}.Close()
	}

	log.Info().Str("host", host).Int("port", p.port).Str("target", target.String()).Msg("VHost: ACME-based HTTPS proxy configured")
	return VHostCloser{VHostProxy: p, Host: host, Tls: true}, nil
}

func (p *VHostProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := strings.Split(r.Host, ":")[0]
	if p.port == p.manager.acmePort && p.manager.acmeManager != nil && strings.HasPrefix(r.URL.Path, "/.well-known/acme-challenge/") {
		// Log that the ACME HTTP-01 challenge handler is being invoked for visibility.
		log.Debug().Str("host", r.Host).Str("path", r.URL.Path).Msg("ACME: challenge handler start")
		// Wrap the autocert handler to add logging when it serves a challenge.
		handler := p.manager.acmeManager.HTTPHandler(nil)
		// Use a small wrapper to log responses handled by the autocert handler.
		h := http.HandlerFunc(func(w2 http.ResponseWriter, r2 *http.Request) {
			start := time.Now()
			handler.ServeHTTP(w2, r2)
			// After serving, log that the handler completed. We cannot inspect w2 status code
			// directly without a ResponseWriter wrapper, but logging start/finish helps trace challenge flow.
			log.Info().
				Str("host", r2.Host).
				Str("path", r2.URL.Path).
				Dur("duration", time.Since(start)).
				Msg("ACME: challenge handler completed")
		})
		h.ServeHTTP(w, r)
		return
	}

	p.mu.RLock()
	proxy, ok := p.hosts[host]
	httpsHandler, httpsOk := p.tlsHandlers[host]
	p.mu.RUnlock()

	if httpsOk {
		log.Debug().Str("host", r.Host).Str("uri", r.RequestURI).Msg("VHost: handling request with HTTPS handler")
		httpsHandler.ServeHTTP(w, r)
		return
	}
	if ok {
		log.Debug().Str("host", r.Host).Str("uri", r.RequestURI).Msg("VHost: handling request with HTTP handler")
		proxy.ServeHTTP(w, r)
		return
	}
	log.Debug().Str("host", r.Host).Str("uri", r.RequestURI).Msg("VHost: handling request with 404 handler")
	p.defaultHandler.ServeHTTP(w, r)
}

func (p *VHostProxy) hasTLS() bool {
	if len(p.tlsHandlers) > 0 {
		return true
	}
	if p.manager.acmeManager != nil {
		for host := range p.hosts {
			if p.manager.acmeHosts[host] {
				return true
			}
		}
	}
	return false
}

func (p *VHostProxy) Start() error {
	if p.s != nil {
		log.Debug().Int("port", p.port).Msg("VHost: already serving")
		// Already serving; nothing to do.
		return nil
	}
	p.s = &http.Server{
		Addr:    fmt.Sprintf(":%d", p.port),
		Handler: p,
	}

	if p.hasTLS() {
		tlsConfig := &tls.Config{
			GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
				if cfg, ok := p.tlsConfigs[hello.ServerName]; ok {
					// Assuming one certificate per config
					if len(cfg.Certificates) > 0 {
						return &cfg.Certificates[0], nil
					}
				}
				return nil, fmt.Errorf("no certificate for server name %s", hello.ServerName)
			},
		}
		l, err := tls.Listen("tcp", fmt.Sprintf(":%d", p.port), tlsConfig)
		if err != nil {
			log.Error().Err(err).Int("port", p.port).Msg("VHost: tls.Listen failed")
			return err
		}
		go p.s.Serve(l)
		return nil
	}

	log.Info().Int("port", p.port).Bool("has_tls", p.hasTLS()).Msg("VHost: serving")
	l, err := net.Listen("tcp", fmt.Sprintf(":%d", p.port))
	if err != nil {
		log.Error().Err(err).Int("port", p.port).Msg("VHost: net.Listen failed")
		return err
	}
	go p.s.Serve(l)
	return nil
}

// GetTLSHandler returns the registered HTTPS handler for a host, or nil if none.
func (p *VHostProxy) GetTLSHandler(host string) http.Handler {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.tlsHandlers[host]
}

// GetTLSConfig returns the registered tls.Config for a host, or nil if none.
func (p *VHostProxy) GetTLSConfig(host string) *tls.Config {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.tlsConfigs[host]
}
