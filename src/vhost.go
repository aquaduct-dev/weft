package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/acme/autocert"
)

// VHostProxy manages name-based vhosts and optional TLS-termination handlers.
type VHostProxy struct {
	mu sync.RWMutex
	s  *http.Server

	hosts map[string]http.Handler
	port  int

	manager *VHostProxyManager

	defaultHandler http.Handler
	// tlsHandlers holds HTTPS handlers per hostname when TLS termination is configured.
	tlsHandlers map[string]http.Handler
	// tlsConfigs holds tls.Config per hostname for mounting listeners.
	tlsConfigs map[string]*tls.Config
}

type VHostProxyManager struct {
	proxies     map[int]*VHostProxy
	mu          sync.Mutex
	acmeManager *autocert.Manager
	acmeHosts   map[string]bool
	acmePort    int
	acmeEmail   string
}

func NewVHostProxyManager() *VHostProxyManager {
	m := &VHostProxyManager{
		proxies:   make(map[int]*VHostProxy),
		acmeHosts: make(map[string]bool),
		acmePort:  80,
	}
	m.acmeManager = &autocert.Manager{
		Prompt: autocert.AcceptTOS,
		HostPolicy: func(ctx context.Context, host string) error {
			m.mu.Lock()
			defer m.mu.Unlock()
			if !m.acmeHosts[host] {
				return fmt.Errorf("acme: host %s not configured for acme", host)
			}
			return nil
		},
		Cache: autocert.DirCache("certs"),
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

func (v *VHostProxyManager) ACMEPort() int {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.acmePort
}

func (v *VHostProxyManager) AddACMEHost(host string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.acmeHosts[host] = true
}

func (v *VHostProxyManager) Proxy(port int) *VHostProxy {
	v.mu.Lock()
	defer v.mu.Unlock()
	proxy, ok := v.proxies[port]
	if ok {
		return proxy
	}
	v.proxies[port] = NewVHostProxy(port, v)
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
		log.Info().Int("port", v.VHostProxy.port).Msg("Shutting down VHost proxy (no proxies)")
		v.VHostProxy.s.Close()
		v.VHostProxy.manager.mu.Lock()
		delete(v.VHostProxy.manager.proxies, v.VHostProxy.port)
		v.VHostProxy.manager.mu.Unlock()
	}
	return nil
}

// NewVHostProxy creates a new VHostProxy backed by the provided userspace device.
func NewVHostProxy(port int, manager *VHostProxyManager) *VHostProxy {
	return &VHostProxy{
		hosts:          make(map[string]http.Handler),
		manager:        manager,
		port:           port,
		defaultHandler: http.NotFoundHandler(),
		tlsHandlers:    make(map[string]http.Handler),
		tlsConfigs:     make(map[string]*tls.Config),
	}
}

// AddHost registers an HTTP reverse proxy for the given host.
func (p *VHostProxy) AddHost(host string, target *url.URL) (VHostCloser, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	proxy := httputil.NewSingleHostReverseProxy(target)

	p.hosts[host] = proxy
	go p.Serve()
	log.Info().Str("host", host).Int("port", p.port).Str("target", target.String()).Msg("VHost: HTTP proxy configured")
	return VHostCloser{VHostProxy: p, Host: host, Tls: false}, nil
}

// AddHostWithTLS registers both an HTTP reverse proxy and a TLS termination handler
// using the provided PEM certificate and key.
/* AddHostWithTLS already declared earlier; no-op here to avoid duplicate definition. */
// AddHostWithTLS registers a host reverse proxy and an HTTPS handler that
// terminates TLS using the provided certificate and key PEM strings.
func (p *VHostProxy) AddHostWithTLS(host string, target *url.URL, certPEM, keyPEM string) (VHostCloser, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	proxy := httputil.NewSingleHostReverseProxy(target)
	// Attach transport that uses the userspace device if present, and accept self-signed certs for upstreams.
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	proxy.Transport = tr
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
	go p.Serve()
	log.Info().Str("host", host).Int("port", p.port).Str("target", target.String()).Msg("VHost: HTTPS proxy configured")
	return VHostCloser{VHostProxy: p, Host: host, Tls: true}, nil
}

// AddHostWithACME registers an HTTP reverse proxy and enables ACME for the given host.
func (p *VHostProxy) AddHostWithACME(host string, target *url.URL) (VHostCloser, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	proxy := httputil.NewSingleHostReverseProxy(target)
	p.hosts[host] = proxy

	p.manager.AddACMEHost(host)

	go p.Serve()
	log.Info().Str("host", host).Int("port", p.port).Str("target", target.String()).Msg("VHost: ACME proxy configured")
	return VHostCloser{VHostProxy: p, Host: host, Tls: true}, nil
}

func (p *VHostProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := strings.Split(r.Host, ":")[0]
	if p.port == p.manager.acmePort && p.manager.acmeManager != nil && strings.HasPrefix(r.URL.Path, "/.well-known/acme-challenge/") {
		p.manager.acmeManager.HTTPHandler(nil).ServeHTTP(w, r)
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
	p.mu.RLock()
	defer p.mu.RUnlock()
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

func (p *VHostProxy) Serve() {
	if p.s != nil {
		log.Debug().Int("port", p.port).Msg("VHost: already serving")
		return
	}
	p.s = &http.Server{
		Addr:    fmt.Sprintf(":%d", p.port),
		Handler: p,
	}

	if p.hasTLS() {
		log.Info().Int("port", p.port).Msg("VHost: serving with TLS")
		tlsConfig := &tls.Config{
			GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
				p.mu.RLock()
				defer p.mu.RUnlock()
				if cfg, ok := p.tlsConfigs[hello.ServerName]; ok {
					// Assuming one certificate per config
					if len(cfg.Certificates) > 0 {
						return &cfg.Certificates[0], nil
					}
				}
				if p.manager.acmeManager != nil {
					return p.manager.acmeManager.GetCertificate(hello)
				}
				return nil, fmt.Errorf("no certificate for server name %s", hello.ServerName)
			},
		}
		l, err := tls.Listen("tcp", fmt.Sprintf(":%d", p.port), tlsConfig)
		if err != nil {
			log.Error().Err(err).Int("port", p.port).Msg("VHost: tls.Listen failed")
			return
		}
		p.s.Serve(l)
	} else {
		log.Info().Int("port", p.port).Msg("VHost: serving")
		p.s.ListenAndServe()
	}

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
