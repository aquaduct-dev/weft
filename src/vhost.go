package server

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
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
	proxies map[int]*VHostProxy
	mu      sync.Mutex
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
		log.Printf("Shutting down VHost proxy on port %d (no proxies)", v.VHostProxy.port)
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
	log.Printf("VHost: HTTP proxy configured for %s:%d -> %s", host, p.port, target.String())
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
	log.Printf("VHost: HTTPS proxy configured for %s:%d -> %s", host, p.port, target.String())
	return VHostCloser{VHostProxy: p, Host: host, Tls: true}, nil
}

func (p *VHostProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := strings.Split(r.Host, ":")[0]
	p.mu.RLock()
	proxy, ok := p.hosts[host]
	httpsHandler, httpsOk := p.tlsHandlers[host]
	p.mu.RUnlock()

	if httpsOk {
		log.Printf("VHost: handling request for %s%s with HTTPS handler", r.Host, r.RequestURI)
		httpsHandler.ServeHTTP(w, r)
		return
	}
	if ok {
		log.Printf("VHost: handling request for %s%s with HTTP handler", r.Host, r.RequestURI)
		proxy.ServeHTTP(w, r)
		return
	}
	log.Printf("VHost: handling request for %s%s with 404 handler", r.Host, r.RequestURI)
	p.defaultHandler.ServeHTTP(w, r)
}

func (p *VHostProxy) Serve() {
	if p.s != nil {
		log.Printf("VHost: already serving on port %d", p.port)
		return
	}
	p.s = &http.Server{
		Addr:    fmt.Sprintf(":%d", p.port),
		Handler: p,
	}

	if len(p.tlsHandlers) > 0 {
		log.Printf("VHost: serving with TLS on port %d", p.port)
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
				return nil, fmt.Errorf("no certificate for server name %s", hello.ServerName)
			},
		}
		l, err := tls.Listen("tcp", fmt.Sprintf(":%d", p.port), tlsConfig)
		if err != nil {
			log.Printf("VHost: tls.Listen on port %d failed: %v", p.port, err)
			return
		}
		p.s.Serve(l)
	} else {
		log.Printf("VHost: serving on port %d", p.port)
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
