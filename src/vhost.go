package server

import (
	"crypto/tls"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"

	"aquaduct.dev/weft/wireguard"
)

// VHostProxy manages name-based vhosts and optional TLS-termination handlers.
type VHostProxy struct {
	mu             sync.RWMutex
	hosts          map[string]http.Handler
	defaultHandler http.Handler
	device         *wireguard.UserspaceDevice
	// tlsHandlers holds HTTPS handlers per hostname when TLS termination is configured.
	tlsHandlers map[string]http.Handler
	// tlsConfigs holds tls.Config per hostname for mounting listeners.
	tlsConfigs map[string]*tls.Config
}

// NewVHostProxy creates a new VHostProxy backed by the provided userspace device.
func NewVHostProxy(device *wireguard.UserspaceDevice) *VHostProxy {
	return &VHostProxy{
		hosts:          make(map[string]http.Handler),
		defaultHandler: http.NotFoundHandler(),
		device:         device,
		tlsHandlers:    make(map[string]http.Handler),
		tlsConfigs:     make(map[string]*tls.Config),
	}
}

// AddHost registers an HTTP reverse proxy for the given host.
func (p *VHostProxy) AddHost(host string, target *url.URL) {
	p.mu.Lock()
	defer p.mu.Unlock()

	proxy := httputil.NewSingleHostReverseProxy(target)
	// Attach transport that uses the userspace device if present, and accept self-signed certs for upstreams.
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	if p != nil && p.device != nil {
		tr.DialContext = p.device.NetStack.DialContext
	}
	proxy.Transport = tr
	p.hosts[host] = proxy
}

// AddHostWithTLS registers both an HTTP reverse proxy and a TLS termination handler
// using the provided PEM certificate and key.
/* AddHostWithTLS already declared earlier; no-op here to avoid duplicate definition. */
// AddHostWithTLS registers a host reverse proxy and an HTTPS handler that
// terminates TLS using the provided certificate and key PEM strings.
func (p *VHostProxy) AddHostWithTLS(host string, target *url.URL, certPEM, keyPEM string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	proxy := httputil.NewSingleHostReverseProxy(target)
	// Attach transport that uses the userspace device if present, and accept self-signed certs for upstreams.
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	if p != nil && p.device != nil {
		tr.DialContext = p.device.NetStack.DialContext
	}
	proxy.Transport = tr
	p.hosts[host] = proxy

	// Create TLS server mux for this host that uses the same proxy.
	mux := http.NewServeMux()
	mux.Handle("/", proxy)

	// Create a tls.Config from the PEMs.
	cert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return err
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

	return nil
}

func (p *VHostProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.mu.RLock()
	proxy, ok := p.hosts[r.Host]
	httpsHandler, httpsOk := p.tlsHandlers[r.Host]
	p.mu.RUnlock()
	if ok {
		proxy.ServeHTTP(w, r)
		return
	}
	if httpsOk {
		httpsHandler.ServeHTTP(w, r)
		return
	}
	p.defaultHandler.ServeHTTP(w, r)
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
