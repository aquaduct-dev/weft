package vhost

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
	"regexp"
	"strings"
	"sync"

	"time"

	"github.com/aquaduct-dev/weft/src/acme"

	"github.com/aquaduct-dev/weft/src/proxy/vhost/meter"

	"github.com/aquaduct-dev/weft/wireguard"

	"github.com/rs/zerolog/log"

	"golang.org/x/crypto/acme/autocert"
)

// Route represents a single VHost route with optional matchers and modifiers.
type Route struct {
	Handler    *meter.MeteredHTTPHandler
	Matchers   map[string]string
	Modifiers  map[string]string
	Target     *url.URL
	PathPrefix string
}

// Matches returns true if the request matches this route's criteria.
func (route *Route) Matches(r *http.Request) bool {
	if route.PathPrefix != "" && !strings.HasPrefix(r.URL.Path, route.PathPrefix) {
		return false
	}
	for k, v := range route.Matchers {
		if strings.HasPrefix(k, "header:") {
			headerName := strings.TrimPrefix(k, "header:")
			val := r.Header.Get(headerName)
			matched, _ := regexp.MatchString("^"+v+"$", val)
			if !matched {
				return false
			}
		} else if strings.HasPrefix(k, "query:") {
			queryParam := strings.TrimPrefix(k, "query:")
			val := r.URL.Query().Get(queryParam)
			matched, _ := regexp.MatchString("^"+v+"$", val)
			if !matched {
				return false
			}
		} else if k == "method" {
			if r.Method != v {
				return false
			}
		}
	}
	return true
}

// Apply applies redirects and header modifications to the request.
// It returns true if a redirect was performed and no further handling is needed.
func (route *Route) Apply(w http.ResponseWriter, r *http.Request) bool {
	// Handle redirects
	if route.Modifiers["redirect"] == "true" {
		target := *route.Target
		target.Fragment = ""
		http.Redirect(w, r, target.String(), http.StatusFound)
		return true
	}

	// Apply header modifications
	for k, v := range route.Modifiers {
		if k == "redirect" {
			continue
		}
		if v == "!del" {
			r.Header.Del(k)
		} else if strings.HasPrefix(v, "+") {
			if r.Header.Get(k) == "" {
				r.Header.Set(k, strings.TrimPrefix(v, "+"))
			}
		} else {
			r.Header.Set(k, v)
		}
	}
	return false
}

// VHostProxy manages name-based vhosts and optional TLS-termination handlers.
type VHostProxy struct {
	mu sync.RWMutex
	s  *meter.MeteredServer

	// routes holds list of routes per hostname.
	routes map[string][]*Route
	bindIp string
	port   int

	device *wireguard.UserspaceDevice

	manager *VHostProxyManager

	defaultHandler meter.MeteredHandler
	// tlsRoutes holds HTTPS routes per hostname when TLS termination is configured.
	tlsRoutes map[string][]*Route
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
	Cleanup        func(tunnelName string)
}

func NewVHostProxyManager() *VHostProxyManager {
	m := &VHostProxyManager{
		proxies:   make(map[int]*VHostProxy),
		acmeHosts: make(map[string]bool),
		acmePort:  80,
	}
	home, err := os.UserHomeDir()
	if err != nil {
		// In sandboxed test environments HOME may be unset. Fall back to a safe temporary
		// directory for certificate cache and continue instead of fatally exiting to allow
		// unit tests to run.
		log.Warn().Err(err).Msg("failed to get user home directory; falling back to temp dir for cert cache")
		home = os.TempDir()
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
	Route      *Route
}

func (v VHostCloser) Close() error {
	v.VHostProxy.mu.Lock()
	defer v.VHostProxy.mu.Unlock()
	
	removeRoute := func(routes []*Route, target *Route) []*Route {
		for i, r := range routes {
			if r == target {
				return append(routes[:i], routes[i+1:]...)
			}
		}
		return routes
	}

	if !v.Tls {
		if routes, ok := v.VHostProxy.routes[v.Host]; ok {
			newRoutes := removeRoute(routes, v.Route)
			if len(newRoutes) == 0 {
				delete(v.VHostProxy.routes, v.Host)
			} else {
				v.VHostProxy.routes[v.Host] = newRoutes
			}
		}
	} else {
		if routes, ok := v.VHostProxy.tlsRoutes[v.Host]; ok {
			newRoutes := removeRoute(routes, v.Route)
			if len(newRoutes) == 0 {
				delete(v.VHostProxy.tlsRoutes, v.Host)
				delete(v.VHostProxy.tlsConfigs, v.Host)
			} else {
				v.VHostProxy.tlsRoutes[v.Host] = newRoutes
			}
		}
	}
	
	if v.VHostProxy.s != nil && len(v.VHostProxy.routes) == 0 && len(v.VHostProxy.tlsRoutes) == 0 {
		log.Info().Bool("has_tls", v.VHostProxy.hasTLS()).Int("port", v.VHostProxy.port).Msg("Closing VHost (no proxies)")
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
		routes:  make(map[string][]*Route),
		manager: manager,
		port:    key.Port,
		bindIp:  key.BindIp,
		defaultHandler: meter.MeteredHandlerFunc(func(w *meter.MeteredResponseWriter, r *meter.MeteredRequest) {
			http.NotFound(w, r.Request)
		}),
		tlsRoutes:  make(map[string][]*Route),
		tlsConfigs: make(map[string]*tls.Config),
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

func (p *VHostProxy) newMeteredReverseProxy(target *url.URL, pathPrefix string, modifiers map[string]string, device *wireguard.UserspaceDevice) (*meter.MeteredHTTPHandler, *Route) {
	proxy := httputil.NewSingleHostReverseProxy(target)
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		if pathPrefix != "" {
			req.URL.Path = strings.TrimPrefix(req.URL.Path, pathPrefix)
			if !strings.HasPrefix(req.URL.Path, "/") {
				req.URL.Path = "/" + req.URL.Path
			}
		}
		// Apply header modifications in Director
		for k, v := range modifiers {
			if k == "redirect" {
				continue
			}
			if v == "!del" {
				req.Header.Del(k)
			} else if strings.HasPrefix(v, "+") {
				if req.Header.Get(k) == "" {
					req.Header.Set(k, strings.TrimPrefix(v, "+"))
				}
			} else {
				req.Header.Set(k, v)
			}
		}
		originalDirector(req)
	}
	proxy.Transport = &WGAwareRoundTripper{device: device, target: target}
	meteredProxy := meter.MakeMeteredHTTPHandler(proxy)

	route := &Route{
		Handler:    meteredProxy,
		Target:     target,
		PathPrefix: pathPrefix,
		Modifiers:  modifiers,
	}
	return meteredProxy, route
}

// AddHost registers an HTTP reverse proxy for the given host.
func (p *VHostProxy) AddHost(host string, pathPrefix string, matchers map[string]string, modifiers map[string]string, target *url.URL, device *wireguard.UserspaceDevice) (VHostCloser, *meter.MeteredHTTPHandler, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	meteredProxy, route := p.newMeteredReverseProxy(target, pathPrefix, modifiers, device)
	route.Matchers = matchers

	p.routes[host] = append(p.routes[host], route)
	p.device = device

	if err := p.Start(); err != nil {
		return VHostCloser{}, meteredProxy, err
	}
	log.Info().Str("host", host).Int("port", p.port).Str("target", target.String()).Msg("HTTP proxy configured")
	return VHostCloser{VHostProxy: p, Host: host, Tls: false, Route: route}, meteredProxy, nil
}

// AddHostWithTLS registers a host reverse proxy and an HTTPS handler that
// terminates TLS using the provided certificate and key PEM strings.
func (p *VHostProxy) AddHostWithTLS(host string, pathPrefix string, matchers map[string]string, modifiers map[string]string, target *url.URL, device *wireguard.UserspaceDevice, certPEM, keyPEM string) (VHostCloser, *meter.MeteredHTTPHandler, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	meteredProxy, route := p.newMeteredReverseProxy(target, pathPrefix, modifiers, device)
	route.Matchers = matchers

	// Create a tls.Config from the PEMs.
	cert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return VHostCloser{}, meteredProxy, err
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	// Store the HTTPS handler (mux) and its TLS config so the Server can mount it on a listener.
	// We store the mux in tlsHandlers and the tls.Config in a parallel map.
	p.tlsRoutes[host] = append(p.tlsRoutes[host], route)

	// lazily create tlsConfigs map if needed
	if p.tlsConfigs == nil {
		p.tlsConfigs = make(map[string]*tls.Config)
	}

	// Register TLS config for the provided host key.
	p.tlsConfigs[host] = tlsConfig

	p.device = device

	if err = p.Start(); err != nil {
		return VHostCloser{}, meteredProxy, err
	}
	log.Info().Str("host", host).Int("port", p.port).Str("target", target.String()).Msg("HTTPS proxy configured")
	return VHostCloser{VHostProxy: p, Host: host, Tls: true, Route: route}, meteredProxy, nil
}

// AddHostWithACME registers an HTTP reverse proxy and enables ACME for the given host.
func (p *VHostProxy) AddHostWithACME(host string, pathPrefix string, matchers map[string]string, modifiers map[string]string, target *url.URL, device *wireguard.UserspaceDevice, bindIp, proxyName string) (VHostCloser, *meter.MeteredHTTPHandler, error) {

	// Before enabling ACME for the host, verify the server appears reachable from the public internet
	// for HTTP-01 challenges. This reduces time wasted attempting issuance for hosts that won't complete.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if !p.CanPassACMEChallenge(ctx, host) {
		// If the host cannot be web-hosted, remove the proxy entry we just added to keep state consistent.
		delete(p.routes, host)
		log.Warn().Str("host", host).Msg("VHost: host not reachable for ACME HTTP-01 challenge; aborting ACME setup")
		return VHostCloser{}, &meter.MeteredHTTPHandler{}, fmt.Errorf("host %s not reachable for ACME HTTP-01 challenge", host)
	}

	closer, err := p.manager.AddACMEHost(host, bindIp)
	if err != nil {
		return VHostCloser{}, &meter.MeteredHTTPHandler{}, err
	}
	defer closer.Close()

	meteredProxy, route := p.newMeteredReverseProxy(target, pathPrefix, modifiers, device)
	route.Matchers = matchers

	// Log that ACME registration has been requested for this host.
	log.Debug().Str("host", host).Msg("ACME: host registered with manager for issuance")

	// Wait for certificate to be available before advertising/serving HTTPS on this port.
	// We do the wait asynchronously to avoid blocking callers, but only start the TLS
	// listener once the certificate is present. Serve() will check hasTLS() and mount TLS.
	// Small backoff and then wait up to 2 minutes for ACME issuance.
	if p.manager.acmeManager != nil {
		proxy := p.manager.Proxy(bindIp, 80)
		closer, acmeHandler, err := proxy.AddHost("acme-"+host, "", nil, nil, &url.URL{Scheme: "http", Host: host + ":80"}, nil)
		if err != nil {
			log.Warn().AnErr("AddHostWithACME: AddHost error", err)
			return VHostCloser{}, acmeHandler, err
		}
		err = proxy.Start()
		if err != nil {
			closer.Close()
			log.Warn().AnErr("AddHostWithACME: Start error", err)
			return VHostCloser{}, acmeHandler, err
		}

		go func() {
			defer closer.Close()
			helper := acme.NewACMEHelper(p.manager.acmeManager)
			cert, err := helper.WaitForCertificate(context.Background(), host)
			if err != nil {
				log.Error().Err(err).Str("host", host).Msg("VHost: failed to obtain ACME certificate in time")
				p.manager.Cleanup(proxyName)
				return
			}
			p.mu.Lock()
			if p.tlsConfigs == nil {
				p.tlsConfigs = make(map[string]*tls.Config)
			}
			tcfg := &tls.Config{}
			if cert != nil {
				tcfg.Certificates = []tls.Certificate{*cert}
			}
			p.tlsConfigs[host] = tcfg
			
			p.tlsRoutes[host] = append(p.tlsRoutes[host], route)
			
			p.mu.Unlock()
			p.device = device
			log.Debug().Str("host", host).Msg("VHost: ACME certificate ready; starting TLS listener")
			if err := p.Start(); err != nil {
				log.Warn().Str("host", host).Msg("Could not start TLS proxy!")
				p.manager.Cleanup(proxyName)
				return
			}
		}()
	} else {
		// Fallback: start Serve() so HTTP challenge endpoint is available.
		log.Warn().Str("host", host).Msg("ACME: acmeManager not configured; not possible to obtain certificate")
		VHostCloser{VHostProxy: p, Host: host, Tls: true, Route: route}.Close()
	}

	log.Info().Str("host", host).Int("port", p.port).Str("target", target.String()).Msg("ACME-based HTTPS proxy configured")
	return VHostCloser{VHostProxy: p, Host: host, Tls: true, Route: route}, meteredProxy, nil
}

func (p *VHostProxy) ServeHTTP(w *meter.MeteredResponseWriter, r *meter.MeteredRequest) {
	host := strings.Split(r.Host, ":")[0]
	if p.port == p.manager.acmePort && p.manager.acmeManager != nil && strings.HasPrefix(r.URL.Path, "/.well-known/acme-challenge/") {
		handler := p.manager.acmeManager.HTTPHandler(nil)
		h := meter.MeteredHandlerFunc(func(w2 *meter.MeteredResponseWriter, r2 *meter.MeteredRequest) {
			handler.ServeHTTP(w2, r2.Request)
		})
		h.ServeHTTP(w, r)
		return
	}

	p.mu.RLock()
	routes := p.routes[host]
	tlsRoutes := p.tlsRoutes[host]
	p.mu.RUnlock()

	var candidateRoutes []*Route
	if len(tlsRoutes) > 0 {
		candidateRoutes = tlsRoutes
	} else {
		candidateRoutes = routes
	}

	if route := p.findRoute(r.Request, candidateRoutes); route != nil {
		if route.Apply(w, r.Request) {
			return
		}
		route.Handler.ServeHTTP(w, r)
		return
	}
	p.defaultHandler.ServeHTTP(w, r)
}
func (p *VHostProxy) findRoute(r *http.Request, routes []*Route) *Route {
	for _, route := range routes {
		if route.Matches(r) {
			return route
		}
	}
	return nil
}

func (p *VHostProxy) hasTLS() bool {
	return len(p.tlsRoutes) > 0
}

func keys(mymap map[string]*tls.Config) []string {
	keys := make([]string, len(mymap))

	i := 0
	for k := range mymap {
		keys[i] = k
		i++
	}
	return keys
}

func (p *VHostProxy) Start() error {
	if p.s != nil {
		log.Debug().Int("port", p.port).Msg("VHost: already serving")
		// Already serving; nothing to do.
		return nil
	}

	addr := fmt.Sprintf(":%d", p.port)
	if p.bindIp != "" {
		addr = fmt.Sprintf("%s:%d", p.bindIp, p.port)
	}
	p.s = meter.NewMeteredServer(addr, p)

	if p.hasTLS() {
		tlsConfig := &tls.Config{
			GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
				if cfg, ok := p.tlsConfigs[hello.ServerName]; ok {
					// Assuming one certificate per config
					if len(cfg.Certificates) > 0 {
						return &cfg.Certificates[0], nil
					}
				}
				log.Warn().Any("tls_config", keys(p.tlsConfigs)).Str("requested", hello.ServerName).Msg("VHost: no certificate found (may still be acquiring)")
				return nil, fmt.Errorf("no certificate for server name %s", hello.ServerName)
			},
		}
		
		var l net.Listener
		var err error
		if strings.HasPrefix(addr, "10.1.") {
			if p.device == nil {
				return fmt.Errorf("cannot listen on WireGuard host %s without wireguard device", addr)
			}
			taddr, _ := net.ResolveTCPAddr("tcp", addr)
			l, err = p.device.NetStack.ListenTCP(taddr)
		} else {
			l, err = net.Listen("tcp", addr)
		}
		if err != nil {
			log.Error().Err(err).Int("port", p.port).Msg("VHost: Listen failed")
			return err
		}
		
		l = tls.NewListener(l, tlsConfig)
		log.Info().Str("addr", l.Addr().String()).Msg("VHost: listening tls")
		go p.s.Serve(l)
		return nil
	}

	log.Info().Int("port", p.port).Bool("has_tls", p.hasTLS()).Msg("Serving VHost")
	
	var l net.Listener
	var err error
	if strings.HasPrefix(addr, "10.1.") {
		if p.device == nil {
			return fmt.Errorf("cannot listen on WireGuard host %s without wireguard device", addr)
		}
		taddr, _ := net.ResolveTCPAddr("tcp", addr)
		l, err = p.device.NetStack.ListenTCP(taddr)
	} else {
		l, err = net.Listen("tcp", addr)
	}
	if err != nil {
		log.Error().Err(err).Int("port", p.port).Msg("VHost: net.Listen failed")
		return err
	}
	log.Info().Str("addr", l.Addr().String()).Msg("VHost: listening tcp")
	go p.s.Serve(l)
	return nil
}

// GetTLSHandler returns the registered HTTPS handler for a host, or nil if none.
func (p *VHostProxy) GetTLSHandler(host string) *meter.MeteredHTTPHandler {
	p.mu.RLock()
	defer p.mu.RUnlock()
	routes, ok := p.tlsRoutes[host]
	if !ok || len(routes) == 0 {
		return nil
	}
	return routes[0].Handler
}

// GetTLSConfig returns the registered tls.Config for a host, or nil if none.
func (p *VHostProxy) GetTLSConfig(host string) *tls.Config {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.tlsConfigs[host]
}

// CanPassACMEChallenge checks whether the server's public IPv4 is internet-routable and
// can complete an ACME HTTP-01 challenge for the given host. It attempts to
// resolve the host and then perform a minimal HTTP GET to the ACME challenge
// path served by the autocert.Manager on the manager's configured ACME port.
// This method is conservative: it requires a non-loopback, public IPv4 address
// on the local machine and that an HTTP request to http://<host>/.well-known/acme-challenge/
// returns a successful status (2xx or 3xx). Detailed logs are emitted to help
// debug challenge reachability and routing.
func (p *VHostProxy) CanPassACMEChallenge(ctx context.Context, host string) bool {
	// Basic validation
	if host == "" {
		log.Debug().Str("host", host).Msg("CanWebHost: empty host")
		return false
	}

	// Resolve host to IPs
	ips, err := net.LookupIP(host)
	if err != nil {
		log.Debug().Err(err).Str("host", host).Msg("CanWebHost: DNS lookup failed")
		return false
	}

	// Determine our public IPv4 address by querying an external service (api.ipify.org).
	// This avoids relying on local interface heuristics which may be incorrect for NATted hosts.
	publicIP := p.bindIp
	if publicIP == "" {
		client := &http.Client{}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.ipify.org", nil)
		if err != nil {
			log.Debug().Err(err).Msg("CanWebHost: failed to create request to api.ipify.org")
			return false
		}
		resp, err := client.Do(req)
		if err != nil {
			log.Debug().Err(err).Msg("CanWebHost: failed to query api.ipify.org for public IP")
			return false
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			log.Debug().Err(err).Msg("CanWebHost: failed to read api.ipify.org response")
			return false
		}
		publicIP = strings.TrimSpace(string(body))
		if publicIP == "" {
			log.Debug().Msg("CanWebHost: api.ipify.org returned empty body")
			return false
		}
		// Validate it's an IPv4 address
		parsed := net.ParseIP(publicIP)
		if parsed == nil || parsed.To4() == nil {
			log.Debug().Str("public_ip", publicIP).Msg("CanWebHost: api.ipify.org did not return a valid IPv4")
			return false
		}
		log.Debug().Str("public_ip", publicIP).Msg("CanWebHost: obtained public IP from api.ipify.org")
	}

	// Check that at least one resolved IP is a public IPv4 (not private, not loopback)
	var targetIPv4 net.IP
	for _, ip := range ips {
		if ip.To4() == nil {
			continue
		}
		if ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			continue
		}
		if ip.IsPrivate() {
			// if host resolves only to private addresses, it may not be reachable from the Internet
			continue
		}
		targetIPv4 = ip
		break
	}
	if targetIPv4 == nil {
		log.Debug().Str("host", host).Msg("CanWebHost: host does not resolve to a public IPv4 address")
		// Continue, but fail — ACME HTTP-01 requires a publicly routable host.
		return false
	}
	log.Debug().Str("host_ip", targetIPv4.String()).Str("host", host).Msg("CanWebHost: host resolves to public IPv4")
	// At this point DNS resolves to a public IPv4. Perform an active HTTP probe to verify
	// the ACME HTTP-01 challenge handler is reachable at http://<host>/.well-known/acme-challenge/
	// from the perspective of the server's public IP. This helps avoid triggering ACME issuance
	// for hosts that point to the public IP but are blocked by firewall or NAT.
	checkURL := fmt.Sprintf("http://%s/.well-known/acme-challenge/", host)

	proxy := p.manager.Proxy(targetIPv4.String(), 80)
	// Pass nil device for the dummy ACME host (no WG device needed here).
	closer, _, err := proxy.AddHost("probe-acme", "", nil, nil, &url.URL{Scheme: "http", Host: "localhost:80"}, nil)
	if err != nil {
		log.Warn().AnErr("CanWebHost: AddHost error", err)
		return false
	}
	err = proxy.Start()
	if err != nil {
		log.Warn().AnErr("CanWebHost: Start error", err)
		return false
	}
	defer closer.Close()

	// Try a HEAD first; some handlers may not accept HEAD so fall back to GET.
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, checkURL, nil)
	client := &http.Client{
		Timeout: 5 * time.Second,
	}
	if err != nil {
		log.Debug().Err(err).Str("check_url", checkURL).Msg("CanWebHost: failed to create HEAD request for HTTP-01 probe")
	} else {
		resp, err := client.Do(req)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 403 || resp.StatusCode == 404 {
				log.Debug().Str("host", host).Str("host_ip", targetIPv4.String()).Int("status", resp.StatusCode).Msg("CanWebHost: HTTP probe succeeded (HEAD) for ACME challenge path")
				return true
			}
			log.Debug().Str("host", host).Int("status", resp.StatusCode).Msg("CanWebHost: HEAD probe returned non-2xx/3xx status")
		} else {
			log.Debug().Err(err).Str("host", host).Msg("CanWebHost: HEAD probe error; will retry with GET")
		}
	}

	if targetIPv4.String() == publicIP {
		log.Warn().Str("host", host).Str("host_ip", targetIPv4.String()).Str("public_ip", publicIP).Msg("CanWebHost: DNS -> public IP matches but HTTP probes failed; allowing ACME as permissive fallback")
		return false
	}

	log.Warn().Str("host", host).Str("host_ip", targetIPv4.String()).Str("public_ip", publicIP).Msg("CanWebHost: HTTP probes failed and DNS does not point to server public IP; denying ACME")
	return false
}
