package vhost

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"time"

	"github.com/aquaduct-dev/weft/src/acme"

	"github.com/aquaduct-dev/weft/src/internal/util"

	"github.com/aquaduct-dev/weft/src/proxy/vhost/meter"

	"github.com/aquaduct-dev/weft/wireguard"

	"github.com/rs/zerolog/log"

	"golang.org/x/crypto/acme/autocert"
)

// Matcher defines an interface for request matching logic.
type Matcher interface {
	Matches(r *http.Request) bool
}

// Modifier defines an interface for request/response modification logic.
// If Apply returns true, the request is considered handled and further processing stops.
type Modifier interface {
	Apply(w http.ResponseWriter, r *http.Request) bool
}

// PathMatcher matches requests based on a path prefix.
//
// Matching is segment-aware (F-7): a prefix of "/api" matches "/api" and
// "/api/anything" but does NOT match "/apiabc". The request path is also
// path.Clean'd before comparison so traversal sequences (e.g. "/api/../x")
// can't slip through as a successful match on the literal prefix.
type PathMatcher struct {
	Prefix string
}

func (m *PathMatcher) Matches(r *http.Request) bool {
	if m.Prefix == "" {
		return true
	}
	cleaned := path.Clean(r.URL.Path)
	prefix := strings.TrimRight(m.Prefix, "/")
	return cleaned == prefix || strings.HasPrefix(cleaned, prefix+"/")
}

// HeaderMatcher matches requests based on a header value regex.
type HeaderMatcher struct {
	Name  string
	Regex *regexp.Regexp
}

func (m *HeaderMatcher) Matches(r *http.Request) bool {
	return m.Regex.MatchString(r.Header.Get(m.Name))
}

// QueryMatcher matches requests based on a query parameter regex.
type QueryMatcher struct {
	Key   string
	Regex *regexp.Regexp
}

func (m *QueryMatcher) Matches(r *http.Request) bool {
	return m.Regex.MatchString(r.URL.Query().Get(m.Key))
}

// MethodMatcher matches requests based on the HTTP method.
type MethodMatcher struct {
	Method string
}

func (m *MethodMatcher) Matches(r *http.Request) bool {
	return r.Method == m.Method
}

// HeaderModifier modifies request headers.
type HeaderModifier struct {
	Name  string
	Value string
}

func (m *HeaderModifier) Apply(w http.ResponseWriter, r *http.Request) bool {
	if m.Value == "!del" {
		r.Header.Del(m.Name)
	} else if strings.HasPrefix(m.Value, "+") {
		if r.Header.Get(m.Name) == "" {
			r.Header.Set(m.Name, strings.TrimPrefix(m.Value, "+"))
		}
	} else {
		r.Header.Set(m.Name, m.Value)
	}
	return false
}

// RedirectModifier performs an HTTP redirect.
type RedirectModifier struct {
	Target *url.URL
}

func (m *RedirectModifier) Apply(w http.ResponseWriter, r *http.Request) bool {
	target := *m.Target
	target.Fragment = ""
	http.Redirect(w, r, target.String(), http.StatusFound)
	return true
}

// PathPrefixModifier strips a path prefix from the request, segment-aware.
//
// F-7: the previous implementation used strings.TrimPrefix on the raw path,
// so "/apifoo/x" with prefix "/api" became "foo/x" → "/foo/x", and
// "/api/../admin" was forwarded verbatim with the leading "/api" stripped.
// We now path.Clean the request path before stripping and only strip on
// segment boundaries, ensuring "/api" matches "/api" or "/api/...", never
// "/apifoo".
type PathPrefixModifier struct {
	Prefix string
}

func (m *PathPrefixModifier) Apply(w http.ResponseWriter, r *http.Request) bool {
	if m.Prefix == "" {
		return false
	}
	// Normalise the request path before any decision, so traversal sequences
	// in the request can't reach upstream verbatim regardless of whether the
	// prefix actually matches. path.Clean collapses "." and "..", removes
	// duplicate slashes, and strips trailing slashes (we re-add a leading "/"
	// below).
	cleaned := path.Clean(r.URL.Path)
	r.URL.Path = cleaned

	prefix := strings.TrimRight(m.Prefix, "/")
	switch {
	case cleaned == prefix:
		r.URL.Path = "/"
	case strings.HasPrefix(cleaned, prefix+"/"):
		r.URL.Path = strings.TrimPrefix(cleaned, prefix)
	default:
		// Prefix doesn't match cleanly — keep the cleaned path. (PathMatcher
		// gates entry to this modifier in normal routing; this branch is the
		// belt-and-braces fallback.)
		return false
	}
	if !strings.HasPrefix(r.URL.Path, "/") {
		r.URL.Path = "/" + r.URL.Path
	}
	return false
}

// Route represents a single VHost route with optional matchers and modifiers.
type Route struct {
	Handler   *meter.MeteredHTTPHandler
	Matchers  []Matcher
	Modifiers []Modifier
}

// Matches returns true if the request matches this route's criteria.
func (route *Route) Matches(r *http.Request) bool {
	for _, m := range route.Matchers {
		if !m.Matches(r) {
			return false
		}
	}
	return true
}

// Apply applies redirects and header modifications to the request.
// It returns true if a redirect was performed and no further handling is needed.
func (route *Route) Apply(w http.ResponseWriter, r *http.Request) bool {
	for _, m := range route.Modifiers {
		if m.Apply(w, r) {
			return true
		}
	}
	return false
}

// RouteConfig groups parameters for adding a host to a VHostProxy.
type RouteConfig struct {
	Host       string
	PathPrefix string
	Matchers   map[string]string
	Modifiers  map[string]string
	Target     *url.URL
	Device     *wireguard.UserspaceDevice

	// Optional TLS/ACME config
	CertPEM   string
	KeyPEM    string
	BindIP    string
	ProxyName string
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
			// Read acmeHosts under m.mu (F-6): the map is mutated by
			// AddACMEHost concurrently with TLS handshakes/HTTP-01
			// challenges that invoke this policy.
			m.mu.Lock()
			ok := m.acmeHosts[host]
			m.mu.Unlock()
			if !ok {
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
	v.mu.Lock()
	v.acmeHosts[host] = true
	v.mu.Unlock()
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
	device    *wireguard.UserspaceDevice
	target    *url.URL
	cleanup   func(tunnelName string)
	proxyName string
	transport *http.Transport
}

// HTTPDialFailureThreshold and HTTPDialFailureWindow control when a series of
// upstream-dial failures triggers tunnel cleanup (F-9). A single failure no
// longer tears the tunnel down — only sustained failures within the window do.
var (
	HTTPDialFailureThreshold = 3
	HTTPDialFailureWindow    = 30 * time.Second
)

// NewWGAwareRoundTripper creates a WGAwareRoundTripper with a reusable transport.
// The transport is created once and reused for all requests to avoid goroutine leaks.
func NewWGAwareRoundTripper(device *wireguard.UserspaceDevice, target *url.URL, cleanup func(tunnelName string), proxyName string) *WGAwareRoundTripper {
	w := &WGAwareRoundTripper{
		device:    device,
		target:    target,
		cleanup:   cleanup,
		proxyName: proxyName,
	}
	if device != nil && strings.HasPrefix(target.Host, "10.1") {
		failures := util.NewFailureTracker(HTTPDialFailureThreshold, HTTPDialFailureWindow)
		w.transport = &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				c, err := device.NetStack.Dial(network, addr)
				if err == nil {
					failures.Reset()
					return c, nil
				}
				if cleanup != nil && failures.Record(time.Now()) {
					log.Warn().Str("proxy", proxyName).Err(err).Msg("WGAwareRoundTripper: dial failure threshold reached, triggering cleanup")
					go cleanup(proxyName)
				} else {
					log.Debug().Str("proxy", proxyName).Err(err).Msg("WGAwareRoundTripper: dial failed (under threshold)")
				}
				return c, err
			},
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     90 * time.Second,
		}
	}
	return w
}

// RoundTrip routes requests whose Host is an IP under 10.1.* through the userspace
// WireGuard device if one is configured. Uses a shared transport to avoid leaking
// goroutines and connections.
func (w *WGAwareRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// Fast path: if no custom transport configured, use default.
	if w.transport == nil {
		return http.DefaultTransport.RoundTrip(req)
	}
	return w.transport.RoundTrip(req)
}

func (p *VHostProxy) parseRoute(cfg RouteConfig) *Route {
	route := &Route{}

	// Matchers
	if cfg.PathPrefix != "" {
		route.Matchers = append(route.Matchers, &PathMatcher{Prefix: cfg.PathPrefix})
	}
	for k, v := range cfg.Matchers {
		if strings.HasPrefix(k, "header:") {
			route.Matchers = append(route.Matchers, &HeaderMatcher{
				Name:  strings.TrimPrefix(k, "header:"),
				Regex: regexp.MustCompile("^" + v + "$"),
			})
		} else if strings.HasPrefix(k, "query:") {
			route.Matchers = append(route.Matchers, &QueryMatcher{
				Key:   strings.TrimPrefix(k, "query:"),
				Regex: regexp.MustCompile("^" + v + "$"),
			})
		} else if k == "method" {
			route.Matchers = append(route.Matchers, &MethodMatcher{Method: v})
		}
	}

	// Modifiers
	if cfg.Modifiers["redirect"] == "true" {
		route.Modifiers = append(route.Modifiers, &RedirectModifier{Target: cfg.Target})
	}

	// Add PathPrefixModifier if needed
	if cfg.PathPrefix != "" {
		route.Modifiers = append(route.Modifiers, &PathPrefixModifier{Prefix: cfg.PathPrefix})
	}

	for k, v := range cfg.Modifiers {
		if k == "redirect" {
			continue
		}
		route.Modifiers = append(route.Modifiers, &HeaderModifier{Name: k, Value: v})
	}

	return route
}

func (p *VHostProxy) newMeteredReverseProxy(cfg RouteConfig) (*meter.MeteredHTTPHandler, *Route) {
	route := p.parseRoute(cfg)

	proxy := httputil.NewSingleHostReverseProxy(cfg.Target)
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		// Apply non-terminal modifiers after originalDirector to ensure they take precedence.
		for _, mod := range route.Modifiers {
			if _, ok := mod.(*RedirectModifier); !ok {
				mod.Apply(nil, req)
			}
		}
	}
	proxy.Transport = NewWGAwareRoundTripper(cfg.Device, cfg.Target, p.manager.Cleanup, cfg.ProxyName)
	meteredProxy := meter.MakeMeteredHTTPHandler(proxy)
	route.Handler = meteredProxy

	return meteredProxy, route
}

// AddHost registers an HTTP reverse proxy for the given host.
func (p *VHostProxy) AddHost(cfg RouteConfig) (VHostCloser, *meter.MeteredHTTPHandler, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	meteredProxy, route := p.newMeteredReverseProxy(cfg)

	p.routes[cfg.Host] = append(p.routes[cfg.Host], route)
	p.device = cfg.Device

	if err := p.Start(); err != nil {
		return VHostCloser{}, meteredProxy, err
	}
	log.Info().Str("host", cfg.Host).Int("port", p.port).Str("target", cfg.Target.String()).Msg("HTTP proxy configured")
	return VHostCloser{VHostProxy: p, Host: cfg.Host, Tls: false, Route: route}, meteredProxy, nil
}

// AddHostWithTLS registers a host reverse proxy and an HTTPS handler that
// terminates TLS using the provided certificate and key PEM strings.
func (p *VHostProxy) AddHostWithTLS(cfg RouteConfig) (VHostCloser, *meter.MeteredHTTPHandler, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	meteredProxy, route := p.newMeteredReverseProxy(cfg)

	cert, err := tls.X509KeyPair([]byte(cfg.CertPEM), []byte(cfg.KeyPEM))
	if err != nil {
		return VHostCloser{}, meteredProxy, err
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	p.tlsRoutes[cfg.Host] = append(p.tlsRoutes[cfg.Host], route)

	// lazily create tlsConfigs map if needed
	if p.tlsConfigs == nil {
		p.tlsConfigs = make(map[string]*tls.Config)
	}

	// Register TLS config for the provided host key.
	p.tlsConfigs[cfg.Host] = tlsConfig

	p.device = cfg.Device

	if err = p.Start(); err != nil {
		return VHostCloser{}, meteredProxy, err
	}
	log.Info().Str("host", cfg.Host).Int("port", p.port).Str("target", cfg.Target.String()).Msg("HTTPS proxy configured")
	return VHostCloser{VHostProxy: p, Host: cfg.Host, Tls: true, Route: route}, meteredProxy, nil
}

// AddHostWithACME registers an HTTP reverse proxy and enables ACME for the given host.
func (p *VHostProxy) AddHostWithACME(cfg RouteConfig) (VHostCloser, *meter.MeteredHTTPHandler, error) {

	// Before enabling ACME for the host, verify the server appears reachable from the public internet
	// for HTTP-01 challenges. This reduces time wasted attempting issuance for hosts that won't complete.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if !p.CanPassACMEChallenge(ctx, cfg.Host) {
		log.Warn().Str("host", cfg.Host).Msg("VHost: host not reachable for ACME HTTP-01 challenge; aborting ACME setup")
		return VHostCloser{}, &meter.MeteredHTTPHandler{}, fmt.Errorf("host %s not reachable for ACME HTTP-01 challenge", cfg.Host)
	}

	closer, err := p.manager.AddACMEHost(cfg.Host, cfg.BindIP)
	if err != nil {
		return VHostCloser{}, &meter.MeteredHTTPHandler{}, err
	}
	defer closer.Close()

	meteredProxy, route := p.newMeteredReverseProxy(cfg)

	// Log that ACME registration has been requested for this host.
	log.Debug().Str("host", cfg.Host).Msg("ACME: host registered with manager for issuance")

	if p.manager.acmeManager != nil {
		proxy := p.manager.Proxy(cfg.BindIP, 80)
		closer, acmeHandler, err := proxy.AddHost(RouteConfig{
			Host:   "acme-" + cfg.Host,
			Target: &url.URL{Scheme: "http", Host: cfg.Host + ":80"},
		})
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
			cert, err := helper.WaitForCertificate(context.Background(), cfg.Host)
			if err != nil {
				log.Error().Err(err).Str("host", cfg.Host).Msg("VHost: failed to obtain ACME certificate in time")
				p.manager.Cleanup(cfg.ProxyName)
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
			p.tlsConfigs[cfg.Host] = tcfg

			p.tlsRoutes[cfg.Host] = append(p.tlsRoutes[cfg.Host], route)

			p.mu.Unlock()
			p.device = cfg.Device
			log.Debug().Str("host", cfg.Host).Msg("VHost: ACME certificate ready; starting TLS listener")
			if err := p.Start(); err != nil {
				log.Warn().Str("host", cfg.Host).Msg("Could not start TLS proxy!")
				p.manager.Cleanup(cfg.ProxyName)
				return
			}
		}()
	} else {
		// Fallback: start Serve() so HTTP challenge endpoint is available.
		log.Warn().Str("host", cfg.Host).Msg("ACME: acmeManager not configured; not possible to obtain certificate")
		VHostCloser{VHostProxy: p, Host: cfg.Host, Tls: true, Route: route}.Close()
	}

	log.Info().Str("host", cfg.Host).Int("port", p.port).Str("target", cfg.Target.String()).Msg("ACME-based HTTPS proxy configured")
	return VHostCloser{VHostProxy: p, Host: cfg.Host, Tls: true, Route: route}, meteredProxy, nil
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
			// acme-tls/1 must be advertised so Let's Encrypt can perform TLS-ALPN-01 challenges
			// against this listener — that's the only renewal path once the transient port-80
			// listener from AddHostWithACME has closed.
			NextProtos: []string{"acme-tls/1", "http/1.1"},
			GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
				// All map reads here happen on TLS handshake goroutines and
				// can race with AddACMEHost / AddHostWithTLS / AddHostWithACME
				// which mutate p.tlsConfigs and manager.acmeHosts (F-6).
				// Snapshot under the appropriate locks before deciding.
				if p.manager.acmeManager != nil {
					p.manager.mu.Lock()
					isAcmeHost := p.manager.acmeHosts[hello.ServerName]
					p.manager.mu.Unlock()
					if isAcmeHost {
						return p.manager.acmeManager.GetCertificate(hello)
					}
					for _, proto := range hello.SupportedProtos {
						if proto == "acme-tls/1" {
							return p.manager.acmeManager.GetCertificate(hello)
						}
					}
				}
				p.mu.RLock()
				cfg, ok := p.tlsConfigs[hello.ServerName]
				cfgKeys := keys(p.tlsConfigs)
				p.mu.RUnlock()
				if ok {
					// Assuming one certificate per config
					if len(cfg.Certificates) > 0 {
						return &cfg.Certificates[0], nil
					}
				}
				log.Warn().Any("tls_config", cfgKeys).Str("requested", hello.ServerName).Msg("VHost: no certificate found (may still be acquiring)")
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
		parsed, err := netip.ParseAddr(publicIP)
		if err != nil || !parsed.Is4() {
			log.Debug().Str("public_ip", publicIP).Msg("CanWebHost: api.ipify.org did not return a valid IPv4")
			return false
		}
		log.Debug().Str("public_ip", publicIP).Msg("CanWebHost: obtained public IP from api.ipify.org")
	}

	// Check that at least one resolved IP is a public IPv4 (not private, not loopback)
	var targetIPv4 netip.Addr
	for _, ip := range ips {
		addr, ok := netip.AddrFromSlice(ip)
		if !ok || !addr.Is4() {
			continue
		}
		addr = addr.Unmap()
		if addr.IsLoopback() || addr.IsUnspecified() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() {
			continue
		}
		if addr.IsPrivate() {
			// if host resolves only to private addresses, it may not be reachable from the Internet
			continue
		}
		targetIPv4 = addr
		break
	}
	if !targetIPv4.IsValid() {
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
	closer, _, err := proxy.AddHost(RouteConfig{
		Host:   "probe-acme",
		Target: &url.URL{Scheme: "http", Host: "localhost:80"},
	})
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
