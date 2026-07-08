package vhost

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
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
	"sort"
	"strings"
	"sync"
	"time"

	stdlog "log"

	"github.com/aquaduct-dev/weft/src/acme"
	"github.com/aquaduct-dev/weft/src/honeypot"
	"github.com/aquaduct-dev/weft/src/internal/util"
	"github.com/aquaduct-dev/weft/src/proxy/vhost/meter"
	"github.com/aquaduct-dev/weft/types"
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

	// enableHTTP2 controls whether this proxy's TLS listener serves HTTP/2
	// (ALPN h2). It is ON by default (see http2Enabled) and can be forced off
	// with WEFT_ENABLE_HTTP2=0 as a kill switch. h2 applies to every host on the
	// port (ALPN is per-connection and one VHostProxy serves all hosts by SNI).
	// WebSockets are unaffected: weft does not advertise RFC 8441 Extended
	// CONNECT, so browsers open WebSockets over HTTP/1.1 — the standard h2-pages
	// + h1-WebSockets setup.
	enableHTTP2 bool
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

	// redirects holds peer-registered ACME challenge redirects (set by
	// RegisterPeerRedirect, read by tryRedirectChallenge). Guarded by
	// redirectsMu — kept distinct from `mu` so the challenge hot-path
	// doesn't contend with the bulk of the manager's state.
	redirects   map[string]peerRedirect
	redirectsMu sync.Mutex

	// honeypotEmitter, when non-nil, receives one structured event per
	// unmatched-host HTTP request (default-handler 404 path) and per TLS
	// handshake failure on any VHost listener. Set by Set/GetHoneypotEmitter
	// — guarded by honeypotMu so a hot reconfigure doesn't race with the
	// request/handshake paths.
	honeypotMu      sync.RWMutex
	honeypotEmitter *honeypot.Emitter
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

// SetHoneypotEmitter installs (or clears, when em is nil) the emitter used to
// publish honeypot events from every VHost on this manager. Safe to call
// concurrently with request handling.
func (v *VHostProxyManager) SetHoneypotEmitter(em *honeypot.Emitter) {
	v.honeypotMu.Lock()
	v.honeypotEmitter = em
	v.honeypotMu.Unlock()
}

// honeypotEmitterLoaded returns the current emitter, or nil if none. Used by
// the request and TLS-error hot paths; readers take only an RLock so a
// reconfigure can't stall request handling.
func (v *VHostProxyManager) honeypotEmitterLoaded() *honeypot.Emitter {
	v.honeypotMu.RLock()
	em := v.honeypotEmitter
	v.honeypotMu.RUnlock()
	return em
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

// ListCertificates reads the autocert cache directory and returns a summary of
// every TLS certificate the bastion has obtained, with validity windows. It
// skips the ACME account key and in-flight challenge tokens (which aren't
// certificates). A missing cache directory yields an empty list, not an error.
func (v *VHostProxyManager) ListCertificates() ([]types.CertInfo, error) {
	v.mu.Lock()
	dir := v.certsCachePath
	v.mu.Unlock()
	if dir == "" {
		return []types.CertInfo{}, nil
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return []types.CertInfo{}, nil
		}
		return nil, fmt.Errorf("read cert cache dir: %w", err)
	}

	out := make([]types.CertInfo, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		// Skip the ACME account key and transient challenge artifacts — only
		// real cached certificates carry a leaf we can parse.
		if name == "acme_account+key" || strings.Contains(name, "+token") ||
			strings.Contains(name, "+http-01") || strings.Contains(name, "+tls-alpn") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		leaf := firstLeafCertificate(data)
		if leaf == nil {
			continue
		}
		out = append(out, types.CertInfo{
			Host:      name,
			Subject:   leaf.Subject.CommonName,
			DNSNames:  leaf.DNSNames,
			Issuer:    leaf.Issuer.CommonName,
			Serial:    leaf.SerialNumber.Text(16),
			NotBefore: leaf.NotBefore,
			NotAfter:  leaf.NotAfter,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Host < out[j].Host })
	return out, nil
}

// firstLeafCertificate returns the first X.509 CERTIFICATE parsed from a PEM
// bundle (autocert stores the leaf first), or nil if none parses.
func firstLeafCertificate(pemBytes []byte) *x509.Certificate {
	for {
		block, rest := pem.Decode(pemBytes)
		if block == nil {
			return nil
		}
		if block.Type == "CERTIFICATE" {
			if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
				return cert
			}
		}
		pemBytes = rest
	}
}

func (v *VHostProxyManager) AddACMEHost(host string, bindIp string) (io.Closer, error) {
	// Bind on the configured ACME port (defaults to 80, overridable via
	// SetACMEPort for tests). ServeHTTP routes /.well-known/acme-challenge/
	// through autocert iff the proxy's port matches manager.acmePort, so
	// they must agree.
	proxy := v.Proxy(bindIp, v.ACMEPort())
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
		tlsRoutes:   make(map[string][]*Route),
		tlsConfigs:  make(map[string]*tls.Config),
		enableHTTP2: http2Enabled(),
	}
}

// http2Enabled reports whether HTTP/2 termination is enabled for vhost TLS
// listeners. It is ON by default: weft aims to be brainless to run, and h2 is
// the correct default for a modern TLS-terminating reverse proxy. Set
// WEFT_ENABLE_HTTP2 to a falsy value (0/false/no/off) as a kill switch to force
// HTTP/1.1 without a code change or redeploy of the image.
//
// WebSockets keep working either way. weft does not advertise RFC 8441 Extended
// CONNECT (SETTINGS_ENABLE_CONNECT_PROTOCOL) — Go leaves that off unless the
// process is started with GODEBUG=http2xconnect=1 — so browsers do not attempt
// WebSockets-over-HTTP/2 and instead open a plain HTTP/1.1 WebSocket, which the
// reverse proxy handles as before (the same h2-pages + h1-WebSockets config
// nginx and every CDN run).
//
// DO NOT set GODEBUG=http2xconnect=1. That advertises WebSocket-over-h2
// support, and because weft does not implement the Extended CONNECT tunnel,
// browsers would then hard-fail WebSockets (RFC 8441 gives no per-attempt
// fallback to h1 once the server claims support).
func http2Enabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("WEFT_ENABLE_HTTP2"))) {
	case "0", "false", "no", "off":
		return false
	default:
		return true
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
//
// The :80 listener is bound BEFORE CanPassACMEChallenge runs. Probing first
// is a chicken-and-egg on cold start: the probe HEADs
// /.well-known/acme-challenge/ at the host's public IP and expects autocert's
// 403 — which only arrives once *we* are answering on :80. With no prior
// ACME hosts, the very first registration would fail the probe, never bind
// :80, and leave every subsequent registration failing the same way.
// Binding first lets the probe see a live listener (the same one autocert
// will answer challenges on); probe failure tears the listener back down via
// the deferred Close.
func (p *VHostProxy) AddHostWithACME(cfg RouteConfig) (VHostCloser, *meter.MeteredHTTPHandler, error) {

	// Bind the ACME challenge listener up front. The deferred Close runs on
	// every return path: on probe failure it collapses the proxy (no other
	// routes were added), on success the persistent "acme-<host>" route
	// added below keeps it alive.
	closer, err := p.manager.AddACMEHost(cfg.Host, cfg.BindIP)
	if err != nil {
		return VHostCloser{}, &meter.MeteredHTTPHandler{}, err
	}
	defer closer.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if !p.CanPassACMEChallenge(ctx, cfg.Host) {
		log.Warn().Str("host", cfg.Host).Msg("VHost: host not reachable for ACME HTTP-01 challenge; aborting ACME setup")
		return VHostCloser{}, &meter.MeteredHTTPHandler{}, fmt.Errorf("host %s not reachable for ACME HTTP-01 challenge", cfg.Host)
	}

	meteredProxy, route := p.newMeteredReverseProxy(cfg)

	// Log that ACME registration has been requested for this host.
	log.Debug().Str("host", cfg.Host).Msg("ACME: host registered with manager for issuance")

	if p.manager.acmeManager != nil {
		proxy := p.manager.Proxy(cfg.BindIP, p.manager.ACMEPort())
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

			// Spin up the peer-redirect loop so that, if the CA's HTTP-01
			// validator lands on a sibling node behind DNS round-robin, that
			// node knows to 301 the challenge back to us. The loop runs until
			// we cancel it once issuance returns (success or failure).
			redirectCtx, cancelRedirect := context.WithCancel(context.Background())
			defer cancelRedirect()
			go acme.RegisterRedirectsLoop(redirectCtx, cfg.Host, acme.DefaultPeerPort)

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
	// r.Host may contain :port (and bracketed IPv6); SplitHostPort handles both.
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if p.port == p.manager.acmePort && p.manager.acmeManager != nil && strings.HasPrefix(r.URL.Path, "/.well-known/acme-challenge/") {
		if p.manager.tryRedirectChallenge(w, r.Request, host) {
			return
		}
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
	// Unmatched host — this is the high-signal abuse path: scanner probing
	// for /.env, /wp-login.php, etc. against a host the bastion doesn't
	// serve. Emit a honeypot event before falling through to 404.
	if em := p.manager.honeypotEmitterLoaded(); em != nil {
		emitUnmatchedHTTPEvent(em, r.Request, p.port, p.hasTLS())
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
	// Route net/http's TLS handshake / connection-state error lines through
	// a structured emitter when honeypot mode is on. The default ErrorLog
	// writes to stderr unstructured (`http: TLS handshake error from ...`),
	// which is unparseable downstream. Attaching this here also unhides
	// these lines if the operator hasn't opted into honeypot mode (zerolog
	// just consumes them as warnings).
	p.s.Server.ErrorLog = stdlog.New(
		&httpErrorLogWriter{port: p.port, manager: p.manager},
		"", 0,
	)

	if p.hasTLS() {
		// ALPN advertisement:
		//   - acme-tls/1 must be advertised so Let's Encrypt can perform
		//     TLS-ALPN-01 challenges against this listener — that's the only
		//     renewal path once the transient port-80 listener from
		//     AddHostWithACME has closed.
		//   - h2 is advertised whenever HTTP/2 is enabled for this proxy (the
		//     default; see http2Enabled) and is preferred so browsers negotiate
		//     it. WebSockets are unaffected — weft does not advertise RFC 8441
		//     Extended CONNECT, so browsers use HTTP/1.1 for WebSockets.
		//   - http/1.1 is always offered as the fallback and carries WebSocket
		//     traffic.
		nextProtos := []string{"acme-tls/1", "http/1.1"}
		if p.enableHTTP2 {
			nextProtos = []string{"h2", "http/1.1", "acme-tls/1"}
		}
		tlsConfig := &tls.Config{
			NextProtos: nextProtos,
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
						return acme.AcquireCertificate(p.manager.acmeManager, hello)
					}
					for _, proto := range hello.SupportedProtos {
						if proto == "acme-tls/1" {
							return acme.AcquireCertificate(p.manager.acmeManager, hello)
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

		if p.enableHTTP2 {
			// HTTP/2 path: the byte counter must sit BENEATH TLS so net/http
			// sees the *tls.Conn and can negotiate h2 via ALPN. ServeTLSCounted
			// wraps the raw listener in the counter, terminates TLS with
			// tlsConfig, enables h2, and serves. (On the default path below the
			// counter wraps the TLS conn, hiding it from net/http — which is
			// why h2 cannot be negotiated there.)
			log.Info().Str("addr", l.Addr().String()).Msg("VHost: listening tls (http/2 enabled)")
			go func(rawListener net.Listener) {
				if err := p.s.ServeTLSCounted(rawListener, tlsConfig); err != nil && !errors.Is(err, http.ErrServerClosed) {
					log.Error().Err(err).Int("port", p.port).Msg("VHost: tls (http/2) serve exited")
				}
			}(l)
			return nil
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

// Test seams. Replaced by tests; production uses net.LookupIP and the real prober.
var (
	lookupIP             = net.LookupIP
	probeACMEChallengeFn = probeACMEChallenge
)

// rrPassThresholdPercent is the minimum fraction of public-IPv4 records that
// must respond to the HTTP-01 probe for an RR-DNS host to be considered ACME-
// reachable. Tuned so a 3-record RR passes with 2/3 hits.
const rrPassThresholdPercent = 66

// ipCategory classifies an IP for operator-friendly diagnostic logging.
// Used to explain *why* a record didn't qualify as a probe target.
func ipCategory(ip net.IP) string {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return "invalid"
	}
	addr = addr.Unmap()
	switch {
	case addr.IsLoopback():
		return "loopback"
	case addr.IsUnspecified():
		return "unspecified"
	case addr.IsLinkLocalUnicast(), addr.IsLinkLocalMulticast():
		return "link-local"
	case addr.IsPrivate():
		return "private"
	case !addr.Is4():
		return "ipv6 (skipped; ACME HTTP-01 here is IPv4-only)"
	default:
		return "public"
	}
}

// describeIPs renders a DNS result list with a category tag per record so
// operators can see at a glance why a record was filtered out.
func describeIPs(ips []net.IP) []string {
	out := make([]string, len(ips))
	for i, ip := range ips {
		out[i] = ip.String() + " (" + ipCategory(ip) + ")"
	}
	return out
}

// publicIPv4sFromIPs filters DNS results to non-loopback, non-private, non-
// link-local IPv4 addresses. IPv6 records and v4-mapped v6 are normalised.
func publicIPv4sFromIPs(ips []net.IP) []netip.Addr {
	out := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		addr, ok := netip.AddrFromSlice(ip)
		if !ok {
			continue
		}
		addr = addr.Unmap()
		if !addr.Is4() {
			continue
		}
		if addr.IsLoopback() || addr.IsUnspecified() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() {
			continue
		}
		if addr.IsPrivate() {
			continue
		}
		out = append(out, addr)
	}
	return out
}

// probeOutcome captures one IP's probe result and a short operator-readable
// reason — propagated up so a failing CanPassACMEChallenge can produce a
// single actionable log instead of fragments scattered across debug lines.
type probeOutcome struct {
	ip     netip.Addr
	ok     bool
	detail string
}

// probeACMEChallenge runs a single HTTP HEAD against /.well-known/acme-challenge/
// on host with the dial pinned to dialIP:80 (F-11 — defeats DNS rebinding).
// Returns ok=true with a short detail string on a 403/404 response (autocert's
// signature for unknown challenge tokens), and ok=false with a reason
// otherwise. Refuses non-public IPs.
func probeACMEChallenge(ctx context.Context, host string, dialIP netip.Addr) (bool, string) {
	if !dialIP.Is4() || dialIP.IsLoopback() || dialIP.IsPrivate() || dialIP.IsLinkLocalUnicast() || dialIP.IsUnspecified() {
		return false, "refused: non-public IP"
	}
	pinned := net.JoinHostPort(dialIP.String(), "80")
	checkURL := fmt.Sprintf("http://%s/.well-known/acme-challenge/", host)
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, checkURL, nil)
	if err != nil {
		return false, fmt.Sprintf("build request: %v", err)
	}
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, network, pinned)
			},
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Sprintf("connect: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusNotFound {
		return true, fmt.Sprintf("ok (status %d)", resp.StatusCode)
	}
	return false, fmt.Sprintf("unexpected status %d (expected 403 or 404 from autocert challenge handler)", resp.StatusCode)
}

// CanPassACMEChallenge checks whether ACME HTTP-01 issuance is likely to
// succeed for host by resolving its DNS and probing each public-IPv4 record
// for an autocert-style 403/404 on the challenge path.
//
// Behaviour by record count (post public-IPv4 filter):
//   - 0 records: deny. ACME requires DNS pointed at a public IP.
//   - 1 record: probe once; require success. (Also covers IP-literal hosts
//     since net.LookupIP returns the literal as a single record.)
//   - N >= 2 (round-robin DNS): probe every record; require >= 66% to respond
//     so a partly-broken RR rotation can't quietly issue.
//
// On failure, emits a single warn-level log with per-IP outcomes and an
// actionable explanation tailored to the failure mode.
func (p *VHostProxy) CanPassACMEChallenge(ctx context.Context, host string) bool {
	if host == "" {
		log.Warn().Msg("CanPassACMEChallenge: empty host — pass a hostname (or public IP literal) to probe")
		return false
	}

	ips, err := lookupIP(host)
	if err != nil {
		log.Warn().Err(err).Str("host", host).Msgf(
			"CanPassACMEChallenge: DNS lookup for %q failed. Verify the domain is registered and propagated (try: dig +short %s).",
			host, host)
		return false
	}
	targets := publicIPv4sFromIPs(ips)
	if len(targets) == 0 {
		log.Warn().Str("host", host).Strs("resolved", describeIPs(ips)).Msgf(
			"CanPassACMEChallenge: %q resolves but no record is a public IPv4. Add an A record pointing to this server's public IP. (Loopback, RFC1918, link-local, and v6-only records are not eligible for ACME HTTP-01 here.)",
			host)
		return false
	}

	outcomes := make([]probeOutcome, len(targets))
	successes := 0
	for i, ip := range targets {
		ok, detail := probeACMEChallengeFn(ctx, host, ip)
		outcomes[i] = probeOutcome{ip: ip, ok: ok, detail: detail}
		if ok {
			successes++
		}
	}

	pass := false
	if len(targets) == 1 {
		pass = successes == 1
	} else {
		// RR DNS: require >= 66% of records to respond. Integer math avoids float.
		pass = successes*100 >= len(targets)*rrPassThresholdPercent
	}

	if pass {
		log.Debug().Str("host", host).Int("records", len(targets)).Int("successes", successes).Msg("CanPassACMEChallenge: probe passed")
		return true
	}

	// Failure path — emit one warn line with per-IP outcomes attached as
	// structured fields so log shippers can grep, plus an actionable Msg.
	ev := log.Warn().Str("host", host).Int("records_total", len(targets)).Int("records_ok", successes)
	if len(targets) > 1 {
		ev = ev.Int("threshold_pct", rrPassThresholdPercent)
	}
	for _, o := range outcomes {
		ev = ev.Str("probe_"+o.ip.String(), o.detail)
	}
	switch {
	case len(targets) == 1:
		ev.Msgf(
			"CanPassACMEChallenge: probe to %s for %q failed (%s). Check: (1) %s is the right public IP for %q, (2) inbound TCP/80 is open through your firewall and any NAT, (3) a handler answering /.well-known/acme-challenge/ (typically `weft server`) is running on this host.",
			outcomes[0].ip, host, outcomes[0].detail, outcomes[0].ip, host)
	default:
		ev.Msgf(
			"CanPassACMEChallenge: round-robin DNS check failed for %q — only %d of %d records (need >=%d%%) responded with the expected ACME handler. Each peer's result is logged above. ACME will fail randomly until every record either runs `weft server` on TCP/80 or is removed from the rotation.",
			host, successes, len(targets), rrPassThresholdPercent)
	}
	return false
}
