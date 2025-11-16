package vhost

import (
	"context"
	"crypto/tls"
	"crypto/x509"
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

	"aquaduct.dev/weft/src/acme"
	"aquaduct.dev/weft/src/vhost/meter"
	"aquaduct.dev/weft/wireguard"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/acme/autocert"
)

// VHostProxy manages name-based vhosts and optional TLS-termination handlers.
type VHostProxy struct {
	mu sync.RWMutex
	s  *meter.MeteredServer

	handlers map[string]meter.MeteredHTTPHandler
	bindIp   string
	port     int

	manager *VHostProxyManager

	defaultHandler meter.MeteredHTTPHandler
	// tlsHandlers holds HTTPS handlers per hostname when TLS termination is configured.
	tlsHandlers map[string]meter.MeteredHTTPHandler
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
}

func (v VHostCloser) Close() error {
	delete(v.VHostProxy.handlers, v.Host)
	if v.Tls {
		delete(v.VHostProxy.tlsHandlers, v.Host)
		delete(v.VHostProxy.tlsConfigs, v.Host)
	}
	if v.VHostProxy.s != nil && len(v.VHostProxy.handlers) == 0 && len(v.VHostProxy.tlsHandlers) == 0 {
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
		handlers: make(map[string]meter.MeteredHTTPHandler),
		manager:  manager,
		port:     key.Port,
		bindIp:   key.BindIp,
		defaultHandler: meter.MeteredHTTPHandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "404 %s not found", r.URL.String())
		}),
		tlsHandlers: make(map[string]meter.MeteredHTTPHandler),
		tlsConfigs:  make(map[string]*tls.Config),
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
func (p *VHostProxy) AddHost(host string, target *url.URL, device *wireguard.UserspaceDevice) (VHostCloser, meter.MeteredHTTPHandler, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.Transport = &WGAwareRoundTripper{device: device, target: target}
	meteredProxy := meter.MakeMeteredHTTPHandler(proxy)

	p.handlers[host] = meteredProxy
	if err := p.Start(); err != nil {
		return VHostCloser{}, meteredProxy, err
	}
	log.Info().Str("host", host).Int("port", p.port).Str("target", target.String()).Msg("VHost: HTTP proxy configured")
	return VHostCloser{VHostProxy: p, Host: host, Tls: false}, meteredProxy, nil
}

// AddHostWithTLS registers a host reverse proxy and an HTTPS handler that
// terminates TLS using the provided certificate and key PEM strings.
func (p *VHostProxy) AddHostWithTLS(host string, target *url.URL, device *wireguard.UserspaceDevice, certPEM, keyPEM string) (VHostCloser, meter.MeteredHTTPHandler, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	proxy := httputil.NewSingleHostReverseProxy(target)
	// Attach transport that uses the userspace device if present, and accept self-signed certs for upstreams.
	proxy.Transport = &WGAwareRoundTripper{device: device, target: target}
	meteredProxy := meter.MakeMeteredHTTPHandler(proxy)

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
	p.tlsHandlers[host] = meteredProxy

	// lazily create tlsConfigs map if needed
	if p.tlsConfigs == nil {
		p.tlsConfigs = make(map[string]*tls.Config)
	}

	// Register TLS config for the provided host key.
	p.tlsConfigs[host] = tlsConfig

	// Additionally, attempt to register the certificate for any DNS names or IPs
	// present in the leaf certificate so SNI lookups (or client connections using
	// the IP string) will be able to find the certificate.
	// Parse the leaf ASN.1 certificate to discover SANs and common name.
	parsedCerts, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err == nil {
		// Attempt to extract DNSNames/IPs from certificate.
		// Use x509 parsing on the first certificate in DER form if possible.
		// This code is best-effort; failures here should not prevent registering the primary host.
		if len(parsedCerts.Certificate) > 0 {
			if x509Cert, err := x509.ParseCertificate(parsedCerts.Certificate[0]); err == nil {
				// Register for CommonName if present and not empty.
				if x509Cert.Subject.CommonName != "" {
					if _, exists := p.tlsConfigs[x509Cert.Subject.CommonName]; !exists {
						p.tlsConfigs[x509Cert.Subject.CommonName] = tlsConfig
					}
				}
				// Register for all DNS SANs.
				for _, dns := range x509Cert.DNSNames {
					if dns == "" {
						continue
					}
					if _, exists := p.tlsConfigs[dns]; !exists {
						p.tlsConfigs[dns] = tlsConfig
					}
				}
				// Register for IP SANs (as string form).
				for _, ip := range x509Cert.IPAddresses {
					ipStr := ip.String()
					if ipStr == "" {
						continue
					}
					if _, exists := p.tlsConfigs[ipStr]; !exists {
						p.tlsConfigs[ipStr] = tlsConfig
					}
				}
			}
		}
	}

	if err = p.Start(); err != nil {
		return VHostCloser{}, meteredProxy, err
	}
	log.Info().Str("host", host).Int("port", p.port).Str("target", target.String()).Msg("VHost: HTTPS proxy configured")
	return VHostCloser{VHostProxy: p, Host: host, Tls: true}, meteredProxy, nil
}

// AddHostWithACME registers an HTTP reverse proxy and enables ACME for the given host.
func (p *VHostProxy) AddHostWithACME(host string, target *url.URL, device *wireguard.UserspaceDevice, bindIp string) (VHostCloser, meter.MeteredHTTPHandler, error) {

	// Before enabling ACME for the host, verify the server appears reachable from the public internet
	// for HTTP-01 challenges. This reduces time wasted attempting issuance for hosts that won't complete.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if !p.CanPassACMEChallenge(ctx, host) {
		// If the host cannot be web-hosted, remove the proxy entry we just added to keep state consistent.
		delete(p.handlers, host)
		log.Warn().Str("host", host).Msg("VHost: host not reachable for ACME HTTP-01 challenge; aborting ACME setup")
		return VHostCloser{}, meter.MeteredHTTPHandler{}, fmt.Errorf("host %s not reachable for ACME HTTP-01 challenge", host)
	}

	closer, err := p.manager.AddACMEHost(host, bindIp)
	if err != nil {
		return VHostCloser{}, meter.MeteredHTTPHandler{}, err
	}
	defer closer.Close()

	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.Transport = &WGAwareRoundTripper{device: device, target: target}
	meteredProxy := meter.MakeMeteredHTTPHandler(proxy)

	// Log that ACME registration has been requested for this host.
	log.Info().Str("host", host).Msg("ACME: host registered with manager for issuance")

	// Wait for certificate to be available before advertising/serving HTTPS on this port.
	// We do the wait asynchronously to avoid blocking callers, but only start the TLS
	// listener once the certificate is present. Serve() will check hasTLS() and mount TLS.
	// Small backoff and then wait up to 2 minutes for ACME issuance.
	if p.manager.acmeManager != nil {
		proxy := p.manager.Proxy(bindIp, 80)
		closer, acmeHandler, err := proxy.AddHost("acme-"+host, &url.URL{Scheme: "http", Host: host + ":80"}, nil)
		if err != nil {
			log.Warn().AnErr("AddHostWithACME: AddHost error", err)
			return VHostCloser{}, acmeHandler, err
		}
		err = proxy.Start()
		if err != nil {
			log.Warn().AnErr("AddHostWithACME: Start error", err)
			return VHostCloser{}, acmeHandler, err
		}
		defer closer.Close()

		helper := acme.NewACMEHelper(p.manager.acmeManager)
		cert, err := helper.WaitForCertificate(context.Background(), host)
		if err != nil {
			log.Error().Err(err).Str("host", host).Msg("VHost: failed to obtain ACME certificate in time")
			return VHostCloser{}, acmeHandler, err
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
		p.tlsHandlers[host] = meteredProxy
		p.mu.Unlock()
		log.Info().Str("host", host).Msg("VHost: ACME certificate ready; starting TLS listener")
		if err := p.Start(); err != nil {
			log.Warn().Str("host", host).Msg("Could not start TLS proxy!")
			VHostCloser{VHostProxy: p, Host: host, Tls: true}.Close()
			return VHostCloser{}, meteredProxy, err
		}
	} else {
		// Fallback: start Serve() so HTTP challenge endpoint is available.
		log.Warn().Str("host", host).Msg("ACME: acmeManager not configured; not possible to obtain certificate")
		VHostCloser{VHostProxy: p, Host: host, Tls: true}.Close()
	}

	log.Info().Str("host", host).Int("port", p.port).Str("target", target.String()).Msg("VHost: ACME-based HTTPS proxy configured")
	return VHostCloser{VHostProxy: p, Host: host, Tls: true}, meteredProxy, nil
}

func (p *VHostProxy) ServeHTTP(w meter.MeteredResponseWriter, r *meter.MeteredRequest) {
	host := strings.Split(r.Host, ":")[0]
	fmt.Printf("GOT REQE")
	log.Debug().Str("host", r.Host).Str("uri", r.RequestURI).Msg("VHost: got request")
	if p.port == p.manager.acmePort && p.manager.acmeManager != nil && strings.HasPrefix(r.URL.Path, "/.well-known/acme-challenge/") {
		// Log that the ACME HTTP-01 challenge handler is being invoked for visibility.
		log.Debug().Str("host", r.Host).Str("path", r.URL.Path).Msg("ACME: challenge handler start")
		// Wrap the autocert handler to add logging when it serves a challenge.
		handler := p.manager.acmeManager.HTTPHandler(nil)
		// Use a small wrapper to log responses handled by the autocert handler.
		h := meter.MeteredHandlerFunc(func(w2 meter.MeteredResponseWriter, r2 *meter.MeteredRequest) {
			start := time.Now()
			handler.ServeHTTP(&w2, r2.Request)
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
	proxy, ok := p.handlers[host]
	httpsHandler, httpsOk := p.tlsHandlers[host]
	p.mu.RUnlock()

	if httpsOk {
		log.Debug().Str("host", r.Host).Str("uri", r.RequestURI).Msg("VHost: handling request with HTTPS handler")
		httpsHandler.ServeHTTP(w, r)
		return
	} else if ok {
		log.Debug().Str("host", r.Host).Str("uri", r.RequestURI).Msg("VHost: handling request with HTTP handler")
		proxy.ServeHTTP(w, r)
		return
	}
	p.defaultHandler.ServeHTTP(w, r)
}

func (p *VHostProxy) hasTLS() bool {
	return len(p.tlsHandlers) > 0
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
	p.s = &meter.MeteredServer{
		Server: &http.Server{
			Addr: fmt.Sprintf(":%d", p.port),
		},
		MeteredHandler: p,
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
				log.Info().Any("tls_config", keys(p.tlsConfigs)).Str("requested", hello.ServerName).Msg("VHost: no certificate found")
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
func (p *VHostProxy) GetTLSHandler(host string) *meter.MeteredHTTPHandler {
	p.mu.RLock()
	defer p.mu.RUnlock()
	handler, ok := p.tlsHandlers[host]
	if !ok {
		return nil
	}
	return &handler
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
	publicIP := ""
	{
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
	closer, _, err := proxy.AddHost("probe-acme", &url.URL{Scheme: "http", Host: "localhost:80"}, nil)
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
				log.Info().Str("host", host).Str("host_ip", targetIPv4.String()).Int("status", resp.StatusCode).Msg("CanWebHost: HTTP probe succeeded (HEAD) for ACME challenge path")
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
