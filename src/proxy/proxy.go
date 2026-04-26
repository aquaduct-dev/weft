package proxy

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/aquaduct-dev/weft/src/internal/util"
	"github.com/aquaduct-dev/weft/src/proxy/vhost"
	"github.com/aquaduct-dev/weft/wireguard"
	"github.com/rs/zerolog/log"
)

// ProxyManager orchestrates the lifecycle of all active proxies (TCP, UDP, and VHost).
type ProxyManager struct {
	// proxies maps tunnel names to their active Proxy implementation.
	proxies map[string]Proxy
	// bindIP constrains proxy listeners to a specific IP when set.
	bindIP            string
	// VHostProxyManager manages shared HTTP/HTTPS listeners for virtual hosting.
	VHostProxyManager *vhost.VHostProxyManager
	// Cleanup is a callback invoked when a proxy is closed.
	Cleanup           func(tunnelName string)
}

// NewProxyManager initializes a new ProxyManager with an empty proxy map.
func NewProxyManager() *ProxyManager {
	return &ProxyManager{
		proxies:           make(map[string]Proxy),
		VHostProxyManager: vhost.NewVHostProxyManager(),
	}
}

// SetBindIP updates the ProxyManager's bind IP in a safe, exported way.
// Server should call this instead of modifying the unexported field directly.
func (p *ProxyManager) SetBindIP(bindIP string) {
	p.bindIP = bindIP
}

/*
GetProxyCounters returns a snapshot of tx/rx counters for all active proxies.

Important: use exported methods only. Do not access internal mutexes or fields
directly. Each Proxy implementation exposes exported accessors for counters
(e.g., BytesTx(), BytesRx()) which provide a safe snapshot.
*/
func (p *ProxyManager) GetProxyCounters() map[string]struct {
	Tx         uint64
	Rx         uint64
	InstanceId string
} {
	result := make(map[string]struct {
		Tx         uint64
		Rx         uint64
		InstanceId string
	})

	for name, pr := range p.proxies {
		result[name] = struct {
			Tx         uint64
			Rx         uint64
			InstanceId string
		}{Tx: pr.BytesTx(), Rx: pr.BytesRx(), InstanceId: pr.InstanceId()}
	}

	return result
}

// TCPDialFailureThreshold and TCPDialFailureWindow control when a series of
// upstream-dial failures triggers tunnel cleanup (F-9). A single failure no
// longer tears the tunnel down — only sustained failures within the window do.
var (
	TCPDialFailureThreshold = 3
	TCPDialFailureWindow    = 30 * time.Second
)

// ProxyTCP is a generic TCP proxy that forwards connections.
func (p *TCPProxy) ProxyTCP(publicConn net.Conn, target string, device *wireguard.UserspaceDevice) {
	log.Debug().Str("target", target).Msg("ProxyTCP: accepted public connection")
	dialAddr, err := net.ResolveTCPAddr("tcp", target)
	if err != nil {
		log.Error().Err(err).Str("target", target).Msg("ProxyTCP: resolve target failed")
		publicConn.Close()
		return
	}
	targetConn, err := WGAwareTCPDial(dialAddr, device)
	if err != nil {
		log.Error().Err(err).Str("target", target).Msg("ProxyTCP: dial to target failed")
		publicConn.Close()
		if p.cleanup != nil && p.dialFailures.Record(time.Now()) {
			log.Warn().Str("proxy", p.name).Msg("ProxyTCP: dial failure threshold reached, triggering cleanup")
			go p.cleanup(p.name)
		}
		return
	}
	p.dialFailures.Reset()

	// copy target->public
	go func() {
		for {
			buf := make([]byte, 0xffff)
			n, err := targetConn.Read(buf)
			if err != nil {
				targetConn.Close()
				publicConn.Close()
				return
			}
			_, err = publicConn.Write(buf[:n])
			if err != nil {
				targetConn.Close()
				publicConn.Close()
				return
			}
			p.bytesRx.Add(uint64(n))
		}
	}()

	// copy public->target (will return when pub closed)
	go func() {
		for {
			buf := make([]byte, 0xffff)
			n, err := publicConn.Read(buf)
			if err != nil {
				targetConn.Close()
				publicConn.Close()
				return
			}
			_, err = targetConn.Write(buf[:n])
			if err != nil {
				log.Debug().Err(err).Msg("ProxyTCP: copy error")
				targetConn.Close()
				publicConn.Close()
				return
			}
			p.bytesTx.Add(uint64(n))
		}
	}()
	log.Debug().Str("target_addr", targetConn.RemoteAddr().String()).Str("public_addr", publicConn.RemoteAddr().String()).Msg("ProxyTCP: started bidirectional proxy")
}

// StartProxy starts the TCP proxy listener and begins forwarding connections.
func (p *TCPProxy) StartProxy(srcURL *url.URL, dstURL *url.URL, device *wireguard.UserspaceDevice, bindIp string) error {
	if p.Listener != nil {
		return errors.New("proxy already started")
	}

	ln, err := WGAwareTCPListen(p.Addr, device)
	if err != nil {
		log.Warn().Str("src", srcURL.String()).Str("dst", dstURL.String()).Err(err).Msg("TCPProxy: listen tcp failed")
		return fmt.Errorf("listen tcp %s: %w", dstURL.Host, err)
	}
	p.Listener = ln // Set the listener for the TCPProxy
	log.Info().Str("addr", ln.Addr().String()).Msg("TCPProxy: listening tcp")

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				log.Error().Err(err).Str("dst", dstURL.Host).Msg("TCPProxy: accept error")
				time.Sleep(250 * time.Millisecond)
				continue
			}
			go p.ProxyTCP(conn, srcURL.Host, device)
		}
	}()
	return nil
}

// StartProxy starts the UDP proxy listener and begins forwarding connections.
func (p *UDPProxy) StartProxy(srcURL *url.URL, dstURL *url.URL, device *wireguard.UserspaceDevice, bindIp string) error {
	srcAddr, err := net.ResolveUDPAddr("udp", srcURL.Host)
	if err != nil {
		return fmt.Errorf("resolve udp %s: %w", srcURL.Host, err)
	}

	l, err := WGAwareUDPListen(p.Addr, device)
	if err != nil {
		return fmt.Errorf("listen udp %s: %w", dstURL.Host, err)
	}
	p.Conn = l // Set the connection for the UDPProxy

	log.Info().Str("src", srcURL.Host).Str("dst", dstURL.Host).Str("addr", l.LocalAddr().String()).Msg("UDPProxy: listening udp")
	go p.acceptUDP(l, srcAddr, srcURL, dstURL, device)
	return nil
}

// acceptUDP runs the UDPProxy accept loop. It maintains a session-per-source-addr
// map under a mutex (F-2: previously this map was mutated concurrently by the
// accept loop and per-session response goroutines, causing fatal "concurrent
// map writes" panics). A return-path goroutine is spawned exactly once per
// session, on the first packet from a new source address.
func (p *UDPProxy) acceptUDP(l WGAwareUDPConn, srcAddr *net.UDPAddr, srcURL, dstURL *url.URL, device *wireguard.UserspaceDevice) {
	var smu sync.Mutex
	sessions := make(map[string]WGAwareUDPConn)
	buf := make([]byte, 65535)
	for {
		n, publicAddr, err := l.ReadFromUDP(buf)
		if err != nil {
			log.Debug().Err(err).Str("dst", dstURL.Host).Msg("UDPProxy: udp read error; accept loop exiting")
			return
		}

		key := publicAddr.String()
		smu.Lock()
		tconn, ok := sessions[key]
		if !ok {
			dialed, derr := WGAwareUDPDial(srcAddr, device)
			if derr != nil {
				smu.Unlock()
				log.Error().Err(derr).Str("src", srcURL.Host).Msg("UDPProxy: dial to upstream failed")
				continue
			}
			sessions[key] = dialed
			tconn = dialed
			smu.Unlock()

			// Spawn the response-path goroutine exactly once per session.
			// Use the parameter (tconn), never the outer-scope variable, so
			// closing the right conn is guaranteed.
			go func(pubAddr *net.UDPAddr, tconn WGAwareUDPConn) {
				defer func() {
					tconn.Close()
					smu.Lock()
					delete(sessions, pubAddr.String())
					smu.Unlock()
				}()
				respBuf := make([]byte, 65535)
				for {
					rn, _, rerr := tconn.ReadFromUDP(respBuf)
					if rerr != nil {
						log.Debug().Err(rerr).Str("src", pubAddr.String()).Msg("UDPProxy: target read error; closing session")
						return
					}
					if _, werr := l.WriteToUDP(respBuf[:rn], pubAddr); werr != nil {
						log.Debug().Err(werr).Str("target", srcAddr.String()).Msg("UDPProxy: failed to write to public; closing session")
						return
					}
					p.bytesTx.Add(uint64(rn))
				}
			}(publicAddr, tconn)
		} else {
			smu.Unlock()
		}

		if _, err := tconn.Write(buf[:n]); err != nil {
			log.Debug().Err(err).Str("target", srcAddr.String()).Msg("UDPProxy: target write error")
			continue
		}
		p.bytesRx.Add(uint64(n))
	}
}

func (p *ProxyManager) Close(proxyName string) {
	if existingProxy, ok := p.proxies[proxyName]; ok {
		existingProxy.Close()
		delete(p.proxies, proxyName)
	}
}

func parseMatchers(u *url.URL) map[string]string {
	matchers := make(map[string]string)
	for k, v := range u.Query() {
		if len(v) > 0 {
			matchers["query:"+k] = v[0]
		}
	}
	if u.Fragment != "" {
		parts := strings.Split(u.Fragment, "&")
		for _, part := range parts {
			if strings.Contains(part, "=") {
				kv := strings.SplitN(part, "=", 2)
				matchers["header:"+kv[0]] = kv[1]
			} else {
				matchers["method"] = part
			}
		}
	}
	return matchers
}

func parseModifiers(u *url.URL) map[string]string {
	modifiers := make(map[string]string)
	if u.Fragment != "" {
		parts := strings.Split(u.Fragment, "&")
		for _, part := range parts {
			if strings.Contains(part, "=") {
				kv := strings.SplitN(part, "=", 2)
				modifiers[kv[0]] = kv[1]
			} else if part == "redirect" {
				modifiers["redirect"] = "true"
			}
		}
	}
	return modifiers
}

func generateInstanceId() string {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		// Should not happen, but if it does, fallback to something
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

// StartProxy initializes and starts a new proxy based on the protocol schemes in srcURL and dstURL.
// It returns the newly created Proxy instance or an error if initialization fails.
func (p *ProxyManager) StartProxy(srcURL *url.URL, dstURL *url.URL, proxyName string, device *wireguard.UserspaceDevice, certPEM, keyPEM []byte, bindIp string) (Proxy, error) {
	log.Debug().Str("src", srcURL.String()).Str("src_fragment", srcURL.Fragment).Str("dst", dstURL.String()).Str("dst_fragment", dstURL.Fragment).Str("proxy", proxyName).Msg("Proxy: starting proxy")
	var err error
	// Ensure ports are set in the URLs.
	if err = util.EnsurePort(srcURL); err != nil {
		return nil, err
	}
	if err = util.EnsurePort(dstURL); err != nil {
		return nil, err
	}

	// Check that no other proxies exist with this name
	if _, ok := p.proxies[proxyName]; ok {
		return nil, fmt.Errorf("proxy %s already exists", proxyName)
	}

	proxyType := fmt.Sprintf("%s>%s", srcURL.Scheme, dstURL.Scheme)

	switch proxyType {
	case "tcp>tcp", "https>https", "http>tcp":
		util.RewriteHost(dstURL, bindIp)
		addr, err := net.ResolveTCPAddr("tcp", dstURL.Host)
		if err != nil {
			return nil, err
		}
		newProxy := &TCPProxy{
			Addr:         addr,
			name:         proxyName,
			instanceId:   generateInstanceId(),
			cleanup:      p.Cleanup,
			dialFailures: util.NewFailureTracker(TCPDialFailureThreshold, TCPDialFailureWindow),
		}
		for name, existingProxy := range p.proxies {
			if newProxy.Conflicts(existingProxy) {
				return nil, fmt.Errorf("proxy %s conflicts with %s", proxyName, name)
			}
		}

		if err := newProxy.StartProxy(srcURL, dstURL, device, bindIp); err != nil {
			return newProxy, err
		}
		p.proxies[proxyName] = newProxy
		return newProxy, nil
	case "udp>udp":
		util.RewriteHost(dstURL, bindIp)
		addr, err := net.ResolveUDPAddr("udp", dstURL.Host)
		if err != nil {
			return nil, err
		}
		newProxy := &UDPProxy{Addr: addr, name: proxyName, instanceId: generateInstanceId()}
		for name, existingProxy := range p.proxies {
			if newProxy.Conflicts(existingProxy) {
				return nil, fmt.Errorf("proxy %s conflicts with %s", proxyName, name)
			}
		}

		if err := newProxy.StartProxy(srcURL, dstURL, device, bindIp); err != nil {
			return newProxy, err
		}
		p.proxies[proxyName] = newProxy
		return newProxy, nil
	case "tcp>http", "http>http":
		dstPort, err := util.ParsePort(dstURL.Host, 80)
		if err != nil {
			return nil, err
		}

		matchers := parseMatchers(dstURL)
		modifiers := parseModifiers(srcURL)

		log.Debug().Interface("matchers", matchers).Interface("modifiers", modifiers).Msg("Proxy: parsed http routes")

		newProxy := &VHostRouteProxy{
			Host:       strings.Split(dstURL.Host, ":")[0],
			Port:       dstPort,
			BindIp:     bindIp,
			IsHTTPS:    false,
			name:       proxyName,
			instanceId: generateInstanceId(),
			Rewrite:    dstURL.Path,
			Matchers:   matchers,
			Modifiers:  modifiers,
		}
		for name, existingProxy := range p.proxies {
			if newProxy.Conflicts(existingProxy) {
				return nil, fmt.Errorf("proxy conflicts with %s", name)
			}
		}

		vhostProxy := p.VHostProxyManager.Proxy(bindIp, dstPort)
		// forward the provided wireguard device so upstream dialing can use its NetStack for WG IPs.
		closer, handler, err := vhostProxy.AddHost(vhost.RouteConfig{
			Host:       strings.Split(dstURL.Host, ":")[0],
			PathPrefix: dstURL.Path,
			Matchers:   matchers,
			Modifiers:  modifiers,
			Target:     srcURL,
			Device:     device,
		})
		if err != nil {
			return nil, err
		}
		newProxy.Closer = closer
		newProxy.handler = handler
		p.proxies[proxyName] = newProxy
		return newProxy, nil
	case "tcp>https", "http>https":
		port, err := util.ParsePort(dstURL.Host, 443)
		if err != nil {
			return nil, err
		}

		matchers := parseMatchers(dstURL)
		modifiers := parseModifiers(srcURL)

		log.Debug().Interface("matchers", matchers).Interface("modifiers", modifiers).Msg("Proxy: parsed https routes")

		host := strings.Split(dstURL.Host, ":")[0]
		newProxy := &VHostRouteProxy{
			Host:       host,
			Port:       port,
			BindIp:     bindIp,
			IsHTTPS:    true,
			name:       proxyName,
			instanceId: generateInstanceId(),
			Rewrite:    dstURL.Path,
			Matchers:   matchers,
			Modifiers:  modifiers,
		}
		for name, existingProxy := range p.proxies {
			if newProxy.Conflicts(existingProxy) {
				return nil, fmt.Errorf("proxy conflicts with %s", name)
			}
		}

		vhostProxy := p.VHostProxyManager.Proxy(bindIp, port)
		cfg := vhost.RouteConfig{
			Host:       host,
			PathPrefix: dstURL.Path,
			Matchers:   matchers,
			Modifiers:  modifiers,
			Target:     srcURL,
			Device:     device,
			BindIP:     bindIp,
			ProxyName:  proxyName,
		}

		// If certPEM/keyPEM not provided, configure automatic issuance via ACME HTTP-01.
		if len(certPEM) == 0 || len(keyPEM) == 0 {
			log.Debug().Str("proxy", proxyName).Msg("Proxy: calling AddHostWithACME")
			closer, handler, err := vhostProxy.AddHostWithACME(cfg)
			if err != nil {
				return nil, err
			}
			newProxy.Closer = closer
			newProxy.handler = handler
			p.proxies[proxyName] = newProxy
			return newProxy, nil
		} else {
			log.Debug().Str("proxy", proxyName).Msg("Proxy: calling AddHostWithTLS")
			cfg.CertPEM = string(certPEM)
			cfg.KeyPEM = string(keyPEM)
			closer, handler, err := vhostProxy.AddHostWithTLS(cfg)
			if err != nil {
				return nil, err
			}
			newProxy.Closer = closer
			newProxy.handler = handler
			p.proxies[proxyName] = newProxy
			return newProxy, nil
		}

	default:
		err = fmt.Errorf("unsupported proxy type: %s", proxyType)
	}
	return nil, err
}
