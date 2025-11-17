package proxy

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"aquaduct.dev/weft/src/vhost"
	"aquaduct.dev/weft/wireguard"
	"github.com/rs/zerolog/log"
)

type ProxyManager struct {
	proxies map[string]Proxy
	// bindIP constrains proxy listeners to a specific IP when set.
	bindIP            string
	VHostProxyManager *vhost.VHostProxyManager
}

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
	Tx uint64
	Rx uint64
} {
	result := make(map[string]struct {
		Tx uint64
		Rx uint64
	})

	for name, pr := range p.proxies {
		// Prefer exported accessor methods on the proxy.
		// Try a few common method names that implementations provide.
		var tx, rx uint64
		switched := false

		// If the Proxy interface already exposes BytesTx/BytesRx, use it.
		if v, ok := pr.(interface {
			BytesTx() uint64
			BytesRx() uint64
		}); ok {
			tx = v.BytesTx()
			rx = v.BytesRx()
			switched = true
		}

		// Some concrete types may expose TxBytes/RxBytes or Tx/Rx accessors.
		if !switched {
			if v, ok := pr.(interface {
				TxBytes() uint64
				RxBytes() uint64
			}); ok {
				tx = v.TxBytes()
				rx = v.RxBytes()
				switched = true
			}
		}

		if !switched {
			if v, ok := pr.(interface {
				Tx() uint64
				Rx() uint64
			}); ok {
				tx = v.Tx()
				rx = v.Rx()
				switched = true
			}
		}

		if !switched {
			// Last resort: if concrete types expose BytesTx/BytesRx methods under different names.
			// Add more type assertions here as necessary.
			log.Debug().Msgf("GetProxyCounters: proxy %s does not expose known counter accessors; skipping", name)
			continue
		}

		result[name] = struct {
			Tx uint64
			Rx uint64
		}{Tx: tx, Rx: rx}
	}

	return result
}

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
		return
	}

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

	log.Info().Str("src", srcURL.Host).Str("dst", dstURL.Host).Msg("UDPProxy: listening udp")
	go func() {
		sessions := make(map[string]WGAwareUDPConn)
		buf := make([]byte, 65535)
		for {
			n, publicAddr, err := l.ReadFromUDP(buf)

			if err != nil {
				log.Error().Err(err).Str("dst", dstURL.Host).Msg("UDPProxy: udp read error")
				return
			}

			key := publicAddr.String()
			targetConn, ok := sessions[key]
			if !ok {
				if err != nil {
					log.Error().Err(err).Str("src", srcURL.Host).Msg("UDPProxy: udp resolve local error")
					continue
				}
				targetConn, err = WGAwareUDPDial(srcAddr, device)
				sessions[key] = targetConn
			}

			targetConn.Write(buf[:n])
			p.bytesRx.Add(uint64(n))
			// goroutine to copy from target to public
			go func(pubAddr net.Addr, tconn WGAwareUDPConn) {
				defer func() {
					targetConn.Close()
					delete(sessions, pubAddr.String())
				}()
				respBuf := make([]byte, 65535)
				if err != nil {
					return
				}
				for {
					n, _, err := tconn.ReadFromUDP(respBuf)
					if err != nil {
						log.Error().Err(err).Str("src", publicAddr.String()).Msg("UDPProxy: failed to read from UDP")
						return
					}
					_, err = l.WriteToUDP(respBuf[:n], publicAddr)
					if err != nil {
						log.Error().Err(err).Str("target", srcAddr.String()).Msg("UDPProxy: failed to write")
						return
					}
					p.bytesTx.Add(uint64(n))
				}
			}(publicAddr, targetConn)

		}
	}()
	return nil
}

func (p *ProxyManager) Close(proxyName string) {
	if existingProxy, ok := p.proxies[proxyName]; ok {
		existingProxy.Close()
		delete(p.proxies, proxyName)
	}
}

func ensurePort(u *url.URL) error {
	if u.Port() == "" {
		switch u.Scheme {
		case "http":
			u.Host += ":80"
		case "https":
			u.Host += ":443"
		default:
			return fmt.Errorf("unsupported scheme for missing port: %s", u.String())
		}
	}
	return nil
}
func rewriteHost(u *url.URL, host string) {
	if host == "0.0.0.0" || host == "" {
		return
	}
	u.Host = host + ":" + u.Port()
}

func (p *ProxyManager) StartProxy(srcURL *url.URL, dstURL *url.URL, proxyName string, device *wireguard.UserspaceDevice, certPEM, keyPEM []byte, bindIp string) (Proxy, error) {
	log.Info().Str("src", srcURL.String()).Str("dst", dstURL.String()).Str("proxy", proxyName).Msg("Proxy: starting proxy")
	var err error
	// Ensure ports are set in the URLs.
	if err = ensurePort(srcURL); err != nil {
		return nil, err
	}
	if err = ensurePort(dstURL); err != nil {
		return nil, err
	}

	// Check that no other proxies exist with this name
	if _, ok := p.proxies[proxyName]; ok {
		return nil, fmt.Errorf("proxy %s already exists", proxyName)
	}

	proxyType := fmt.Sprintf("%s>%s", srcURL.Scheme, dstURL.Scheme)

	switch proxyType {
	case "tcp>tcp", "https>https", "http>tcp":
		rewriteHost(dstURL, bindIp)
		addr, err := net.ResolveTCPAddr("tcp", dstURL.Host)
		if err != nil {
			return nil, err
		}
		newProxy := &TCPProxy{Addr: addr, name: proxyName}
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
		rewriteHost(dstURL, bindIp)
		addr, err := net.ResolveUDPAddr("udp", dstURL.Host)
		if err != nil {
			return nil, err
		}
		newProxy := &UDPProxy{Addr: addr, name: proxyName}
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
		split := strings.Split(dstURL.Host, ":")
		port := 80
		if len(split) > 1 {
			port, err = strconv.Atoi(split[1])
			if err != nil {
				return nil, fmt.Errorf("invalid port %s: %w", split[1], err)
			}
		}
		newProxy := &VHostRouteProxy{Host: split[0], Port: port, BindIp: bindIp, IsHTTPS: false, name: proxyName}
		for name, existingProxy := range p.proxies {
			if newProxy.Conflicts(existingProxy) {
				return nil, fmt.Errorf("proxy conflicts with %s", name)
			}
		}

		vhostProxy := p.VHostProxyManager.Proxy(bindIp, port)
		// forward the provided wireguard device so upstream dialing can use its NetStack for WG IPs.
		closer, handler, err := vhostProxy.AddHost(split[0], srcURL, device)
		if err != nil {
			return nil, err
		}
		newProxy.Closer = closer
		newProxy.handler = handler
		p.proxies[proxyName] = newProxy
		return newProxy, nil
	case "tcp>https", "http>https":
		split := strings.Split(dstURL.Host, ":")
		port := 443
		if len(split) > 1 {
			port, err = strconv.Atoi(split[1])
			if err != nil {
				return nil, fmt.Errorf("invalid port %s: %w", split[1], err)
			}
		}
		newProxy := &VHostRouteProxy{Host: split[0], Port: port, BindIp: bindIp, IsHTTPS: true, name: proxyName}
		for name, existingProxy := range p.proxies {
			if newProxy.Conflicts(existingProxy) {
				return nil, fmt.Errorf("proxy conflicts with %s", name)
			}
		}

		vhostProxy := p.VHostProxyManager.Proxy(bindIp, port)
		// If certPEM/keyPEM not provided, configure automatic issuance via ACME HTTP-01.
		if len(certPEM) == 0 || len(keyPEM) == 0 {
			log.Debug().Str("proxy", proxyName).Msg("Proxy: calling AddHostWithACME")
			closer, handler, err := vhostProxy.AddHostWithACME(split[0], srcURL, device, bindIp)
			if err != nil {
				return nil, err
			}
			newProxy.Closer = closer
			newProxy.handler = handler
			p.proxies[proxyName] = newProxy
			return newProxy, nil
		} else {
			log.Debug().Str("proxy", proxyName).Msg("Proxy: calling AddHostWithTLS")
			closer, handler, err := vhostProxy.AddHostWithTLS(split[0], srcURL, device, string(certPEM), string(keyPEM))
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
