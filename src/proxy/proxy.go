package proxy

import (
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"aquaduct.dev/weft/src/vhost"
	"aquaduct.dev/weft/wireguard"
	"github.com/rs/zerolog/log"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
)

type ProxyManager struct {
	proxies map[string]io.Closer
	// bindIP constrains proxy listeners to a specific IP when set.
	bindIP            string
	hostToProxyName   map[string]string // New map to store host to proxyName mapping
	proxyNameToHost   map[string]string // New map to store proxyName to host mapping
	VHostProxyManager *vhost.VHostProxyManager
}

func NewProxyManager() *ProxyManager {
	return &ProxyManager{
		proxies:           make(map[string]io.Closer),
		hostToProxyName:   make(map[string]string), // Initialize the new map
		proxyNameToHost:   make(map[string]string), // Initialize the new map
		VHostProxyManager: vhost.NewVHostProxyManager(),
	}
}

// SetBindIP updates the ProxyManager's bind IP in a safe, exported way.
// Server should call this instead of modifying the unexported field directly.
func (p *ProxyManager) SetBindIP(bindIP string) {
	p.bindIP = bindIP
}

// ProxyTCP is a generic TCP proxy that forwards connections.
func ProxyTCP(publicConn net.Conn, target string, device *wireguard.UserspaceDevice) {
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
		}
	}()
	log.Debug().Str("target_addr", targetConn.RemoteAddr().String()).Str("public_addr", publicConn.RemoteAddr().String()).Msg("ProxyTCP: started bidirectional proxy")
}

func UDPListen(publicConn *net.UDPConn, clientAddr netip.Addr) {
	// Maintain per-public-source mapping to a target UDP connection.
	// This lets concurrent public clients each get their own UDP "session".
	type session struct {
		target *net.UDPConn
		// lastSeen is the public address we've last seen for this session.
		publicAddr *net.UDPAddr
	}

	sessions := make(map[string]*session)

	// Buffer to read incoming packets
	buf := make([]byte, 64*1024)

	for {
		n, publicAddr, err := publicConn.ReadFromUDP(buf)
		if err != nil {
			// socket closed or error; exit goroutine
			log.Error().Err(err).Msg("UDPListen: ReadFromUDP error")
			return
		}

		// copy packet payload
		payload := make([]byte, n)
		copy(payload, buf[:n])

		key := publicAddr.String()

		sess, ok := sessions[key]
		if !ok {
			// create a new UDP connection to the clientAddr for this public source
			clientAddrPort := netip.AddrPortFrom(clientAddr, uint16(publicConn.LocalAddr().(*net.UDPAddr).Port))
			log.Debug().Str("public_addr", publicAddr.String()).Str("target_addr", clientAddrPort.String()).Msg("UDPListen: new session")
			raddr, err := net.ResolveUDPAddr("udp", clientAddrPort.String())
			if err != nil {
				log.Error().Err(err).Str("target_addr", clientAddr.String()).Msg("UDPListen: ResolveUDPAddr failed")
				continue
			}
			targetConn, err := net.DialUDP("udp", nil, raddr)
			if err != nil {
				log.Error().Err(err).Str("target_addr", clientAddr.String()).Msg("UDPListen: DialUDP to target failed")
				continue
			}

			sess = &session{
				target:     targetConn,
				publicAddr: publicAddr,
			}
			sessions[key] = sess

			// start goroutine to read responses from target and forward back to the publicAddr
			go func(pubAddr *net.UDPAddr, tconn *net.UDPConn) {
				rbuf := make([]byte, 64*1024)
				for {
					nr, err := tconn.Read(rbuf)
					if err != nil {
						// Target closed or error - remove session and exit goroutine.
						log.Error().Err(err).Str("public_addr", pubAddr.String()).Msg("UDPListen: target Read error for session")
						// best-effort: close target and remove mapping
						tconn.Close()
						return
					}
					if nr > 0 {
						// send back to public source
						_, err := publicConn.WriteToUDP(rbuf[:nr], pubAddr)
						if err != nil {
							log.Error().Err(err).Str("public_addr", pubAddr.String()).Msg("UDPListen: WriteToUDP to public failed")
							// continue; connection may still be usable
						} else {
							log.Debug().Int("bytes", nr).Str("target_addr", tconn.RemoteAddr().String()).Str("public_addr", pubAddr.String()).Msg("UDPListen: forwarded from target to public")
						}
					}
				}
			}(publicAddr, targetConn)
		}

		// forward the received public packet to the corresponding target
		_, err = sess.target.Write(payload)
		if err != nil {
			log.Error().Err(err).Str("target_addr", clientAddr.String()).Str("public_addr", publicAddr.String()).Msg("UDPListen: write to target failed for public")
			// on write error, close target and delete session
			sess.target.Close()
			delete(sessions, key)
			continue
		}
		log.Debug().Int("bytes", len(payload)).Str("public_addr", publicAddr.String()).Str("target_addr", clientAddr.String()).Msg("UDPListen: forwarded from public to target")
	}
}

func (p *ProxyManager) Close(proxyName string) {
	if existingProxy, ok := p.proxies[proxyName]; ok {
		existingProxy.Close()
		delete(p.proxies, proxyName)
		if host, ok := p.proxyNameToHost[proxyName]; ok {
			delete(p.hostToProxyName, host)
			delete(p.proxyNameToHost, proxyName)
		}
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

type WGAwareUDPConn struct {
	goNetConn *gonet.UDPConn
	netConn   *net.UDPConn
}

func (w *WGAwareUDPConn) ReadFromUDP(b []byte) (int, *net.UDPAddr, error) {
	if w.netConn != nil {
		return w.netConn.ReadFromUDP(b)
	}
	n, addr, err := w.goNetConn.ReadFrom(b)
	return n, addr.(*net.UDPAddr), err
}

func (w *WGAwareUDPConn) Write(b []byte) (int, error) {
	if w.netConn != nil {
		return w.netConn.Write(b)
	}
	return w.goNetConn.Write(b)
}

func (w *WGAwareUDPConn) WriteToUDP(b []byte, addr *net.UDPAddr) (int, error) {
	if w.netConn != nil {
		return w.netConn.WriteToUDP(b, addr)
	}
	return w.goNetConn.WriteTo(b, addr)
}

func (w WGAwareUDPConn) Close() error {
	if w.netConn != nil {
		return w.netConn.Close()
	}
	return w.goNetConn.Close()
}

func WGAwareUDPDial(addr *net.UDPAddr, device *wireguard.UserspaceDevice) (WGAwareUDPConn, error) {
	if strings.HasPrefix(addr.String(), "10.1.") {
		if device == nil {
			return WGAwareUDPConn{}, fmt.Errorf("cannot dial on WireGuard host %s without wireguard device", addr.String())
		}
		outgoingConn, err := device.NetStack.DialUDP(nil, addr)
		return WGAwareUDPConn{goNetConn: outgoingConn, netConn: nil}, err
	} else {
		outgoingConn, err := net.DialUDP("udp", nil, addr)
		return WGAwareUDPConn{goNetConn: nil, netConn: outgoingConn}, err

	}
}

func WGAwareUDPListen(addr *net.UDPAddr, device *wireguard.UserspaceDevice) (WGAwareUDPConn, error) {
	if strings.HasPrefix(addr.String(), "10.1.") {
		rawListener, err := device.NetStack.ListenUDP(addr)
		if device == nil {
			return WGAwareUDPConn{}, fmt.Errorf("cannot listen on WireGuard host %s without wireguard device", addr.String())
		}
		return WGAwareUDPConn{goNetConn: rawListener, netConn: nil}, err
	} else {
		rawListener, err := net.ListenUDP("udp", addr)
		return WGAwareUDPConn{goNetConn: nil, netConn: rawListener}, err
	}
}

func WGAwareTCPDial(addr *net.TCPAddr, device *wireguard.UserspaceDevice) (net.Conn, error) {
	if strings.HasPrefix(addr.String(), "10.1.") {
		if device == nil {
			return nil, fmt.Errorf("cannot dial on WireGuard host %s without wireguard device", addr.String())
		}
		return device.NetStack.DialTCP(addr)
	} else {
		return net.DialTCP("tcp", nil, addr)
	}
}

func WGAwareTCPListen(addr *net.TCPAddr, device *wireguard.UserspaceDevice) (net.Listener, error) {
	if strings.HasPrefix(addr.String(), "10.1.") {
		if device == nil {
			return nil, fmt.Errorf("cannot listen on WireGuard host %s without wireguard device", addr.String())
		}
		return device.NetStack.ListenTCP(addr)
	} else {
		return net.ListenTCP("tcp", addr)
	}
}

func (p *ProxyManager) StartProxy(srcURL *url.URL, dstURL *url.URL, proxyName string, device *wireguard.UserspaceDevice, certPEM, keyPEM []byte, bindIp string) error {
	log.Info().Str("src", srcURL.String()).Str("dst", dstURL.String()).Str("proxy", proxyName).Msg("Proxy: starting proxy")
	var err error
	// Ensure ports are set in the URLs.
	if ensurePort(srcURL) != nil {
		return err
	}
	if ensurePort(dstURL) != nil {
		return err
	}

	// Validate by checking that no other proxies exist with this name
	if _, ok := p.proxies[proxyName]; ok {
		return fmt.Errorf("proxy %s already exists", proxyName)
	}
	if existingProxyName, ok := p.hostToProxyName[dstURL.Host]; ok {
		return fmt.Errorf("proxy for host %s already exists (named %s)", dstURL.Host, existingProxyName)
	}

	proxyType := fmt.Sprintf("%s>%s", srcURL.Scheme, dstURL.Scheme)
	switch proxyType {
	case "tcp>tcp", "https>https", "http>tcp":
		// Enforce that the TCP listener host must be the same as bindIP.
		rewriteHost(dstURL, bindIp)
		// Create a listener on the validated host:port. If host is in the wireguard subnet and we
		// have a device, listen via the device's NetStack; otherwise use the system net.Listen.
		listenAddr, err := net.ResolveTCPAddr("tcp", dstURL.Host)
		if err != nil {
			return fmt.Errorf("resolve tcp %s: %w", dstURL.Host, err)
		}
		ln, err := WGAwareTCPListen(listenAddr, device)
		if err != nil {
			log.Warn().Str("proxy_type", proxyType).Str("src", srcURL.String()).Str("dst", dstURL.String()).Err(err).Msg("Proxy: listen tcp failed")
			return fmt.Errorf("listen tcp %s: %w", dstURL.Host, err)
		}
		go func() {
			for {
				conn, err := ln.Accept()
				if err != nil {
					log.Error().Err(err).Str("dst", dstURL.Host).Msg("proxy accept error")
					time.Sleep(250 * time.Millisecond)
					continue
				}
				go ProxyTCP(conn, srcURL.Host, device)
			}
		}()
		p.proxies[proxyName] = ln
		p.hostToProxyName[dstURL.Host] = proxyName
		p.proxyNameToHost[proxyName] = dstURL.Host
	case "udp>udp":
		// Enforce that the UDP listener host must be the same as bindIP.
		rewriteHost(dstURL, bindIp)
		// For UDP, bind explicitly to the provided host (which may be a WG IP).
		addr, err := net.ResolveUDPAddr("udp", dstURL.Host)
		if err != nil {
			return fmt.Errorf("resolve udp %s: %w", dstURL.Host, err)
		}
		srcAddr, err := net.ResolveUDPAddr("udp", srcURL.Host)
		if err != nil {
			return fmt.Errorf("resolve udp %s: %w", srcURL.Host, err)
		}
		l, err := WGAwareUDPListen(addr, device)
		if err != nil {
			return fmt.Errorf("listen udp %s: %w", dstURL.Host, err)
		}
		log.Info().Str("proxy_type", proxyType).Str("src", srcURL.Host).Str("dst", dstURL.Host).Msg("Proxy: listening udp")
		go func() {
			sessions := make(map[string]WGAwareUDPConn)
			buf := make([]byte, 65535)
			for {
				n, publicAddr, err := l.ReadFromUDP(buf)

				if err != nil {
					log.Error().Err(err).Str("dst", dstURL.Host).Msg("udp read error")
					return
				}

				key := publicAddr.String()
				targetConn, ok := sessions[key]
				if !ok {
					if err != nil {
						log.Error().Err(err).Str("src", srcURL.Host).Msg("udp resolve local error")
						continue
					}
					targetConn, err = WGAwareUDPDial(srcAddr, device)
					sessions[key] = targetConn
				}
				targetConn.Write(buf[:n])

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
							log.Error().Err(err).Str("src", publicAddr.String()).Msg("Proxy: failed to read from UDP")
							return
						}
						_, err = l.WriteToUDP(respBuf[:n], publicAddr)
						if err != nil {
							log.Error().Err(err).Str("target", srcAddr.String()).Msg("Proxy: failed to write")
							return
						}
					}
				}(publicAddr, targetConn)

			}
		}()
		p.proxies[proxyName] = l
		p.hostToProxyName[dstURL.Host] = proxyName
		p.proxyNameToHost[proxyName] = dstURL.Host
	case "tcp>http", "http>http":
		split := strings.Split(dstURL.Host, ":")
		port := 80
		if len(split) > 1 {
			port, err = strconv.Atoi(split[1])
			if err != nil {
				return fmt.Errorf("invalid port %s: %w", split[1], err)
			}
		}
		proxy := p.VHostProxyManager.Proxy(bindIp, port)
		// forward the provided wireguard device so upstream dialing can use its NetStack for WG IPs.
		closer, err := proxy.AddHost(split[0], srcURL, device)
		if err != nil {
			return err
		}
		p.proxies[proxyName] = closer
		p.hostToProxyName[dstURL.Host] = proxyName
		p.proxyNameToHost[proxyName] = dstURL.Host
	case "tcp>https", "http>https":
		split := strings.Split(dstURL.Host, ":")
		port := 443
		if len(split) > 1 {
			port, err = strconv.Atoi(split[1])
			if err != nil {
				return fmt.Errorf("invalid port %s: %w", split[1], err)
			}
		}
		proxy := p.VHostProxyManager.Proxy(bindIp, port)
		// If certPEM/keyPEM not provided, configure automatic issuance via ACME HTTP-01.
		if len(certPEM) == 0 || len(keyPEM) == 0 {
			closer, err := proxy.AddHostWithACME(split[0], srcURL, device, bindIp)
			if err != nil {
				return err
			}
			p.proxies[proxyName] = closer
			p.hostToProxyName[dstURL.Host] = proxyName
			p.proxyNameToHost[proxyName] = dstURL.Host
		} else {
			closer, err := proxy.AddHostWithTLS(split[0], srcURL, device, string(certPEM), string(keyPEM))
			if err != nil {
				return err
			}
			p.proxies[proxyName] = closer
			p.hostToProxyName[dstURL.Host] = proxyName
			p.proxyNameToHost[proxyName] = dstURL.Host
		}
	default:
		err = fmt.Errorf("unsupported proxy type: %s", proxyType)
	}
	return err
}
