package server

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"aquaduct.dev/weft/wireguard"
)

type ProxyManager struct {
	proxies           map[string]io.Closer
	VHostProxyManager *VHostProxyManager
}

func NewProxyManager() *ProxyManager {
	return &ProxyManager{
		proxies:           make(map[string]io.Closer),
		VHostProxyManager: &VHostProxyManager{proxies: make(map[int]*VHostProxy)},
	}
}

// ProxyTCP is a generic TCP proxy that forwards connections.
func ProxyTCP(publicConn net.Conn, target string, device *wireguard.UserspaceDevice) {
	fmt.Printf("ProxyTCP: accepted public connection from %v — dialing target %s\n", publicConn.RemoteAddr(), target)
	if device == nil {
		if strings.HasPrefix(target, "10.1") {
			log.Printf("ProxyTCP: no wireguard device but destination %s can only be served on wireguard!", target)
		}
	}
	var targetConn net.Conn
	var err error
	if strings.HasPrefix(target, "10.1") {
		fmt.Printf("ProxyTCP: dial to target %s via wireguard %v", target, device)
		targetConn, err = device.NetStack.Dial("tcp", target)
	} else {
		fmt.Printf("ProxyTCP: dial to target %s", target)
		targetConn, err = net.Dial("tcp", target)
	}
	if err != nil {
		fmt.Printf("ProxyTCP: dial to target %s failed: %v — closing public connection\n", target, err)
		publicConn.Close()
		return
	}

	// Wire up copy in both directions. Close both sides when done.
	go func(pub net.Conn, tgt net.Conn) {
		defer pub.Close()
		defer tgt.Close()
		fmt.Printf("ProxyTCP: proxy start %v <-> %v\n", tgt.RemoteAddr(), pub.RemoteAddr())

		// copy target->public
		done := make(chan struct{})
		go func() {
			_, err := io.Copy(pub, tgt)
			if err != nil {
				fmt.Printf("ProxyTCP: copy target->public error: %v\n", err)
			}
			close(done)
		}()

		// copy public->target (will return when pub closed)
		_, err := io.Copy(tgt, pub)
		if err != nil {
			fmt.Printf("ProxyTCP: copy public->target error: %v\n", err)
		}
		<-done
		fmt.Printf("ProxyTCP: proxy finished %v <-> %v\n", tgt.RemoteAddr(), pub.RemoteAddr())
	}(publicConn, targetConn)
}

func UDPListen(s *Server, publicConn *net.UDPConn, clientAddr netip.Addr) {
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
			fmt.Printf("UDPListen: ReadFromUDP error: %v\n", err)
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
			fmt.Printf("UDPListen: new session for public %s -> dialing target %s\n", publicAddr, clientAddrPort.String())
			raddr, err := net.ResolveUDPAddr("udp", clientAddrPort.String())
			if err != nil {
				fmt.Printf("UDPListen: ResolveUDPAddr(%s) failed: %v\n", clientAddr, err)
				continue
			}
			targetConn, err := net.DialUDP("udp", nil, raddr)
			if err != nil {
				fmt.Printf("UDPListen: DialUDP to %s failed: %v\n", clientAddr, err)
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
						fmt.Printf("UDPListen: target Read error for session %s -> %v\n", pubAddr, err)
						// best-effort: close target and remove mapping
						tconn.Close()
						return
					}
					if nr > 0 {
						// send back to public source
						_, err := publicConn.WriteToUDP(rbuf[:nr], pubAddr)
						if err != nil {
							fmt.Printf("UDPListen: WriteToUDP to %s failed: %v\n", pubAddr, err)
							// continue; connection may still be usable
						} else {
							fmt.Printf("UDPListen: forwarded %d bytes from target %s -> public %s\n", nr, tconn.RemoteAddr(), pubAddr)
						}
					}
				}
			}(publicAddr, targetConn)
		}

		// forward the received public packet to the corresponding target
		_, err = sess.target.Write(payload)
		if err != nil {
			fmt.Printf("UDPListen: write to target %s failed for public %s: %v\n", clientAddr, publicAddr, err)
			// on write error, close target and delete session
			sess.target.Close()
			delete(sessions, key)
			continue
		}
		fmt.Printf("UDPListen: forwarded %d bytes from public %s -> target %s\n", len(payload), publicAddr, clientAddr)
	}
}

func (p *ProxyManager) Close(proxyName string) {
	p.proxies[proxyName].Close()
	delete(p.proxies, proxyName)
}

func (p *ProxyManager) StartProxy(srcURL *url.URL, dstURL *url.URL, proxyName string, device *wireguard.UserspaceDevice) error {
	var err error
	if device == nil {
		if strings.HasPrefix(dstURL.Host, "10.1") {
			return fmt.Errorf("no wireguard device but destination %s can only be served on wireguard", dstURL.String())
		}
		if strings.HasPrefix(dstURL.Host, "10.1") {
			return fmt.Errorf("no wireguard device but source %s can only be served on wireguard", srcURL.String())
		}
	}
	// remoteURL.Host is expected to include the desired bind IP (e.g. the assigned WG IP) and port.
	switch srcURL.Scheme {
	case "tcp":
		var ln net.Listener
		var err error
		if strings.HasPrefix(dstURL.Host, "10.1") {
			tcpAddr, err := net.ResolveTCPAddr("tcp", dstURL.Host)
			if err != nil {
				return fmt.Errorf("resolve tcp address %s: %w", dstURL.Host, err)
			}
			ln, err = device.NetStack.ListenTCP(tcpAddr)
			log.Printf("proxy: listening tcp on wireguard %s -> forwarding to %s", dstURL.Host, srcURL.Host)
			if err != nil {
				return fmt.Errorf("ListenTCP error for %s: %w", dstURL.Host, err)
			}
		} else {
			ln, err = net.Listen("tcp", dstURL.Host)
			log.Printf("proxy: listening tcp on %s -> forwarding to %s", dstURL.Host, srcURL.Host)
		}
		if err != nil {
			return fmt.Errorf("listen tcp %s: %w", dstURL.Host, err)
		}
		go func() {
			for {
				conn, err := ln.Accept()
				if err != nil {
					log.Printf("proxy accept error on %s: %v", dstURL.Host, err)
					return
				}
				go ProxyTCP(conn, srcURL.Host, device)
			}
		}()
		p.proxies[proxyName] = ln
	case "udp":
		// For UDP, bind explicitly to the provided host (which may be a WG IP).
		addr, err := net.ResolveUDPAddr("udp", dstURL.Host)
		if err != nil {
			return fmt.Errorf("resolve udp %s: %w", dstURL.Host, err)
		}
		l, err := net.ListenUDP("udp", addr)
		if err != nil {
			return fmt.Errorf("listen udp %s: %w", dstURL.Host, err)
		}
		log.Printf("proxy: listening udp on %s -> forwarding to %s", dstURL.Host, srcURL.Host)
		go func() {
			sessions := make(map[string]*net.UDPConn)
			buf := make([]byte, 65535)
			for {
				n, publicAddr, err := l.ReadFromUDP(buf)
				if err != nil {
					log.Printf("udp read error on %s: %v", dstURL.Host, err)
					return
				}

				key := publicAddr.String()
				targetConn, ok := sessions[key]
				if !ok {
					dst, err := net.ResolveUDPAddr("udp", srcURL.Host)
					if err != nil {
						log.Printf("udp resolve local %s error: %v", srcURL.Host, err)
						continue
					}
					newTargetConn, err := net.DialUDP("udp", nil, dst)
					if err != nil {
						log.Printf("udp dial error to %s: %v", srcURL.Host, err)
						continue
					}
					targetConn = newTargetConn
					sessions[key] = targetConn

					// goroutine to copy from target to public
					go func(publicAddr *net.UDPAddr, targetConn *net.UDPConn) {
						defer func() {
							targetConn.Close()
							delete(sessions, publicAddr.String())
						}()
						respBuf := make([]byte, 65535)
						for {
							// TODO: add timeout and session cleanup
							n, _, err := targetConn.ReadFrom(respBuf)
							if err != nil {
								return
							}
							_, err = l.WriteToUDP(respBuf[:n], publicAddr)
							if err != nil {
								return
							}
						}
					}(publicAddr, targetConn)
				}

				if _, err := targetConn.Write(buf[:n]); err != nil {
					log.Printf("udp write error to %s: %v", srcURL.Host, err)
					// handle error, maybe close and delete session
				}
			}
		}()
		p.proxies[proxyName] = l

	case "http":
		split := strings.Split(dstURL.Host, ":")
		port := 80
		if len(split) > 1 {
			port, err = strconv.Atoi(split[1])
			if err != nil {
				return fmt.Errorf("invalid port %s: %w", split[1], err)
			}
		}
		proxy := p.VHostProxyManager.Proxy(port)
		closer, err := proxy.AddHost(split[0], srcURL)
		if err != nil {
			return err
		}
		p.proxies[proxyName] = closer
	case "https":
		split := strings.Split(dstURL.Host, ":")
		port := 443
		if len(split) > 1 {
			port, err = strconv.Atoi(split[1])
			if err != nil {
				return fmt.Errorf("invalid port %s: %w", split[1], err)
			}
		}
		proxy := p.VHostProxyManager.Proxy(port)
		closer, err := proxy.AddHost(split[0], srcURL)
		if err != nil {
			return err
		}
		p.proxies[proxyName] = closer
	default:
		err = fmt.Errorf("unsupported protocol: %s", srcURL.Scheme)
	}
	return err
}
