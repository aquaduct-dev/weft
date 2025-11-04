package server

import (
	"fmt"
	"io"
	"net"
)

// NewTCPProxy creates a TCP listener on a public port and returns a closer.
func NewTCPProxy(s *Server, publicPort int, clientAddr string) (io.Closer, error) {
	addr := fmt.Sprintf(":%d", publicPort)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	go TCPListen(s, ln, clientAddr)
	return ln, nil
}

// NewUDPProxy creates a UDP listener on a public port and returns a closer.
func NewUDPProxy(s *Server, publicPort int, clientAddr string) (io.Closer, error) {
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", publicPort))
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, err
	}
	go UDPListen(s, conn, clientAddr)
	return conn, nil
}

// TCPListen accepts a Server, a net.Listener for public connections and a client address (string).
// It accepts incoming connections on the listener and forwards data between the accepted public
// connection and the corresponding client connection obtained from the Server using clientAddr.
func TCPListen(s *Server, ln net.Listener, clientAddr string) {
	// For TCP we open a new client connection for every accepted public connection.
	// This avoids multiplexing multiple public clients onto a single TCP stream.
	// Add detailed logs to observe dialing and connection lifecycles.

	for {
		publicConn, err := ln.Accept()
		if err != nil {
			// listener closed or error accepting; exit goroutine
			return
		}

		// Dial a fresh target connection for this public connection.
		fmt.Printf("TCPListen: accepted public connection from %v — dialing target %s\n", publicConn.RemoteAddr(), clientAddr)
		targetConn, err := net.Dial("tcp", clientAddr)
		if err != nil {
			fmt.Printf("TCPListen: dial to target %s failed: %v — closing public connection\n", clientAddr, err)
			publicConn.Close()
			continue
		}

		// Wire up copy in both directions. Close both sides when done.
		go func(pub net.Conn, tgt net.Conn) {
			defer pub.Close()
			defer tgt.Close()
			fmt.Printf("TCPListen: proxy start %v <-> %v\n", tgt.RemoteAddr(), pub.RemoteAddr())

			// copy target->public
			done := make(chan struct{})
			go func() {
				_, err := io.Copy(pub, tgt)
				if err != nil {
					fmt.Printf("TCPListen: copy target->public error: %v\n", err)
				}
				close(done)
			}()

			// copy public->target (will return when pub closed)
			_, err := io.Copy(tgt, pub)
			if err != nil {
				fmt.Printf("TCPListen: copy public->target error: %v\n", err)
			}
			<-done
			fmt.Printf("TCPListen: proxy finished %v <-> %v\n", tgt.RemoteAddr(), pub.RemoteAddr())
		}(publicConn, targetConn)
	}
}

// UDPListen accepts a Server, a public UDPConn and a client address string. It reads packets
// from the public UDP socket and forwards them to the client connection resolved via the Server.
// Responses from the target connection are written back to the last seen public address.
func UDPListen(s *Server, publicConn *net.UDPConn, clientAddr string) {
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
			fmt.Printf("UDPListen: new session for public %s -> dialing target %s\n", publicAddr, clientAddr)
			raddr, err := net.ResolveUDPAddr("udp", clientAddr)
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
