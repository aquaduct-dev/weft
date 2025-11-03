package server

import (
	"io"
	"net"
	"sync"
)

// TCPProxy forwards data between two connections.
func TCPProxy(from net.Conn, to net.Conn) {
	go func() {
		defer from.Close()
		defer to.Close()
		io.Copy(from, to)
	}()
	go func() {
		defer from.Close()
		defer to.Close()
		io.Copy(to, from)
	}()
}

func UDPProxy(publicConn *net.UDPConn, targetConn net.Conn) {
	var clientAddr net.Addr
	var mu sync.Mutex

	// Read from public and write to target
	go func() {
		buf := make([]byte, 1500)
		for {
			n, addr, err := publicConn.ReadFrom(buf)
			if err != nil {
				return
			}
			mu.Lock()
			clientAddr = addr
			mu.Unlock()
			_, err = targetConn.Write(buf[:n])
			if err != nil {
				return
			}
		}
	}()

	// Read from target and write to public
	go func() {
		buf := make([]byte, 1500)
		for {
			n, err := targetConn.Read(buf)
			if err != nil {
				return
			}
			mu.Lock()
			addr := clientAddr
			mu.Unlock()
			if addr != nil {
				_, err = publicConn.WriteTo(buf[:n], addr)
				if err != nil {
					return
				}
			}
		}
	}()
}
