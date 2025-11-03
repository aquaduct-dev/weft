package wireguard

import (
	"io"
	"log"
	"net"
)

// TCPProxy forwards a connection to a given address.
func TCPProxy(from net.Conn, to string) {
	toConn, err := net.Dial("tcp", to)
	if err != nil {
		log.Printf("Failed to connect to local service: %v", err)
		from.Close()
		return
	}

	go func() {
		defer from.Close()
		defer toConn.Close()
		io.Copy(from, toConn)
	}()
	go func() {
		defer from.Close()
		defer toConn.Close()
		io.Copy(toConn, from)
	}()
}
