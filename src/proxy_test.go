package server

import (
	"fmt"
	"io"
	"net"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestProxy(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Proxy Suite")
}

var _ = Describe("L3 Proxy Test", func() {
	var s *Server
	var remotePort int
	var target string

	BeforeEach(func() {
		remotePort = 12345
		target = "127.0.0.1:54321"
	})

	It("should create a new UDP proxy and listen for connections", func() {
		// Start a UDP echo server for testing
		a, err := net.ResolveUDPAddr("udp", target)
		Expect(err).ToNot(HaveOccurred())
		echoConn, err := net.ListenUDP("udp", a)
		Expect(err).ToNot(HaveOccurred())
		defer echoConn.Close()

		go func() {
			buf := make([]byte, 1500)
			for {
				n, addr, err := echoConn.ReadFromUDP(buf)
				if err != nil {
					return
				}
				_, err = echoConn.WriteToUDP(buf[:n], addr)
				if err != nil {
					return
				}
			}
		}()

		// Create a new UDP proxy
		proxyConn, err := NewUDPProxy(s, remotePort, target)
		Expect(err).ToNot(HaveOccurred())
		defer proxyConn.Close()

		// Send a UDP packet to the proxy
		clientConn, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", remotePort))
		Expect(err).ToNot(HaveOccurred())
		defer clientConn.Close()

		message := "Hello UDP Proxy"
		_, err = clientConn.Write([]byte(message))
		Expect(err).ToNot(HaveOccurred())

		// Read the response from the proxy
		response := make([]byte, 1500)
		n, err := clientConn.Read(response)
		Expect(err).ToNot(HaveOccurred())
		Expect(string(response[:n])).To(Equal(message))
	})

	It("should create a new TCP proxy and forward data", func() {
		// Start a TCP echo server for testing
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		Expect(err).ToNot(HaveOccurred())
		defer ln.Close()
		upstreamPort := ln.Addr().(*net.TCPAddr).Port

		// Echo handler
		go func() {
			for {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				go func(c net.Conn) {
					defer c.Close()
					buf := make([]byte, 1024)
					for {
						n, err := c.Read(buf)
						if err != nil {
							return
						}
						_, _ = c.Write(buf[:n])
					}
				}(conn)
			}
		}()

		// Create a TCP proxy listener on a dynamic port
		publicPort := 0
		// ask OS for a free port
		l, err := net.Listen("tcp", "127.0.0.1:0")
		Expect(err).ToNot(HaveOccurred())
		publicPort = l.Addr().(*net.TCPAddr).Port
		l.Close()

		// NewTCPProxy binds to :publicPort; use the upstream address as target
		proxyConn, err := NewTCPProxy(nil, publicPort, fmt.Sprintf("127.0.0.1:%d", upstreamPort))
		Expect(err).ToNot(HaveOccurred())
		defer proxyConn.Close()

		// Connect to proxy and send data
		clientConn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", publicPort))
		Expect(err).ToNot(HaveOccurred())
		defer clientConn.Close()

		msg := "hello-tcp-proxy"
		_, err = clientConn.Write([]byte(msg))
		Expect(err).ToNot(HaveOccurred())

		resp := make([]byte, len(msg))
		_, err = io.ReadFull(clientConn, resp)
		Expect(err).ToNot(HaveOccurred())
		Expect(string(resp)).To(Equal(msg))
	})
})
