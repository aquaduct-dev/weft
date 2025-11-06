package server

import (
	"io"
	"net"
	"net/url"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("TunnelTCPProxy", func() {
	It("should proxy TCP traffic", func() {
		// Create a mock TCP server
		mockServer, err := net.Listen("tcp", "127.0.0.1:12030")
		Expect(err).ToNot(HaveOccurred())
		defer mockServer.Close()
		go func() {
			for {
				conn, err := mockServer.Accept()
				if err != nil {
					return
				}
				go func(c net.Conn) {
					defer c.Close()
					io.Copy(c, c)
				}(conn)
			}
		}()
		// Create a tunnel proxy
		localURL, err := url.Parse("tcp://127.0.0.1:12030")
		Expect(err).ToNot(HaveOccurred())
		remoteURL, err := url.Parse("tcp://127.0.0.1:12031")
		Expect(err).ToNot(HaveOccurred())
		err = NewProxyManager().StartProxy(localURL, remoteURL, "test-tunnel", nil)
		Expect(err).ToNot(HaveOccurred())
		// Connect to the tunnel proxy
		conn, err := net.Dial("tcp", remoteURL.Host)
		Expect(err).ToNot(HaveOccurred())
		defer conn.Close()
		// Send data to the tunnel proxy
		message := "hello"
		_, err = conn.Write([]byte(message))
		Expect(err).ToNot(HaveOccurred())
		// Assert that the mock TCP server received the data
		buf := make([]byte, len(message))
		_, err = conn.Read(buf)
		Expect(err).ToNot(HaveOccurred())
		Expect(string(buf)).To(Equal(message))
	})

	It("should proxy UDP traffic", func() {
		// Create a mock UDP server
		mockAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:12040")
		Expect(err).ToNot(HaveOccurred())
		mockServer, err := net.ListenUDP("udp", mockAddr)
		Expect(err).ToNot(HaveOccurred())
		defer mockServer.Close()
		go func() {
			buf := make([]byte, 1024)
			for {
				n, addr, err := mockServer.ReadFromUDP(buf)
				if err != nil {
					return
				}
				_, err = mockServer.WriteToUDP(buf[0:n], addr)
				Expect(err).ToNot(HaveOccurred())
			}
		}()

		// Create a tunnel proxy
		localURL, err := url.Parse("udp://127.0.0.1:12040")
		Expect(err).ToNot(HaveOccurred())
		remoteURL, err := url.Parse("udp://127.0.0.1:12041")
		Expect(err).ToNot(HaveOccurred())
		err = NewProxyManager().StartProxy(localURL, remoteURL, "test-tunnel-udp", nil)
		Expect(err).ToNot(HaveOccurred())

		// Connect to the tunnel proxy
		conn, err := net.Dial("udp", remoteURL.Host)
		Expect(err).ToNot(HaveOccurred())
		defer conn.Close()

		// Send data to the tunnel proxy
		message := "hello udp"
		_, err = conn.Write([]byte(message))
		Expect(err).ToNot(HaveOccurred())

		// Assert that the mock UDP server received the data
		buf := make([]byte, len(message))
		Eventually(func() string {
			conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			n, err := conn.Read(buf)
			if err != nil {
				return ""
			}
			return string(buf[:n])
		}).Should(Equal(message))
	})
})
