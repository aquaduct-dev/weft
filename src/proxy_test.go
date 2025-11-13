package server

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("TunnelTCPProxy", func() {
	It("should proxy tcp>tcp traffic", func() {
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
		err = NewProxyManager().StartProxy(localURL, remoteURL, "test-tunnel", nil, nil, nil, "")
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

	It("should proxy udp>udp traffic", func() {
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
		err = NewProxyManager().StartProxy(localURL, remoteURL, "test-tunnel-udp", nil, nil, nil, "")
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

	It("should proxy http>http traffic", func() {
		// Create a mock HTTP server
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("hello"))
		}))
		defer mockServer.Close()

		// Create a tunnel proxy
		localURL, err := url.Parse(mockServer.URL)
		Expect(err).ToNot(HaveOccurred())
		remoteURL, err := url.Parse("http://testhost:12051")
		Expect(err).ToNot(HaveOccurred())
		err = NewProxyManager().StartProxy(localURL, remoteURL, "test-tunnel-http", nil, nil, nil, "")
		Expect(err).ToNot(HaveOccurred())

		// Wait for the proxy to be ready
		Eventually(func() error {
			conn, err := net.Dial("tcp", "127.0.0.1:12051")
			if err != nil {
				return err
			}
			conn.Close()
			return nil
		}).Should(Succeed())

		// Connect to the tunnel proxy
		req, err := http.NewRequest("GET", "http://testhost:12051", nil)
		Expect(err).ToNot(HaveOccurred())

		client := &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					if addr == "testhost:12051" {
						addr = "127.0.0.1:12051"
					}
					return (&net.Dialer{}).DialContext(ctx, network, addr)
				},
			},
		}
		resp, err := client.Do(req)
		Expect(err).ToNot(HaveOccurred())
		defer resp.Body.Close()

		// Assert that the mock HTTP server received the data
		Expect(resp.StatusCode).To(Equal(http.StatusOK))
		body, err := io.ReadAll(resp.Body)
		Expect(err).ToNot(HaveOccurred())
		Expect(string(body)).To(Equal("hello"))
	})

	It("should not allow duplicate tunnels by name", func() {
		// Create a tunnel proxy
		localURL, err := url.Parse("tcp://127.0.0.1:12032")
		Expect(err).ToNot(HaveOccurred())
		remoteURL, err := url.Parse("tcp://127.0.0.1:12033")
		Expect(err).ToNot(HaveOccurred())
		proxyManager := NewProxyManager()
		err = proxyManager.StartProxy(localURL, remoteURL, "duplicate-tunnel", nil, nil, nil, "")
		Expect(err).ToNot(HaveOccurred())

		// Attempt to create another tunnel with the same name
		err = proxyManager.StartProxy(localURL, remoteURL, "duplicate-tunnel", nil, nil, nil, "")
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(Equal("proxy duplicate-tunnel already exists"))
	})

	It("should not allow duplicate tunnels by host", func() {
		// Create a tunnel proxy
		localURL1, err := url.Parse("tcp://127.0.0.1:12034")
		Expect(err).ToNot(HaveOccurred())
		remoteURL1, err := url.Parse("tcp://127.0.0.1:12035")
		Expect(err).ToNot(HaveOccurred())
		proxyManager := NewProxyManager()
		err = proxyManager.StartProxy(localURL1, remoteURL1, "tunnel-host-1", nil, nil, nil, "")
		Expect(err).ToNot(HaveOccurred())

		// Attempt to create another tunnel with a different name but same host
		localURL2, err := url.Parse("tcp://127.0.0.1:12036")
		Expect(err).ToNot(HaveOccurred())
		remoteURL2, err := url.Parse("tcp://127.0.0.1:12035") // Same host as remoteURL1
		Expect(err).ToNot(HaveOccurred())
		err = proxyManager.StartProxy(localURL2, remoteURL2, "tunnel-host-2", nil, nil, nil, "")
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(SatisfyAny(
			ContainSubstring("proxy for host 127.0.0.1:12035 already exists"),
		))
	})
})
