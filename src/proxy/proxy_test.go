package proxy

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
		_, err = NewProxyManager().StartProxy(localURL, remoteURL, "test-tunnel", nil, nil, nil, "")
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
		_, err = NewProxyManager().StartProxy(localURL, remoteURL, "test-tunnel-udp", nil, nil, nil, "")
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
		_, err = NewProxyManager().StartProxy(localURL, remoteURL, "test-tunnel-http", nil, nil, nil, "")
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
		_, err = proxyManager.StartProxy(localURL, remoteURL, "duplicate-tunnel", nil, nil, nil, "")
		Expect(err).ToNot(HaveOccurred())
		// Attempt to create another tunnel with the same name
		_, err = proxyManager.StartProxy(localURL, remoteURL, "duplicate-tunnel", nil, nil, nil, "")
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
		_, err = proxyManager.StartProxy(localURL1, remoteURL1, "tunnel-host-1", nil, nil, nil, "")
		Expect(err).ToNot(HaveOccurred())

		// Attempt to create another tunnel with a different name but same host
		localURL2, err := url.Parse("tcp://127.0.0.1:12036")
		Expect(err).ToNot(HaveOccurred())
		remoteURL2, err := url.Parse("tcp://127.0.0.1:12035") // Same host as remoteURL1
		Expect(err).ToNot(HaveOccurred())
		_, err = proxyManager.StartProxy(localURL2, remoteURL2, "tunnel-host-2", nil, nil, nil, "")
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(SatisfyAny(
			ContainSubstring("conflicts with tunnel-host-1"),
		))
	})

	It("enforces bindIp strictness for tcp listeners", func() {
		// Start a real backend to be proxied
		backend, err := net.Listen("tcp", "127.0.0.1:12060")
		Expect(err).ToNot(HaveOccurred())
		defer backend.Close()
		go func() {
			for {
				c, err := backend.Accept()
				if err != nil {
					return
				}
				go func(cc net.Conn) {
					defer cc.Close()
					io.Copy(cc, cc)
				}(c)
			}
		}()

		// Request a proxy whose dst host is 127.0.0.1:12060 but ask StartProxy to bind to 0.0.0.0
		localURL, err := url.Parse("tcp://127.0.0.1:12060")
		Expect(err).ToNot(HaveOccurred())
		// dst originally different host; StartProxy should rewrite dst to bindIp
		remoteURL, err := url.Parse("tcp://127.0.0.1:12061")
		Expect(err).ToNot(HaveOccurred())

		pm := NewProxyManager()
		// bindIp empty: it will listen on dst host (127.0.0.1:12061)
		_, err = pm.StartProxy(localURL, remoteURL, "bindip-test-1", nil, nil, nil, "")
		Expect(err).ToNot(HaveOccurred())
		// connect should succeed to the configured host (127.0.0.1:12061)
		conn1, err := net.Dial("tcp", "127.0.0.1:12061")
		Expect(err).ToNot(HaveOccurred())
		conn1.Close()
		pm.Close("bindip-test-1")

		// Now request proxy but force bindIp of 0.0.0.0 and ensure StartProxy rewrites dst to that host.
		_, err = pm.StartProxy(localURL, remoteURL, "bindip-test-2", nil, nil, nil, "0.0.0.0")
		// When bindIp is 0.0.0.0 rewriteHost is a no-op (per implementation), so it should still succeed.
		Expect(err).ToNot(HaveOccurred())
		// connecting to 127.0.0.1:12061 should still work because listener on 0.0.0.0 accepts connections for loopback
		conn2, err := net.Dial("tcp", "127.0.0.1:12061")
		Expect(err).ToNot(HaveOccurred())
		conn2.Close()
		pm.Close("bindip-test-2")
	})

	It("enforces bindIp strictness for udp listeners", func() {
		// Setup UDP echo backend
		backendAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:12070")
		Expect(err).ToNot(HaveOccurred())
		backendConn, err := net.ListenUDP("udp", backendAddr)
		Expect(err).ToNot(HaveOccurred())
		defer backendConn.Close()
		go func() {
			buf := make([]byte, 1024)
			for {
				n, addr, err := backendConn.ReadFromUDP(buf)
				if err != nil {
					return
				}
				backendConn.WriteToUDP(buf[:n], addr)
			}
		}()

		localURL, err := url.Parse("udp://127.0.0.1:12070")
		Expect(err).ToNot(HaveOccurred())
		remoteURL, err := url.Parse("udp://127.0.0.1:12071")
		Expect(err).ToNot(HaveOccurred())

		pm := NewProxyManager()
		// Start proxy without bindIp -> listens on remoteURL host (127.0.0.1:12071)
		_, err = pm.StartProxy(localURL, remoteURL, "bindip-udp-1", nil, nil, nil, "")
		Expect(err).ToNot(HaveOccurred())

		// Talk to proxy
		conn, err := net.Dial("udp", "127.0.0.1:12071")
		Expect(err).ToNot(HaveOccurred())
		defer conn.Close()
		msg := []byte("ping")
		_, err = conn.Write(msg)
		Expect(err).ToNot(HaveOccurred())

		buf := make([]byte, 10)
		conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, err := conn.Read(buf)
		Expect(err).ToNot(HaveOccurred())
		Expect(string(buf[:n])).To(Equal("ping"))

		pm.Close("bindip-udp-1")

		// Now test with bindIp set to 0.0.0.0 (should still succeed - rewriteHost is noop for 0.0.0.0)
		_, err = pm.StartProxy(localURL, remoteURL, "bindip-udp-2", nil, nil, nil, "0.0.0.0")
		Expect(err).ToNot(HaveOccurred())
		conn2, err := net.Dial("udp", "127.0.0.1:12071")
		Expect(err).ToNot(HaveOccurred())
		defer conn2.Close()
		_, err = conn2.Write([]byte("ping2"))
		Expect(err).ToNot(HaveOccurred())
		buf2 := make([]byte, 10)
		conn2.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n2, err := conn2.Read(buf2)
		Expect(err).ToNot(HaveOccurred())
		Expect(string(buf2[:n2])).To(Equal("ping2"))
		pm.Close("bindip-udp-2")
	})
})

var _ = Describe("Proxy Conflicts", func() {
	It("should return true for conflicting TCP proxies", func() {
		l, err := net.Listen("tcp", "127.0.0.1:12080")
		Expect(err).ToNot(HaveOccurred())
		defer l.Close()
		p1 := &TCPProxy{Listener: l}
		p2 := &TCPProxy{Listener: l}
		Expect(p1.Conflicts(p2)).To(BeTrue())
	})

	It("should return false for non-conflicting TCP proxies", func() {
		l1, err := net.Listen("tcp", "127.0.0.1:12081")
		Expect(err).ToNot(HaveOccurred())
		defer l1.Close()
		l2, err := net.Listen("tcp", "127.0.0.1:12082")
		Expect(err).ToNot(HaveOccurred())
		defer l2.Close()
		p1 := &TCPProxy{Listener: l1}
		p2 := &TCPProxy{Listener: l2}
		Expect(p1.Conflicts(p2)).To(BeFalse())
	})

	It("should return true for conflicting UDP proxies", func() {
		addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:12090")
		Expect(err).ToNot(HaveOccurred())
		conn, err := net.ListenUDP("udp", addr)
		Expect(err).ToNot(HaveOccurred())
		defer conn.Close()
		p1 := &UDPProxy{Conn: WGAwareUDPConn{netConn: conn}}
		p2 := &UDPProxy{Conn: WGAwareUDPConn{netConn: conn}}
		Expect(p1.Conflicts(p2)).To(BeTrue())
	})

	It("should return false for non-conflicting UDP proxies", func() {
		addr1, err := net.ResolveUDPAddr("udp", "127.0.0.1:12091")
		Expect(err).ToNot(HaveOccurred())
		conn1, err := net.ListenUDP("udp", addr1)
		Expect(err).ToNot(HaveOccurred())
		defer conn1.Close()
		addr2, err := net.ResolveUDPAddr("udp", "127.0.0.1:12092")
		Expect(err).ToNot(HaveOccurred())
		conn2, err := net.ListenUDP("udp", addr2)
		Expect(err).ToNot(HaveOccurred())
		defer conn2.Close()
		p1 := &UDPProxy{Conn: WGAwareUDPConn{netConn: conn1}}
		p2 := &UDPProxy{Conn: WGAwareUDPConn{netConn: conn2}}
		Expect(p1.Conflicts(p2)).To(BeFalse())
	})

	It("should return true for conflicting VHost proxies", func() {
		p1 := &VHostRouteProxy{Host: "example.com", Port: 80, BindIp: "0.0.0.0"}
		p2 := &VHostRouteProxy{Host: "example.com", Port: 80, BindIp: "0.0.0.0"}
		Expect(p1.Conflicts(p2)).To(BeTrue())
	})

	It("should return false for non-conflicting VHost proxies", func() {
		p1 := &VHostRouteProxy{Host: "example.com", Port: 80, BindIp: "0.0.0.0"}
		p2 := &VHostRouteProxy{Host: "example.org", Port: 80, BindIp: "0.0.0.0"}
		Expect(p1.Conflicts(p2)).To(BeFalse())
	})

	It("should return false for proxies of different types", func() {
		l, err := net.Listen("tcp", "127.0.0.1:12093")
		Expect(err).ToNot(HaveOccurred())
		defer l.Close()
		p1 := &TCPProxy{Listener: l}
		p2 := &VHostRouteProxy{Host: "example.com", Port: 80, BindIp: "0.0.0.0"}
		Expect(p1.Conflicts(p2)).To(BeFalse())
	})

	It("should return true for conflicting TCP and VHost proxies", func() {
		l, err := net.Listen("tcp", "127.0.0.1:12094")
		Expect(err).ToNot(HaveOccurred())
		defer l.Close()
		p1 := &TCPProxy{Listener: l}
		p2 := &VHostRouteProxy{Host: "example.com", Port: 12094, BindIp: "127.0.0.1"}
		Expect(p1.Conflicts(p2)).To(BeTrue())
	})
})
