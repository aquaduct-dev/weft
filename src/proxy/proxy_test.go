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

var _ = Describe("Proxy Tests", func() {
	It("should proxy tcp>tcp traffic", func() {
		// Create a mock TCP server
		mockServer, err := net.Listen("tcp", "127.0.0.1:13030")
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
		localURL, err := url.Parse("tcp://127.0.0.1:13030")
		Expect(err).ToNot(HaveOccurred())
		remoteURL, err := url.Parse("tcp://127.0.0.1:13031")
		Expect(err).ToNot(HaveOccurred())
		proxyManager := NewProxyManager()
		_, err = proxyManager.StartProxy(localURL, remoteURL, "test-tunnel", nil, nil, nil, "")
		Expect(err).ToNot(HaveOccurred())
		defer proxyManager.Close("test-tunnel")
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
		mockAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:13040")
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
		localURL, err := url.Parse("udp://127.0.0.1:13040")
		Expect(err).ToNot(HaveOccurred())
		remoteURL, err := url.Parse("udp://127.0.0.1:13041")
		Expect(err).ToNot(HaveOccurred())
		proxyManager := NewProxyManager()
		_, err = proxyManager.StartProxy(localURL, remoteURL, "test-tunnel-udp", nil, nil, nil, "")
		Expect(err).ToNot(HaveOccurred())
		defer proxyManager.Close("test-tunnel-udp")

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
	It("should not allow two TCP proxies on the same address and port", func() {
		// Case 1: Conflicting proxies (same address and port)
		addr1, err := net.ResolveTCPAddr("tcp", "127.0.0.1:12072")
		Expect(err).ToNot(HaveOccurred())
		p1 := &TCPProxy{Addr: addr1}

		addr2, err := net.ResolveTCPAddr("tcp", "127.0.0.1:12072")
		Expect(err).ToNot(HaveOccurred())
		p2 := &TCPProxy{Addr: addr2}

		Expect(p1.Conflicts(p2)).To(BeTrue())
		Expect(p2.Conflicts(p1)).To(BeTrue())

	})

	It("should allow two TCP proxies on different ports", func() {
		// Case 2: Non-conflicting proxies (different ports)
		addr1, err := net.ResolveTCPAddr("tcp", "127.0.0.1:12073")
		Expect(err).ToNot(HaveOccurred())
		p1 := &TCPProxy{Addr: addr1}

		addr2, err := net.ResolveTCPAddr("tcp", "127.0.0.1:12074")
		Expect(err).ToNot(HaveOccurred())
		p2 := &TCPProxy{Addr: addr2}

		Expect(p1.Conflicts(p2)).To(BeFalse())
		Expect(p2.Conflicts(p1)).To(BeFalse())
	})

	It("should not allow two UDP proxies on the same address and port", func() {
		addr1, err := net.ResolveUDPAddr("udp", "127.0.0.1:12075")
		Expect(err).ToNot(HaveOccurred())
		p1 := &UDPProxy{Addr: addr1}

		addr2, err := net.ResolveUDPAddr("udp", "127.0.0.1:12075")
		Expect(err).ToNot(HaveOccurred())
		p2 := &UDPProxy{Addr: addr2}

		Expect(p1.Conflicts(p2)).To(BeTrue())
		Expect(p2.Conflicts(p1)).To(BeTrue())
	})

	It("should allow two UDP proxies on different ports", func() {
		addr1, err := net.ResolveUDPAddr("udp", "127.0.0.1:12076")
		Expect(err).ToNot(HaveOccurred())
		p1 := &UDPProxy{Addr: addr1}

		addr2, err := net.ResolveUDPAddr("udp", "127.0.0.1:12077")
		Expect(err).ToNot(HaveOccurred())
		p2 := &UDPProxy{Addr: addr2}

		Expect(p1.Conflicts(p2)).To(BeFalse())
		Expect(p2.Conflicts(p1)).To(BeFalse())
	})

	It("should not allow an HTTP and TCP proxy on the same local address and port", func() {
		addr1, err := net.ResolveTCPAddr("tcp", "127.0.0.1:12078")
		Expect(err).ToNot(HaveOccurred())
		tcpProxy := &TCPProxy{Addr: addr1}

		httpProxy := &VHostRouteProxy{Host: "", Port: 12078, BindIp: "127.0.0.1", IsHTTPS: false}
		Expect(tcpProxy.Conflicts(httpProxy)).To(BeTrue())
		Expect(httpProxy.Conflicts(tcpProxy)).To(BeTrue())
	})

	It("should allow an HTTP and UDP proxy on the same local address and port", func() {
		addr1, err := net.ResolveUDPAddr("udp", "127.0.0.1:12078")
		Expect(err).ToNot(HaveOccurred())
		udpProxy := &UDPProxy{Addr: addr1}

		httpProxy := &VHostRouteProxy{Host: "", Port: 12078, BindIp: "127.0.0.1", IsHTTPS: false}

		Expect(udpProxy.Conflicts(httpProxy)).To(BeFalse())
		Expect(httpProxy.Conflicts(udpProxy)).To(BeFalse())
	})

	It("should allow two HTTP VHost proxies to bind to the same host and port if they have different hostnames", func() {
		p1 := &VHostRouteProxy{Host: "example.com", Port: 80, BindIp: "0.0.0.0", IsHTTPS: false}
		p2 := &VHostRouteProxy{Host: "example.org", Port: 80, BindIp: "0.0.0.0", IsHTTPS: false}
		Expect(p1.Conflicts(p2)).To(BeFalse())
		Expect(p2.Conflicts(p1)).To(BeFalse())
	})

	It("should not allow two HTTP VHost proxies to bind to the same host and port if they have the same hostnames", func() {
		p1 := &VHostRouteProxy{Host: "example.com", Port: 80, BindIp: "0.0.0.0", IsHTTPS: false}
		p2 := &VHostRouteProxy{Host: "example.com", Port: 80, BindIp: "0.0.0.0", IsHTTPS: false}
		Expect(p1.Conflicts(p2)).To(BeTrue())
		Expect(p2.Conflicts(p1)).To(BeTrue())
	})

	It("should allow two HTTPS VHost proxies to bind to the same host and port if they have different hostnames", func() {
		p1 := &VHostRouteProxy{Host: "secure.example.com", Port: 443, BindIp: "0.0.0.0", IsHTTPS: true}
		p2 := &VHostRouteProxy{Host: "secure.example.org", Port: 443, BindIp: "0.0.0.0", IsHTTPS: true}
		Expect(p1.Conflicts(p2)).To(BeFalse())
		Expect(p2.Conflicts(p1)).To(BeFalse())
	})

	It("should not allow two HTTPS VHost proxies to bind to the same host and port if they have the same hostnames", func() {
		p1 := &VHostRouteProxy{Host: "secure.example.com", Port: 443, BindIp: "0.0.0.0", IsHTTPS: true}
		p2 := &VHostRouteProxy{Host: "secure.example.com", Port: 443, BindIp: "0.0.0.0", IsHTTPS: true}
		Expect(p1.Conflicts(p2)).To(BeTrue())
		Expect(p2.Conflicts(p1)).To(BeTrue())
	})

	It("should not allow an HTTP VHost proxy and an HTTPS VHost proxy to bind to the same IP and port, regardless of hostname", func() {
		// HTTP proxy on port 80
		p1 := &VHostRouteProxy{Host: "example.com", Port: 80, BindIp: "0.0.0.0", IsHTTPS: false}
		// HTTPS proxy on port 80
		p2 := &VHostRouteProxy{Host: "secure.example.com", Port: 80, BindIp: "0.0.0.0", IsHTTPS: true}
		Expect(p1.Conflicts(p2)).To(BeTrue())
		Expect(p2.Conflicts(p1)).To(BeTrue())

		// HTTP proxy on port 443
		p3 := &VHostRouteProxy{Host: "example.com", Port: 443, BindIp: "0.0.0.0", IsHTTPS: false}
		// HTTPS proxy on port 443
		p4 := &VHostRouteProxy{Host: "secure.example.com", Port: 443, BindIp: "0.0.0.0", IsHTTPS: true}
		Expect(p3.Conflicts(p4)).To(BeTrue())
		Expect(p4.Conflicts(p3)).To(BeTrue())
	})

})
