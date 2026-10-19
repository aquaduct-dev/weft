package acme

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// stubLookupIP returns a closure suitable for replacing the package-level
// lookupIP test seam.
func stubLookupIP(table map[string][]net.IP) func(string) ([]net.IP, error) {
	return func(host string) ([]net.IP, error) {
		if ips, ok := table[host]; ok {
			return ips, nil
		}
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
}

// stubInterfaceAddrs returns a closure for replacing interfaceAddrs.
func stubInterfaceAddrs(ips []net.IP) func() ([]net.Addr, error) {
	return func() ([]net.Addr, error) {
		var out []net.Addr
		for _, ip := range ips {
			out = append(out, &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)})
		}
		return out, nil
	}
}

var _ = Describe("DescendingPeerIPs", func() {
	var origLookup func(string) ([]net.IP, error)
	BeforeEach(func() { origLookup = lookupIP })
	AfterEach(func() { lookupIP = origLookup })

	It("returns IPs sorted descending by byte order", func() {
		lookupIP = stubLookupIP(map[string][]net.IP{
			"example.com": {
				net.ParseIP("10.0.0.5"),
				net.ParseIP("10.0.0.99"),
				net.ParseIP("10.0.0.42"),
			},
		})
		got, err := DescendingPeerIPs("example.com")
		Expect(err).ToNot(HaveOccurred())
		Expect(got).To(HaveLen(3))
		Expect(got[0].String()).To(Equal("10.0.0.99"))
		Expect(got[1].String()).To(Equal("10.0.0.42"))
		Expect(got[2].String()).To(Equal("10.0.0.5"))
	})

	It("propagates lookup errors", func() {
		lookupIP = stubLookupIP(map[string][]net.IP{})
		_, err := DescendingPeerIPs("missing.example.com")
		Expect(err).To(HaveOccurred())
	})
})

var _ = Describe("LocalIPs", func() {
	var origAddrs func() ([]net.Addr, error)
	BeforeEach(func() { origAddrs = interfaceAddrs })
	AfterEach(func() { interfaceAddrs = origAddrs })

	It("filters out loopback addresses", func() {
		interfaceAddrs = stubInterfaceAddrs([]net.IP{
			net.ParseIP("127.0.0.1"),
			net.ParseIP("10.0.0.1"),
			net.ParseIP("::1"),
			net.ParseIP("2001:db8::1"),
		})
		got, err := LocalIPs()
		Expect(err).ToNot(HaveOccurred())
		// Only the non-loopback v4 + v6 should remain.
		strs := make([]string, len(got))
		for i, ip := range got {
			strs[i] = ip.String()
		}
		Expect(strs).To(ConsistOf("10.0.0.1", "2001:db8::1"))
	})
})

var _ = Describe("IsLocalIP", func() {
	It("matches by Equal, not String", func() {
		locals := []net.IP{net.ParseIP("10.0.0.1")}
		Expect(IsLocalIP(net.ParseIP("10.0.0.1"), locals)).To(BeTrue())
		Expect(IsLocalIP(net.ParseIP("10.0.0.2"), locals)).To(BeFalse())
	})

	It("treats an IPv4-mapped v6 form as equal to the v4 form", func() {
		locals := []net.IP{net.ParseIP("10.0.0.1")}
		v4mapped := net.ParseIP("10.0.0.1").To16()
		Expect(IsLocalIP(v4mapped, locals)).To(BeTrue())
	})
})

var _ = Describe("PostACMERedirect", func() {
	It("POSTs /acme-redirect with the host query param and accepts 204", func() {
		var (
			gotMethod string
			gotPath   string
			gotQuery  url.Values
		)
		ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotMethod = r.Method
			gotPath = r.URL.Path
			gotQuery = r.URL.Query()
			w.WriteHeader(http.StatusNoContent)
		}))
		defer ts.Close()

		// The httptest.NewTLSServer presents a self-signed cert; PostACMERedirect
		// uses InsecureSkipVerify so this should work.
		peerAddr := strings.TrimPrefix(ts.URL, "https://")
		err := PostACMERedirect(peerAddr, "example.com")
		Expect(err).ToNot(HaveOccurred())
		Expect(gotMethod).To(Equal(http.MethodPost))
		Expect(gotPath).To(Equal("/acme-redirect"))
		Expect(gotQuery.Get("host")).To(Equal("example.com"))
	})

	It("returns an error when the peer rejects with 4xx", func() {
		ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "no thanks", http.StatusForbidden)
		}))
		defer ts.Close()
		peerAddr := strings.TrimPrefix(ts.URL, "https://")
		err := PostACMERedirect(peerAddr, "example.com")
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("403"))
	})

	It("returns an error when the peer is unreachable", func() {
		// 127.0.0.1:1 is reserved/unused — connection refused.
		err := PostACMERedirect("127.0.0.1:1", "example.com")
		Expect(err).To(HaveOccurred())
	})
})

var _ = Describe("RegisterRedirectsLoop", func() {
	var (
		origLookup func(string) ([]net.IP, error)
		origAddrs  func() ([]net.Addr, error)
	)
	BeforeEach(func() {
		origLookup = lookupIP
		origAddrs = interfaceAddrs
	})
	AfterEach(func() {
		lookupIP = origLookup
		interfaceAddrs = origAddrs
	})

	// lockedBuffer lets the test read log output the loop goroutine writes.
	type lockedBuffer struct {
		mu  sync.Mutex
		buf bytes.Buffer
	}
	var logs *lockedBuffer
	var origLogger zerolog.Logger
	writeFn := func(lb *lockedBuffer) zerolog.Logger {
		return zerolog.New(writerFunc(func(p []byte) (int, error) {
			lb.mu.Lock()
			defer lb.mu.Unlock()
			return lb.buf.Write(p)
		}))
	}
	logText := func() string {
		logs.mu.Lock()
		defer logs.mu.Unlock()
		return logs.buf.String()
	}
	BeforeEach(func() {
		origLogger = log.Logger
		logs = &lockedBuffer{}
		log.Logger = writeFn(logs)
	})
	AfterEach(func() { log.Logger = origLogger })

	// startPeer serves /acme-redirect over TLS on ip:0 and counts POSTs.
	startPeer := func(ip string, hits *atomic.Int32) (*httptest.Server, int) {
		ln, err := net.Listen("tcp", ip+":0")
		Expect(err).ToNot(HaveOccurred())
		ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost && r.URL.Path == "/acme-redirect" && r.URL.Query().Get("host") == "example.com" {
				hits.Add(1)
			}
			w.WriteHeader(http.StatusNoContent)
		}))
		ts.Listener.Close()
		ts.Listener = ln
		ts.StartTLS()
		return ts, ln.Addr().(*net.TCPAddr).Port
	}

	// runLoop starts the loop and returns a stop func that cancels it and
	// waits for it to exit.
	runLoop := func(port int) func() {
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			RegisterRedirectsLoop(ctx, "example.com", port)
			close(done)
		}()
		return func() {
			cancel()
			Eventually(done).Should(BeClosed())
			GinkgoWriter.Printf("loop logs:\n%s\n", logText())
		}
	}

	It("skips an unreachable higher peer and registers with the next one", func() {
		// Descending order: 127.0.0.4 (nothing listening) > 127.0.0.3 (live
		// peer) > 10.0.0.99 (this node). The loop must fall past .4 to .3.
		var hits atomic.Int32
		ts, port := startPeer("127.0.0.3", &hits)
		defer ts.Close()
		interfaceAddrs = stubInterfaceAddrs([]net.IP{net.ParseIP("10.0.0.99")})
		lookupIP = stubLookupIP(map[string][]net.IP{
			"example.com": {net.ParseIP("10.0.0.99"), net.ParseIP("127.0.0.3"), net.ParseIP("127.0.0.4")},
		})

		stop := runLoop(port)
		Eventually(hits.Load).Should(BeNumerically(">=", 1))
		Eventually(logText).Should(ContainSubstring(EventRedirectTargetChanged))
		stop()

		out := logText()
		Expect(out).To(ContainSubstring(EventRedirectPostFailed))
		Expect(out).To(ContainSubstring(`"peer":"127.0.0.4"`))
		Expect(out).To(ContainSubstring(fmt.Sprintf(`"target":"127.0.0.3:%d"`, port)))
		Expect(out).ToNot(ContainSubstring(EventRedirectLeaderSelf))
	})

	It("becomes the leader when no higher peer is reachable", func() {
		// 127.0.0.4 is higher but unreachable; the next IP is this node.
		var hits atomic.Int32
		ts, port := startPeer("127.0.0.3", &hits)
		defer ts.Close()
		interfaceAddrs = stubInterfaceAddrs([]net.IP{net.ParseIP("10.0.0.99")})
		lookupIP = stubLookupIP(map[string][]net.IP{
			"example.com": {net.ParseIP("10.0.0.99"), net.ParseIP("127.0.0.4")},
		})

		stop := runLoop(port)
		Eventually(logText).Should(ContainSubstring(EventRedirectLeaderSelf))
		stop()

		out := logText()
		Expect(out).To(ContainSubstring(EventRedirectPostFailed))
		Expect(out).ToNot(ContainSubstring(EventRedirectTargetChanged))
		Expect(hits.Load()).To(BeZero())
	})

	It("returns immediately when ctx is already canceled", func() {
		// Set up: this node is the highest IP so the first tick goes to the
		// "I am leader" branch and the loop sleeps until ctx.Done.
		interfaceAddrs = stubInterfaceAddrs([]net.IP{net.ParseIP("10.0.0.99")})
		lookupIP = stubLookupIP(map[string][]net.IP{
			"example.com": {net.ParseIP("10.0.0.99"), net.ParseIP("10.0.0.5")},
		})
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		done := make(chan struct{})
		go func() {
			RegisterRedirectsLoop(ctx, "example.com", DefaultPeerPort)
			close(done)
		}()
		Eventually(done).Should(BeClosed())
	})
})

// writerFunc adapts a function to io.Writer.
type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }
