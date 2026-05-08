package acme

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
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
