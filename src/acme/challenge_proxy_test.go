// Tests for FetchChallengeFromPeers: the parallel peer fan-out, its filters,
// and the NoProxyParam it adds so peers never forward again.
package acme

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

const testToken = "abcDEF123_-xyz"
const testPath = ChallengePathPrefix + testToken

// fakePeers starts one HTTP server per fake IP and routes dialPeer to it.
// handlers maps an IP (as it appears in DNS) to that peer's handler.
func fakePeers(t *testing.T, host string, local []string, handlers map[string]http.HandlerFunc) {
	t.Helper()
	addrs := map[string]string{}
	var dnsIPs []string
	for ip, h := range handlers {
		srv := httptest.NewServer(h)
		t.Cleanup(srv.Close)
		addrs[ip] = strings.TrimPrefix(srv.URL, "http://")
		dnsIPs = append(dnsIPs, ip)
	}
	dnsIPs = append(dnsIPs, local...)
	prevLookup := SwapLookupIPForTest(map[string][]string{host: dnsIPs})
	prevAddrs := SwapInterfaceAddrsForTest(local)
	prevDial := SwapDialPeerForTest(func(ctx context.Context, ip net.IP) (net.Conn, error) {
		addr, ok := addrs[ip.String()]
		if !ok {
			return nil, errors.New("test: no fake peer at " + ip.String())
		}
		return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	})
	t.Cleanup(func() {
		RestoreLookupIPForTest(prevLookup)
		RestoreInterfaceAddrsForTest(prevAddrs)
		RestoreDialPeerForTest(prevDial)
	})
}

func notFound(w http.ResponseWriter, _ *http.Request) { http.NotFound(w, nil) }

func TestFetchChallengeFromPeers_ReturnsTheOnePeerWithTheToken(t *testing.T) {
	var mu sync.Mutex
	seen := map[string]*http.Request{}
	record := func(ip string, h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			seen[ip] = r
			mu.Unlock()
			h(w, r)
		}
	}
	fakePeers(t, "rr.example.com", []string{"203.0.113.1"}, map[string]http.HandlerFunc{
		"203.0.113.2": record("203.0.113.2", notFound),
		"203.0.113.3": record("203.0.113.3", func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(testToken + ".thumb"))
		}),
		"203.0.113.4": record("203.0.113.4", notFound),
	})

	body, peer, err := FetchChallengeFromPeers(context.Background(), "rr.example.com", testPath)
	if err != nil {
		t.Fatalf("FetchChallengeFromPeers: %v", err)
	}
	if string(body) != testToken+".thumb" {
		t.Errorf("body = %q", body)
	}
	if peer.String() != "203.0.113.3" {
		t.Errorf("peer = %s, want 203.0.113.3", peer)
	}

	// Give the losing goroutines a moment, then check what the peers saw.
	time.Sleep(50 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if _, ok := seen["203.0.113.1"]; ok {
		t.Error("the local IP must not be asked")
	}
	for ip, r := range seen {
		if r.URL.Path != testPath {
			t.Errorf("%s: path = %q, want %q", ip, r.URL.Path, testPath)
		}
		if r.URL.Query().Get(NoProxyParam) != "true" {
			t.Errorf("%s: missing %s=true in %q", ip, NoProxyParam, r.URL.RawQuery)
		}
		if r.Host != "rr.example.com" {
			t.Errorf("%s: Host = %q, want rr.example.com", ip, r.Host)
		}
	}
}

func TestFetchChallengeFromPeers_NoPeerHasIt(t *testing.T) {
	fakePeers(t, "rr.example.com", nil, map[string]http.HandlerFunc{
		"203.0.113.2": notFound,
		"203.0.113.3": func(w http.ResponseWriter, r *http.Request) { http.Error(w, "no", http.StatusForbidden) },
	})
	_, _, err := FetchChallengeFromPeers(context.Background(), "rr.example.com", testPath)
	if !errors.Is(err, ErrNoPeerAnswered) {
		t.Fatalf("err = %v, want ErrNoPeerAnswered", err)
	}
}

func TestFetchChallengeFromPeers_DoesNotFollowRedirects(t *testing.T) {
	fakePeers(t, "rr.example.com", nil, map[string]http.HandlerFunc{
		"203.0.113.2": func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "http://elsewhere.example.com"+r.URL.Path, http.StatusMovedPermanently)
		},
	})
	_, _, err := FetchChallengeFromPeers(context.Background(), "rr.example.com", testPath)
	if !errors.Is(err, ErrNoPeerAnswered) {
		t.Fatalf("err = %v, want ErrNoPeerAnswered", err)
	}
}

func TestFetchChallengeFromPeers_RejectsOversizedBody(t *testing.T) {
	fakePeers(t, "rr.example.com", nil, map[string]http.HandlerFunc{
		"203.0.113.2": func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(strings.Repeat("x", maxKeyAuthBytes+1)))
		},
	})
	_, _, err := FetchChallengeFromPeers(context.Background(), "rr.example.com", testPath)
	if !errors.Is(err, ErrNoPeerAnswered) {
		t.Fatalf("err = %v, want ErrNoPeerAnswered", err)
	}
}

func TestFetchChallengeFromPeers_SkipsLoopbackAndLinkLocal(t *testing.T) {
	dialed := make(chan string, 4)
	prevLookup := SwapLookupIPForTest(map[string][]string{"rr.example.com": {"127.0.0.1", "169.254.169.254", "::1", "fe80::1"}})
	prevAddrs := SwapInterfaceAddrsForTest(nil)
	prevDial := SwapDialPeerForTest(func(ctx context.Context, ip net.IP) (net.Conn, error) {
		dialed <- ip.String()
		return nil, errors.New("test: should not dial")
	})
	t.Cleanup(func() {
		RestoreLookupIPForTest(prevLookup)
		RestoreInterfaceAddrsForTest(prevAddrs)
		RestoreDialPeerForTest(prevDial)
	})
	_, _, err := FetchChallengeFromPeers(context.Background(), "rr.example.com", testPath)
	if !errors.Is(err, ErrNoPeerAnswered) {
		t.Fatalf("err = %v, want ErrNoPeerAnswered", err)
	}
	select {
	case ip := <-dialed:
		t.Errorf("dialed %s; loopback and link-local records must be skipped", ip)
	default:
	}
}

func TestFetchChallengeFromPeers_RejectsNonChallengePaths(t *testing.T) {
	for _, p := range []string{"/", "/admin", ChallengePathPrefix, ChallengePathPrefix + "a/b", ChallengePathPrefix + "a.b", ChallengePathPrefix + "..%2f"} {
		if _, _, err := FetchChallengeFromPeers(context.Background(), "rr.example.com", p); err == nil {
			t.Errorf("path %q: expected an error", p)
		}
	}
}

func TestIsNoProxyRequest(t *testing.T) {
	cases := map[string]bool{
		testPath:                                 false,
		testPath + "?" + NoProxyParam + "=true":  true,
		testPath + "?" + NoProxyParam + "=false": false,
		testPath + "?other=true":                 false,
	}
	for target, want := range cases {
		r := httptest.NewRequest(http.MethodGet, target, nil)
		if got := IsNoProxyRequest(r); got != want {
			t.Errorf("%s: got %v, want %v", target, got, want)
		}
	}
}
