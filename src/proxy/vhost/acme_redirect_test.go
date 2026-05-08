package vhost

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/aquaduct-dev/weft/src/acme"
)

func TestRegisterAndLookupPeerRedirect_RoundTrip(t *testing.T) {
	m := &VHostProxyManager{acmeHosts: map[string]bool{}}
	m.RegisterPeerRedirect("example.com", "10.0.0.42")

	got, ok := m.lookupPeerRedirect("example.com")
	if !ok {
		t.Fatal("expected registration to be found")
	}
	if got != "10.0.0.42" {
		t.Errorf("peerIP = %q, want 10.0.0.42", got)
	}
}

func TestLookupPeerRedirect_ExpiresEntries(t *testing.T) {
	m := &VHostProxyManager{
		acmeHosts: map[string]bool{},
		redirects: map[string]peerRedirect{
			"stale.example.com": {peerIP: "10.0.0.1", expires: time.Now().Add(-1 * time.Second)},
		},
	}
	if _, ok := m.lookupPeerRedirect("stale.example.com"); ok {
		t.Fatal("expired entry should not be returned")
	}
	// And the expired entry should have been deleted from the map.
	m.redirectsMu.Lock()
	_, present := m.redirects["stale.example.com"]
	m.redirectsMu.Unlock()
	if present {
		t.Errorf("expired entry should be evicted from map")
	}
}

func TestLookupPeerRedirect_MissingHost(t *testing.T) {
	m := &VHostProxyManager{acmeHosts: map[string]bool{}}
	if _, ok := m.lookupPeerRedirect("nope.example.com"); ok {
		t.Fatal("should not find unregistered host")
	}
}

func TestRegisterPeerRedirect_OverwritesPriorEntry(t *testing.T) {
	m := &VHostProxyManager{acmeHosts: map[string]bool{}}
	m.RegisterPeerRedirect("example.com", "10.0.0.1")
	m.RegisterPeerRedirect("example.com", "10.0.0.2")
	got, ok := m.lookupPeerRedirect("example.com")
	if !ok || got != "10.0.0.2" {
		t.Errorf("got (%q,%v), want (10.0.0.2,true)", got, ok)
	}
}

func TestRegisterPeerRedirect_ConcurrentSafe(t *testing.T) {
	// Detect data races under -race when N goroutines pound the same host.
	m := &VHostProxyManager{acmeHosts: map[string]bool{}}
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func() { defer wg.Done(); m.RegisterPeerRedirect("example.com", "10.0.0.1") }()
		go func() { defer wg.Done(); m.lookupPeerRedirect("example.com") }()
	}
	wg.Wait()
}

// --- tryRedirectChallenge ---

// withInjectedNet swaps the package-level net seams in src/acme for the
// duration of the test. Callers receive a restore func.
func withInjectedNet(t *testing.T, hostsToIPs map[string][]string, localIPs []string) func() {
	t.Helper()
	origLookup, origAddrs := acme.SwapLookupIPForTest(hostsToIPs), acme.SwapInterfaceAddrsForTest(localIPs)
	return func() {
		acme.RestoreLookupIPForTest(origLookup)
		acme.RestoreInterfaceAddrsForTest(origAddrs)
	}
}

func TestTryRedirectChallenge_PeerRegisteredWins(t *testing.T) {
	m := &VHostProxyManager{acmeHosts: map[string]bool{}}
	m.RegisterPeerRedirect("example.com", "10.0.0.50")

	req := httptest.NewRequest(http.MethodGet, "http://example.com/.well-known/acme-challenge/abc", nil)
	rr := httptest.NewRecorder()
	if !m.tryRedirectChallenge(rr, req, "example.com") {
		t.Fatal("expected redirect to be issued")
	}
	if rr.Code != http.StatusMovedPermanently {
		t.Errorf("status = %d, want 301", rr.Code)
	}
	loc := rr.Header().Get("Location")
	if loc != "http://10.0.0.50/.well-known/acme-challenge/abc" {
		t.Errorf("Location = %q, want http://10.0.0.50/...", loc)
	}
}

func TestTryRedirectChallenge_OurOwnHostFallsThrough(t *testing.T) {
	m := &VHostProxyManager{acmeHosts: map[string]bool{"mine.example.com": true}}

	req := httptest.NewRequest(http.MethodGet, "http://mine.example.com/.well-known/acme-challenge/abc", nil)
	rr := httptest.NewRecorder()
	if m.tryRedirectChallenge(rr, req, "mine.example.com") {
		t.Fatal("expected fall-through (false) when host is our own ACME host")
	}
	if rr.Code != http.StatusOK {
		t.Errorf("no response should have been written; status = %d", rr.Code)
	}
}

func TestTryRedirectChallenge_HighestIPFallback(t *testing.T) {
	restore := withInjectedNet(t,
		map[string][]string{"peer.example.com": {"10.0.0.5", "10.0.0.99", "10.0.0.42"}},
		[]string{"10.0.0.5"}, // we are NOT the highest
	)
	defer restore()

	m := &VHostProxyManager{acmeHosts: map[string]bool{}}
	req := httptest.NewRequest(http.MethodGet, "http://peer.example.com/.well-known/acme-challenge/xyz", nil)
	rr := httptest.NewRecorder()
	if !m.tryRedirectChallenge(rr, req, "peer.example.com") {
		t.Fatal("expected redirect to highest-IP fallback")
	}
	if loc := rr.Header().Get("Location"); loc != "http://10.0.0.99/.well-known/acme-challenge/xyz" {
		t.Errorf("Location = %q, want redirect to highest IP", loc)
	}
}

func TestTryRedirectChallenge_WeAreTheHighestFallsThrough(t *testing.T) {
	restore := withInjectedNet(t,
		map[string][]string{"peer.example.com": {"10.0.0.5", "10.0.0.99"}},
		[]string{"10.0.0.99"}, // we ARE the highest
	)
	defer restore()

	m := &VHostProxyManager{acmeHosts: map[string]bool{}}
	req := httptest.NewRequest(http.MethodGet, "http://peer.example.com/.well-known/acme-challenge/xyz", nil)
	rr := httptest.NewRecorder()
	if m.tryRedirectChallenge(rr, req, "peer.example.com") {
		t.Fatal("expected fall-through when this node is the highest IP")
	}
}

func TestTryRedirectChallenge_DNSFailureFallsThrough(t *testing.T) {
	restore := withInjectedNet(t, map[string][]string{}, []string{"10.0.0.5"})
	defer restore()

	m := &VHostProxyManager{acmeHosts: map[string]bool{}}
	req := httptest.NewRequest(http.MethodGet, "http://unknown.example.com/.well-known/acme-challenge/xyz", nil)
	rr := httptest.NewRecorder()
	if m.tryRedirectChallenge(rr, req, "unknown.example.com") {
		t.Fatal("expected fall-through (false) when DNS lookup fails")
	}
}
