// Tests for challenge fall-through: a host with its own plain-HTTP route on
// :80 that weft doesn't issue for may run its own ACME client behind the
// tunnel. When no weft node has the token, the request must reach that
// backend instead of being answered by weft.
package vhost

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/aquaduct-dev/weft/src/acme"
	"github.com/aquaduct-dev/weft/src/proxy/vhost/meter"
)

const plainHost = "plain.example.com"

// userBackend is a tunnel backend running its own ACME client: it answers
// one token and records every request it sees.
type userBackend struct {
	srv *httptest.Server
	mu  sync.Mutex
	got []*http.Request
}

func newUserBackend(t *testing.T, token, keyAuth string) *userBackend {
	t.Helper()
	b := &userBackend{}
	b.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b.mu.Lock()
		b.got = append(b.got, r)
		b.mu.Unlock()
		if r.URL.Path == acme.ChallengePathPrefix+token {
			_, _ = w.Write([]byte(keyAuth))
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(b.srv.Close)
	return b
}

func (b *userBackend) requests() []*http.Request {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]*http.Request(nil), b.got...)
}

// newPlainNode returns a challenge-port proxy. If backend is non-nil, host
// gets a plain-HTTP route to it.
func newPlainNode(t *testing.T, host string, backend *userBackend) (*VHostProxyManager, *VHostProxy) {
	t.Helper()
	port := freePort(t)
	m := NewVHostProxyManager()
	m.SetCertsCachePath(t.TempDir())
	m.SetACMEPort(port)
	p := m.Proxy("127.0.0.1", port)
	if backend != nil {
		target, _ := url.Parse(backend.srv.URL)
		closer, _, err := p.AddHost(RouteConfig{Host: host, Target: target})
		if err != nil {
			t.Fatalf("AddHost: %v", err)
		}
		t.Cleanup(func() { _ = closer.Close() })
	} else if err := m.StartChallengeListener("127.0.0.1"); err != nil {
		t.Fatalf("StartChallengeListener: %v", err)
	}
	return m, p
}

// serve runs target through p.ServeHTTP the way the listener does.
func serve(p *VHostProxy, host, target string) (int, string) {
	req := httptest.NewRequest(http.MethodGet, target, nil)
	req.Host = host
	raw := httptest.NewRecorder()
	p.ServeHTTP(&meter.MeteredResponseWriter{ResponseWriter: raw}, meter.NewMeteredRequestForTest(req))
	body, _ := io.ReadAll(raw.Result().Body)
	return raw.Code, string(body)
}

// noPeers makes every DNS lookup in the acme package fail, so no node but
// the local one is asked.
func noPeers(t *testing.T) {
	t.Helper()
	prevLookup := acme.SwapLookupIPForTest(nil)
	prevAddrs := acme.SwapInterfaceAddrsForTest(nil)
	t.Cleanup(func() {
		acme.RestoreLookupIPForTest(prevLookup)
		acme.RestoreInterfaceAddrsForTest(prevAddrs)
	})
}

func TestChallengeFallThrough_UserACMEClientGetsItsChallenge(t *testing.T) {
	noPeers(t)
	backend := newUserBackend(t, "userToken", "userToken.userThumb")
	_, p := newPlainNode(t, plainHost, backend)

	code, body := serve(p, plainHost, acme.ChallengePathPrefix+"userToken")
	if code != http.StatusOK || body != "userToken.userThumb" {
		t.Fatalf("got %d %q, want 200 from the user's backend", code, body)
	}
	if n := len(backend.requests()); n != 1 {
		t.Errorf("backend saw %d requests, want 1", n)
	}
}

func TestChallengeFallThrough_PeerRequestReachesBackendWithoutMarker(t *testing.T) {
	noPeers(t)
	backend := newUserBackend(t, "userToken", "userToken.userThumb")
	_, p := newPlainNode(t, plainHost, backend)

	code, body := serve(p, plainHost, acme.ChallengePathPrefix+"userToken?"+acme.NoProxyParam+"=true")
	if code != http.StatusOK || body != "userToken.userThumb" {
		t.Fatalf("got %d %q, want 200 from the user's backend", code, body)
	}
	reqs := backend.requests()
	if len(reqs) != 1 {
		t.Fatalf("backend saw %d requests, want 1", len(reqs))
	}
	if q := reqs[0].URL.RawQuery; strings.Contains(q, acme.NoProxyParam) {
		t.Errorf("backend saw weft's internal marker in the query: %q", q)
	}
}

func TestChallengeFallThrough_NotForHostsWeftIssuesFor(t *testing.T) {
	noPeers(t)
	backend := newUserBackend(t, "userToken", "userToken.userThumb")
	m, p := newPlainNode(t, plainHost, backend)
	closer, err := m.AddACMEHost(plainHost, "127.0.0.1")
	if err != nil {
		t.Fatalf("AddACMEHost: %v", err)
	}
	t.Cleanup(func() { _ = closer.Close() })

	code, _ := serve(p, plainHost, acme.ChallengePathPrefix+"userToken")
	if code != http.StatusNotFound {
		t.Fatalf("got %d, want weft's own 404: weft owns challenges for hosts it issues for", code)
	}
	if n := len(backend.requests()); n != 0 {
		t.Errorf("backend saw %d requests, want 0", n)
	}
}

func TestChallengeFallThrough_NotForHostsWithoutARoute(t *testing.T) {
	noPeers(t)
	_, p := newPlainNode(t, plainHost, nil)
	code, _ := serve(p, plainHost, acme.ChallengePathPrefix+"userToken")
	if code != http.StatusForbidden {
		t.Fatalf("got %d, want 403 from autocert's host policy", code)
	}
}

// Round-robin across bastions: the CA hits B, which has no route for the
// host; the user's tunnel (and ACME client) sits behind A. B must relay A's
// backend answer.
func TestChallengeFallThrough_SiblingRelaysUserBackend(t *testing.T) {
	backend := newUserBackend(t, "userToken", "userToken.userThumb")
	_, nodeA := newPlainNode(t, plainHost, backend)
	_, nodeB := newPlainNode(t, plainHost, nil)

	aListener := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nodeA.ServeHTTP(&meter.MeteredResponseWriter{ResponseWriter: w}, meter.NewMeteredRequestForTest(r))
	}))
	t.Cleanup(aListener.Close)
	aAddr := strings.TrimPrefix(aListener.URL, "http://")

	prevLookup := acme.SwapLookupIPForTest(map[string][]string{plainHost: {"203.0.113.10"}})
	prevAddrs := acme.SwapInterfaceAddrsForTest(nil)
	prevDial := acme.SwapDialPeerForTest(func(ctx context.Context, ip net.IP) (net.Conn, error) {
		if ip.String() != "203.0.113.10" {
			return nil, errors.New("test: unexpected peer " + ip.String())
		}
		return (&net.Dialer{}).DialContext(ctx, "tcp", aAddr)
	})
	t.Cleanup(func() {
		acme.RestoreLookupIPForTest(prevLookup)
		acme.RestoreInterfaceAddrsForTest(prevAddrs)
		acme.RestoreDialPeerForTest(prevDial)
	})

	code, body := serve(nodeB, plainHost, acme.ChallengePathPrefix+"userToken")
	if code != http.StatusOK || body != "userToken.userThumb" {
		t.Fatalf("via B: got %d %q, want 200 relayed from A's backend", code, body)
	}
}
