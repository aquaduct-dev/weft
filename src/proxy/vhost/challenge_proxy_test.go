// End-to-end tests for serveChallenge: three nodes share one hostname, only
// one holds the token, and every node must answer the CA with it, without
// any node forwarding a request more than one hop.
package vhost

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/aquaduct-dev/weft/src/acme"
)

const rrHost = "rr.example.com"

// testNode is one weft node's ACME challenge handler on a real listener.
type testNode struct {
	ip      string
	manager *VHostProxyManager
	server  *httptest.Server

	mu       sync.Mutex
	requests []*http.Request
}

func (n *testNode) received() []*http.Request {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]*http.Request(nil), n.requests...)
}

// newRRCluster starts one node per IP, all configured for rrHost, and routes
// DNS and peer dials so the nodes find each other through the acme seams.
func newRRCluster(t *testing.T, ips ...string) map[string]*testNode {
	t.Helper()
	nodes := map[string]*testNode{}
	addrs := map[string]string{}
	for _, ip := range ips {
		m := NewVHostProxyManager()
		m.SetCertsCachePath(t.TempDir())
		m.acmeHosts[rrHost] = true
		n := &testNode{ip: ip, manager: m}
		n.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			n.mu.Lock()
			n.requests = append(n.requests, r)
			n.mu.Unlock()
			host := r.Host
			if h, _, err := net.SplitHostPort(host); err == nil {
				host = h
			}
			n.manager.serveChallenge(w, r, host, false)
		}))
		t.Cleanup(n.server.Close)
		nodes[ip] = n
		addrs[ip] = strings.TrimPrefix(n.server.URL, "http://")
	}
	// Every node runs in this process, so none of the fake IPs is "local";
	// a node may ask itself, which NoProxyParam keeps to a single local answer.
	prevLookup := acme.SwapLookupIPForTest(map[string][]string{rrHost: ips})
	prevAddrs := acme.SwapInterfaceAddrsForTest(nil)
	prevDial := acme.SwapDialPeerForTest(func(ctx context.Context, ip net.IP) (net.Conn, error) {
		addr, ok := addrs[ip.String()]
		if !ok {
			return nil, errors.New("test: no node at " + ip.String())
		}
		return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	})
	t.Cleanup(func() {
		acme.RestoreLookupIPForTest(prevLookup)
		acme.RestoreInterfaceAddrsForTest(prevAddrs)
		acme.RestoreDialPeerForTest(prevDial)
	})
	return nodes
}

// challengeGet sends the CA's validation request for token to node n.
func challengeGet(t *testing.T, n *testNode, token string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, n.server.URL+acme.ChallengePathPrefix+token, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = rrHost
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET via %s: %v", n.ip, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

func TestServeChallenge_EveryNodeAnswersForTheOrderer(t *testing.T) {
	nodes := newRRCluster(t, "203.0.113.1", "203.0.113.2", "203.0.113.3")
	const token = "tokenHeldByNodeTwo"
	const keyAuth = token + ".thumbprint"
	writeToken(t, nodes["203.0.113.2"], token, keyAuth)

	for ip, n := range nodes {
		code, body := challengeGet(t, n, token)
		if code != http.StatusOK || body != keyAuth {
			t.Errorf("via %s: got %d %q, want 200 %q", ip, code, body, keyAuth)
		}
	}

	// Loop check: every request a node got from a peer carries the no-proxy
	// marker, and each node saw exactly one direct request (ours) plus at
	// most one forwarded request per direct request in the cluster.
	for ip, n := range nodes {
		direct, forwarded := 0, 0
		for _, r := range n.received() {
			if r.URL.Query().Get(acme.NoProxyParam) == "true" {
				forwarded++
			} else {
				direct++
			}
		}
		if direct != 1 {
			t.Errorf("%s: %d direct requests, want 1", ip, direct)
		}
		if forwarded > len(nodes) {
			t.Errorf("%s: %d forwarded requests, want at most %d", ip, forwarded, len(nodes))
		}
	}
}

func TestServeChallenge_SeveralOrdersInFlight(t *testing.T) {
	nodes := newRRCluster(t, "203.0.113.1", "203.0.113.2", "203.0.113.3")
	// Each node has its own order in flight at the same time.
	for ip, n := range nodes {
		writeToken(t, n, "tok"+strings.ReplaceAll(ip, ".", ""), "auth-"+ip)
	}
	for _, via := range nodes {
		for ip := range nodes {
			token := "tok" + strings.ReplaceAll(ip, ".", "")
			code, body := challengeGet(t, via, token)
			if code != http.StatusOK || body != "auth-"+ip {
				t.Errorf("token for %s via %s: got %d %q", ip, via.ip, code, body)
			}
		}
	}
}

func TestServeChallenge_UnknownTokenIs404Everywhere(t *testing.T) {
	nodes := newRRCluster(t, "203.0.113.1", "203.0.113.2")
	for ip, n := range nodes {
		code, _ := challengeGet(t, n, "nobodyHasThis")
		if code != http.StatusNotFound {
			t.Errorf("via %s: got %d, want 404", ip, code)
		}
	}
}

func TestServeChallenge_NoProxyRequestIsAnsweredLocally(t *testing.T) {
	nodes := newRRCluster(t, "203.0.113.1", "203.0.113.2")
	writeToken(t, nodes["203.0.113.2"], "onlyOnTwo", "auth")

	req, _ := http.NewRequest(http.MethodGet, nodes["203.0.113.1"].server.URL+acme.ChallengePathPrefix+"onlyOnTwo?"+acme.NoProxyParam+"=true", nil)
	req.Host = rrHost
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("got %d, want 404: a no-proxy request must not be forwarded", resp.StatusCode)
	}
	if n := len(nodes["203.0.113.2"].received()); n != 0 {
		t.Errorf("node 2 got %d requests, want 0", n)
	}
}

// writeToken stores keyAuth for token in n's autocert DirCache, under the
// key autocert itself uses for HTTP-01 tokens ("<token>+http-01").
func writeToken(t *testing.T, n *testNode, token, keyAuth string) {
	t.Helper()
	dir := n.manager.certsCachePath
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, token+"+http-01"), []byte(keyAuth), 0o600); err != nil {
		t.Fatal(err)
	}
}
