// Tests for StartChallengeListener: a node's :80 challenge listener must stay
// open with no ACME hosts of its own, so sibling bastions' reachability
// probes (and the CA) can always reach it.
package vhost

import (
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/aquaduct-dev/weft/src/acme"
)

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// probeStatus sends the same request CanPassACMEChallenge sends and returns
// the status, or an error if nothing is listening.
func probeStatus(port int, host string) (int, error) {
	req, err := http.NewRequest(http.MethodHead, fmt.Sprintf("http://127.0.0.1:%d%s?%s=true", port, acme.ChallengePathPrefix, acme.NoProxyParam), nil)
	if err != nil {
		return 0, err
	}
	req.Host = host
	resp, err := (&http.Client{Timeout: 2 * time.Second}).Do(req)
	if err != nil {
		return 0, err
	}
	resp.Body.Close()
	return resp.StatusCode, nil
}

// waitListening polls until port accepts a probe or the deadline passes.
func waitListening(t *testing.T, port int, host string) int {
	t.Helper()
	var lastErr error
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		code, err := probeStatus(port, host)
		if err == nil {
			return code
		}
		lastErr = err
	}
	t.Fatalf("port %d never answered: %v", port, lastErr)
	return 0
}

// A sibling with no tunnels for the host must still answer the probe the way
// CanPassACMEChallenge accepts (403 from autocert's host policy).
func TestStartChallengeListener_SiblingAnswersProbeWithNoHosts(t *testing.T) {
	port := freePort(t)
	sibling := NewVHostProxyManager()
	sibling.SetCertsCachePath(t.TempDir())
	sibling.SetACMEPort(port)
	if err := sibling.StartChallengeListener("127.0.0.1"); err != nil {
		t.Fatalf("StartChallengeListener: %v", err)
	}

	code := waitListening(t, port, "new.example.com")
	if code != http.StatusForbidden && code != http.StatusNotFound {
		t.Fatalf("probe got %d, want 403 or 404 (what CanPassACMEChallenge accepts)", code)
	}
}

// Finishing an issuance used to close :80 once no route was left on it. With
// the persistent listener it must stay open.
func TestStartChallengeListener_SurvivesLastACMEHostClosing(t *testing.T) {
	port := freePort(t)
	m := NewVHostProxyManager()
	m.SetCertsCachePath(t.TempDir())
	m.SetACMEPort(port)
	if err := m.StartChallengeListener("127.0.0.1"); err != nil {
		t.Fatalf("StartChallengeListener: %v", err)
	}
	closer, err := m.AddACMEHost("issued.example.com", "127.0.0.1")
	if err != nil {
		t.Fatalf("AddACMEHost: %v", err)
	}
	waitListening(t, port, "issued.example.com")
	if err := closer.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if _, err := probeStatus(port, "other.example.com"); err != nil {
		t.Fatalf("listener closed after the last ACME host went away: %v", err)
	}
}

// Without StartChallengeListener the old lifecycle is unchanged: the listener
// closes with its last route. This pins down that keepOpen is what keeps the
// persistent listener alive.
func TestChallengeListener_ClosesWithoutKeepOpen(t *testing.T) {
	port := freePort(t)
	m := NewVHostProxyManager()
	m.SetCertsCachePath(t.TempDir())
	m.SetACMEPort(port)
	p := m.Proxy("127.0.0.1", port)
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	route := &Route{}
	p.mu.Lock()
	p.routes["x.example.com"] = []*Route{route}
	p.mu.Unlock()
	// Probe another host: the fake route above has no handler to fall
	// through to.
	waitListening(t, port, "probe.example.com")

	if err := (VHostCloser{VHostProxy: p, Host: "x.example.com", Route: route}).Close(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	if _, err := probeStatus(port, "probe.example.com"); err == nil {
		t.Fatal("listener still open; expected it to close with its last route")
	}
}
