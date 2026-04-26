package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aquaduct-dev/weft/src/internal/constants"
)

// TestMetricsHandler_AuthRejectsWrongSecret verifies that a Basic-Auth username
// that does not match the connection secret is rejected with 401 regardless of
// where the difference falls — there is no early-exit path that would leak via
// timing.
func TestMetricsHandler_AuthRejectsWrongSecret(t *testing.T) {
	s := &Server{ConnectionSecret: "supersecret-abcdefgh"}
	mockDP := newTestDataplane()
	s.Dataplane = mockDP
	s.Store = NewInMemoryTunnelStore()

	cases := []string{
		"",                       // empty
		"a",                      // first-byte different
		"supersecret-abcdefgg",   // last-byte different
		"supersecret-abcdefghxx", // longer
		"supersecret-abcdefg",    // shorter
	}
	for _, user := range cases {
		req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
		req.SetBasicAuth(user, "")
		rr := httptest.NewRecorder()
		s.MetricsHandler(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("user=%q: status = %d, want 401", user, rr.Code)
		}
	}
}

// TestMetricsHandler_AuthAcceptsCorrectSecret confirms the happy path still works.
func TestMetricsHandler_AuthAcceptsCorrectSecret(t *testing.T) {
	s := &Server{ConnectionSecret: "supersecret-abcdefgh"}
	s.Dataplane = newTestDataplane()
	s.Store = NewInMemoryTunnelStore()

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.SetBasicAuth(s.ConnectionSecret, "")
	rr := httptest.NewRecorder()
	s.MetricsHandler(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}
}

// TestPromQuote covers the Prometheus label escaping helper added for F-13.
func TestPromQuote(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{`plain`, `plain`},
		{`a"b`, `a\"b`},
		{`a\b`, `a\\b`},
		{"a\nb", `a\nb`},
		{`"\` + "\n", `\"\\\n`}, // all three at once
	}
	for _, c := range cases {
		if got := promQuote(c.in); got != c.want {
			t.Errorf("promQuote(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestMetricsHandler_EscapesUserInput proves that a malicious tunnel client
// cannot break the Prometheus exposition format by stuffing quotes/newlines
// into proxied_upstream / dst URL: the rendered exposition has exactly two
// metric lines and no quote-injection.
func TestMetricsHandler_EscapesUserInput(t *testing.T) {
	s := &Server{ConnectionSecret: "secret"}
	mock := newTestDataplane()
	mock.counters["evil"] = ProxyCounters{Tx: 1, Rx: 2, InstanceId: "x"}
	s.Dataplane = mock
	store := NewInMemoryTunnelStore()
	store.peers["evil"] = Peer{
		IP:              constants.DefaultServerIP,
		ProxiedUpstream: "http://hacker\"} 999\nweft_injected_total{x=\"y",
		DstURL:          "https://example.com\\bad",
	}
	s.Store = store

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.SetBasicAuth(s.ConnectionSecret, "")
	rr := httptest.NewRecorder()
	s.MetricsHandler(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}

	body := rr.Body.String()
	// Two real lines, and only the two legitimate metric names should appear
	// at the start of any line. The "injected" metric name only appears
	// inside an escaped label value, not as the start of a series.
	lines := strings.Split(strings.TrimRight(body, "\n"), "\n")
	if len(lines) != 2 {
		t.Errorf("got %d non-empty lines, want 2 (body: %q)", len(lines), body)
	}
	allowedPrefixes := []string{
		"weft_tunnel_bytes_transmitted_total{",
		"weft_tunnel_bytes_received_total{",
	}
	for _, line := range lines {
		ok := false
		for _, p := range allowedPrefixes {
			if strings.HasPrefix(line, p) {
				ok = true
				break
			}
		}
		if !ok {
			t.Errorf("unexpected metric line (possible injection): %q", line)
		}
	}
	// Newline in label must be escaped as literal \n
	if !strings.Contains(body, `\n`) {
		t.Errorf("expected escaped newline (\\n) in body: %q", body)
	}
	// Backslash in label must be escaped as \\
	if !strings.Contains(body, `\\bad`) {
		t.Errorf("expected escaped backslash (\\\\) in body: %q", body)
	}
}
