package vhost

import (
	"context"
	"net"
	"net/netip"
	"testing"
)

// TestCanPassACMEChallenge_RejectsLoopback verifies the F-11 fix: even if
// DNS for the supplied host yields only a loopback / private IP, the probe
// must refuse to attempt the HTTP fetch (preventing DNS-rebinding-style
// SSRF where the second resolution returns 127.0.0.1).
func TestCanPassACMEChallenge_RejectsLoopback(t *testing.T) {
	m := NewVHostProxyManager()
	p := NewVHostProxy(VHostKey{BindIp: "203.0.113.1", Port: 0}, m)

	ok := p.CanPassACMEChallenge(context.Background(), "localhost")
	if ok {
		t.Errorf("expected probe to refuse loopback host, got true")
	}
}

// TestCanPassACMEChallenge_RejectsEmpty covers the basic guard.
func TestCanPassACMEChallenge_RejectsEmpty(t *testing.T) {
	m := NewVHostProxyManager()
	p := NewVHostProxy(VHostKey{BindIp: "203.0.113.1", Port: 0}, m)
	if p.CanPassACMEChallenge(context.Background(), "") {
		t.Errorf("expected empty host to be rejected")
	}
}

// withSeams installs test fakes for lookupIP and probeACMEChallengeFn for
// the duration of the test, restoring the originals on cleanup.
func withSeams(t *testing.T, ips []net.IP, lookupErr error, probeResults map[string]bool) {
	t.Helper()
	origLookup := lookupIP
	origProbe := probeACMEChallengeFn
	lookupIP = func(string) ([]net.IP, error) { return ips, lookupErr }
	probeACMEChallengeFn = func(_ context.Context, _ string, dialIP netip.Addr) (bool, string) {
		if probeResults[dialIP.String()] {
			return true, "ok (test fake)"
		}
		return false, "test fake says fail"
	}
	t.Cleanup(func() {
		lookupIP = origLookup
		probeACMEChallengeFn = origProbe
	})
}

func newProxy() *VHostProxy {
	return NewVHostProxy(VHostKey{BindIp: "203.0.113.1", Port: 0}, NewVHostProxyManager())
}

// 0 public-IPv4 records — DNS not pointed at any public IP. Deny.
func TestCanPassACMEChallenge_NoPublicRecords(t *testing.T) {
	withSeams(t, []net.IP{net.ParseIP("10.0.0.1"), net.ParseIP("127.0.0.1")}, nil, nil)
	if newProxy().CanPassACMEChallenge(context.Background(), "host.example.") {
		t.Fatalf("expected deny when no public IPv4 records resolved")
	}
}

// Lookup error — also deny.
func TestCanPassACMEChallenge_LookupError(t *testing.T) {
	withSeams(t, nil, &net.DNSError{Err: "no such host"}, nil)
	if newProxy().CanPassACMEChallenge(context.Background(), "nx.example.") {
		t.Fatalf("expected deny on DNS lookup failure")
	}
}

// 1 record, probe succeeds — pass. Also verifies IP-literal-style hosting,
// since net.LookupIP("203.0.113.1") returns the literal as a single record.
func TestCanPassACMEChallenge_SingleRecord_Pass(t *testing.T) {
	withSeams(t, []net.IP{net.ParseIP("203.0.113.5")}, nil, map[string]bool{"203.0.113.5": true})
	if !newProxy().CanPassACMEChallenge(context.Background(), "203.0.113.5") {
		t.Fatalf("expected pass for single record with successful probe")
	}
}

// 1 record, probe fails — deny.
func TestCanPassACMEChallenge_SingleRecord_Fail(t *testing.T) {
	withSeams(t, []net.IP{net.ParseIP("203.0.113.5")}, nil, map[string]bool{"203.0.113.5": false})
	if newProxy().CanPassACMEChallenge(context.Background(), "host.example.") {
		t.Fatalf("expected deny when single record's probe fails")
	}
}

// RR-DNS threshold matrix: success counts are evaluated against rrPassThresholdPercent.
func TestCanPassACMEChallenge_RRThreshold(t *testing.T) {
	cases := []struct {
		name      string
		records   []string
		successes []string // subset of records whose probe returns true
		want      bool
	}{
		// 2 records: 100% pass, 50% fail.
		{"2/2 pass", []string{"203.0.113.1", "203.0.113.2"}, []string{"203.0.113.1", "203.0.113.2"}, true},
		{"1/2 below", []string{"203.0.113.1", "203.0.113.2"}, []string{"203.0.113.1"}, false},
		// 3 records: 2/3 = 66.67% passes, 1/3 = 33% fails.
		{"3/3 pass", []string{"203.0.113.1", "203.0.113.2", "203.0.113.3"}, []string{"203.0.113.1", "203.0.113.2", "203.0.113.3"}, true},
		{"2/3 pass", []string{"203.0.113.1", "203.0.113.2", "203.0.113.3"}, []string{"203.0.113.1", "203.0.113.2"}, true},
		{"1/3 below", []string{"203.0.113.1", "203.0.113.2", "203.0.113.3"}, []string{"203.0.113.1"}, false},
		// 4 records: 3/4 = 75% passes, 2/4 = 50% fails.
		{"3/4 pass", []string{"203.0.113.1", "203.0.113.2", "203.0.113.3", "203.0.113.4"}, []string{"203.0.113.1", "203.0.113.2", "203.0.113.3"}, true},
		{"2/4 below", []string{"203.0.113.1", "203.0.113.2", "203.0.113.3", "203.0.113.4"}, []string{"203.0.113.1", "203.0.113.2"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ips := make([]net.IP, len(tc.records))
			for i, r := range tc.records {
				ips[i] = net.ParseIP(r)
			}
			results := map[string]bool{}
			for _, s := range tc.successes {
				results[s] = true
			}
			withSeams(t, ips, nil, results)
			got := newProxy().CanPassACMEChallenge(context.Background(), "rr.example.")
			if got != tc.want {
				t.Errorf("got %v, want %v (records=%d successes=%d)", got, tc.want, len(tc.records), len(tc.successes))
			}
		})
	}
}
