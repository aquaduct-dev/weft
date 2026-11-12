package acme

import (
	"context"
	"errors"
	"net"
	"testing"
)

// TestLookupIPFresh: a new host is resolved at its zone's own nameservers,
// so a resolver that cached NXDOMAIN for it moments earlier is never asked.
func TestLookupIPFresh(t *testing.T) {
	prevNS, prevQuery, prevSystem := lookupNS, queryAt, systemLookupIP
	t.Cleanup(func() { lookupNS, queryAt, systemLookupIP = prevNS, prevQuery, prevSystem })

	var nsAsked []string
	lookupNS = func(_ context.Context, zone string) ([]*net.NS, error) {
		nsAsked = append(nsAsked, zone)
		if zone == "lab0.us" {
			return []*net.NS{{Host: "a.ns.example."}, {Host: "b.ns.example."}}, nil
		}
		return nil, &net.DNSError{Err: "no such host", Name: zone, IsNotFound: true}
	}
	systemCalls := 0
	systemLookupIP = func(string) ([]net.IP, error) {
		systemCalls++
		return nil, &net.DNSError{Err: "no such host (cached)", IsNotFound: true}
	}

	// The first nameserver is down; the second has the new record.
	queryAt = func(_ context.Context, server, host string) ([]net.IP, error) {
		if server == "a.ns.example" {
			return nil, errors.New("timeout")
		}
		if host != "new-1.thirdeye.lab0.us" {
			t.Fatalf("queried %q", host)
		}
		return []net.IP{net.ParseIP("5.78.28.244")}, nil
	}
	ips, err := LookupIPFresh("new-1.thirdeye.lab0.us.")
	if err != nil || len(ips) != 1 || !ips[0].Equal(net.ParseIP("5.78.28.244")) {
		t.Fatalf("got %v %v", ips, err)
	}
	if systemCalls != 0 {
		t.Fatal("asked the caching resolver although the zone answered")
	}
	// Never an NS query for the host itself: that would cache its NXDOMAIN too.
	for _, z := range nsAsked {
		if z == "new-1.thirdeye.lab0.us" {
			t.Fatal("NS lookup for the host itself")
		}
	}

	// The zone's own server says the name does not exist: that is the answer.
	queryAt = func(context.Context, string, string) ([]net.IP, error) {
		return nil, &net.DNSError{Err: "no such host", IsNotFound: true}
	}
	if _, err := LookupIPFresh("missing.thirdeye.lab0.us"); err == nil || systemCalls != 0 {
		t.Fatalf("missing host: err=%v systemCalls=%d", err, systemCalls)
	}

	// No authoritative server reachable: fall back to the system resolver.
	queryAt = func(context.Context, string, string) ([]net.IP, error) { return nil, errors.New("unreachable") }
	if _, err := LookupIPFresh("x.thirdeye.lab0.us"); err == nil || systemCalls != 1 {
		t.Fatalf("fallback: err=%v systemCalls=%d", err, systemCalls)
	}

	// An IP literal is not looked up at the zone.
	systemLookupIP = func(h string) ([]net.IP, error) { return []net.IP{net.ParseIP(h)}, nil }
	if ips, _ := LookupIPFresh("5.78.28.244"); len(ips) != 1 {
		t.Fatalf("literal: %v", ips)
	}
}
