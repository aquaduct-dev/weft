package vhost

import (
	"context"
	"testing"
)

// TestCanPassACMEChallenge_RejectsLoopback verifies the F-11 fix: even if
// DNS for the supplied host yields only a loopback / private IP, the probe
// must refuse to attempt the HTTP fetch (preventing DNS-rebinding-style
// SSRF where the second resolution returns 127.0.0.1).
//
// We exercise this with a host that resolves to localhost. The function
// should return false without ever making an HTTP request.
func TestCanPassACMEChallenge_RejectsLoopback(t *testing.T) {
	m := NewVHostProxyManager()
	p := NewVHostProxy(VHostKey{BindIp: "203.0.113.1", Port: 0}, m)
	// Set a public-looking bindIp so the function doesn't fall through to
	// api.ipify.org during the unit test.
	p.bindIp = "203.0.113.1"

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
