// acme_failure_test.go — verifies that AddHostWithACME's background issuance
// goroutine makes failures observable: a failing ACME helper stub must be
// recorded as the host's last error (reported by ACMEFailures), must still
// trigger the tunnel Cleanup, and a later successful issuance must clear it.
// AddHostWithACME itself keeps returning success immediately (async contract).
package vhost

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

// withACMEStubs replaces the certificate wait seam for the duration of the
// test.
func withACMEStubs(t *testing.T, wait func(context.Context, *autocert.Manager, string) (*tls.Certificate, error)) {
	t.Helper()
	origWait := waitForCertificateFn
	waitForCertificateFn = wait
	t.Cleanup(func() {
		waitForCertificateFn = origWait
	})
}

func newACMETestManager(t *testing.T, acmePort int) (*VHostProxyManager, chan string) {
	t.Helper()
	manager := NewVHostProxyManager()
	manager.SetCertsCachePath(t.TempDir())
	manager.SetACMEPort(acmePort)
	cleaned := make(chan string, 4)
	manager.Cleanup = func(name string) {
		t.Logf("Cleanup called for tunnel %q", name)
		cleaned <- name
	}
	withSeams(t, []net.IP{net.ParseIP("203.0.113.5")}, nil, nil)
	probeACMEChallengeFn = func(_ context.Context, _ string, _ netip.Addr) (bool, string) {
		return true, "ok (test fake)"
	}
	return manager, cleaned
}

func TestAddHostWithACME_RecordsFailingIssuance(t *testing.T) {
	manager, cleaned := newACMETestManager(t, 18181)
	withACMEStubs(t, func(_ context.Context, _ *autocert.Manager, host string) (*tls.Certificate, error) {
		t.Logf("stub WaitForCertificate failing for %s", host)
		return nil, errors.New("acme: urn:ietf:params:acme:error:rateLimited")
	})

	p := manager.Proxy("127.0.0.1", 19193)
	target, _ := url.Parse("http://upstream.invalid:80")
	if _, _, err := p.AddHostWithACME(RouteConfig{
		Host:      "fail.example",
		BindIP:    "127.0.0.1",
		Target:    target,
		ProxyName: "tunnel-fail",
	}); err != nil {
		t.Fatalf("AddHostWithACME should keep its async contract and return nil, got %v", err)
	}

	select {
	case name := <-cleaned:
		if name != "tunnel-fail" {
			t.Fatalf("Cleanup called for %q, want tunnel-fail", name)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("Cleanup was not called after the ACME helper failed")
	}

	failures := manager.ACMEFailures()
	t.Logf("ACMEFailures after failing issuance: %+v", failures)
	if len(failures) != 1 {
		t.Fatalf("want 1 ACME failure, got %d: %+v", len(failures), failures)
	}
	f := failures[0]
	if f.Host != "fail.example" {
		t.Errorf("failure host = %q, want fail.example", f.Host)
	}
	if !strings.Contains(f.Error, "rateLimited") || !strings.Contains(f.Error, "obtain certificate") {
		t.Errorf("failure error = %q, want stage and helper error", f.Error)
	}
	if f.Time.IsZero() {
		t.Errorf("failure time not set")
	}
}

func TestAddHostWithACME_SuccessClearsPreviousFailure(t *testing.T) {
	manager, _ := newACMETestManager(t, 18182)
	manager.recordACMEFailure("ok.example", "obtain certificate", errors.New("earlier failure"))
	if got := len(manager.ACMEFailures()); got != 1 {
		t.Fatalf("precondition: want 1 failure, got %d", got)
	}

	done := make(chan struct{})
	withACMEStubs(t, func(_ context.Context, _ *autocert.Manager, host string) (*tls.Certificate, error) {
		t.Logf("stub WaitForCertificate succeeding for %s", host)
		defer close(done)
		return nil, nil
	})

	p := manager.Proxy("127.0.0.1", 19194)
	target, _ := url.Parse("http://upstream.invalid:80")
	closer, _, err := p.AddHostWithACME(RouteConfig{
		Host:      "ok.example",
		BindIP:    "127.0.0.1",
		Target:    target,
		ProxyName: "tunnel-ok",
	})
	if err != nil {
		t.Fatalf("AddHostWithACME: %v", err)
	}

	<-done
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if len(manager.ACMEFailures()) == 0 {
			t.Logf("previous failure cleared; closing route")
			_ = closer.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("previous failure not cleared after successful issuance: %+v", manager.ACMEFailures())
}
