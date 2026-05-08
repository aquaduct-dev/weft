package server

import (
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// recordingDataplane is a testDataplane that captures RegisterACMERedirect calls.
type recordingDataplane struct {
	*testDataplane
	mu     sync.Mutex
	host   string
	peerIP string
	calls  int
}

func (d *recordingDataplane) RegisterACMERedirect(host, peerIP string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.host = host
	d.peerIP = peerIP
	d.calls++
	return nil
}

// withStubDNS replaces the package-level lookupIP seam for a single test and
// restores it on cleanup.
func withStubDNS(t *testing.T, table map[string][]string) {
	t.Helper()
	prev := lookupIP
	parsed := make(map[string][]net.IP, len(table))
	for h, addrs := range table {
		ips := make([]net.IP, 0, len(addrs))
		for _, a := range addrs {
			if ip := net.ParseIP(a); ip != nil {
				ips = append(ips, ip)
			}
		}
		parsed[h] = ips
	}
	lookupIP = func(host string) ([]net.IP, error) {
		if ips, ok := parsed[host]; ok {
			return ips, nil
		}
		return nil, &net.DNSError{Err: "no such host (test stub)", Name: host, IsNotFound: true}
	}
	t.Cleanup(func() { lookupIP = prev })
}

func TestACMERedirectHandler_RejectsNonPOST(t *testing.T) {
	s := &Server{}
	s.Dataplane = &recordingDataplane{testDataplane: newTestDataplane()}

	req := httptest.NewRequest(http.MethodGet, "/acme-redirect?host=example.com", nil)
	rr := httptest.NewRecorder()
	s.ACMERedirectHandler(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", rr.Code)
	}
}

func TestACMERedirectHandler_RejectsMissingHost(t *testing.T) {
	s := &Server{}
	s.Dataplane = &recordingDataplane{testDataplane: newTestDataplane()}

	req := httptest.NewRequest(http.MethodPost, "/acme-redirect", nil)
	rr := httptest.NewRecorder()
	s.ACMERedirectHandler(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
}

func TestACMERedirectHandler_RejectsSenderNotInDNS(t *testing.T) {
	withStubDNS(t, map[string][]string{
		"example.com": {"10.0.0.1", "10.0.0.2"}, // 10.0.0.99 is NOT in this set
	})

	dp := &recordingDataplane{testDataplane: newTestDataplane()}
	s := &Server{}
	s.Dataplane = dp

	req := httptest.NewRequest(http.MethodPost, "/acme-redirect?host=example.com", nil)
	req.RemoteAddr = "10.0.0.99:54321"
	rr := httptest.NewRecorder()
	s.ACMERedirectHandler(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rr.Code)
	}
	if dp.calls != 0 {
		t.Errorf("Dataplane.RegisterACMERedirect should not have been called; calls = %d", dp.calls)
	}
}

func TestACMERedirectHandler_AcceptsSenderInDNS(t *testing.T) {
	withStubDNS(t, map[string][]string{
		"example.com": {"10.0.0.1", "10.0.0.2", "10.0.0.99"},
	})

	dp := &recordingDataplane{testDataplane: newTestDataplane()}
	s := &Server{}
	s.Dataplane = dp

	req := httptest.NewRequest(http.MethodPost, "/acme-redirect?host=example.com", nil)
	req.RemoteAddr = "10.0.0.99:54321"
	rr := httptest.NewRecorder()
	s.ACMERedirectHandler(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Errorf("status = %d, want 204", rr.Code)
	}
	if dp.calls != 1 {
		t.Errorf("Dataplane.RegisterACMERedirect calls = %d, want 1", dp.calls)
	}
	if dp.host != "example.com" {
		t.Errorf("registered host = %q, want example.com", dp.host)
	}
	if dp.peerIP != "10.0.0.99" {
		t.Errorf("registered peerIP = %q, want 10.0.0.99", dp.peerIP)
	}
}

func TestACMERedirectHandler_DNSFailureReturns500(t *testing.T) {
	withStubDNS(t, map[string][]string{}) // nothing maps; lookup fails for any host

	dp := &recordingDataplane{testDataplane: newTestDataplane()}
	s := &Server{}
	s.Dataplane = dp

	req := httptest.NewRequest(http.MethodPost, "/acme-redirect?host=missing.example.com", nil)
	req.RemoteAddr = "10.0.0.99:54321"
	rr := httptest.NewRecorder()
	s.ACMERedirectHandler(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rr.Code)
	}
	if dp.calls != 0 {
		t.Errorf("Dataplane.RegisterACMERedirect should not have been called on DNS failure")
	}
}

func TestACMERedirectHandler_RejectsMalformedRemoteAddr(t *testing.T) {
	dp := &recordingDataplane{testDataplane: newTestDataplane()}
	s := &Server{}
	s.Dataplane = dp

	req := httptest.NewRequest(http.MethodPost, "/acme-redirect?host=example.com", nil)
	req.RemoteAddr = "not-a-valid-addr"
	rr := httptest.NewRecorder()
	s.ACMERedirectHandler(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
}
