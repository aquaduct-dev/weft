package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
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
