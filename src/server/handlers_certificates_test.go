// handlers_certificates_test.go — verifies GET /certificates reports hosts
// whose background ACME issuance failed alongside the cached certificates,
// and omits the field when there are no failures.
package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aquaduct-dev/weft/types"
)

func TestCertificatesHandler_ReportsACMEFailures(t *testing.T) {
	dp := newTestDataplane()
	when := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	dp.acmeFailures = []types.ACMEFailure{{Host: "fail.example", Error: "obtain certificate: rate limited", Time: when}}
	s := &Server{Dataplane: dp}

	rec := httptest.NewRecorder()
	s.CertificatesHandler(rec, httptest.NewRequest(http.MethodGet, "/certificates", nil))
	t.Logf("GET /certificates -> %d %s", rec.Code, rec.Body.String())
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var resp types.CertificatesResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.ACMEFailures) != 1 || resp.ACMEFailures[0].Host != "fail.example" ||
		!resp.ACMEFailures[0].Time.Equal(when) || !strings.Contains(resp.ACMEFailures[0].Error, "rate limited") {
		t.Fatalf("acme_failures = %+v, want the fail.example failure", resp.ACMEFailures)
	}
}

func TestCertificatesHandler_OmitsEmptyACMEFailures(t *testing.T) {
	s := &Server{Dataplane: newTestDataplane()}
	rec := httptest.NewRecorder()
	s.CertificatesHandler(rec, httptest.NewRequest(http.MethodGet, "/certificates", nil))
	t.Logf("GET /certificates -> %d %s", rec.Code, rec.Body.String())
	if strings.Contains(rec.Body.String(), "acme_failures") {
		t.Fatalf("acme_failures should be omitted when empty: %s", rec.Body.String())
	}
}
