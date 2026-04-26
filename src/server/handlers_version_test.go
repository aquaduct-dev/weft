package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aquaduct-dev/weft/src/version"
)

func TestVersionHandler_ReturnsBuildInfo(t *testing.T) {
	s := &Server{}
	rr := httptest.NewRecorder()
	s.VersionHandler(rr, httptest.NewRequest(http.MethodGet, "/version", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if got := rr.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}

	var body map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("body is not valid JSON: %v (body=%q)", err, rr.Body.String())
	}
	if body["commit"] != version.Commit {
		t.Errorf("commit = %q, want %q", body["commit"], version.Commit)
	}
	if body["date"] != version.CommitDate {
		t.Errorf("date = %q, want %q", body["date"], version.CommitDate)
	}
}
