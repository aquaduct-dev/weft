package auth

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aquaduct-dev/weft/src/version"
	"github.com/golang-jwt/jwt/v4"
)

// MockRoundTripper implements http.RoundTripper
type MockRoundTripper struct {
	lastRequest *http.Request
}

func (m *MockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	m.lastRequest = req
	return &http.Response{StatusCode: http.StatusOK}, nil
}

func generateToken(expiry time.Time) string {
	claims := jwt.MapClaims{
		"exp": expiry.Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	// Signing key doesn't matter for ParseUnverified
	s, _ := token.SignedString([]byte("secret"))
	return s
}

func TestWithJwt_Renewal(t *testing.T) {
	mockRT := &MockRoundTripper{}

	// 1. Create a token that expires in 30 seconds (needs renewal, since threshold is 1 min)
	oldToken := generateToken(time.Now().Add(30 * time.Second))

	// 2. Create a token that expires in 1 hour (valid)
	newToken := generateToken(time.Now().Add(1 * time.Hour))

	renewalCount := 0
	renewalFunc := func() (string, error) {
		renewalCount++
		return newToken, nil
	}

	// 3. Initialize transport
	// WithJWT returns a struct value. We take the address to use pointer receivers.
	transportVal := WithJWT(mockRT, oldToken, renewalFunc)
	transport := &transportVal

	req, _ := http.NewRequest("GET", "http://example.com", nil)

	// 4. First Request - Should trigger renewal
	_, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip failed: %v", err)
	}

	if renewalCount != 1 {
		t.Errorf("Expected renewal count 1, got %d", renewalCount)
	}

	authHeader := mockRT.lastRequest.Header.Get("Authorization")
	expectedHeader := "Bearer " + newToken
	if authHeader != expectedHeader {
		t.Errorf("Expected header %s, got %s", expectedHeader, authHeader)
	}

	// Verify internal state (accessible since we are in package auth)
	if transport.jwt != newToken {
		t.Errorf("Transport JWT not updated internally")
	}

	// 5. Second Request - Should NOT trigger renewal
	_, err = transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip failed: %v", err)
	}

	if renewalCount != 1 {
		t.Errorf("Expected renewal count to remain 1, got %d", renewalCount)
	}

	authHeader = mockRT.lastRequest.Header.Get("Authorization")
	if authHeader != expectedHeader {
		t.Errorf("Expected header %s, got %s", expectedHeader, authHeader)
	}
}

// startVersionServer spins up an httptest TLS server that responds to /version
// with the provided commit and date. Returns the host:port the client should
// dial.
func startVersionServer(t *testing.T, commit, date string) string {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/version", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"commit":%q,"date":%q}`, commit, date)
	})
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "https://")
}

func TestAnnotateWithVersions_Mismatch(t *testing.T) {
	addr := startVersionServer(t, "deadbee", "2026-01-01")

	loginErr := errors.New("login boom")
	wrapped := annotateWithVersions(addr, loginErr)
	msg := wrapped.Error()

	if !strings.Contains(msg, "version mismatch") {
		t.Errorf("expected 'version mismatch' in error, got: %s", msg)
	}
	if !strings.Contains(msg, "deadbee") || !strings.Contains(msg, "2026-01-01") {
		t.Errorf("expected server version in error, got: %s", msg)
	}
	if !strings.Contains(msg, version.Commit) {
		t.Errorf("expected client commit %q in error, got: %s", version.Commit, msg)
	}
	if !errors.Is(wrapped, loginErr) {
		t.Errorf("expected wrapped error to unwrap to original via errors.Is")
	}
}

func TestAnnotateWithVersions_Match(t *testing.T) {
	addr := startVersionServer(t, version.Commit, version.CommitDate)

	wrapped := annotateWithVersions(addr, errors.New("login boom"))
	msg := wrapped.Error()

	if strings.Contains(msg, "version mismatch") {
		t.Errorf("expected NO 'version mismatch' when versions agree, got: %s", msg)
	}
	if !strings.Contains(msg, "both at version") {
		t.Errorf("expected 'both at version' phrasing, got: %s", msg)
	}
	if !strings.Contains(msg, "login boom") {
		t.Errorf("expected original error preserved, got: %s", msg)
	}
}

func TestAnnotateWithVersions_ServerUnreachable(t *testing.T) {
	// Reserved-for-documentation address; nothing listens on it.
	wrapped := annotateWithVersions("192.0.2.1:1", errors.New("login boom"))
	msg := wrapped.Error()

	if !strings.Contains(msg, "could not fetch server version") {
		t.Errorf("expected unreachable-server hint, got: %s", msg)
	}
	if !strings.Contains(msg, "login boom") {
		t.Errorf("expected original error preserved, got: %s", msg)
	}
	if !strings.Contains(msg, version.Commit) {
		t.Errorf("expected client commit %q in error, got: %s", version.Commit, msg)
	}
}
