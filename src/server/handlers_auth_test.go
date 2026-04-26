package server

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aquaduct-dev/weft/src/crypto"
	"github.com/golang-jwt/jwt/v4"
)

func newAuthTestServer(secret string) *Server {
	return &Server{
		ConnectionSecret: secret,
		challenges:       make(map[string]challengeEntry),
	}
}

// TestGetChallenge_StoresExpiringEntry verifies the new bounded/expiring
// challenge map (F-1): each GET /login adds an entry with a future expiry.
func TestGetChallenge_StoresExpiringEntry(t *testing.T) {
	s := newAuthTestServer("secret")

	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	req.RemoteAddr = "1.2.3.4:1111"
	rr := httptest.NewRecorder()
	s.getChallenge(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	entry, ok := s.challenges[req.RemoteAddr]
	if !ok {
		t.Fatalf("expected challenge stored for %s", req.RemoteAddr)
	}
	if entry.expiresAt.Before(time.Now()) {
		t.Errorf("expected future expiresAt, got %v", entry.expiresAt)
	}
	if entry.value == "" {
		t.Errorf("expected non-empty challenge value")
	}
}

// TestGetChallenge_RejectsAtCap is the F-1 regression: when the table is full
// of unexpired entries, further GET /login requests are rejected with 503
// instead of growing the map without bound.
func TestGetChallenge_RejectsAtCap(t *testing.T) {
	s := newAuthTestServer("secret")
	now := time.Now()
	for i := 0; i < maxOutstandingChallenges; i++ {
		s.challenges[fmt.Sprintf("filler-%d", i)] = challengeEntry{value: "x", expiresAt: now.Add(challengeTTL)}
	}

	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	req.RemoteAddr = "9.9.9.9:9999"
	rr := httptest.NewRecorder()
	s.getChallenge(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", rr.Code)
	}
	if _, exists := s.challenges[req.RemoteAddr]; exists {
		t.Errorf("rejected request must not be inserted into challenges map")
	}
	// Cap is preserved.
	if got := len(s.challenges); got != maxOutstandingChallenges {
		t.Errorf("len(challenges) = %d, want %d", got, maxOutstandingChallenges)
	}
}

// TestGetChallenge_SweepsExpired verifies that getChallenge garbage-collects
// expired entries on each call, so attacker churn doesn't permanently use cap.
func TestGetChallenge_SweepsExpired(t *testing.T) {
	s := newAuthTestServer("secret")
	stale := time.Now().Add(-time.Minute)
	for i := 0; i < maxOutstandingChallenges; i++ {
		s.challenges[fmt.Sprintf("expired-%d", i)] = challengeEntry{value: "x", expiresAt: stale}
	}

	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	req.RemoteAddr = "5.5.5.5:5555"
	rr := httptest.NewRecorder()
	s.getChallenge(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (expired entries should be swept)", rr.Code)
	}
	if _, ok := s.challenges[req.RemoteAddr]; !ok {
		t.Errorf("new challenge not inserted after sweep")
	}
	for k, v := range s.challenges {
		if strings.HasPrefix(k, "expired-") {
			_ = v
			t.Errorf("expired entry %q was not swept", k)
		}
	}
}

// TestGetChallenge_OverwriteSameAddrDoesNotGrow ensures repeated GETs from the
// same RemoteAddr only ever count as one slot.
func TestGetChallenge_OverwriteSameAddrDoesNotGrow(t *testing.T) {
	s := newAuthTestServer("secret")
	for i := 0; i < 10; i++ {
		req := httptest.NewRequest(http.MethodGet, "/login", nil)
		req.RemoteAddr = "1.1.1.1:1111"
		s.getChallenge(httptest.NewRecorder(), req)
	}
	if got := len(s.challenges); got != 1 {
		t.Errorf("len(challenges) = %d, want 1", got)
	}
}

// TestVerifyChallenge_DeletesOnDecryptFailure is the F-1 regression: failed
// verifyChallenge attempts must not leave stale entries.
func TestVerifyChallenge_DeletesOnDecryptFailure(t *testing.T) {
	s := newAuthTestServer("secret")
	s.certPEM = []byte("dummy-cert") // not exercised on the failure path

	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	req.RemoteAddr = "8.8.8.8:8888"
	s.getChallenge(httptest.NewRecorder(), req)
	if _, ok := s.challenges[req.RemoteAddr]; !ok {
		t.Fatal("setup: challenge should be present after GET")
	}

	// POST garbage that won't decrypt.
	bad := map[string]any{
		"challenge":  base64.StdEncoding.EncodeToString([]byte("not-a-valid-ciphertext-not-a-valid-ciphertext")),
		"proxy_name": "anything",
	}
	body, _ := json.Marshal(bad)
	post := httptest.NewRequest(http.MethodPost, "/login", bytes.NewReader(body))
	post.RemoteAddr = req.RemoteAddr
	post.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	s.verifyChallenge(rr, post)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rr.Code)
	}
	if _, exists := s.challenges[req.RemoteAddr]; exists {
		t.Errorf("challenge entry leaked across failed POST")
	}
}

// TestVerifyChallenge_NoAudClaim is the F-8 regression: ensure the JWT issued
// on a successful login does NOT carry an aud claim (which the server never
// enforced and was misleading to readers), and DOES carry iss/iat.
func TestVerifyChallenge_NoAudClaim(t *testing.T) {
	s := newAuthTestServer("secret")
	s.certPEM = []byte("-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n")

	get := httptest.NewRequest(http.MethodGet, "/login", nil)
	get.RemoteAddr = "10.0.0.2:5001"
	rrGet := httptest.NewRecorder()
	s.getChallenge(rrGet, get)
	plaintext, err := crypto.Decrypt(s.ConnectionSecret, rrGet.Body.Bytes())
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	suffix := strings.TrimPrefix(string(plaintext), "server-")
	answer, err := crypto.Encrypt(s.ConnectionSecret, suffix)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	body, _ := json.Marshal(map[string]any{
		"challenge":  base64.StdEncoding.EncodeToString(answer),
		"proxy_name": "alice",
	})
	post := httptest.NewRequest(http.MethodPost, "/login", bytes.NewReader(body))
	post.RemoteAddr = get.RemoteAddr
	post.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	s.verifyChallenge(rr, post)
	if rr.Code != http.StatusOK {
		t.Fatalf("verify status = %d (body=%s)", rr.Code, rr.Body.String())
	}
	var resp struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	// Validate the JWT and check claims.
	tok, err := s.ValidateJWT(resp.Token)
	if err != nil {
		t.Fatalf("ValidateJWT: %v", err)
	}
	mclaims, ok := tok.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatalf("claims are not MapClaims, got %T", tok.Claims)
	}
	if _, hasAud := mclaims["aud"]; hasAud {
		t.Errorf("aud claim must not be present (was unverified) — F-8")
	}
	if iss, _ := mclaims["iss"].(string); iss != "weft" {
		t.Errorf("iss = %q, want \"weft\"", iss)
	}
	if _, hasIat := mclaims["iat"]; !hasIat {
		t.Errorf("iat claim must be set")
	}
	if sub, _ := mclaims["sub"].(string); sub != "alice" {
		t.Errorf("sub = %q, want \"alice\"", sub)
	}
}

// TestValidateJWT_RejectsForeignIssuer covers the F-8 hardening of
// ValidateJWT: a token signed with the same connection secret but issued
// by something other than weft (e.g. an unrelated app reusing the secret)
// must not validate.
func TestValidateJWT_RejectsForeignIssuer(t *testing.T) {
	s := newAuthTestServer("secret")

	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss": "other-service",
		"sub": "alice",
		"iat": time.Now().Unix(),
		"nbf": time.Now().Unix(),
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	signed, err := tok.SignedString([]byte("secret"))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := s.ValidateJWT(signed); err == nil {
		t.Errorf("expected validation error for foreign issuer")
	}
}

// TestValidateJWT_RejectsFutureIat covers F-8 skew protection: a token whose
// iat is far in the future must be rejected (clamps the replay burn-window).
func TestValidateJWT_RejectsFutureIat(t *testing.T) {
	s := newAuthTestServer("secret")

	future := time.Now().Add(time.Hour)
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss": "weft",
		"sub": "alice",
		"iat": future.Unix(),
		"nbf": future.Add(-time.Minute).Unix(),
		"exp": future.Add(time.Hour).Unix(),
	})
	signed, err := tok.SignedString([]byte("secret"))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := s.ValidateJWT(signed); err == nil {
		t.Errorf("expected validation error for far-future iat")
	}
}

// TestVerifyChallenge_FullFlow proves the happy path still works.
func TestVerifyChallenge_FullFlow(t *testing.T) {
	s := newAuthTestServer("secret")
	s.certPEM = []byte("-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n")

	get := httptest.NewRequest(http.MethodGet, "/login", nil)
	get.RemoteAddr = "10.0.0.1:5000"
	rrGet := httptest.NewRecorder()
	s.getChallenge(rrGet, get)
	if rrGet.Code != http.StatusOK {
		t.Fatalf("GET status = %d", rrGet.Code)
	}
	// Decrypt the challenge ciphertext just like a real client would.
	plaintext, err := crypto.Decrypt(s.ConnectionSecret, rrGet.Body.Bytes())
	if err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}
	if !strings.HasPrefix(string(plaintext), "server-") {
		t.Fatalf("unexpected challenge plaintext %q", plaintext)
	}
	suffix := strings.TrimPrefix(string(plaintext), "server-")
	answer, err := crypto.Encrypt(s.ConnectionSecret, suffix)
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}
	body, _ := json.Marshal(map[string]any{
		"challenge":  base64.StdEncoding.EncodeToString(answer),
		"proxy_name": "alice",
	})
	post := httptest.NewRequest(http.MethodPost, "/login", bytes.NewReader(body))
	post.RemoteAddr = get.RemoteAddr
	post.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	s.verifyChallenge(rr, post)

	if rr.Code != http.StatusOK {
		t.Errorf("verify status = %d, want 200 (body=%s)", rr.Code, rr.Body.String())
	}
	if _, exists := s.challenges[post.RemoteAddr]; exists {
		t.Errorf("challenge entry should be consumed after success")
	}
}
