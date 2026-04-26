package auth

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func leafFingerprintHex(srv *httptest.Server, t *testing.T) string {
	t.Helper()
	cert, err := x509.ParseCertificate(srv.Certificate().Raw)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

// TestLoginTLSConfig_PinnedFingerprintAccepts verifies the F-10 happy path:
// when PinnedFingerprint matches the server's leaf cert sha256, the TLS
// handshake completes.
func TestLoginTLSConfig_PinnedFingerprintAccepts(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	prev := PinnedFingerprint
	defer func() { PinnedFingerprint = prev }()
	PinnedFingerprint = leafFingerprintHex(srv, t)

	client := http.Client{Transport: &http.Transport{TLSClientConfig: loginTLSConfig()}}
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	resp.Body.Close()
}

// TestLoginTLSConfig_PinnedFingerprintRejects: F-10 negative path. When the
// pin doesn't match, the handshake must fail.
func TestLoginTLSConfig_PinnedFingerprintRejects(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()

	prev := PinnedFingerprint
	defer func() { PinnedFingerprint = prev }()
	// 32 bytes of zeros, in hex.
	PinnedFingerprint = strings.Repeat("00", 32)

	client := http.Client{Transport: &http.Transport{TLSClientConfig: loginTLSConfig()}}
	_, err := client.Get(srv.URL)
	if err == nil {
		t.Fatalf("expected handshake error for mismatched fingerprint")
	}
	if !strings.Contains(err.Error(), "fingerprint mismatch") {
		t.Errorf("expected 'fingerprint mismatch' in error, got: %v", err)
	}
}

// TestLoginTLSConfig_AcceptsSha256Prefix: tolerate either bare hex or the
// "sha256:" prefix, since users will copy-paste either form.
func TestLoginTLSConfig_AcceptsSha256Prefix(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	prev := PinnedFingerprint
	defer func() { PinnedFingerprint = prev }()
	PinnedFingerprint = "sha256:" + leafFingerprintHex(srv, t)

	client := http.Client{Transport: &http.Transport{TLSClientConfig: loginTLSConfig()}}
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("expected success with sha256: prefix, got %v", err)
	}
	resp.Body.Close()
}

// TestLoginTLSConfig_NoPinIsLegacyBehaviour: empty PinnedFingerprint means
// fall back to the legacy InsecureSkipVerify path.
func TestLoginTLSConfig_NoPinIsLegacyBehaviour(t *testing.T) {
	prev := PinnedFingerprint
	defer func() { PinnedFingerprint = prev }()
	PinnedFingerprint = ""

	cfg := loginTLSConfig()
	if !cfg.InsecureSkipVerify {
		t.Errorf("expected InsecureSkipVerify=true when no pin set")
	}
	if cfg.VerifyPeerCertificate != nil {
		t.Errorf("expected VerifyPeerCertificate=nil when no pin set")
	}
}

// We import tls only to keep the package import graph aligned with the
// production code; the symbol use below ensures the import isn't dropped.
var _ = tls.VersionTLS12
