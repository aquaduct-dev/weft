// certificates_test.go — verifies ListCertificates parses cached certs and
// skips ACME account/challenge artifacts.
package vhost

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeSelfSignedCert writes a PEM cert (autocert-style: key first, then the
// CERTIFICATE block) named after host into dir, and returns its NotAfter.
func writeSelfSignedCert(t *testing.T, dir, host, cn string) time.Time {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	notAfter := time.Now().Add(48 * time.Hour).UTC().Truncate(time.Second)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		DNSNames:     []string{host},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("createcert: %v", err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(key)
	var buf []byte
	buf = append(buf, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})...)
	buf = append(buf, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	if err := os.WriteFile(filepath.Join(dir, host), buf, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return notAfter
}

func TestListCertificates(t *testing.T) {
	dir := t.TempDir()
	wantExpiry := writeSelfSignedCert(t, dir, "example.com", "example.com")
	writeSelfSignedCert(t, dir, "api.example.com", "api.example.com")
	// Artifacts that must be skipped (not certificates).
	_ = os.WriteFile(filepath.Join(dir, "acme_account+key"), []byte("not a cert"), 0o600)
	_ = os.WriteFile(filepath.Join(dir, "example.com+token"), []byte("challenge"), 0o600)

	m := NewVHostProxyManager()
	m.SetCertsCachePath(dir)

	certs, err := m.ListCertificates()
	if err != nil {
		t.Fatalf("ListCertificates: %v", err)
	}
	if len(certs) != 2 {
		t.Fatalf("expected 2 certs (account key + token skipped), got %d: %+v", len(certs), certs)
	}
	// Sorted by host: api.example.com then example.com.
	if certs[0].Host != "api.example.com" || certs[1].Host != "example.com" {
		t.Fatalf("unexpected order/hosts: %q, %q", certs[0].Host, certs[1].Host)
	}
	c := certs[1]
	// Self-signed, so issuer CN == subject CN.
	if c.Subject != "example.com" || c.Issuer != "example.com" {
		t.Errorf("subject/issuer: %q / %q", c.Subject, c.Issuer)
	}
	if !c.NotAfter.Equal(wantExpiry) {
		t.Errorf("expiry: got %v want %v", c.NotAfter, wantExpiry)
	}
	if len(c.DNSNames) != 1 || c.DNSNames[0] != "example.com" {
		t.Errorf("dns names: %v", c.DNSNames)
	}
}

func TestListCertificatesMissingDir(t *testing.T) {
	m := NewVHostProxyManager()
	m.SetCertsCachePath(filepath.Join(t.TempDir(), "does-not-exist"))
	certs, err := m.ListCertificates()
	if err != nil {
		t.Fatalf("expected no error for missing dir, got %v", err)
	}
	if len(certs) != 0 {
		t.Fatalf("expected empty, got %d", len(certs))
	}
}
