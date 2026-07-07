package meter_test

// End-to-end coverage for MeteredServer.ServeTLSCounted (the HTTP/2 serve
// path). Uses the standard testing package (not Ginkgo) so it actually runs
// under `go test`, and validates the three things that must not regress when
// h2 is enabled: h2 is negotiated and served, HTTP/1.1 still works as a
// fallback, the ACME TLS-ALPN-01 protocol (acme-tls/1) is still selectable, and
// byte metering still counts.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aquaduct-dev/weft/src/proxy/vhost/meter"
)

// selfSignedCert builds an in-memory cert/key valid for localhost/127.0.0.1.
func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestServeTLSCounted_NegotiatesHTTP2_KeepsH1_ACME_AndMeters(t *testing.T) {
	handler := meter.MakeMeteredHTTPHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		_, _ = io.WriteString(w, "served "+r.Proto)
	}))
	srv := meter.NewMeteredServer("", handler)
	defer srv.Close()

	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := raw.Addr().String()

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{selfSignedCert(t)},
		// Mirror the vhost h2 ALPN advertisement.
		NextProtos: []string{"h2", "http/1.1", "acme-tls/1"},
	}
	go func() { _ = srv.ServeTLSCounted(raw, tlsCfg) }()

	waitReady(t, addr)

	// --- HTTP/2: a client that offers h2 must be served over h2. ---
	h2resp, h2body := doGet(t, addr, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2", "http/1.1"}}, true)
	if h2resp.ProtoMajor != 2 {
		t.Fatalf("expected HTTP/2, got %s", h2resp.Proto)
	}
	if !strings.Contains(h2body, "HTTP/2.0") {
		t.Errorf("handler did not see an h2 request; body=%q", h2body)
	}

	// --- HTTP/1.1: a client that only offers http/1.1 still works. ---
	h1resp, h1body := doGet(t, addr, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}}, false)
	if h1resp.ProtoMajor != 1 {
		t.Fatalf("expected HTTP/1.1, got %s", h1resp.Proto)
	}
	if !strings.Contains(h1body, "HTTP/1.1") {
		t.Errorf("handler did not see an h1 request; body=%q", h1body)
	}

	// --- ACME TLS-ALPN-01: acme-tls/1 must still be selectable at handshake. ---
	c, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"acme-tls/1"}})
	if err != nil {
		t.Fatalf("acme-tls/1 dial: %v", err)
	}
	if got := c.ConnectionState().NegotiatedProtocol; got != "acme-tls/1" {
		t.Errorf("acme ALPN negotiated %q, want acme-tls/1", got)
	}
	_ = c.Close()

	// --- Metering: bytes were counted across the requests above. ---
	if total := handler.BytesTotal(); total == 0 {
		t.Errorf("expected metered bytes > 0, got 0")
	}
}

// doGet issues a GET over TLS with the given client TLS config. forceH2 enables
// the transport's HTTP/2 attempt so an h2-capable server is used over h2.
func doGet(t *testing.T, addr string, cfg *tls.Config, forceH2 bool) (*http.Response, string) {
	t.Helper()
	tr := &http.Transport{TLSClientConfig: cfg, ForceAttemptHTTP2: forceH2}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	resp, err := client.Get("https://" + addr + "/")
	if err != nil {
		t.Fatalf("GET (forceH2=%v): %v", forceH2, err)
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp, string(body)
}

// waitReady blocks until the TLS listener accepts a handshake or times out.
func waitReady(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		c, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}})
		if err == nil {
			_ = c.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("server at %s not ready", addr)
}
