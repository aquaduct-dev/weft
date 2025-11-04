package server

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"testing"
	"time"
)

// Tests for vhost.go: GetTLSHandler, GetTLSConfig and ServeHTTP routing.
// Note: AddHost requires a non-nil UserspaceDevice in production code. For unit tests
// we bypass AddHost by inserting a reverse proxy directly into the VHostProxy.hosts map.

func TestVHost_AddHostAndServeHTTP(t *testing.T) {
	// upstream server that returns a body so reverse proxy can forward it
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("upstream-ok"))
	}))
	defer up.Close()

	u, err := url.Parse(up.URL)
	if err != nil {
		t.Fatalf("parse upstream url: %v", err)
	}

	manager := &VHostProxyManager{proxies: make(map[int]*VHostProxy)}
	vp := NewVHostProxy(0, nil, manager)

	// Add a reverse proxy directly into the hosts map (bypass AddHost which requires a device).
	vp.mu.Lock()
	vp.hosts["example.test"] = httputil.NewSingleHostReverseProxy(u)
	vp.mu.Unlock()

	// Craft a request that targets the vhost by Host header
	req := httptest.NewRequest("GET", "http://example.test/", nil)
	req.Host = "example.test"
	rec := httptest.NewRecorder()
	vp.ServeHTTP(rec, req)

	res := rec.Result()
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK; got %d", res.StatusCode)
	}
	b, _ := io.ReadAll(res.Body)
	if string(b) != "upstream-ok" {
		t.Fatalf("unexpected body: %q", string(b))
	}
}

func TestVHost_AddHostWithTLSAndRetrieval(t *testing.T) {
	// upstream handler that will be proxied to
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("secure-upstream"))
	}))
	defer up.Close()
	u, err := url.Parse(up.URL)
	if err != nil {
		t.Fatalf("parse upstream url: %v", err)
	}

	manager := &VHostProxyManager{proxies: make(map[int]*VHostProxy)}
	vp := NewVHostProxy(0, nil, manager)

	// generate cert/key for the host
	certPEM, keyPEM, err := GenerateCert("secure.test")
	if err != nil {
		t.Fatalf("GenerateCert failed: %v", err)
	}

	closer, err := vp.AddHostWithTLS("secure.test", u, string(certPEM), string(keyPEM))
	if err != nil {
		t.Fatalf("AddHostWithTLS failed: %v", err)
	}
	defer closer.Close()

	// GetTLSHandler and GetTLSConfig should return non-nil values
	h := vp.GetTLSHandler("secure.test")
	if h == nil {
		t.Fatalf("GetTLSHandler returned nil")
	}
	cfg := vp.GetTLSConfig("secure.test")
	if cfg == nil {
		t.Fatalf("GetTLSConfig returned nil")
	}

	// Start TLS listener using returned config and handler to exercise TLS handler end-to-end.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	tlsLn := tls.NewListener(ln, cfg)
	defer ln.Close()

	go func() {
		_ = http.Serve(tlsLn, h)
	}()

	// create a client that skips cert verification (we use self-signed test certs)
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	client := &http.Client{Transport: tr, Timeout: 3 * time.Second}
	url := fmt.Sprintf("https://%s/", ln.Addr().String())
	req, _ := http.NewRequest("GET", url, nil)
	req.Host = "secure.test"
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("https request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK; got %d", resp.StatusCode)
	}
	b, _ := io.ReadAll(resp.Body)
	if string(b) != "secure-upstream" {
		t.Fatalf("unexpected body: %q", string(b))
	}
}

func TestVHost_UnknownHostReturns404(t *testing.T) {
	manager := &VHostProxyManager{proxies: make(map[int]*VHostProxy)}
	vp := NewVHostProxy(0, nil, manager)

	req := httptest.NewRequest("GET", "http://unknown/", nil)
	req.Host = "unknown"
	rec := httptest.NewRecorder()
	vp.ServeHTTP(rec, req)

	res := rec.Result()
	defer res.Body.Close()
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 Not Found; got %d", res.StatusCode)
	}
}