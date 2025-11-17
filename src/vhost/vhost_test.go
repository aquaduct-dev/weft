package vhost

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"

	"aquaduct.dev/weft/src/crypto"
	"aquaduct.dev/weft/src/vhost/meter"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
	"github.com/rs/zerolog/log"
)

// Tests for vhost.go: GetTLSHandler, GetTLSConfig and ServeHTTP routing.
// Note: AddHost requires a non-nil UserspaceDevice in production code. For unit tests
// we bypass AddHost by inserting a reverse proxy directly into the VHostProxy.hosts map.

var _ = ginkgo.Describe("VHostProxy", func() {
	ginkgo.It("forwards requests to added host via ServeHTTP", func() {
		up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("upstream-ok"))
		}))
		defer up.Close()

		u, err := url.Parse(up.URL)
		gomega.Expect(err).ToNot(gomega.HaveOccurred())

		manager := NewVHostProxyManager()
		vp := NewVHostProxy(VHostKey{Port: 0}, manager)
		vp.mu.Lock()
		vp.handlers["example.test"] = meter.MakeMeteredHTTPHandler(httputil.NewSingleHostReverseProxy(u))
		vp.mu.Unlock()

		req := httptest.NewRequest("GET", "http://example.test/", nil)
		rawRec := httptest.NewRecorder()
		rec := meter.MeteredResponseWriter{ResponseWriter: rawRec}
		vp.ServeHTTP(&rec, meter.NewMeteredRequestForTest(req))

		res := rawRec.Result()
		defer res.Body.Close()
		gomega.Expect(res.StatusCode).To(gomega.Equal(http.StatusOK))
		b, _ := io.ReadAll(res.Body)
		gomega.Expect(string(b)).To(gomega.Equal("upstream-ok"))
	})

	ginkgo.It("adds host with TLS and serves over HTTPS", func() {
		up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("secure-upstream\n"))
		}))
		defer up.Close()
		u, err := url.Parse(up.URL)
		log.Debug().Str("url", up.URL).Msg("started debug server")
		gomega.Expect(err).ToNot(gomega.HaveOccurred())

		manager := NewVHostProxyManager()
		vp := manager.Proxy("", 21341)
		certPEM, keyPEM, err := crypto.GenerateCert("secure.test", []string{})
		gomega.Expect(err).ToNot(gomega.HaveOccurred())

		closer, _, err := vp.AddHostWithTLS("secure.test", u, nil, string(certPEM), string(keyPEM))
		gomega.Expect(err).ToNot(gomega.HaveOccurred())
		defer closer.Close()

		h := vp.GetTLSHandler("secure.test")
		gomega.Expect(h).ToNot(gomega.BeNil())
		cfg := vp.GetTLSConfig("secure.test")
		gomega.Expect(cfg).ToNot(gomega.BeNil())

		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			if addr == "secure.test:21341" {
				log.Debug().Str("addr", addr).Msg("intercepting addr")
				addr = "127.0.0.1:21341"
			}
			log.Debug().Str("addr", addr).Msg("intercepted addr")
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		}
		http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		client := &http.Client{Transport: transport}
		urlStr := "https://secure.test:21341"
		req, _ := http.NewRequest("GET", urlStr, nil)
		log.Debug().Str("url", urlStr).Msg("making request")
		resp, err := client.Do(req)
		gomega.Expect(err).ToNot(gomega.HaveOccurred())
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)

		gomega.Expect(resp.StatusCode).To(gomega.Equal(http.StatusOK))
		gomega.Expect(string(b)).To(gomega.Equal("secure-upstream\n"))
	})

	ginkgo.It("returns 404 for unknown host", func() {
		manager := NewVHostProxyManager()
		vp := NewVHostProxy(VHostKey{Port: 0}, manager)

		req := httptest.NewRequest("GET", "http://unknown/", nil)
		req.Host = "unknown"
		rawRec := httptest.NewRecorder()
		rec := meter.MeteredResponseWriter{ResponseWriter: rawRec}
		vp.ServeHTTP(&rec, meter.NewMeteredRequestForTest(req))

		res := rawRec.Result()
		defer res.Body.Close()
		gomega.Expect(res.StatusCode).To(gomega.Equal(http.StatusNotFound))
	})

	ginkgo.It("manages certs cache path", func() {
		manager := NewVHostProxyManager()
		home, err := os.UserHomeDir()
		if err != nil {
			home = os.TempDir()
		}
		expectedDefaultPath := filepath.Join(home, ".certs")
		gomega.Expect(manager.certsCachePath).To(gomega.Equal(expectedDefaultPath))

		newPath := "/tmp/certs"
		manager.SetCertsCachePath(newPath)
		gomega.Expect(manager.certsCachePath).To(gomega.Equal(newPath))
	})

	ginkgo.It("handles ACME challenge when regular vhost exists", func() {
		manager := NewVHostProxyManager()
		acmeTestPort := 18080
		manager.SetACMEPort(acmeTestPort)

		proxy := manager.Proxy("", acmeTestPort)
		proxy.defaultHandler = meter.MakeMeteredHTTPHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "custom not found", http.StatusNotFound)
		}))

		up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("upstream-ok"))
		}))
		defer up.Close()
		u, err := url.Parse(up.URL)
		gomega.Expect(err).ToNot(gomega.HaveOccurred())
		proxy.AddHost("example.test", u, nil)

		go proxy.Start()

		req := httptest.NewRequest("GET", "http://example.test/", nil)
		req.Host = "example.test"
		rawRec := httptest.NewRecorder()
		rec := meter.MeteredResponseWriter{ResponseWriter: rawRec}
		proxy.ServeHTTP(&rec, meter.NewMeteredRequestForTest(req))
		res := rawRec.Result()
		gomega.Expect(res.StatusCode).To(gomega.Equal(http.StatusOK))
		b, _ := io.ReadAll(res.Body)
		gomega.Expect(string(b)).To(gomega.Equal("upstream-ok"))

		manager.AddACMEHost("acme.test", "")

		acmeReq := httptest.NewRequest("GET", "/.well-known/acme-challenge/some-token", nil)
		acmeReq.Host = "acme.test"
		acmeRawRec := httptest.NewRecorder()
		acmeRec := meter.MeteredResponseWriter{ResponseWriter: acmeRawRec}
		proxy.ServeHTTP(&acmeRec, meter.NewMeteredRequestForTest(acmeReq))
		acmeRes := acmeRawRec.Result()
		body, _ := io.ReadAll(acmeRes.Body)
		gomega.Expect(string(body)).ToNot(gomega.Equal("custom not found\n"))
	})
})
