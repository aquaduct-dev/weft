package vhost

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"time"

	"github.com/aquaduct-dev/weft/src/honeypot"
	"github.com/aquaduct-dev/weft/src/proxy/vhost/meter"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

func ctx2s() context.Context {
	ctx, _ := context.WithTimeout(context.Background(), 2*time.Second)
	return ctx
}

// Behaviour: when a honeypot Emitter is attached to a VHostProxyManager,
// every unmatched-host HTTP request that lands on the default 404 handler
// produces one POST to the configured ingest URL — exploit-shape paths
// classify as exploit_probe; everything else as port_scan.
var _ = ginkgo.Describe("VHostProxy honeypot emit", func() {
	var (
		mu       sync.Mutex
		received []honeypot.Event
		ts       *httptest.Server
	)

	ginkgo.BeforeEach(func() {
		mu.Lock()
		received = nil
		mu.Unlock()
		ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			var doc struct {
				Events []honeypot.Event `json:"events"`
			}
			_ = json.Unmarshal(body, &doc)
			mu.Lock()
			received = append(received, doc.Events...)
			mu.Unlock()
			w.WriteHeader(http.StatusAccepted)
		}))
	})

	ginkgo.AfterEach(func() {
		ts.Close()
	})

	ginkgo.It("emits an exploit_probe event for /.env on an unmatched host", func() {
		manager := NewVHostProxyManager()
		em := honeypot.NewEmitter(ts.URL, "test-secret", "host-under-test")
		manager.SetHoneypotEmitter(em)
		defer em.Shutdown(ctx2s())

		vp := NewVHostProxy(VHostKey{Port: 80}, manager)

		req := httptest.NewRequest("GET", "http://unknown/.env", nil)
		req.Host = "unknown"
		req.RemoteAddr = "203.0.113.7:51234"
		req.Header.Set("User-Agent", "zgrab2 (test)")
		rawRec := httptest.NewRecorder()
		rec := meter.MeteredResponseWriter{ResponseWriter: rawRec}
		vp.ServeHTTP(&rec, meter.NewMeteredRequestForTest(req))

		gomega.Expect(rawRec.Result().StatusCode).To(gomega.Equal(http.StatusNotFound))

		// Emitter is async — drain the queue before asserting.
		gomega.Eventually(func() []honeypot.Event {
			mu.Lock()
			defer mu.Unlock()
			out := make([]honeypot.Event, len(received))
			copy(out, received)
			return out
		}).Should(gomega.HaveLen(1))

		mu.Lock()
		ev := received[0]
		mu.Unlock()
		gomega.Expect(ev.SrcIP).To(gomega.Equal("203.0.113.7"))
		gomega.Expect(ev.SrcPort).To(gomega.Equal(51234))
		gomega.Expect(ev.DstPort).To(gomega.Equal(80))
		gomega.Expect(string(ev.Type)).To(gomega.Equal("exploit_probe"))
		gomega.Expect(ev.Detail["path"]).To(gomega.Equal("/.env"))
		gomega.Expect(ev.Detail["host"]).To(gomega.Equal("unknown"))
		gomega.Expect(ev.Detail["user_agent"]).To(gomega.Equal("zgrab2 (test)"))
	})

	ginkgo.It("emits a port_scan event for a bare GET / on an unmatched host", func() {
		manager := NewVHostProxyManager()
		em := honeypot.NewEmitter(ts.URL, "", "")
		manager.SetHoneypotEmitter(em)
		defer em.Shutdown(ctx2s())

		vp := NewVHostProxy(VHostKey{Port: 8080}, manager)

		req := httptest.NewRequest("GET", "http://nowhere/", nil)
		req.Host = "nowhere"
		req.RemoteAddr = "198.51.100.5:42022"
		rawRec := httptest.NewRecorder()
		rec := meter.MeteredResponseWriter{ResponseWriter: rawRec}
		vp.ServeHTTP(&rec, meter.NewMeteredRequestForTest(req))

		gomega.Eventually(func() int {
			mu.Lock()
			defer mu.Unlock()
			return len(received)
		}).Should(gomega.Equal(1))

		mu.Lock()
		ev := received[0]
		mu.Unlock()
		gomega.Expect(string(ev.Type)).To(gomega.Equal("port_scan"))
		gomega.Expect(ev.DstPort).To(gomega.Equal(8080))
	})

	ginkgo.It("does not emit when no emitter is attached", func() {
		manager := NewVHostProxyManager()
		vp := NewVHostProxy(VHostKey{Port: 80}, manager)

		req := httptest.NewRequest("GET", "http://unknown/.env", nil)
		req.Host = "unknown"
		req.RemoteAddr = "203.0.113.7:51234"
		rawRec := httptest.NewRecorder()
		rec := meter.MeteredResponseWriter{ResponseWriter: rawRec}
		vp.ServeHTTP(&rec, meter.NewMeteredRequestForTest(req))

		// Receiver should never get a hit; with the suite's default poll
		// timeout that's a quick negative confirmation.
		gomega.Consistently(func() int {
			mu.Lock()
			defer mu.Unlock()
			return len(received)
		}).Should(gomega.Equal(0))
	})
})
