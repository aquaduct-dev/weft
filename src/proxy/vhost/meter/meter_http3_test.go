package meter_test

// Coverage for the HTTP/3 metering path (MeteredHTTPHandler.ServeHTTPMetered):
// a deterministic unit test of the byte accounting, plus a real QUIC round-trip
// proving h3 is served and metered end to end. Standard testing (not Ginkgo) so
// it runs under `go test`. Reuses selfSignedCert from meter_http2_test.go.

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aquaduct-dev/weft/src/proxy/vhost/meter"
	"github.com/quic-go/quic-go/http3"
)

func TestServeHTTPMetered_CountsRequestAndResponse(t *testing.T) {
	respBody := strings.Repeat("Z", 5000)
	mh := meter.MakeMeteredHTTPHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, respBody)
	}))

	reqBody := strings.Repeat("q", 1000)
	r := httptest.NewRequest(http.MethodPost, "https://example.test/some/path?x=1", strings.NewReader(reqBody))
	r.Header.Set("User-Agent", "h3-meter-test")
	rr := httptest.NewRecorder()

	mh.ServeHTTPMetered(rr, r)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if rr.Body.String() != respBody {
		t.Fatalf("response body mismatch")
	}
	// Rx must include at least the request body plus some header bytes.
	if rx := mh.BytesRx(); rx <= uint64(len(reqBody)) {
		t.Errorf("BytesRx = %d, want > %d (body + headers)", rx, len(reqBody))
	}
	// Tx must include at least the response body plus some header bytes.
	if tx := mh.BytesTx(); tx <= uint64(len(respBody)) {
		t.Errorf("BytesTx = %d, want > %d (body + headers)", tx, len(respBody))
	}
}

// TestServeHTTPMetered_FlushPropagates checks that a streaming handler can
// flush through the counting writer to the underlying writer, and that
// flushing between chunks does not change the byte accounting.
func TestServeHTTPMetered_FlushPropagates(t *testing.T) {
	chunk := strings.Repeat("s", 700)
	run := func(flush bool) (*httptest.ResponseRecorder, uint64) {
		mh := meter.MakeMeteredHTTPHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			for i := 0; i < 3; i++ {
				_, _ = io.WriteString(w, chunk)
				if flush {
					f, ok := w.(http.Flusher)
					if !ok {
						t.Fatalf("metered writer does not implement http.Flusher")
					}
					f.Flush()
				}
			}
		}))
		rr := httptest.NewRecorder()
		mh.ServeHTTPMetered(rr, httptest.NewRequest(http.MethodGet, "https://example.test/stream", nil))
		t.Logf("flush=%v flushed=%v body=%d BytesTx=%d", flush, rr.Flushed, rr.Body.Len(), mh.BytesTx())
		return rr, mh.BytesTx()
	}

	flushed, flushedTx := run(true)
	plain, plainTx := run(false)

	if !flushed.Flushed {
		t.Fatalf("Flush did not reach the underlying ResponseWriter")
	}
	if plain.Flushed {
		t.Fatalf("recorder reports a flush although the handler never flushed")
	}
	if flushed.Body.String() != strings.Repeat(chunk, 3) {
		t.Fatalf("streamed body mismatch: got %d bytes", flushed.Body.Len())
	}
	if flushedTx != plainTx {
		t.Errorf("BytesTx with flushes = %d, without = %d; flushing must not change accounting", flushedTx, plainTx)
	}
	if flushedTx <= uint64(3*len(chunk)) {
		t.Errorf("BytesTx = %d, want > %d (body + headers)", flushedTx, 3*len(chunk))
	}
}

func TestHTTP3_RoundTripAndMeters(t *testing.T) {
	respBody := strings.Repeat("Y", 4096)
	mh := meter.MakeMeteredHTTPHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		_, _ = io.WriteString(w, respBody)
	}))

	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	port := udp.LocalAddr().(*net.UDPAddr).Port

	h3srv := &http3.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mh.ServeHTTPMetered(w, r)
		}),
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{selfSignedCert(t)}},
	}
	go func() { _ = h3srv.Serve(udp) }()
	defer h3srv.Close()

	tr := &http3.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	defer tr.Close()
	client := &http.Client{Transport: tr, Timeout: 8 * time.Second}

	// The QUIC listener may need a moment to be ready.
	var resp *http.Response
	deadline := time.Now().Add(6 * time.Second)
	for {
		resp, err = client.Get(fmt.Sprintf("https://127.0.0.1:%d/", port))
		if err == nil || time.Now().After(deadline) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("h3 GET: %v", err)
	}
	defer resp.Body.Close()

	if resp.ProtoMajor != 3 {
		t.Fatalf("expected HTTP/3, got %s", resp.Proto)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(body) != respBody {
		t.Errorf("response body mismatch over h3")
	}
	if total := mh.BytesTotal(); total == 0 {
		t.Errorf("expected h3 metering to count bytes, got 0")
	}
}
