package meter

import (
	"io"
	"net/http"
)

// ServeHTTPMetered serves r on the wrapped handler while metering at the
// application layer: request line + headers + body counted as Rx, and response
// status line + headers + body counted as Tx. It exists for transports that
// have no per-connection countingConn to hook — HTTP/3 over QUIC, where there is
// no net.Conn per request. Compared with the conn-level metering used for
// HTTP/1.1 and HTTP/2 it undercounts only by transport framing overhead
// (QUIC/TLS); header sizes are counted uncompressed while HTTP/3 compresses them
// with QPACK, which partly offsets that. Counts are added straight to the
// completed totals (atomic), so they compose safely with the conn-level path.
func (h *MeteredHTTPHandler) ServeHTTPMetered(w http.ResponseWriter, r *http.Request) {
	rx := requestHeaderBytes(r)
	var body *countingReadCloser
	if r.Body != nil {
		body = &countingReadCloser{rc: r.Body}
		r.Body = body
	}
	cw := &countingResponseWriter{ResponseWriter: w}

	h.handler.ServeHTTP(cw, r)

	if body != nil {
		rx += body.n
	}
	h.completedBytesRx.Add(rx)
	h.completedBytesTx.Add(cw.txBytes())
}

// countingReadCloser counts bytes read from the wrapped request body.
type countingReadCloser struct {
	rc io.ReadCloser
	n  uint64
}

func (c *countingReadCloser) Read(p []byte) (int, error) {
	n, err := c.rc.Read(p)
	c.n += uint64(n)
	return n, err
}

func (c *countingReadCloser) Close() error { return c.rc.Close() }

// countingResponseWriter counts response status-line + header + body bytes.
type countingResponseWriter struct {
	http.ResponseWriter
	wroteHeader bool
	headerBytes uint64
	bodyBytes   uint64
}

func (w *countingResponseWriter) WriteHeader(code int) {
	if !w.wroteHeader {
		w.wroteHeader = true
		w.headerBytes = responseHeaderBytes(code, w.ResponseWriter.Header())
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *countingResponseWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	n, err := w.ResponseWriter.Write(b)
	w.bodyBytes += uint64(n)
	return n, err
}

// Flush supports streaming handlers.
func (w *countingResponseWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *countingResponseWriter) txBytes() uint64 {
	if !w.wroteHeader {
		// Handler returned without writing; net/http still emits a 200 + headers.
		w.headerBytes = responseHeaderBytes(http.StatusOK, w.ResponseWriter.Header())
	}
	return w.headerBytes + w.bodyBytes
}

// requestHeaderBytes approximates the on-the-wire size of the request line and
// headers (HTTP/1-equivalent framing; QPACK makes the real h3 bytes smaller).
func requestHeaderBytes(r *http.Request) uint64 {
	uri := r.RequestURI
	if uri == "" && r.URL != nil {
		uri = r.URL.RequestURI()
	}
	// METHOD SP URI SP PROTO CRLF
	n := len(r.Method) + 1 + len(uri) + 1 + len(r.Proto) + 2
	// Host travels as :authority over h2/h3, not in r.Header — count it once.
	n += len("Host: ") + len(r.Host) + 2
	for k, vs := range r.Header {
		for _, v := range vs {
			n += len(k) + len(": ") + len(v) + 2
		}
	}
	n += 2 // blank line terminating the header block
	return uint64(n)
}

// responseHeaderBytes approximates the on-the-wire size of the response status
// line and headers.
func responseHeaderBytes(code int, h http.Header) uint64 {
	// "HTTP/1.1 " + 3-digit code + SP + reason + CRLF
	n := len("HTTP/1.1 ") + 3 + 1 + len(http.StatusText(code)) + 2
	for k, vs := range h {
		for _, v := range vs {
			n += len(k) + len(": ") + len(v) + 2
		}
	}
	n += 2
	return uint64(n)
}
