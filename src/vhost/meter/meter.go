// Package meter provides a simple HTTP server that meters requests.
package meter

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"sync"
)

// MeteredHandler is a http.Handler that can handle MeteredRequest.
type MeteredHandler interface {
	ServeHTTP(MeteredResponseWriter, *MeteredRequest)
}

// MeteredRequest is a http.Request that has been metered.
type MeteredRequest struct {
	*http.Request
	size uint64
}

// TotalSize returns the size of the request in bytes.
func (r *MeteredRequest) TotalSize() uint64 {
	return r.size
}

// MeteredResponseWriter is a wrapper around http.ResponseWriter that counts bytes written.
type MeteredResponseWriter struct {
	http.ResponseWriter
	bytesWritten uint64
}

func (w *MeteredResponseWriter) Write(b []byte) (int, error) {
	n, err := w.ResponseWriter.Write(b)
	w.bytesWritten += uint64(n)
	return n, err
}

func (w *MeteredResponseWriter) BytesWritten() uint64 {
	return w.bytesWritten
}

func (w *MeteredResponseWriter) Header() http.Header {
	return w.ResponseWriter.Header()
}

func (w *MeteredResponseWriter) WriteHeader(statusCode int) {
	w.ResponseWriter.WriteHeader(statusCode)
}

// MeteredHandlerFunc is an adapter to allow the use of ordinary functions as MeteredHandlers.
type MeteredHandlerFunc func(MeteredResponseWriter, *MeteredRequest)

// ServeHTTP calls f(w, r).
func (f MeteredHandlerFunc) ServeHTTP(w MeteredResponseWriter, r *MeteredRequest) {
	f(w, r)
}

func MeteredHTTPHandlerFunc(f func(http.ResponseWriter, *http.Request)) MeteredHTTPHandler {
	return MakeMeteredHTTPHandler(http.HandlerFunc(f))
}

type MeteredHTTPHandler struct {
	MeteredHandler
	handler    http.Handler
	bytesTx    uint64
	bytesRx    uint64
	bytesTotal uint64
	mu         sync.Mutex
}

func (h *MeteredHTTPHandler) BytesTx() uint64 {
	return h.bytesTx
}

func (h *MeteredHTTPHandler) BytesRx() uint64 {
	return h.bytesRx
}

func (h *MeteredHTTPHandler) BytesTotal() uint64 {
	return h.bytesTotal
}

func (h MeteredHTTPHandler) ServeHTTP(w MeteredResponseWriter, r *MeteredRequest) {
	h.handler.ServeHTTP(&w, r.Request)
	h.mu.Lock()
	defer h.mu.Unlock()
	h.bytesTx += w.BytesWritten()
	h.bytesRx += r.TotalSize()
	h.bytesTotal += w.BytesWritten() + r.TotalSize()
}

func MakeMeteredHTTPHandler(handler http.Handler) MeteredHTTPHandler {
	return MeteredHTTPHandler{handler: handler}
}

// NewMeteredRequestForTest creates a new MeteredRequest for testing purposes.
func NewMeteredRequestForTest(r *http.Request, size uint64) *MeteredRequest {
	return &MeteredRequest{
		Request: r,
		size:    size,
	}
}

// MeteredServer is an http.Server that meters the requests it serves.
type MeteredServer struct {
	*http.Server
	MeteredHandler MeteredHandler
}

type contextKey string

const requestSizeKey = contextKey("requestSize")

// NewMeteredServer creates a new MeteredServer.
func NewMeteredServer(addr string, handler MeteredHandler) *MeteredServer {
	srv := &MeteredServer{
		Server: &http.Server{
			Addr: addr,
		},
		MeteredHandler: handler,
	}
	srv.Server.Handler = srv.wrapHandler()
	srv.Server.ConnContext = func(ctx context.Context, c net.Conn) context.Context {
		if mc, ok := c.(*meteredConn); ok {
			return context.WithValue(ctx, requestSizeKey, mc.size)
		}
		return ctx
	}
	return srv
}

func (srv *MeteredServer) wrapHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if srv.MeteredHandler == nil {
			panic("meter: MeteredServer.MeteredHandler is nil")
		}

		size, _ := r.Context().Value(requestSizeKey).(uint64)

		meteredRequest := &MeteredRequest{
			Request: r,
			size:    size,
		}

		// Wrap the response writer to count bytes
		countingWriter := MeteredResponseWriter{ResponseWriter: w}

		srv.MeteredHandler.ServeHTTP(countingWriter, meteredRequest)
	})
}

// Serve serves requests.
func (srv *MeteredServer) Serve(l net.Listener) error {
	ml := &meteredListener{
		Listener: l,
	}
	return srv.Server.Serve(ml)
}

// meteredListener wraps a net.Listener to produce meteredConn.
type meteredListener struct {
	net.Listener
}

// Accept waits for and returns the next connection to the listener.
func (l *meteredListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	tee := io.TeeReader(conn, &buf)
	reader := bufio.NewReader(tee)

	// http.ReadRequest will read the request from the tee reader,
	// which will in turn write the raw request to the buffer.
	req, err := http.ReadRequest(reader)
	if err != nil {
		conn.Close()
		return nil, err
	}

	// Read the body to ensure it's captured by the TeeReader.
	if req.Body != nil {
		io.Copy(io.Discard, req.Body)
		req.Body.Close()
	}

	// The buffer now contains the entire raw request.
	rawRequestBytes := buf.Bytes()
	size := uint64(len(rawRequestBytes))

	// Return a new connection that reads from the buffered raw request.
	return &meteredConn{
		Conn:   conn,
		reader: bytes.NewReader(rawRequestBytes),
		size:   size,
	}, nil
}

// meteredConn is a net.Conn that reads from a pre-buffered request.
type meteredConn struct {
	net.Conn
	reader io.Reader
	size   uint64
}

// Read reads data from the connection.
func (c *meteredConn) Read(b []byte) (int, error) {
	return c.reader.Read(b)
}
