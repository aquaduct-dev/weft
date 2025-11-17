// Package meter provides a simple HTTP server that meters requests.
package meter

import (
	"context"
	"net"
	"net/http"
	"sync"
)

// MeteredHandler is a http.Handler that can handle MeteredRequest.
type MeteredHandler interface {
	ServeHTTP(*MeteredResponseWriter, *MeteredRequest)
}

// MeteredRequest is a http.Request that has been metered.
type MeteredRequest struct {
	*http.Request
	bytesRead *uint64
}

// TotalSize returns the size of the request in bytes.
func (r *MeteredRequest) TotalSize() uint64 {
	if r.bytesRead == nil {
		return 0
	}
	return *r.bytesRead
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

// MeteredHandlerFunc is an adapter to allow the use of ordinary functions as MeteredHandlers.
type MeteredHandlerFunc func(*MeteredResponseWriter, *MeteredRequest)

// ServeHTTP calls f(w, r).
func (f MeteredHandlerFunc) ServeHTTP(w *MeteredResponseWriter, r *MeteredRequest) {
	f(w, r)
}

func MeteredHTTPHandlerFunc(f func(http.ResponseWriter, *http.Request)) MeteredHandler {
	return MakeMeteredHTTPHandler(http.HandlerFunc(f))
}

type MeteredHTTPHandler struct {
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

func (h *MeteredHTTPHandler) ServeHTTP(w *MeteredResponseWriter, r *MeteredRequest) {
	h.handler.ServeHTTP(w, r.Request)
	h.mu.Lock()
	defer h.mu.Unlock()
	h.bytesTx += w.BytesWritten()
	h.bytesRx += r.TotalSize()
	h.bytesTotal += w.BytesWritten() + r.TotalSize()
}

func MakeMeteredHTTPHandler(handler http.Handler) *MeteredHTTPHandler {
	return &MeteredHTTPHandler{handler: handler}
}

// NewMeteredRequestForTest creates a new MeteredRequest for testing purposes.
func NewMeteredRequestForTest(r *http.Request, size uint64) *MeteredRequest {
	s := size
	return &MeteredRequest{
		Request:   r,
		bytesRead: &s,
	}
}

// MeteredServer is an http.Server that meters the requests it serves.
type MeteredServer struct {
	*http.Server
	MeteredHandler MeteredHandler
}

type contextKey string

const bytesReadKey = contextKey("bytesRead")

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
		if mc, ok := c.(*countingConn); ok {
			return context.WithValue(ctx, bytesReadKey, mc.bytesRead)
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

		bytesReadPtr, _ := r.Context().Value(bytesReadKey).(*uint64)

		meteredRequest := &MeteredRequest{
			Request:   r,
			bytesRead: bytesReadPtr,
		}

		// Wrap the response writer to count bytes
		countingWriter := &MeteredResponseWriter{ResponseWriter: w}

		srv.MeteredHandler.ServeHTTP(countingWriter, meteredRequest)
	})
}

// Serve serves requests.
func (srv *MeteredServer) Serve(l net.Listener) error {
	ml := &countingListener{
		Listener: l,
	}
	return srv.Server.Serve(ml)
}

// countingListener wraps a net.Listener to produce countingConn.
type countingListener struct {
	net.Listener
}

// Accept waits for and returns the next connection to the listener.
func (l *countingListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	var bytesRead uint64
	return &countingConn{
		Conn:      conn,
		bytesRead: &bytesRead,
	}, nil
}

// countingConn is a net.Conn that counts bytes read.
type countingConn struct {
	net.Conn
	bytesRead *uint64
}

// Read reads data from the connection.
func (c *countingConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	*c.bytesRead += uint64(n)
	return n, err
}
