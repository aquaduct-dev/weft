// Package meter provides a simple HTTP server that meters requests.
package meter

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"sync/atomic"
)

var (
	bytesReadKey = "countingconn"
)

// MeteredHandler is a http.Handler that can handle MeteredRequest.
type MeteredHandler interface {
	ServeHTTP(*MeteredResponseWriter, *MeteredRequest)
}

// MeteredRequest is a http.Request that has been metered.
type MeteredRequest struct {
	*http.Request
	*countingConn
}

// TotalSize returns the size of the request in bytes.
func (r *MeteredRequest) TotalSize() uint64 {
	return r.countingConn.bytesRx.Load()
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

func (w *MeteredResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := w.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, fmt.Errorf("http.Hijacker interface is not supported by underlying ResponseWriter")
}

func (w *MeteredResponseWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
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
	handler http.Handler
	bytesTx atomic.Uint64
	bytesRx atomic.Uint64
}

func (h *MeteredHTTPHandler) BytesTx() uint64 {
	return h.bytesTx.Load()
}

func (h *MeteredHTTPHandler) BytesRx() uint64 {
	return h.bytesRx.Load()
}

func (h *MeteredHTTPHandler) BytesTotal() uint64 {
	return h.BytesRx() + h.BytesTx()
}

func (h *MeteredHTTPHandler) ServeHTTP(w *MeteredResponseWriter, r *MeteredRequest) {
	h.handler.ServeHTTP(w, r.Request)
	bytesRx := r.countingConn.bytesRx.Load()
	//bytesTx := r.countingConn.bytesTx.Load()
	r.countingConn.bytesRx.Store(0)
	r.countingConn.bytesTx.Store(0)
	h.bytesTx.Add(w.BytesWritten())
	h.bytesRx.Add(bytesRx)
}

func MakeMeteredHTTPHandler(handler http.Handler) *MeteredHTTPHandler {
	return &MeteredHTTPHandler{handler: handler}
}

// NewMeteredRequestForTest creates a new MeteredRequest for testing purposes.
func NewMeteredRequestForTest(r *http.Request) *MeteredRequest {
	return &MeteredRequest{
		Request: r,
		countingConn: &countingConn{
			Conn:    nil,
			bytesRx: &atomic.Uint64{},
			bytesTx: &atomic.Uint64{},
		},
	}
}

// MeteredServer is an http.Server that meters the requests it serves.
type MeteredServer struct {
	*http.Server
	MeteredHandler MeteredHandler
}

// NewMeteredServer creates a new MeteredServer.
func NewMeteredServer(addr string, handler MeteredHandler) *MeteredServer {
	srv := &MeteredServer{
		Server: &http.Server{
			Addr: addr,
			ConnContext: func(ctx context.Context, c net.Conn) context.Context {
				return context.WithValue(ctx, bytesReadKey, c.(*countingConn))
			},
		},
		MeteredHandler: handler,
	}
	srv.Server.Handler = srv.wrapHandler()
	return srv
}

func (srv *MeteredServer) wrapHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if srv.MeteredHandler == nil {
			panic("meter: MeteredServer.MeteredHandler is nil")
		}

		meteredRequest := &MeteredRequest{
			Request:      r,
			countingConn: r.Context().Value(bytesReadKey).(*countingConn),
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
	return &countingConn{
		Conn:    conn,
		bytesRx: &atomic.Uint64{},
		bytesTx: &atomic.Uint64{},
	}, nil
}

// countingConn is a net.Conn that counts bytes read.
type countingConn struct {
	net.Conn
	bytesRx *atomic.Uint64
	bytesTx *atomic.Uint64
}

// Read reads data from the connection.
func (c countingConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if err == nil {
		c.bytesRx.Add(uint64(n))
	}
	return n, err
}

func (c countingConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if err == nil {
		c.bytesTx.Add(uint64(n))
	}
	return n, err
}
