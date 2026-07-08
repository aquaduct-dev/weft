// Package meter provides a simple HTTP server that meters requests.
package meter

import (
"bufio"
"context"
"crypto/tls"
"fmt"
"net"
"net/http"
"sync"
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

// MeteredHTTPHandler wraps an http.Handler and tracks bytes transmitted/received.
// It tracks both completed requests (via atomic counters) and in-flight requests
// (via activeConns map) to provide accurate real-time byte counts.
type MeteredHTTPHandler struct {
	handler http.Handler
	// completedBytesTx/Rx track bytes from requests that have fully completed.
	completedBytesTx atomic.Uint64
	completedBytesRx atomic.Uint64
	// activeConns tracks countingConn and MeteredResponseWriter for in-flight requests.
	// This allows BytesTx/Rx to include bytes that haven't been finalized yet.
activeConns sync.Map // map[*countingConn]*MeteredResponseWriter
}

// BytesTx returns the total bytes transmitted, including in-flight requests.
func (h *MeteredHTTPHandler) BytesTx() uint64 {
total := h.completedBytesTx.Load()
h.activeConns.Range(func(key, value interface{}) bool {
if cc, ok := key.(*countingConn); ok {
total += cc.bytesTx.Load()
}
if w, ok := value.(*MeteredResponseWriter); ok && w != nil {
total += w.bytesWritten
}
return true
})
return total
}

// BytesRx returns the total bytes received, including in-flight requests.
func (h *MeteredHTTPHandler) BytesRx() uint64 {
total := h.completedBytesRx.Load()
h.activeConns.Range(func(key, value interface{}) bool {
if cc, ok := key.(*countingConn); ok {
total += cc.bytesRx.Load()
}
return true
})
return total
}

func (h *MeteredHTTPHandler) BytesTotal() uint64 {
return h.BytesRx() + h.BytesTx()
}

func (h *MeteredHTTPHandler) ServeHTTP(w *MeteredResponseWriter, r *MeteredRequest) {
// Track the active connection and response writer
h.activeConns.Store(r.countingConn, w)
defer func() {
// Remove from active connections
h.activeConns.Delete(r.countingConn)
// Add final counts to completed totals
bytesRx := r.countingConn.bytesRx.Load()
bytesTx := r.countingConn.bytesTx.Load()
r.countingConn.bytesRx.Store(0)
r.countingConn.bytesTx.Store(0)
h.completedBytesTx.Add(w.BytesWritten() + bytesTx)
h.completedBytesRx.Add(bytesRx)
}()

h.handler.ServeHTTP(w, r.Request)
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
// Recover the per-connection byte counter. On the plaintext-counting
// path (Serve) c is the *countingConn directly; on the HTTP/2 path
// (ServeTLSCounted) the counter sits beneath TLS, so unwrap the
// *tls.Conn to reach it.
if cc := asCountingConn(c); cc != nil {
return context.WithValue(ctx, bytesReadKey, cc)
}
return ctx
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

cc, _ := r.Context().Value(bytesReadKey).(*countingConn)
if cc == nil {
// No per-connection counter on the context (unexpected listener
// wrapping). Degrade metering to zero for this request rather than
// panicking the edge handler.
cc = &countingConn{bytesRx: &atomic.Uint64{}, bytesTx: &atomic.Uint64{}}
}
meteredRequest := &MeteredRequest{
Request:      r,
countingConn: cc,
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

// asCountingConn extracts the *countingConn from c, unwrapping a *tls.Conn when
// the counter sits beneath TLS termination (the ServeTLSCounted / HTTP/2 path).
// Returns nil if no counter is present. The loop is bounded to avoid spinning
// on a pathological wrapping chain.
func asCountingConn(c net.Conn) *countingConn {
for i := 0; i < 4 && c != nil; i++ {
switch v := c.(type) {
case *countingConn:
return v
case *tls.Conn:
c = v.NetConn()
default:
return nil
}
}
return nil
}

// ServeTLSCounted serves HTTPS on rawListener with HTTP/2 enabled (in addition
// to HTTP/1.1). Unlike Serve, the byte counter is wrapped BENEATH TLS
// termination so net/http sees the underlying *tls.Conn and can negotiate h2
// via ALPN. The counter therefore measures on-the-wire (encrypted) bytes rather
// than plaintext — a sub-1% TLS-record-overhead difference, partly offset by h2
// reusing one connection instead of several. ConnContext recovers the counter
// from the *tls.Conn via asCountingConn. tlsConfig must advertise "h2" in
// NextProtos.
func (srv *MeteredServer) ServeTLSCounted(rawListener net.Listener, tlsConfig *tls.Config) error {
// Enable HTTP/2 using net/http's built-in support (Go 1.24+ Protocols),
// so no golang.org/x/net/http2 dependency is required. HTTP/1.1 stays on
// as the fallback for clients (and WebSocket proxying) that don't use h2.
if srv.Server.Protocols == nil {
p := new(http.Protocols)
p.SetHTTP1(true)
p.SetHTTP2(true)
srv.Server.Protocols = p
}
counted := &countingListener{Listener: rawListener}
tlsListener := tls.NewListener(counted, tlsConfig)
return srv.Server.Serve(tlsListener)
}
