package meter_test

// This file contains a Ginkgo-based rewrite of the original TestMeteredServer.
// It uses Ginkgo v2 and Gomega for assertions and keeps detailed logs
// to aid debugging as required by repository guidelines.

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"time"

    "github.com/aquaduct-dev/weft/src/proxy/vhost/meter"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

type testHandler struct {
	reqChan chan struct {
		req          *meter.MeteredRequest
		bytesWritten uint64
	}
}

func (h *testHandler) ServeHTTP(w meter.MeteredResponseWriter, r *meter.MeteredRequest) {
	// Ensure MeteredRequest is fully populated.
	_, _ = io.ReadAll(r.Body)
	responseBody := "Response from server"
	_, _ = w.Write([]byte(responseBody))

	written := w.BytesWritten()

	// Non-blocking send with timeout to avoid test hanging forever.
	select {
	case h.reqChan <- struct {
		req          *meter.MeteredRequest
		bytesWritten uint64
	}{req: r, bytesWritten: written}:
	case <-time.After(2 * time.Second):
		// Log so failures are visible in test output.
		Fail("timed out sending metered request info from handler")
	}
}

var _ = Describe("MeteredServer", func() {
	It("meters request and response sizes correctly", func() {
		// 1. Setup a MeteredServer with a test handler
		handler := meter.MakeMeteredHTTPHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("Response from server"))
		}))
		server := meter.NewMeteredServer("", handler)

		// 2. Start the server on a random available port
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		Expect(err).ToNot(HaveOccurred(), "failed to listen on a port")
		serverAddr := listener.Addr().String()

		go func() {
			if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
				// Use Ginkgo's Fail to make the error visible in the spec.
				Fail(fmt.Sprintf("server failed: %v", err))
			}
		}()
		defer server.Close()

		// 3. Make a client request
		client := &http.Client{}

		req, err := http.NewRequest("GET", fmt.Sprintf("http://%s/test", serverAddr), nil)
		Expect(err).ToNot(HaveOccurred(), "failed to create request for client.Do")
		req.Header.Set("User-Agent", "meter-test")

		dump, err := httputil.DumpRequestOut(req, true)
		Expect(err).ToNot(HaveOccurred(), "failed to dump request")
		expectedRequestSize := uint64(len(dump))
		GinkgoWriter.Printf("Raw Request (DumpRequestOut):\n%s\n", string(dump))

		resp, err := client.Do(req)
		Expect(err).ToNot(HaveOccurred(), "request failed")
		defer resp.Body.Close()

		Expect(resp.StatusCode).To(Equal(http.StatusOK))

		// Read the response body to ensure it's fully consumed
		responseBodyBytes, err := io.ReadAll(resp.Body)
		Expect(err).ToNot(HaveOccurred(), "failed to read response body")
		expectedResponseBody := "Response from server"
		Expect(string(responseBodyBytes)).To(Equal(expectedResponseBody))

		// 4. Check the metered request size and response size
		// The handler returned by MakeMeteredHTTPHandler exposes BytesRx/BytesTx methods.
		Expect(handler.BytesRx()).To(Equal(expectedRequestSize))
		expectedResponseSize := uint64(len(expectedResponseBody))
		Expect(handler.BytesTx()).To(Equal(expectedResponseSize))
	})

	It("supports http.Hijacker interface", func() {
		// 1. Create a handler that asserts Hijacker support
		hijackHandler := meter.MakeMeteredHTTPHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hijacker, ok := w.(http.Hijacker)
			if !ok {
				http.Error(w, "Hijacker not supported", http.StatusInternalServerError)
				return
			}
			conn, _, err := hijacker.Hijack()
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			defer conn.Close()
			conn.Write([]byte("HTTP/1.1 200 OK\r\n\r\nHijacked!"))
		}))
		server := meter.NewMeteredServer("", hijackHandler)

		// 2. Start server
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		Expect(err).ToNot(HaveOccurred())
		serverAddr := listener.Addr().String()

		go func() {
			if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
				Fail(fmt.Sprintf("server failed: %v", err))
			}
		}()
		defer server.Close()

		// 3. Client request
		conn, err := net.Dial("tcp", serverAddr)
		Expect(err).ToNot(HaveOccurred())
		defer conn.Close()

		fmt.Fprintf(conn, "GET /hijack HTTP/1.1\r\nHost: %s\r\n\r\n", serverAddr)

		// Read response
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		Expect(err).ToNot(HaveOccurred())
		response := string(buf[:n])

		Expect(response).To(ContainSubstring("Hijacked!"))
	})

	It("supports http.Flusher interface", func() {
		// 1. Create a handler that uses Flusher
		flushHandler := meter.MakeMeteredHTTPHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			flusher, ok := w.(http.Flusher)
			if !ok {
				http.Error(w, "Flusher not supported", http.StatusInternalServerError)
				return
			}
			w.Write([]byte("Part1"))
			flusher.Flush()
			time.Sleep(10 * time.Millisecond)
			w.Write([]byte("Part2"))
		}))
		server := meter.NewMeteredServer("", flushHandler)

		// 2. Start server
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		Expect(err).ToNot(HaveOccurred())
		serverAddr := listener.Addr().String()

		go func() {
			server.Serve(listener)
		}()
		defer server.Close()

		// 3. Client request
		resp, err := http.Get(fmt.Sprintf("http://%s/flush", serverAddr))
		Expect(err).ToNot(HaveOccurred())
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		Expect(err).ToNot(HaveOccurred())
		Expect(string(body)).To(Equal("Part1Part2"))
	})
})
