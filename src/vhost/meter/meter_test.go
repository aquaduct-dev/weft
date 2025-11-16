package meter_test

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil" // Added for DumpRequestOut
	"testing"
	"time"

	"aquaduct.dev/weft/src/vhost/meter"
)

type testHandler struct {
	reqChan chan struct {
		req          *meter.MeteredRequest
		bytesWritten uint64
	}
}

func (h *testHandler) ServeHTTP(w meter.MeteredResponseWriter, r *meter.MeteredRequest) {
	// To ensure the MeteredRequest is fully populated, we need to read the body.
	_, _ = io.ReadAll(r.Body)
	responseBody := "Response from server"
	w.Write([]byte(responseBody))

	written := w.BytesWritten()

	h.reqChan <- struct {
		req          *meter.MeteredRequest
		bytesWritten uint64
	}{
		req:          r,
		bytesWritten: written,
	}
}

func TestMeteredServer(t *testing.T) {
	// 1. Setup a MeteredServer with a test handler
	handler := &testHandler{
		reqChan: make(chan struct {
			req          *meter.MeteredRequest
			bytesWritten uint64
		}, 1),
	}
	server := meter.NewMeteredServer("", handler)

	// 2. Start the server on a random available port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen on a port: %v", err)
	}
	serverAddr := listener.Addr().String()

	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			t.Errorf("Server failed: %v", err)
		}
	}()
	defer server.Close()

	// 3. Make a client request
	client := &http.Client{}

	// Create a request for the actual client.Do call
	req, err := http.NewRequest("GET", fmt.Sprintf("http://%s/test", serverAddr), nil)
	if err != nil {
		t.Fatalf("Failed to create request for client.Do: %v", err)
	}
	req.Header.Set("User-Agent", "meter-test")

	// Use httputil.DumpRequestOut to get the raw bytes as sent over the wire
	dump, err := httputil.DumpRequestOut(req, true) // true to include body, though GET has no body
	if err != nil {
		t.Fatalf("Failed to dump request: %v", err)
	}
	expectedRequestSize := uint64(len(dump))
	t.Logf("Raw Request (DumpRequestOut):\n%s", string(dump))

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status OK, got %d", resp.StatusCode)
	}

	// Read the response body to ensure it's fully consumed
	responseBodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}
	expectedResponseBody := "Response from server"
	if string(responseBodyBytes) != expectedResponseBody {
		t.Errorf("Expected response body %q, got %q", expectedResponseBody, string(responseBodyBytes))
	}

	// 4. Check the metered request size and response size
	select {
	case result := <-handler.reqChan:
		if result.req.TotalSize() != expectedRequestSize {
			t.Errorf("Expected request size %d, got %d", expectedRequestSize, result.req.TotalSize())
		}
		expectedResponseSize := uint64(len(expectedResponseBody))
		if result.bytesWritten != expectedResponseSize {
			t.Errorf("Expected response size %d, got %d", expectedResponseSize, result.bytesWritten)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timed out waiting for request to be handled")
	}
}
