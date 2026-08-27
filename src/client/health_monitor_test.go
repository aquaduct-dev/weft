package client_test

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aquaduct-dev/weft/src/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A 404 means the server's janitor pruned this tunnel after our healthchecks
// went stale. That is recoverable by registering again, so the monitor must
// hand it to OnTunnelGone rather than killing the process — otherwise a single
// bastion stall takes down every client attached to it at once.
func TestHealthcheckTunnelGoneTriggersReregistration(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	var gone, fatal int32
	monitor := client.NewHealthMonitor(client.HealthMonitorConfig{
		Client:       srv.Client(),
		HealthURL:    srv.URL + "/healthcheck",
		TunnelName:   "gw-test",
		MaxRetries:   3,
		BaseInterval: 10 * time.Millisecond,
		OnTunnelGone: func() { atomic.AddInt32(&gone, 1) },
		OnFatal:      func(string) { atomic.AddInt32(&fatal, 1) },
	})

	done := make(chan struct{})
	go func() { monitor.Start(); close(done) }()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		monitor.Stop()
		t.Fatal("monitor did not stop after the server reported the tunnel gone")
	}

	assert.Equal(t, int32(1), atomic.LoadInt32(&gone), "OnTunnelGone should fire exactly once")
	assert.Zero(t, atomic.LoadInt32(&fatal), "a 404 must not be treated as a permanent failure")
}

// Without an OnTunnelGone hook the caller has no way to re-register, so the
// historical fail-fast behavior is preserved for library users.
func TestHealthcheckTunnelGoneFatalWithoutHook(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	var fatal int32
	monitor := client.NewHealthMonitor(client.HealthMonitorConfig{
		Client:       srv.Client(),
		HealthURL:    srv.URL + "/healthcheck",
		TunnelName:   "gw-test",
		MaxRetries:   3,
		BaseInterval: 10 * time.Millisecond,
		OnFatal:      func(string) { atomic.AddInt32(&fatal, 1) },
	})

	done := make(chan struct{})
	go func() { monitor.Start(); close(done) }()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		monitor.Stop()
		t.Fatal("monitor did not stop")
	}
	assert.Equal(t, int32(1), atomic.LoadInt32(&fatal))
}

// 401 is a real credential problem and retrying cannot help, so it stays fatal
// even when a re-registration hook is available.
func TestHealthcheckUnauthorizedStaysFatal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	var gone, fatal int32
	monitor := client.NewHealthMonitor(client.HealthMonitorConfig{
		Client:       srv.Client(),
		HealthURL:    srv.URL + "/healthcheck",
		TunnelName:   "gw-test",
		MaxRetries:   3,
		BaseInterval: 10 * time.Millisecond,
		OnTunnelGone: func() { atomic.AddInt32(&gone, 1) },
		OnFatal:      func(string) { atomic.AddInt32(&fatal, 1) },
	})

	done := make(chan struct{})
	go func() { monitor.Start(); close(done) }()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		monitor.Stop()
		t.Fatal("monitor did not stop")
	}
	require.Zero(t, atomic.LoadInt32(&gone), "401 is not a missing tunnel")
	assert.Equal(t, int32(1), atomic.LoadInt32(&fatal))
}
