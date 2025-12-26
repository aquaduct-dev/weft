package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aquaduct-dev/weft/types"
)

func TestHTTPUsageReporter_ReportsUsagePeriodically(t *testing.T) {
	var reportCount atomic.Int32
	var lastReport types.UsageReport

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reportCount.Add(1)
		if err := json.NewDecoder(r.Body).Decode(&lastReport); err != nil {
			t.Errorf("failed to decode report: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	reporter := NewHTTPUsageReporter(
		server.URL,
		10*time.Millisecond,
		func() map[string]ProxyCounters {
			return map[string]ProxyCounters{
				"test-tunnel": {Tx: 100, Rx: 200, InstanceId: "abc123"},
			}
		},
		func() map[string]Peer {
			return map[string]Peer{
				"test-tunnel": {ProxiedUpstream: "http://localhost:3000", DstURL: "https://example.com"},
			}
		},
		func() bool { return false },
	)

	reporter.Start()
	time.Sleep(50 * time.Millisecond)
	reporter.Stop()

	if reportCount.Load() < 1 {
		t.Errorf("expected at least 1 report, got %d", reportCount.Load())
	}
	if len(lastReport.Tunnels) != 1 {
		t.Errorf("expected 1 tunnel in report, got %d", len(lastReport.Tunnels))
	}
	if lastReport.Tunnels[0].TunnelName != "test-tunnel" {
		t.Errorf("expected tunnel name 'test-tunnel', got %q", lastReport.Tunnels[0].TunnelName)
	}
}

func TestHTTPUsageReporter_ReportsSpecificTunnels(t *testing.T) {
	var lastReport types.UsageReport

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&lastReport); err != nil {
			t.Errorf("failed to decode report: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	reporter := NewHTTPUsageReporter(
		server.URL,
		1*time.Minute, // Long interval - we'll call ReportUsage directly
		func() map[string]ProxyCounters {
			return map[string]ProxyCounters{
				"tunnel-1": {Tx: 100, Rx: 200, InstanceId: "id1"},
				"tunnel-2": {Tx: 300, Rx: 400, InstanceId: "id2"},
			}
		},
		func() map[string]Peer {
			return map[string]Peer{
				"tunnel-1": {ProxiedUpstream: "http://localhost:3001", DstURL: "https://example1.com"},
				"tunnel-2": {ProxiedUpstream: "http://localhost:3002", DstURL: "https://example2.com"},
			}
		},
		func() bool { return false },
	)

	// Report only tunnel-1
	reporter.ReportUsage(context.Background(), []string{"tunnel-1"})

	if len(lastReport.Tunnels) != 1 {
		t.Errorf("expected 1 tunnel in report, got %d", len(lastReport.Tunnels))
	}
	if len(lastReport.Tunnels) > 0 && lastReport.Tunnels[0].TunnelName != "tunnel-1" {
		t.Errorf("expected 'tunnel-1', got %q", lastReport.Tunnels[0].TunnelName)
	}
}

func TestHTTPUsageReporter_SkipsWhenURLEmpty(t *testing.T) {
	var called bool

	reporter := NewHTTPUsageReporter(
		"", // Empty URL
		10*time.Millisecond,
		func() map[string]ProxyCounters {
			called = true
			return nil
		},
		func() map[string]Peer { return nil },
		func() bool { return false },
	)

	reporter.Start()
	time.Sleep(30 * time.Millisecond)
	reporter.Stop()

	// Getters should not be called when URL is empty
	if called {
		t.Errorf("expected no calls when URL is empty")
	}
}

func TestHTTPUsageReporter_SkipsWhenClosing(t *testing.T) {
	var reportCount atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reportCount.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	var closing atomic.Bool
	closing.Store(true)

	reporter := NewHTTPUsageReporter(
		server.URL,
		1*time.Minute,
		func() map[string]ProxyCounters {
			return map[string]ProxyCounters{
				"test": {Tx: 100, Rx: 200},
			}
		},
		func() map[string]Peer {
			return map[string]Peer{
				"test": {},
			}
		},
		closing.Load,
	)

	reporter.ReportUsage(context.Background(), nil)

	if reportCount.Load() != 0 {
		t.Errorf("expected no reports when closing, got %d", reportCount.Load())
	}
}

func TestHTTPUsageReporter_SkipsEmptyReport(t *testing.T) {
	var reportCount atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reportCount.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	reporter := NewHTTPUsageReporter(
		server.URL,
		1*time.Minute,
		func() map[string]ProxyCounters { return nil }, // No counters
		func() map[string]Peer { return nil },
		func() bool { return false },
	)

	reporter.ReportUsage(context.Background(), nil)

	if reportCount.Load() != 0 {
		t.Errorf("expected no reports for empty data, got %d", reportCount.Load())
	}
}
