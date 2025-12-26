package server

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// mockTunnelStore provides a minimal TunnelStore implementation for testing.
type mockTunnelStore struct {
	mu       sync.RWMutex
	lastSeen map[string]time.Time
}

func newMockTunnelStore() *mockTunnelStore {
	return &mockTunnelStore{
		lastSeen: make(map[string]time.Time),
	}
}

func (m *mockTunnelStore) GetLastSeen(name string) (time.Time, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	t, ok := m.lastSeen[name]
	return t, ok
}

func (m *mockTunnelStore) SetLastSeen(name string, t time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastSeen[name] = t
}

func (m *mockTunnelStore) GetAllLastSeen() map[string]time.Time {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make(map[string]time.Time, len(m.lastSeen))
	for k, v := range m.lastSeen {
		result[k] = v
	}
	return result
}

// Unused but required by interface
func (m *mockTunnelStore) GetPeer(name string) (Peer, bool)       { return Peer{}, false }
func (m *mockTunnelStore) SetPeer(name string, p Peer)            {}
func (m *mockTunnelStore) DeletePeer(name string)                 {}
func (m *mockTunnelStore) GetAllPeers() map[string]Peer           { return nil }
func (m *mockTunnelStore) DeleteLastSeen(name string)             {}
func (m *mockTunnelStore) GetFreeIP() (netip.Addr, error)         { return netip.Addr{}, nil }
func (m *mockTunnelStore) ReleaseIP(ip netip.Addr)                {}

import "net/netip"

func TestJanitor_SweepsStaleTunnels(t *testing.T) {
	store := newMockTunnelStore()

	var cleanedUp []string
	var cleanupMu sync.Mutex
	cleanup := func(name string) {
		cleanupMu.Lock()
		cleanedUp = append(cleanedUp, name)
		cleanupMu.Unlock()
	}

	var reported []string
	var reportMu sync.Mutex
	report := func(ctx context.Context, tunnels []string) {
		reportMu.Lock()
		reported = append(reported, tunnels...)
		reportMu.Unlock()
	}

	// Add one stale and one fresh tunnel
	store.SetLastSeen("stale-tunnel", time.Now().Add(-1*time.Hour))
	store.SetLastSeen("fresh-tunnel", time.Now())

	janitor := NewJanitor(
		10*time.Millisecond,
		store,
		cleanup,
		report,
		func() bool { return false },
	)

	janitor.Start()
	time.Sleep(50 * time.Millisecond)
	janitor.Stop()

	// Verify stale tunnel was cleaned up
	cleanupMu.Lock()
	defer cleanupMu.Unlock()
	
	if len(cleanedUp) != 1 {
		t.Errorf("expected 1 cleanup, got %d", len(cleanedUp))
	}
	if len(cleanedUp) > 0 && cleanedUp[0] != "stale-tunnel" {
		t.Errorf("expected 'stale-tunnel' to be cleaned up, got %q", cleanedUp[0])
	}

	// Verify usage was reported before cleanup
	reportMu.Lock()
	defer reportMu.Unlock()
	if len(reported) != 1 {
		t.Errorf("expected 1 report, got %d", len(reported))
	}
}

func TestJanitor_StopsGracefully(t *testing.T) {
	store := newMockTunnelStore()

	var sweepCount atomic.Int32
	cleanup := func(name string) {
		sweepCount.Add(1)
	}

	janitor := NewJanitor(
		1*time.Millisecond,
		store,
		cleanup,
		func(ctx context.Context, tunnels []string) {},
		func() bool { return false },
	)

	janitor.Start()
	time.Sleep(10 * time.Millisecond)
	janitor.Stop()

	// After stopping, no more sweeps should occur
	countAfterStop := sweepCount.Load()
	time.Sleep(20 * time.Millisecond)
	
	if sweepCount.Load() != countAfterStop {
		t.Errorf("janitor continued sweeping after Stop()")
	}
}

func TestJanitor_RespectsClosingFlag(t *testing.T) {
	store := newMockTunnelStore()
	store.SetLastSeen("stale-tunnel", time.Now().Add(-1*time.Hour))

	var cleanedUp []string
	cleanup := func(name string) {
		cleanedUp = append(cleanedUp, name)
	}

	var closing atomic.Bool
	closing.Store(true)

	janitor := NewJanitor(
		10*time.Millisecond,
		store,
		cleanup,
		func(ctx context.Context, tunnels []string) {},
		closing.Load,
	)

	janitor.Start()
	time.Sleep(50 * time.Millisecond)
	janitor.Stop()

	// No cleanup should occur when closing
	if len(cleanedUp) != 0 {
		t.Errorf("expected no cleanups when closing, got %d", len(cleanedUp))
	}
}
