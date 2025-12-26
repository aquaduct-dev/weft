package server

import (
	"context"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// Janitor periodically cleans up stale tunnels that have not reported a healthcheck
// within the configured threshold. It reports usage before removing tunnels and
// delegates actual cleanup to the provided callback.
type Janitor struct {
	interval time.Duration
	store    TunnelStore
	cleanup  func(string)
	report   func(ctx context.Context, tunnels []string)
	closing  func() bool

	stopCh chan struct{}
	wg     sync.WaitGroup
}

// NewJanitor creates a new Janitor that checks for stale tunnels at the given interval.
// Parameters:
//   - interval: how often to check for stale tunnels
//   - store: the tunnel store to query for last-seen timestamps
//   - cleanup: callback to remove a tunnel by name
//   - report: callback to report usage for tunnels before removal
//   - closing: function that returns true if the server is shutting down
func NewJanitor(
	interval time.Duration,
	store TunnelStore,
	cleanup func(string),
	report func(ctx context.Context, tunnels []string),
	closing func() bool,
) *Janitor {
	return &Janitor{
		interval: interval,
		store:    store,
		cleanup:  cleanup,
		report:   report,
		closing:  closing,
		stopCh:   make(chan struct{}),
	}
}

// Start begins the janitor's periodic cleanup loop in a background goroutine.
func (j *Janitor) Start() {
	j.wg.Add(1)
	go j.run()
}

// Stop signals the janitor to stop and waits for it to finish.
func (j *Janitor) Stop() {
	close(j.stopCh)
	j.wg.Wait()
}

func (j *Janitor) run() {
	defer j.wg.Done()

	ticker := time.NewTicker(j.interval)
	defer ticker.Stop()

	for {
		select {
		case <-j.stopCh:
			return
		case <-ticker.C:
			if j.closing() {
				return
			}
			j.sweep()
		}
	}
}

// sweep checks for stale tunnels and removes them.
// A tunnel is considered stale if it hasn't been seen in 3x the interval.
func (j *Janitor) sweep() {
	cutoff := time.Now().Add(-3 * j.interval)
	lastSeen := j.store.GetAllLastSeen()

	var staleTunnels []string
	for name, last := range lastSeen {
		if last.Before(cutoff) {
			staleTunnels = append(staleTunnels, name)
		}
	}

	if len(staleTunnels) == 0 {
		return
	}

	// Report usage for stale tunnels before removing them
	j.report(context.Background(), staleTunnels)

	// Remove each stale tunnel, double-checking it's still stale
	for _, name := range staleTunnels {
		if last, ok := j.store.GetLastSeen(name); ok && last.Before(cutoff) {
			j.cleanup(name)
			log.Info().Str("peer", name).Msg("Janitor: removed stale tunnel")
		}
	}
}
