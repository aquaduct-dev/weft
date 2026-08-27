// Package client provides a library for communicating with the Weft server's administrative endpoints.
// This file contains the HealthMonitor component for adaptive healthcheck logic.
package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/aquaduct-dev/weft/types"
	"github.com/rs/zerolog/log"
)

// HealthMonitorConfig configures the adaptive healthcheck behavior.
type HealthMonitorConfig struct {
	// Client is the HTTP client to use for healthcheck requests (must have JWT auth).
	Client *http.Client
	// HealthURL is the full URL to the /healthcheck endpoint.
	HealthURL string
	// TunnelName is the name of the tunnel being monitored.
	TunnelName string
	// MaxRetries is the failure threshold for the sliding window exit condition.
	MaxRetries int

	// BaseInterval is the healthcheck interval when healthy (default: 5s).
	BaseInterval time.Duration
	// RetryInterval is the interval after first failure (default: 3s).
	RetryInterval time.Duration
	// MaxInterval is the maximum backoff interval (default: 15s).
	MaxInterval time.Duration
	// WindowDuration is the sliding window for failure tracking (default: 60s).
	WindowDuration time.Duration
	// BackoffMultiplier is the multiplier for exponential backoff (default: 1.5).
	BackoffMultiplier float64

	// OnFatal is called with a reason when a permanent failure occurs.
	// If nil, log.Fatal is used. Provided for testability.
	OnFatal func(reason string)

	// OnTunnelGone is called when the server reports it has no such tunnel
	// (HTTP 404). That is not a permanent condition: it is what the server's
	// janitor leaves behind after pruning a tunnel whose healthchecks went
	// stale, and the correct response is to register again rather than die.
	// The monitor stops its loop after invoking this, leaving the caller to
	// re-establish and start a fresh monitor.
	//
	// If nil, a 404 is treated as permanent (the historical behavior), so
	// library callers that do not know how to re-register keep failing fast.
	OnTunnelGone func()
}

// HealthMonitor performs adaptive healthchecks with sliding window failure tracking.
type HealthMonitor struct {
	cfg HealthMonitorConfig

	mu              sync.Mutex
	done            chan struct{}
	stopped         bool
	currentInterval time.Duration

	// Failure tracking
	consecutiveFailures int
	recentFailures      []time.Time
}

// NewHealthMonitor creates a new HealthMonitor with the given configuration.
// Default values are applied for any zero-valued config fields.
func NewHealthMonitor(cfg HealthMonitorConfig) *HealthMonitor {
	// Apply defaults
	if cfg.BaseInterval == 0 {
		cfg.BaseInterval = 5 * time.Second
	}
	if cfg.RetryInterval == 0 {
		cfg.RetryInterval = 3 * time.Second
	}
	if cfg.MaxInterval == 0 {
		cfg.MaxInterval = 15 * time.Second
	}
	if cfg.WindowDuration == 0 {
		cfg.WindowDuration = 60 * time.Second
	}
	if cfg.BackoffMultiplier == 0 {
		cfg.BackoffMultiplier = 1.5
	}
	if cfg.MaxRetries == 0 {
		cfg.MaxRetries = 3
	}
	if cfg.OnFatal == nil {
		cfg.OnFatal = func(reason string) {
			log.Fatal().Str("tunnel", cfg.TunnelName).Str("reason", reason).Msg("Healthcheck failed permanently; shutting down")
		}
	}

	return &HealthMonitor{
		cfg:             cfg,
		done:            make(chan struct{}),
		currentInterval: cfg.BaseInterval,
	}
}

// Start begins the healthcheck loop. It blocks until Stop is called or a fatal error occurs.
func (h *HealthMonitor) Start() {
	ticker := time.NewTicker(h.currentInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if h.doHealthcheck() {
				// Fatal error occurred, exit
				return
			}
			// Update ticker if interval changed
			h.mu.Lock()
			ticker.Reset(h.currentInterval)
			h.mu.Unlock()

		case <-h.done:
			return
		}
	}
}

// Stop signals the healthcheck loop to stop.
func (h *HealthMonitor) Stop() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.stopped {
		h.stopped = true
		close(h.done)
	}
}

// doHealthcheck performs a single healthcheck and returns true if a fatal error occurred.
func (h *HealthMonitor) doHealthcheck() bool {
	healthReq := types.HealthcheckRequest{
		Message: fmt.Sprintf("Healthcheck from tunnel %s at %s", h.cfg.TunnelName, time.Now().Format(time.RFC3339)),
	}
	reqBody, err := json.Marshal(healthReq)
	if err != nil {
		log.Error().Err(err).Msg("Failed to marshal healthcheck request")
		return false
	}

	req, _ := http.NewRequest(http.MethodPost, h.cfg.HealthURL, bytes.NewBuffer(reqBody))
	req.Header.Set("Content-Type", "application/json")

	resp, err := h.cfg.Client.Do(req)

	// Classify the failure type
	isPermanentFailure := false
	isTransientFailure := false
	var failureReason string

	if err != nil {
		// Check for permanent failures (cert issues)
		if strings.Contains(err.Error(), "x509") || strings.Contains(err.Error(), "certificate") {
			isPermanentFailure = true
			failureReason = "certificate error"
		} else {
			isTransientFailure = true
			failureReason = err.Error()
		}
	} else {
		defer resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusOK:
			// Success - reset tracking
			var healthResp types.HealthcheckResponse
			if err := json.NewDecoder(resp.Body).Decode(&healthResp); err == nil {
				log.Debug().Str("status", healthResp.Status).Str("tunnel", h.cfg.TunnelName).Msg("Healthcheck successful")
			}
			h.mu.Lock()
			if h.consecutiveFailures > 0 {
				log.Info().Str("tunnel", h.cfg.TunnelName).Int("recovered_after", h.consecutiveFailures).Msg("Healthcheck recovered")
			}
			h.consecutiveFailures = 0
			h.currentInterval = h.cfg.BaseInterval
			h.mu.Unlock()
			return false // Success, not fatal

		case http.StatusNotFound:
			// The server has no record of this tunnel. Nearly always this is
			// the janitor having pruned us after our healthchecks went stale
			// (a server hiccup of >15s is enough), which is recoverable: the
			// WireGuard config is void but the credentials are still good, so
			// re-running /connect restores service.
			//
			// Treating this as fatal meant every client on a bastion dropped
			// together on any stall and only came back because a supervisor
			// restarted the process.
			if h.cfg.OnTunnelGone != nil {
				log.Warn().
					Str("tunnel", h.cfg.TunnelName).
					Msg("Server no longer knows this tunnel; re-registering")
				h.cfg.OnTunnelGone()
				return true // stop this monitor; the new registration starts its own
			}
			isPermanentFailure = true
			failureReason = fmt.Sprintf("server returned %d", resp.StatusCode)

		case http.StatusUnauthorized:
			// Auth is genuinely invalid - not something a retry fixes.
			isPermanentFailure = true
			failureReason = fmt.Sprintf("server returned %d", resp.StatusCode)

		default:
			// Other errors are transient
			isTransientFailure = true
			var healthResp types.HealthcheckResponse
			if decodeErr := json.NewDecoder(resp.Body).Decode(&healthResp); decodeErr == nil {
				failureReason = fmt.Sprintf("status %d: %s", resp.StatusCode, healthResp.Message)
			} else {
				failureReason = fmt.Sprintf("status %d", resp.StatusCode)
			}
		}
	}

	// Handle permanent failures - exit immediately
	if isPermanentFailure {
		h.cfg.OnFatal(failureReason)
		return true
	}

	// Handle transient failures
	if isTransientFailure {
		h.mu.Lock()
		h.consecutiveFailures++
		h.recentFailures = append(h.recentFailures, time.Now())
		recentCount := h.countRecentFailures()

		log.Warn().
			Int("consecutive", h.consecutiveFailures).
			Int("recent", recentCount).
			Int("max_retries", h.cfg.MaxRetries).
			Str("tunnel", h.cfg.TunnelName).
			Str("reason", failureReason).
			Msg("Healthcheck failed")

		// Adaptive interval: faster retry on first failure, then backoff
		if h.consecutiveFailures == 1 {
			h.currentInterval = h.cfg.RetryInterval
		} else if h.consecutiveFailures > 1 {
			newInterval := time.Duration(float64(h.currentInterval) * h.cfg.BackoffMultiplier)
			if newInterval > h.cfg.MaxInterval {
				newInterval = h.cfg.MaxInterval
			}
			h.currentInterval = newInterval
		}
		log.Debug().Dur("interval", h.currentInterval).Str("tunnel", h.cfg.TunnelName).Msg("Healthcheck interval adjusted")

		consecutiveFailures := h.consecutiveFailures
		maxRetries := h.cfg.MaxRetries
		h.mu.Unlock()

		// Exit conditions:
		// 1. Too many consecutive failures (hard failure)
		// 2. Too many failures in the sliding window
		if consecutiveFailures >= maxRetries*2 {
			h.cfg.OnFatal(fmt.Sprintf("Too many consecutive healthcheck failures; shutting down (consecutive=%d)", consecutiveFailures))
			return true
		}
		if recentCount >= maxRetries {
			h.cfg.OnFatal(fmt.Sprintf("Too many healthcheck failures in window; shutting down (failures_in_window=%d)", recentCount))
			return true
		}
	}

	return false
}

// countRecentFailures returns the number of failures within the sliding window.
// Must be called with h.mu held.
func (h *HealthMonitor) countRecentFailures() int {
	cutoff := time.Now().Add(-h.cfg.WindowDuration)
	valid := h.recentFailures[:0]
	for _, t := range h.recentFailures {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}
	h.recentFailures = valid
	return len(h.recentFailures)
}
