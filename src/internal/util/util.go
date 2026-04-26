package util

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// FailureTracker counts upstream-dial failures in a sliding window. It exists
// to avoid tearing a tunnel down on the first dial failure (F-9): a single
// public client connecting during an upstream restart shouldn't wipe the
// tunnel out from under the legitimate operator.
//
// Zero value is invalid; use NewFailureTracker.
type FailureTracker struct {
	mu        sync.Mutex
	failures  []time.Time
	threshold int
	window    time.Duration
}

// NewFailureTracker returns a tracker that will report "tripped" once it has
// recorded `threshold` failures within `window`. A threshold of 1 reproduces
// the original fail-fast behaviour; higher thresholds smooth over transient
// upstream outages.
func NewFailureTracker(threshold int, window time.Duration) *FailureTracker {
	if threshold < 1 {
		threshold = 1
	}
	return &FailureTracker{threshold: threshold, window: window}
}

// Record adds a failure observation and returns true if the threshold has
// been crossed within the sliding window. The tracker resets on a Record that
// returns true, so repeated trips don't continue firing.
func (f *FailureTracker) Record(now time.Time) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	cutoff := now.Add(-f.window)
	keep := f.failures[:0]
	for _, t := range f.failures {
		if t.After(cutoff) {
			keep = append(keep, t)
		}
	}
	keep = append(keep, now)
	f.failures = keep
	if len(f.failures) >= f.threshold {
		f.failures = f.failures[:0]
		return true
	}
	return false
}

// Reset drops any recorded failures (used on a successful operation).
func (f *FailureTracker) Reset() {
	f.mu.Lock()
	f.failures = f.failures[:0]
	f.mu.Unlock()
}

// EnsurePort ensures that the URL has a port set, using defaults for http/https.
func EnsurePort(u *url.URL) error {
	if u.Port() == "" {
		switch strings.ToLower(u.Scheme) {
		case "http":
			u.Host = net.JoinHostPort(u.Hostname(), "80")
		case "https":
			u.Host = net.JoinHostPort(u.Hostname(), "443")
		case "tcp", "udp":
			// For tcp/udp we can't easily guess a default port if it's missing.
			return fmt.Errorf("missing port for %s scheme: %s", u.Scheme, u.String())
		default:
			return fmt.Errorf("unsupported scheme for missing port: %s", u.String())
		}
	}
	return nil
}

// ParsePort parses the port from a host string, with a default if missing.
func ParsePort(host string, defaultPort int) (int, error) {
	_, portStr, err := net.SplitHostPort(host)
	if err != nil {
		// Might be just the host without port
		if strings.Contains(host, ":") {
			return 0, fmt.Errorf("invalid host format: %s", host)
		}
		return defaultPort, nil
	}
	return strconv.Atoi(portStr)
}

// RewriteHost updates the host part of a URL while preserving the port.
func RewriteHost(u *url.URL, newHost string) {
	if newHost == "0.0.0.0" || newHost == "" {
		return
	}
	port := u.Port()
	if port != "" {
		u.Host = net.JoinHostPort(newHost, port)
	} else {
		u.Host = newHost
	}
}
