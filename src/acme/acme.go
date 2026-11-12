// Package server: ACME helper utilities.
//
// This file provides a small wrapper around autocert.Manager to allow waiting
// for certificates to become available before mounting HTTPS listeners.
// It exposes WaitForCertificate to poll the autocert cache / manager and
// return when a certificate for a host is ready or when a timeout occurs.
//
// NOTE: keep logs detailed to help debug ACME ordering and challenge issues.
package acme

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	xacme "golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// Event names emitted on the structured "event" field of every cert
// acquisition log line. Operators / log pipelines should filter on these.
const (
	EventCacheHit          = "acme_cache_hit"
	EventIssuanceStarted   = "acme_issuance_started"
	EventIssuanceSucceeded = "acme_issuance_succeeded"
	EventIssuanceFailed    = "acme_issuance_failed"
)

// ACMEHelper wraps an autocert.Manager and exposes helpers used by server startup.
type ACMEHelper struct {
	Manager *autocert.Manager
}

// NewACMEHelper constructs an ACMEHelper from an existing autocert.Manager.
func NewACMEHelper(m *autocert.Manager) *ACMEHelper {
	return &ACMEHelper{Manager: m}
}

// AcquireCertificate fetches a certificate via autocert.Manager.GetCertificate
// and emits structured log events for cache hits, issuance start, success, and
// failure. Use this anywhere a cert is fetched from autocert so all acquisition
// paths produce a consistent audit trail — operators rely on these events to
// track cert lifecycle across multi-node deployments.
func AcquireCertificate(m *autocert.Manager, hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if m == nil {
		return nil, errors.New("acme manager not configured")
	}
	host := hello.ServerName

	// Probe the cache so we can distinguish "served from disk" from "round-tripped
	// to the CA" in logs. autocert will check the cache itself; this extra read is
	// purely for observability.
	cacheHit := false
	if m.Cache != nil {
		if cert, err := m.Cache.Get(context.Background(), host); err == nil && len(cert) > 0 {
			cacheHit = true
		}
	}

	if !cacheHit {
		log.Info().Str("event", EventIssuanceStarted).Str("host", host).Msg("ACME: cert acquisition starting")
	}

	// While the CA has this host rate limited, asking again only fails and,
	// for some limits, extends the wait: answer from here until the time
	// the CA gave. This is the only failure that is ever remembered.
	if until, limited := rateLimitedUntil(host, time.Now()); limited {
		return nil, fmt.Errorf("acme: %s is rate limited by the CA until %s; not asking again before then", host, until.UTC().Format(time.RFC3339))
	}

	start := time.Now()
	cert, err := m.GetCertificate(hello)
	dur := time.Since(start)

	if err != nil {
		if until, ok := rateLimitEnd(err, time.Now()); ok {
			holdRateLimit(host, until)
			log.Warn().Str("event", EventIssuanceFailed).Str("host", host).Time("retry_after", until).Err(err).Msg("ACME: CA rate limit; holding issuance for this host until the CA's retry-after")
			return nil, err
		}
		log.Warn().Str("event", EventIssuanceFailed).Str("host", host).Dur("duration", dur).Err(err).Msg("ACME: cert acquisition failed")
		return nil, err
	}
	if cacheHit {
		log.Info().Str("event", EventCacheHit).Str("host", host).Dur("duration", dur).Msg("ACME: cert served from cache")
	} else {
		log.Info().Str("event", EventIssuanceSucceeded).Str("host", host).Dur("duration", dur).Msg("ACME: cert acquired from CA")
	}
	return cert, nil
}

// WaitForCertificate waits until a certificate for host is available in the Manager's cache
// (or can be obtained) or until timeout elapses. It returns the certificate if successful.
func (a *ACMEHelper) WaitForCertificate(ctx context.Context, host string) (*tls.Certificate, error) {
	if a == nil || a.Manager == nil {
		return nil, errors.New("acme manager not configured")
	}
	hello := &tls.ClientHelloInfo{ServerName: host}
	return AcquireCertificate(a.Manager, hello)
}

// Rate limits the CA has placed on hosts: host -> when the CA said to try
// again. Nothing else about a failed issuance is kept, so any other failure
// is retried as soon as it is asked for.
var (
	rateLimitsMu sync.Mutex
	rateLimits   = map[string]time.Time{}
)

// retryAfterText matches the time Let's Encrypt writes into a rate-limit
// problem's detail, e.g. "..., retry after 2026-06-12 19:00:00 UTC: see ...".
var retryAfterText = regexp.MustCompile(`retry after (\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) UTC`)

// rateLimitEnd says whether err is the CA's rate limit and, if so, when it
// ends: the Retry-After header, else the time in the problem's detail. A
// rate limit that names no end is not held: the next request finds out.
func rateLimitEnd(err error, now time.Time) (time.Time, bool) {
	var ae *xacme.Error
	if errors.As(err, &ae) {
		if d, ok := xacme.RateLimit(ae); ok {
			if d > 0 {
				return now.Add(d), true
			}
			if t, ok := retryAfterIn(ae.Detail); ok {
				return t, t.After(now)
			}
			return time.Time{}, false
		}
	}
	msg := err.Error()
	if !strings.Contains(strings.ToLower(msg), "ratelimited") && !strings.Contains(strings.ToLower(msg), "rate limit") {
		return time.Time{}, false
	}
	if t, ok := retryAfterIn(msg); ok && t.After(now) {
		return t, true
	}
	return time.Time{}, false
}

func retryAfterIn(text string) (time.Time, bool) {
	m := retryAfterText.FindStringSubmatch(text)
	if m == nil {
		return time.Time{}, false
	}
	t, err := time.ParseInLocation("2006-01-02 15:04:05", m[1], time.UTC)
	return t, err == nil
}

func holdRateLimit(host string, until time.Time) {
	rateLimitsMu.Lock()
	defer rateLimitsMu.Unlock()
	rateLimits[host] = until
}

// rateLimitedUntil reports a hold still in force, dropping one that ended.
func rateLimitedUntil(host string, now time.Time) (time.Time, bool) {
	rateLimitsMu.Lock()
	defer rateLimitsMu.Unlock()
	until, ok := rateLimits[host]
	if !ok {
		return time.Time{}, false
	}
	if !now.Before(until) {
		delete(rateLimits, host)
		return time.Time{}, false
	}
	return until, true
}
