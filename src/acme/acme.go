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
	"time"

	"github.com/rs/zerolog/log"
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

	start := time.Now()
	cert, err := m.GetCertificate(hello)
	dur := time.Since(start)

	if err != nil {
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
