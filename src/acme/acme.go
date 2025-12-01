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

// ACMEHelper wraps an autocert.Manager and exposes helpers used by server startup.
type ACMEHelper struct {
	Manager *autocert.Manager
}

// NewACMEHelper constructs an ACMEHelper from an existing autocert.Manager.
func NewACMEHelper(m *autocert.Manager) *ACMEHelper {
	return &ACMEHelper{Manager: m}
}

// WaitForCertificate waits until a certificate for host is available in the Manager's cache
// (or can be obtained) or until timeout elapses. It returns the certificate if successful.
func (a *ACMEHelper) WaitForCertificate(ctx context.Context, host string) (*tls.Certificate, error) {
	if a == nil || a.Manager == nil {
		return nil, errors.New("acme manager not configured")
	}

	// Quick attempt: try to get cert immediately (may trigger issuance).
	tick := time.NewTicker(1 * time.Second)
	defer tick.Stop()

	// First try manager.Cache to see if cert exists on disk (DirCache).
	if a.Manager.Cache != nil {
		if cert, err := a.Manager.Cache.Get(context.Background(), host); err == nil && len(cert) > 0 {
			// Try to parse into tls.Certificate
			tc, err := tls.X509KeyPair(cert, cert)
			if err == nil {
				log.Info().Str("host", host).Msg("ACME: certificate found in cache")
				return &tc, nil
			}
			// If parsing with same bytes fails, continue to attempt GetCertificate below.
			log.Debug().Err(err).Str("host", host).Msg("ACME: cache present but failed to parse cert")
		}
	}

	// Ask Manager to provide certificate via GetCertificate to trigger issuance if needed.
	hello := &tls.ClientHelloInfo{ServerName: host}
	log.Info().Str("host", host).Msg("Acquiring certificate via LetsEncrypt with ACME http01 challenge...")
	cert, err := a.Manager.GetCertificate(hello)
	if err != nil {
		log.Warn().Err(err).Str("host", host).Msg("ACME: GetCertificate error")
		return nil, err
	}
	log.Info().Str("host", host).Msg("Acquired TLS certificate")
	return cert, nil
}
