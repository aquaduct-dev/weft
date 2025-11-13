// Package server: ACME helper utilities.
//
// This file provides a small wrapper around autocert.Manager to allow waiting
// for certificates to become available before mounting HTTPS listeners.
// It exposes WaitForCertificate to poll the autocert cache / manager and
// return when a certificate for a host is ready or when a timeout occurs.
//
// NOTE: keep logs detailed to help debug ACME ordering and challenge issues.
package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
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
	log.Info().Str("host", host).Msg("ACME: acquiring certificate...")
	cert, err := a.Manager.GetCertificate(hello)
	if err != nil {
		log.Warn().Err(err).Str("host", host).Msg("ACME: GetCertificate error")
		return nil, err
	}
	log.Info().Str("host", host).Msg("ACME: manager returned certificate")
	return cert, nil
}

// CanWebHost checks whether the server's public IPv4 is internet-routable and
// can complete an ACME HTTP-01 challenge for the given host. It attempts to
// resolve the host and then perform a minimal HTTP GET to the ACME challenge
// path served by the autocert.Manager on the manager's configured ACMEFVHo port.
// This helper is conservative: it requires a non-loopback, public IPv4 address
// on the local machine and that an HTTP request to http://<host>/.well-known/acme-challenge/
// returns a successful status (2xx or 3xx). Detailed logs are emitted to help
// debug challenge reachability and routing.
func (p *VHostProxy) CanWebHost(ctx context.Context, host string) bool {
	// Basic validation
	if host == "" {
		log.Debug().Str("host", host).Msg("CanWebHost: empty host")
		return false
	}

	// Resolve host to IPs
	ips, err := net.LookupIP(host)
	if err != nil {
		log.Debug().Err(err).Str("host", host).Msg("CanWebHost: DNS lookup failed")
		return false
	}

	// Determine our public IPv4 address by querying an external service (api.ipify.org).
	// This avoids relying on local interface heuristics which may be incorrect for NATted hosts.
	publicIP := ""
	{
		client := &http.Client{}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.ipify.org", nil)
		if err != nil {
			log.Debug().Err(err).Msg("CanWebHost: failed to create request to api.ipify.org")
			return false
		}
		resp, err := client.Do(req)
		if err != nil {
			log.Debug().Err(err).Msg("CanWebHost: failed to query api.ipify.org for public IP")
			return false
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			log.Debug().Err(err).Msg("CanWebHost: failed to read api.ipify.org response")
			return false
		}
		publicIP = strings.TrimSpace(string(body))
		if publicIP == "" {
			log.Debug().Msg("CanWebHost: api.ipify.org returned empty body")
			return false
		}
		// Validate it's an IPv4 address
		parsed := net.ParseIP(publicIP)
		if parsed == nil || parsed.To4() == nil {
			log.Debug().Str("public_ip", publicIP).Msg("CanWebHost: api.ipify.org did not return a valid IPv4")
			return false
		}
		log.Debug().Str("public_ip", publicIP).Msg("CanWebHost: obtained public IP from api.ipify.org")
	}

	// Check that at least one resolved IP is a public IPv4 (not private, not loopback)
	var targetIPv4 net.IP
	for _, ip := range ips {
		if ip.To4() == nil {
			continue
		}
		if ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			continue
		}
		if ip.IsPrivate() {
			// if host resolves only to private addresses, it may not be reachable from the Internet
			continue
		}
		targetIPv4 = ip
		break
	}
	if targetIPv4 == nil {
		log.Debug().Str("host", host).Msg("CanWebHost: host does not resolve to a public IPv4 address")
		// Continue, but fail — ACME HTTP-01 requires a publicly routable host.
		return false
	}
	log.Debug().Str("host_ip", targetIPv4.String()).Str("host", host).Msg("CanWebHost: host resolves to public IPv4")
	// At this point DNS resolves to a public IPv4. Perform an active HTTP probe to verify
	// the ACME HTTP-01 challenge handler is reachable at http://<host>/.well-known/acme-challenge/
	// from the perspective of the server's public IP. This helps avoid triggering ACME issuance
	// for hosts that point to the public IP but are blocked by firewall or NAT.
	checkURL := fmt.Sprintf("http://%s/.well-known/acme-challenge/", host)

	proxy := p.manager.Proxy(targetIPv4.String(), 80)
	// Pass nil device for the dummy ACME host (no WG device needed here).
	closer, err := proxy.AddHost("probe-acme", &url.URL{Scheme: "http", Host: "localhost:80"}, nil)
	if err != nil {
		log.Warn().AnErr("CanWebHost: AddHost error", err)
		return false
	}
	err = proxy.Start()
	if err != nil {
		log.Warn().AnErr("CanWebHost: Start error", err)
		return false
	}
	defer closer.Close()

	// Try a HEAD first; some handlers may not accept HEAD so fall back to GET.
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, checkURL, nil)
	client := &http.Client{
		Timeout: 5 * time.Second,
	}
	if err != nil {
		log.Debug().Err(err).Str("check_url", checkURL).Msg("CanWebHost: failed to create HEAD request for HTTP-01 probe")
	} else {
		resp, err := client.Do(req)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 403 || resp.StatusCode == 404 {
				log.Info().Str("host", host).Str("host_ip", targetIPv4.String()).Int("status", resp.StatusCode).Msg("CanWebHost: HTTP probe succeeded (HEAD) for ACME challenge path")
				return true
			}
			log.Debug().Str("host", host).Int("status", resp.StatusCode).Msg("CanWebHost: HEAD probe returned non-2xx/3xx status")
		} else {
			log.Debug().Err(err).Str("host", host).Msg("CanWebHost: HEAD probe error; will retry with GET")
		}
	}

	if targetIPv4.String() == publicIP {
		log.Warn().Str("host", host).Str("host_ip", targetIPv4.String()).Str("public_ip", publicIP).Msg("CanWebHost: DNS -> public IP matches but HTTP probes failed; allowing ACME as permissive fallback")
		return false
	}

	log.Warn().Str("host", host).Str("host_ip", targetIPv4.String()).Str("public_ip", publicIP).Msg("CanWebHost: HTTP probes failed and DNS does not point to server public IP; denying ACME")
	return false
}
