package acme

import (
	"context"
	"errors"
	"net"
	"strings"
	"time"
)

// LookupIPFresh resolves host at its zone's authoritative nameservers, so
// the answer is never a cached failure.
//
// A host is usually registered moments before its first tunnel asks for a
// certificate. If the reachability probe looked the name up through the
// system resolver even a second before the A record existed, that resolver
// cached NXDOMAIN for the zone's SOA minimum (1800 s for lab0.us), and every
// retry for the next half hour failed although the record was live. Asking
// the authoritative servers directly answers from the zone as it is now.
//
// The zone is found by walking up from the host's parent (the host itself
// may not exist yet, and an NS query for it would itself cache NXDOMAIN).
// When no authoritative server answers, it falls back to the system resolver.
func LookupIPFresh(host string) ([]net.IP, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	host = strings.TrimSuffix(host, ".")
	if net.ParseIP(host) == nil {
		for _, server := range authoritativeServers(ctx, host) {
			ips, err := queryAt(ctx, server, host)
			if err == nil && len(ips) > 0 {
				return ips, nil
			}
			var dnsErr *net.DNSError
			if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
				// The zone's own server says it does not exist (yet).
				return nil, err
			}
		}
	}
	return systemLookupIP(host)
}

// Test seams.
var (
	systemLookupIP = net.LookupIP
	lookupNS       = func(ctx context.Context, zone string) ([]*net.NS, error) {
		return net.DefaultResolver.LookupNS(ctx, zone)
	}
	queryAt = func(ctx context.Context, server, host string) ([]net.IP, error) {
		r := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, network, net.JoinHostPort(server, "53"))
			},
		}
		addrs, err := r.LookupIPAddr(ctx, host+".")
		if err != nil {
			return nil, err
		}
		ips := make([]net.IP, 0, len(addrs))
		for _, a := range addrs {
			ips = append(ips, a.IP)
		}
		return ips, nil
	}
)

// authoritativeServers returns the nameserver hosts of the closest enclosing
// zone of host, starting from its parent.
func authoritativeServers(ctx context.Context, host string) []string {
	labels := strings.Split(host, ".")
	for i := 1; i < len(labels)-1; i++ {
		nss, err := lookupNS(ctx, strings.Join(labels[i:], "."))
		if err != nil || len(nss) == 0 {
			continue
		}
		out := make([]string, 0, len(nss))
		for _, ns := range nss {
			out = append(out, strings.TrimSuffix(ns.Host, "."))
		}
		return out
	}
	return nil
}
