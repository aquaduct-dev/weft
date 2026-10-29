// Package acme: fetching HTTP-01 challenge responses from sibling nodes.
//
// Background: a weft cluster typically has several nodes behind DNS
// round-robin for the same hostname, and each node runs its own ACME order.
// The CA validates every order from several vantage points, and each one may
// pick any A/AAAA record, so the request for a token often lands on a node
// that didn't place the order and doesn't know the key authorization.
//
// To bridge this, a node that can't answer a challenge itself asks every
// other node in the host's DNS set for the same path, with NoProxyParam set,
// and relays the first 200 it gets back. Every token path is unique, so only
// the node that placed the order can answer with a 200; the rest return 404.
// NoProxyParam makes the peer answer from its own state only, so the fan-out
// is one hop and can never loop.
//
// We proxy rather than 301-redirect because Let's Encrypt refuses redirects to
// bare IP addresses, and the node set is only known by IP.
package acme

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

// Event names emitted by the challenge proxy. Operators should filter on the
// structured "event" field of log lines to track health.
const (
	EventChallengeProxied     = "acme_challenge_proxied"
	EventChallengeProxyMissed = "acme_challenge_proxy_missed"
	EventChallengePeerFailed  = "acme_challenge_peer_failed"
)

// NoProxyParam is the query parameter a node adds when it asks a peer for a
// challenge. A request carrying NoProxyParam=true is answered from local
// state only and is never forwarded again.
const NoProxyParam = "weft-redirect"

// ChallengePathPrefix is the HTTP-01 well-known path prefix (RFC 8555 §8.3).
const ChallengePathPrefix = "/.well-known/acme-challenge/"

// ChallengePort is the port HTTP-01 validation always uses, so it is the port
// every peer serves challenges on.
const ChallengePort = 80

const (
	// peerFetchTimeout bounds the whole fan-out. Let's Encrypt's validator
	// gives up after about 10s, so this leaves room for our own reply.
	peerFetchTimeout = 5 * time.Second
	// maxPeers caps how many DNS records we fan out to per request.
	maxPeers = 16
	// maxKeyAuthBytes caps a peer's response body. A key authorization is
	// "<token>.<thumbprint>", well under 200 bytes.
	maxKeyAuthBytes = 4096
)

// Test seams: overridden in unit tests so the logic can be exercised without
// real DNS, interface state or port-80 listeners. Production callers go
// through net.LookupIP / net.InterfaceAddrs / a plain dialer unchanged.
var (
	lookupIP       = net.LookupIP
	interfaceAddrs = net.InterfaceAddrs
	dialPeer       = func(ctx context.Context, ip net.IP) (net.Conn, error) {
		addr := net.JoinHostPort(ip.String(), fmt.Sprint(ChallengePort))
		return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "tcp", addr)
	}
)

// IsNoProxyRequest reports whether r was forwarded by a peer and so must be
// answered locally.
func IsNoProxyRequest(r *http.Request) bool {
	return r.URL.Query().Get(NoProxyParam) == "true"
}

// LocalIPs returns the non-loopback IPs bound to local network interfaces.
func LocalIPs() ([]net.IP, error) {
	addrs, err := interfaceAddrs()
	if err != nil {
		return nil, err
	}
	var ips []net.IP
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		if ipnet.IP.IsLoopback() {
			continue
		}
		ips = append(ips, ipnet.IP)
	}
	return ips, nil
}

// IsLocalIP reports whether ip is bound to a local network interface.
func IsLocalIP(ip net.IP, locals []net.IP) bool {
	for _, l := range locals {
		if l.Equal(ip) {
			return true
		}
	}
	return false
}

// validToken reports whether token looks like an ACME token: non-empty
// base64url (RFC 8555 §8.1). Anything else can't be a real challenge, so we
// don't spend a fan-out on it.
func validToken(token string) bool {
	if token == "" || len(token) > 256 {
		return false
	}
	for _, c := range token {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}

// peerCandidates returns the DNS records for host that are worth asking:
// not bound locally, and not loopback, link-local or unspecified. The last
// filter keeps a spoofed Host header from pointing the fan-out at the node
// itself or at a cloud metadata endpoint (169.254.169.254).
func peerCandidates(host string) ([]net.IP, error) {
	ips, err := lookupIP(host)
	if err != nil {
		return nil, err
	}
	locals, err := LocalIPs()
	if err != nil {
		return nil, fmt.Errorf("enumerate local IPs: %w", err)
	}
	var out []net.IP
	for _, ip := range ips {
		addr, ok := netip.AddrFromSlice(ip)
		if !ok {
			continue
		}
		addr = addr.Unmap()
		if addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsUnspecified() || addr.IsMulticast() {
			continue
		}
		if IsLocalIP(ip, locals) {
			continue
		}
		out = append(out, ip)
		if len(out) == maxPeers {
			break
		}
	}
	return out, nil
}

// fetchFromPeer asks one peer for path on host with NoProxyParam set and
// returns the body when the peer answers 200.
func fetchFromPeer(ctx context.Context, dial func(context.Context, net.IP) (net.Conn, error), ip net.IP, host, path string) ([]byte, error) {
	u := url.URL{
		Scheme:   "http",
		Host:     host,
		Path:     path,
		RawQuery: url.Values{NoProxyParam: {"true"}}.Encode(),
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return dial(ctx, ip)
			},
			DisableKeepAlives: true,
		},
		// A peer must answer the challenge itself; a redirect means it
		// isn't a weft node (or is misconfigured), so don't follow it.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxKeyAuthBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxKeyAuthBytes {
		return nil, fmt.Errorf("response larger than %d bytes", maxKeyAuthBytes)
	}
	return body, nil
}

// ErrNoPeerAnswered is returned by FetchChallengeFromPeers when no peer in
// the DNS set had the token.
var ErrNoPeerAnswered = errors.New("no peer answered the challenge")

// FetchChallengeFromPeers asks every other node in host's DNS set for the
// challenge at path, in parallel, and returns the first 200 body along with
// the IP of the peer that sent it. path must start with ChallengePathPrefix.
func FetchChallengeFromPeers(ctx context.Context, host, path string) ([]byte, net.IP, error) {
	token := strings.TrimPrefix(path, ChallengePathPrefix)
	if !strings.HasPrefix(path, ChallengePathPrefix) || !validToken(token) {
		return nil, nil, fmt.Errorf("not an ACME challenge path: %q", path)
	}
	peers, err := peerCandidates(host)
	if err != nil {
		log.Warn().Str("event", EventChallengeProxyMissed).Err(err).Str("host", host).Msg("acme-proxy: cannot find peers for host; challenge can only be answered locally")
		return nil, nil, err
	}
	if len(peers) == 0 {
		log.Debug().Str("event", EventChallengeProxyMissed).Str("host", host).Msg("acme-proxy: no other nodes in DNS for host")
		return nil, nil, ErrNoPeerAnswered
	}

	ctx, cancel := context.WithTimeout(ctx, peerFetchTimeout)
	defer cancel()

	type result struct {
		ip   net.IP
		body []byte
		err  error
	}
	// Read the dial seam once: the losing fetches may still be running
	// after we return.
	dial := dialPeer
	results := make(chan result, len(peers))
	for _, ip := range peers {
		go func(ip net.IP) {
			body, err := fetchFromPeer(ctx, dial, ip, host, path)
			results <- result{ip: ip, body: body, err: err}
		}(ip)
	}

	for range peers {
		r := <-results
		if r.err == nil {
			log.Info().Str("event", EventChallengeProxied).Str("host", host).Str("peer", r.ip.String()).Str("token", token).Msg("acme-proxy: relayed challenge answer from peer")
			return r.body, r.ip, nil
		}
		log.Debug().Str("event", EventChallengePeerFailed).Str("host", host).Str("peer", r.ip.String()).Str("token", token).Err(r.err).Msg("acme-proxy: peer did not have the challenge")
	}
	log.Warn().Str("event", EventChallengeProxyMissed).Str("host", host).Int("peers", len(peers)).Str("token", token).Msg("acme-proxy: no node in DNS had the challenge token; validation for this request will fail")
	return nil, nil, ErrNoPeerAnswered
}
