// Receiver-side ACME challenge redirect coordination.
//
// The /acme-redirect HTTP endpoint lives on the weft server (control plane,
// see src/server). After validating the inbound IP appears in DNS for the
// host, the server calls RegisterPeerRedirect on the VHostProxyManager. The
// vhost's challenge handler at /.well-known/acme-challenge/* then 301-
// redirects to the registered peer.
//
// When no peer has registered, the challenge handler falls back to the
// "leader" rule: 301 to the highest-IP entry in DNS for the host, or serve
// directly if this node is the highest IP. See src/acme/acme_redirect.go for
// the full trust model.
package vhost

import (
	"fmt"
	"net/http"
	"time"

	"github.com/aquaduct-dev/weft/src/acme"
	"github.com/rs/zerolog/log"
)

// peerRedirect records a peer's request to forward HTTP-01 challenges for a
// host to that peer's IP. Entries auto-expire if not refreshed.
type peerRedirect struct {
	peerIP  string
	expires time.Time
}

// peerRedirectTTL is how long a registration is honored without a refresh.
// The sender re-POSTs every ~30s in the steady-state loop; 5 minutes leaves
// generous slack for transient peer drops without the registration going stale
// on the receiver.
const peerRedirectTTL = 5 * time.Minute

// RegisterPeerRedirect stores a peer's redirect request for host. The caller
// (the /acme-redirect HTTP handler) MUST validate the peer's IP appears in
// DNS for host before calling this.
func (m *VHostProxyManager) RegisterPeerRedirect(host, peerIP string) {
	m.redirectsMu.Lock()
	if m.redirects == nil {
		m.redirects = make(map[string]peerRedirect)
	}
	m.redirects[host] = peerRedirect{
		peerIP:  peerIP,
		expires: time.Now().Add(peerRedirectTTL),
	}
	m.redirectsMu.Unlock()
	log.Info().Str("event", acme.EventRedirectRegistered).Str("host", host).Str("peer", peerIP).Msg("acme-redirect: registered peer for host")
}

// lookupPeerRedirect returns the peer IP registered for host if a non-expired
// entry exists, deleting expired entries on the way.
func (m *VHostProxyManager) lookupPeerRedirect(host string) (string, bool) {
	m.redirectsMu.Lock()
	defer m.redirectsMu.Unlock()
	e, ok := m.redirects[host]
	if !ok {
		return "", false
	}
	if time.Now().After(e.expires) {
		delete(m.redirects, host)
		return "", false
	}
	return e.peerIP, true
}

// tryRedirectChallenge implements the redirect logic for /.well-known/acme-challenge/*
// requests. Returns true if a redirect was issued (and the caller should not
// fall through to autocert); false if the caller should hand the request to
// autocert as usual.
//
// Order of operations:
//  1. If a peer has POSTed /acme-redirect for this host: 301 to that peer.
//  2. If we're running our own ACME order for this host (host is in acmeHosts):
//     fall through so autocert can serve the keyAuth.
//  3. Cold-start fallback: 301 to the highest-IP entry in DNS for host, unless
//     we ARE that highest IP (in which case fall through to autocert).
func (m *VHostProxyManager) tryRedirectChallenge(w http.ResponseWriter, r *http.Request, host string) bool {
	if peerIP, ok := m.lookupPeerRedirect(host); ok {
		target := fmt.Sprintf("http://%s%s", peerIP, r.URL.RequestURI())
		log.Info().Str("event", acme.EventChallengeRedirected).Str("host", host).Str("target", peerIP).Str("source", "peer_registration").Msg("acme-redirect: redirecting challenge to registered peer")
		http.Redirect(w, r, target, http.StatusMovedPermanently)
		return true
	}

	m.mu.Lock()
	isOurHost := m.acmeHosts[host]
	m.mu.Unlock()
	if isOurHost {
		return false
	}

	locals, err := acme.LocalIPs()
	if err != nil {
		log.Warn().Err(err).Str("host", host).Msg("acme-redirect: cannot enumerate local IPs; cannot decide leader; falling through to autocert")
		return false
	}
	peers, err := acme.DescendingPeerIPs(host)
	if err != nil || len(peers) == 0 {
		log.Warn().Err(err).Str("host", host).Msg("acme-redirect: DNS lookup empty or failed; cannot pick highest-IP fallback")
		return false
	}
	highest := peers[0]
	if acme.IsLocalIP(highest, locals) {
		return false
	}
	target := fmt.Sprintf("http://%s%s", highest.String(), r.URL.RequestURI())
	log.Info().Str("event", acme.EventChallengeRedirected).Str("host", host).Str("target", highest.String()).Str("source", "highest_ip_fallback").Msg("acme-redirect: redirecting challenge to highest-IP fallback")
	http.Redirect(w, r, target, http.StatusMovedPermanently)
	return true
}
