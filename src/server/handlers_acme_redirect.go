// Handler for POST /acme-redirect.
//
// A peer weft server POSTs here when it wants this server to 301-redirect
// /.well-known/acme-challenge/* requests for a given host to the peer's IP.
// We register the redirect only after confirming the peer's source IP appears
// in DNS A records for the host. The trust model is documented in
// src/acme/acme_redirect.go: we trust public DNS, an attacker who can edit DNS
// for the host can already obtain a cert via plain HTTP-01.
package server

import (
	"net"
	"net/http"

	"github.com/aquaduct-dev/weft/src/acme"
	"github.com/rs/zerolog/log"
)

// lookupIP is a test seam — production code uses net.LookupIP unchanged.
var lookupIP = net.LookupIP

// ACMERedirectHandler accepts POST /acme-redirect?host=<host>. On success it
// records the redirect via the Dataplane and returns 204. On any failure it
// logs a warning naming the offending IP so operators can chase forwarding
// problems without grepping debug logs.
func (s *Server) ACMERedirectHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	host := r.URL.Query().Get("host")
	if host == "" {
		http.Error(w, "missing host", http.StatusBadRequest)
		return
	}

	senderHost, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		log.Warn().Str("event", acme.EventRedirectRejected).Str("remote_addr", r.RemoteAddr).Str("host", host).Msg("acme-redirect: cannot parse remote address; cannot set up forwarding")
		http.Error(w, "cannot parse remote addr", http.StatusBadRequest)
		return
	}
	senderIP := net.ParseIP(senderHost)
	if senderIP == nil {
		log.Warn().Str("event", acme.EventRedirectRejected).Str("offending_ip", senderHost).Str("host", host).Msg("acme-redirect: invalid sender IP; cannot set up forwarding")
		http.Error(w, "invalid sender IP", http.StatusBadRequest)
		return
	}

	ips, err := lookupIP(host)
	if err != nil {
		log.Warn().Str("event", acme.EventRedirectRejected).Err(err).Str("offending_ip", senderHost).Str("host", host).Msg("acme-redirect: DNS lookup failed; cannot set up forwarding")
		http.Error(w, "dns lookup failed", http.StatusInternalServerError)
		return
	}

	inSet := false
	for _, ip := range ips {
		if ip.Equal(senderIP) {
			inSet = true
			break
		}
	}
	if !inSet {
		log.Warn().Str("event", acme.EventRedirectRejected).Str("offending_ip", senderHost).Str("host", host).Msg("acme-redirect: sender IP not in DNS for host; cannot set up forwarding")
		http.Error(w, "sender IP not in DNS for host", http.StatusForbidden)
		return
	}

	if err := s.Dataplane.RegisterACMERedirect(host, senderHost); err != nil {
		log.Warn().Str("event", acme.EventRedirectRejected).Err(err).Str("offending_ip", senderHost).Str("host", host).Msg("acme-redirect: failed to register; cannot set up forwarding")
		http.Error(w, "failed to register", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
