// Serving HTTP-01 challenges when several nodes share a hostname.
//
// Every request under /.well-known/acme-challenge/ on the ACME port lands
// here. We answer from our own autocert state first. If autocert doesn't have
// a 200 for the token (another node placed the order), we ask the other nodes
// in the host's DNS set and relay the first 200. Requests a peer forwarded to
// us carry acme.NoProxyParam and are answered locally only, so the fan-out is
// a single hop. See src/acme/challenge_proxy.go for the full rationale.
package vhost

import (
	"bytes"
	"net/http"

	"github.com/aquaduct-dev/weft/src/acme"
	"github.com/rs/zerolog/log"
)

// bufferedResponse captures a handler's response so we can decide whether to
// send it or replace it with a peer's answer.
type bufferedResponse struct {
	header http.Header
	code   int
	body   bytes.Buffer
}

func (b *bufferedResponse) Header() http.Header { return b.header }

func (b *bufferedResponse) WriteHeader(code int) {
	if b.code == 0 {
		b.code = code
	}
}

func (b *bufferedResponse) Write(p []byte) (int, error) {
	if b.code == 0 {
		b.code = http.StatusOK
	}
	return b.body.Write(p)
}

// copyTo writes the captured response to w.
func (b *bufferedResponse) copyTo(w http.ResponseWriter) {
	for k, v := range b.header {
		w.Header()[k] = v
	}
	code := b.code
	if code == 0 {
		code = http.StatusOK
	}
	w.WriteHeader(code)
	_, _ = w.Write(b.body.Bytes())
}

// serveChallenge answers an HTTP-01 challenge request for host, locally if we
// can and otherwise by relaying a sibling node's answer.
func (m *VHostProxyManager) serveChallenge(w http.ResponseWriter, r *http.Request, host string) {
	handler := m.acmeManager.HTTPHandler(nil)

	// A peer asked us directly: answer from our own state only, never
	// forward again. That is what keeps the fan-out from looping.
	if acme.IsNoProxyRequest(r) {
		handler.ServeHTTP(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		handler.ServeHTTP(w, r)
		return
	}

	local := &bufferedResponse{header: make(http.Header)}
	handler.ServeHTTP(local, r)
	if local.code == http.StatusOK {
		log.Debug().Str("host", host).Str("path", r.URL.Path).Msg("acme-proxy: answered challenge locally")
		local.copyTo(w)
		return
	}

	body, peer, err := acme.FetchChallengeFromPeers(r.Context(), host, r.URL.Path)
	if err != nil {
		// No node had it: return our own answer (404 for an unknown token,
		// 403 for a host we don't issue for).
		log.Debug().Str("host", host).Str("path", r.URL.Path).Int("local_status", local.code).Err(err).Msg("acme-proxy: no peer answered; returning local response")
		local.copyTo(w)
		return
	}
	log.Debug().Str("host", host).Str("path", r.URL.Path).Str("peer", peer.String()).Msg("acme-proxy: serving peer's challenge answer")
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(body)
	}
}
