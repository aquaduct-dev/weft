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
//
// canFallThrough is true when host has a plain HTTP route on this port and
// weft isn't issuing its certificate. Then the challenge may belong to the
// user's own ACME client behind the tunnel: if neither we nor a sibling has
// the token, serveChallenge writes nothing and returns false, and the caller
// routes the request to the backend like any other.
//
// It returns true when it wrote a response.
func (m *VHostProxyManager) serveChallenge(w http.ResponseWriter, r *http.Request, host string, canFallThrough bool) bool {
	handler := m.acmeManager.HTTPHandler(nil)

	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		if canFallThrough {
			return false
		}
		handler.ServeHTTP(w, r)
		return true
	}

	local := &bufferedResponse{header: make(http.Header)}
	handler.ServeHTTP(local, r)
	if local.code == http.StatusOK {
		log.Debug().Str("host", host).Str("path", r.URL.Path).Msg("acme-proxy: answered challenge locally")
		local.copyTo(w)
		return true
	}

	// A peer asked us directly: answer from our own state (autocert, or the
	// backend if we fall through), never forward to peers again. That is
	// what keeps the fan-out from looping.
	if acme.IsNoProxyRequest(r) {
		if canFallThrough {
			stripNoProxyParam(r)
			log.Debug().Str("host", host).Str("path", r.URL.Path).Msg("acme-proxy: peer request not ours; passing to the host's own route")
			return false
		}
		local.copyTo(w)
		return true
	}

	body, peer, err := acme.FetchChallengeFromPeers(r.Context(), host, r.URL.Path)
	if err != nil {
		if canFallThrough {
			log.Debug().Str("host", host).Str("path", r.URL.Path).Err(err).Msg("acme-proxy: no weft node has the token; passing to the host's own route")
			return false
		}
		// No node had it: return our own answer (404 for an unknown token,
		// 403 for a host we don't issue for).
		log.Debug().Str("host", host).Str("path", r.URL.Path).Int("local_status", local.code).Err(err).Msg("acme-proxy: no peer answered; returning local response")
		local.copyTo(w)
		return true
	}
	log.Debug().Str("host", host).Str("path", r.URL.Path).Str("peer", peer.String()).Msg("acme-proxy: serving peer's challenge answer")
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(body)
	}
	return true
}

// stripNoProxyParam removes weft's internal marker before a request goes to
// a user's backend.
func stripNoProxyParam(r *http.Request) {
	q := r.URL.Query()
	q.Del(acme.NoProxyParam)
	r.URL.RawQuery = q.Encode()
	r.RequestURI = r.URL.RequestURI()
}

// isACMEHost reports whether weft is issuing host's certificate.
func (m *VHostProxyManager) isACMEHost(host string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.acmeHosts[host]
}
