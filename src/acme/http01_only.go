// Package acme: restrict autocert to the HTTP-01 challenge.
//
// autocert always offers the CA a tls-alpn-01 answer first and only falls
// back to http-01 after that authorization fails. With round-robin DNS that
// first attempt can't succeed: the CA validates tls-alpn-01 on :443 of
// whichever node each vantage point resolves, and only the node that placed
// the order holds the challenge certificate. Unlike http-01 (see
// challenge_proxy.go) there is no per-token path to forward on, so siblings
// can't answer for each other.
//
// Every issuance therefore burned one failed authorization before http-01
// got a turn. Let's Encrypt allows 5 failed authorizations per hostname per
// hour, so a host whose tunnel retried a few times got stuck: each attempt
// after the limit lifted burned another failure on tls-alpn-01 and the
// window never cleared (2026-10-30, cooking/openscan on lab0-east).
//
// autocert has no switch for this, so HTTP01OnlyTransport removes
// tls-alpn-01 from the authorizations the CA returns. autocert then picks
// http-01 straight away. The :80 challenge listener stays open for the life
// of the server, so http-01 also covers renewals.
package acme

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// tlsALPN01 is the ACME challenge type removed from authorizations.
const tlsALPN01 = "tls-alpn-01"

// maxACMEBody caps how much of a CA response we buffer to filter. ACME
// authorization objects are a few hundred bytes.
const maxACMEBody = 1 << 20

// HTTP01OnlyTransport wraps base (http.DefaultTransport when nil) so that
// ACME authorization responses no longer list tls-alpn-01 challenges.
// Everything else passes through unchanged.
func HTTP01OnlyTransport(base http.RoundTripper) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	return &http01OnlyTransport{base: base}
}

// NewHTTP01OnlyClient returns an ACME client for autocert.Manager.Client
// that only ever answers http-01. Key is left nil so autocert loads the
// existing account key from its cache.
func NewHTTP01OnlyClient() *acme.Client {
	return &acme.Client{
		DirectoryURL: autocert.DefaultACMEDirectory,
		HTTPClient:   &http.Client{Transport: HTTP01OnlyTransport(nil)},
	}
}

type http01OnlyTransport struct {
	base http.RoundTripper
}

func (t *http01OnlyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	if err != nil || resp.StatusCode != http.StatusOK || !strings.Contains(resp.Header.Get("Content-Type"), "json") {
		return resp, err
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxACMEBody+1))
	resp.Body.Close()
	if err != nil {
		return nil, err
	}
	if len(body) <= maxACMEBody {
		if filtered, ok := dropTLSALPN01(body); ok {
			log.Debug().Str("url", req.URL.String()).Msg("acme: removed tls-alpn-01 from authorization; only http-01 will be attempted")
			body = filtered
		}
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
	return resp, nil
}

// dropTLSALPN01 removes tls-alpn-01 entries from an authorization's
// "challenges" array. It returns ok=false, leaving body untouched, when body
// isn't an authorization or lists no tls-alpn-01 challenge.
func dropTLSALPN01(body []byte) ([]byte, bool) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(body, &obj); err != nil {
		return nil, false
	}
	raw, ok := obj["challenges"]
	if !ok {
		return nil, false
	}
	var challenges []json.RawMessage
	if err := json.Unmarshal(raw, &challenges); err != nil {
		return nil, false
	}
	kept := make([]json.RawMessage, 0, len(challenges))
	for _, c := range challenges {
		var head struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(c, &head); err == nil && head.Type == tlsALPN01 {
			continue
		}
		kept = append(kept, c)
	}
	if len(kept) == len(challenges) {
		return nil, false
	}
	newRaw, err := json.Marshal(kept)
	if err != nil {
		return nil, false
	}
	obj["challenges"] = newRaw
	out, err := json.Marshal(obj)
	if err != nil {
		return nil, false
	}
	return out, true
}
