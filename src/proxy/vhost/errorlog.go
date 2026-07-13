package vhost

import (
	"strings"

	"github.com/rs/zerolog/log"
)

// httpErrorLogWriter is plugged into http.Server.ErrorLog so net/http's
// unstructured error lines are routed through zerolog rather than written raw
// to stderr. TLS handshake errors (`http: TLS handshake error from ...`) fire
// constantly on internet-exposed bastions — typically scanners that don't
// speak modern TLS — so they're logged at debug; anything else is surfaced as
// a warning so it stays visible.
type httpErrorLogWriter struct {
	port int
}

const tlsHandshakeErrPrefix = "http: TLS handshake error from "

func (w *httpErrorLogWriter) Write(p []byte) (int, error) {
	line := strings.TrimRight(string(p), "\n")
	if strings.HasPrefix(line, tlsHandshakeErrPrefix) {
		log.Debug().Int("port", w.port).Str("line", line).Msg("vhost: tls handshake error")
		return len(p), nil
	}
	log.Warn().Int("port", w.port).Str("line", line).Msg("vhost: http server error")
	return len(p), nil
}
