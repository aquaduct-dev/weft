package vhost

import (
	"net"
	"net/http"
	"strings"

	"github.com/aquaduct-dev/weft/src/honeypot"
	"github.com/rs/zerolog/log"
)

// emitUnmatchedHTTPEvent records one honeypot event for an HTTP request that
// landed on the default 404 handler. Called only when an emitter is
// installed; the unmatched-host path is the highest-signal abuse signal weft
// can see — every byte of detail (method, path, UA, referer) goes through.
func emitUnmatchedHTTPEvent(em *honeypot.Emitter, r *http.Request, port int, isTLS bool) {
	srcIP, srcPort := splitConnAddr(r.RemoteAddr)

	detail := map[string]string{
		"method": r.Method,
		"path":   r.URL.RequestURI(),
	}
	if r.Host != "" {
		detail["host"] = r.Host
	}
	if ua := r.Header.Get("User-Agent"); ua != "" {
		detail["user_agent"] = ua
	}
	if ref := r.Header.Get("Referer"); ref != "" {
		detail["referer"] = ref
	}

	em.Emit(honeypot.Event{
		SrcIP:    srcIP,
		SrcPort:  srcPort,
		DstPort:  port,
		Protocol: httpProtocolForPort(port, isTLS),
		Type:     classifyHTTPPath(r.URL.RequestURI(), r.Method),
		Detail:   detail,
	})
}

func httpProtocolForPort(port int, isTLS bool) string {
	if isTLS {
		if port == 443 {
			return "https"
		}
		return "https"
	}
	if port == 80 {
		return "http"
	}
	return "http"
}

// suspiciousPathSubstrings — same list used by the standalone honeypot's
// HTTP handler. Duplicated here rather than imported so vhost stays a leaf
// dependency of honeypot (avoids a circular import path through honeypot).
var suspiciousPathSubstrings = []string{
	".env", ".git", ".aws", ".ssh", ".htaccess",
	"wp-login", "wp-admin", "wp-config",
	"phpmyadmin", "phpinfo",
	"admin/login", "admin.php", "manager/html",
	"shell.php", "cmd.php", "eval.php", "backdoor",
	"cgi-bin",
	"actuator/", "/api/v1/secret",
	"console/", "jenkins/",
	"druid/index.html", "solr/",
	"hudson",
	"struts2", "owa/", "ews/exchange.asmx",
}

func classifyHTTPPath(path, method string) honeypot.EventType {
	low := strings.ToLower(path)
	for _, s := range suspiciousPathSubstrings {
		if strings.Contains(low, s) {
			return honeypot.TypeExploitProbe
		}
	}
	if method == http.MethodPost && (strings.Contains(low, "login") || strings.Contains(low, "signin")) {
		return honeypot.TypeCredentialStuffing
	}
	return honeypot.TypePortScan
}

func splitConnAddr(addr string) (string, int) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return addr, 0
	}
	port := 0
	for i := 0; i < len(portStr); i++ {
		c := portStr[i]
		if c < '0' || c > '9' {
			return host, 0
		}
		port = port*10 + int(c-'0')
	}
	return host, port
}

// httpErrorLogWriter is plugged into http.Server.ErrorLog. net/http writes
// lines like `http: TLS handshake error from <ip>:<port>: <reason>` for
// every failed TLS handshake — typically a scanner that doesn't speak modern
// TLS. We parse those lines into structured honeypot events; everything
// else passes through as a debug log so we don't lose any context.
type httpErrorLogWriter struct {
	port    int
	manager *VHostProxyManager
}

const tlsHandshakeErrPrefix = "http: TLS handshake error from "

func (w *httpErrorLogWriter) Write(p []byte) (int, error) {
	em := w.manager.honeypotEmitterLoaded()
	line := strings.TrimRight(string(p), "\n")

	if strings.HasPrefix(line, tlsHandshakeErrPrefix) {
		if em != nil {
			rest := line[len(tlsHandshakeErrPrefix):]
			sep := strings.Index(rest, ": ")
			if sep > 0 {
				addr := rest[:sep]
				reason := rest[sep+2:]
				srcIP, srcPort := splitConnAddr(addr)
				em.Emit(honeypot.Event{
					SrcIP:    srcIP,
					SrcPort:  srcPort,
					DstPort:  w.port,
					Protocol: "https",
					Type:     classifyTLSError(reason),
					Detail: map[string]string{
						"tls_handshake_err": reason,
					},
				})
			}
		}
		// Keep the visible log volume low — these lines fire constantly on
		// internet-exposed bastions. The structured event is sufficient.
		log.Debug().Str("line", line).Msg("vhost: tls handshake error (emitted as honeypot event)")
		return len(p), nil
	}

	// Non-TLS-error lines from http.Server fall through to a warn log so
	// they're at least visible — these tend to be transient proxy errors
	// (context cancelled, etc.) and don't reach the honeypot pipeline.
	log.Warn().Str("line", line).Msg("vhost: http server error")
	return len(p), nil
}

// classifyTLSError buckets the net/http error reason into a honeypot event
// type. Most fall under exploit_probe (broken/ancient TLS = scanner
// fingerprinting); a few specific reasons map cleanly to port_scan.
func classifyTLSError(reason string) honeypot.EventType {
	low := strings.ToLower(reason)
	switch {
	case strings.Contains(low, "first record does not look like a tls handshake"),
		strings.Contains(low, "client sent an http request to an https server"),
		strings.Contains(low, "unsupported sslv2 handshake"):
		return honeypot.TypeExploitProbe
	case strings.Contains(low, "client offered only unsupported versions"),
		strings.Contains(low, "no cipher suite supported"),
		strings.Contains(low, "unsupported application protocols"):
		return honeypot.TypeExploitProbe
	default:
		return honeypot.TypePortScan
	}
}
