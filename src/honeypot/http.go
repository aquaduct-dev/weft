package honeypot

import (
	"bufio"
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"strings"
)

// suspiciousPathSubstrings are fragments common in opportunistic exploit and
// credential probes. A request whose path contains any of these is tagged
// `exploit_probe`; anything else against the HTTP honeypot is `port_scan`.
// Intentionally case-insensitive (compared against strings.ToLower(path)).
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

// classifyHTTPPath buckets an inbound HTTP request into an EventType. The
// goal is good-enough categorisation for the visualization, not security
// detection — false positives are fine (a curious legitimate request
// looking at /.env is also abusive from this bastion's perspective: the
// honeypot owns no real services).
func classifyHTTPPath(path string) EventType {
	low := strings.ToLower(path)
	for _, s := range suspiciousPathSubstrings {
		if strings.Contains(low, s) {
			return TypeExploitProbe
		}
	}
	return TypePortScan
}

// handleHTTP reads one HTTP request off the connection, emits an event with
// the request line, host, user-agent, and a small classification, then
// returns a fake nginx-shaped 404 so the scanner sees a "plausible" reply
// and doesn't immediately retry on a different port.
func (h *Honeypot) handleHTTP(ctx context.Context, conn net.Conn) {
	srcIP, srcPort := splitHostPort(conn.RemoteAddr())
	_, dstPort := splitHostPort(conn.LocalAddr())

	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)

	detail := map[string]string{}
	var (
		method, path, hostHeader, ua string
		evType                       EventType
	)

	if req != nil {
		method = req.Method
		path = req.URL.RequestURI()
		hostHeader = req.Host
		ua = req.Header.Get("User-Agent")
		evType = classifyHTTPPath(path)
		if method == http.MethodPost && (strings.Contains(strings.ToLower(path), "login") || strings.Contains(strings.ToLower(path), "signin")) {
			evType = TypeCredentialStuffing
		}
		detail["method"] = method
		detail["path"] = path
		if hostHeader != "" {
			detail["host"] = hostHeader
		}
		if ua != "" {
			detail["user_agent"] = ua
		}
		if ref := req.Header.Get("Referer"); ref != "" {
			detail["referer"] = ref
		}
	} else {
		evType = TypePortScan
		if err != nil {
			detail["parse_err"] = err.Error()
		}
	}

	h.Emitter.Emit(Event{
		SrcIP:    srcIP,
		SrcPort:  srcPort,
		DstPort:  dstPort,
		Protocol: protocolForHTTPPort(dstPort, false),
		Type:     evType,
		Detail:   detail,
	})

	// Fake response — looks like a vanilla nginx 404 so scanners don't
	// fingerprint us as obviously a honeypot. We never advertise real
	// services, so 404 is honest.
	_, _ = conn.Write([]byte("HTTP/1.1 404 Not Found\r\n" +
		"Server: nginx\r\n" +
		"Content-Type: text/html\r\n" +
		"Content-Length: 0\r\n" +
		"Connection: close\r\n\r\n"))
}

// handleHTTPS terminates TLS with a self-signed certificate, captures the
// SNI presented by the client, then hands the decrypted stream to the HTTP
// handler. Most scanners proceed straight to an HTTP request after the
// handshake; we get the full HTTP detail plus the TLS metadata.
func (h *Honeypot) handleHTTPS(ctx context.Context, conn net.Conn) {
	srcIP, srcPort := splitHostPort(conn.RemoteAddr())
	_, dstPort := splitHostPort(conn.LocalAddr())

	var capturedSNI, capturedALPN string
	cfg := tlsConfigWithCapture(&capturedSNI, &capturedALPN)
	tlsConn := tls.Server(conn, cfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		// TLS handshake failed — still a useful event. We have the SNI if
		// the client got that far, plus the error reason.
		detail := map[string]string{"tls_handshake_err": err.Error()}
		if capturedSNI != "" {
			detail["sni"] = capturedSNI
		}
		h.Emitter.Emit(Event{
			SrcIP:    srcIP,
			SrcPort:  srcPort,
			DstPort:  dstPort,
			Protocol: "https",
			Type:     TypePortScan,
			Detail:   detail,
		})
		return
	}

	// At this point TLS is up. Read one HTTP request and emit a single
	// event tagging both the TLS and HTTP fields. We don't reuse
	// handleHTTP directly because we want to merge SNI/ALPN into the
	// same Detail map rather than emit two separate events.
	br := bufio.NewReader(tlsConn)
	req, err := http.ReadRequest(br)
	detail := map[string]string{}
	if capturedSNI != "" {
		detail["sni"] = capturedSNI
	}
	if capturedALPN != "" {
		detail["alpn"] = capturedALPN
	}
	var evType EventType
	if req != nil {
		method := req.Method
		path := req.URL.RequestURI()
		detail["method"] = method
		detail["path"] = path
		if req.Host != "" {
			detail["host"] = req.Host
		}
		if ua := req.Header.Get("User-Agent"); ua != "" {
			detail["user_agent"] = ua
		}
		evType = classifyHTTPPath(path)
		if method == http.MethodPost && (strings.Contains(strings.ToLower(path), "login") || strings.Contains(strings.ToLower(path), "signin")) {
			evType = TypeCredentialStuffing
		}
	} else {
		evType = TypePortScan
		if err != nil {
			detail["read_err"] = err.Error()
		}
	}

	h.Emitter.Emit(Event{
		SrcIP:    srcIP,
		SrcPort:  srcPort,
		DstPort:  dstPort,
		Protocol: protocolForHTTPPort(dstPort, true),
		Type:     evType,
		Detail:   detail,
	})

	_, _ = tlsConn.Write([]byte("HTTP/1.1 404 Not Found\r\n" +
		"Server: nginx\r\n" +
		"Content-Type: text/html\r\n" +
		"Content-Length: 0\r\n" +
		"Connection: close\r\n\r\n"))
}

// protocolForHTTPPort decides the `protocol` field. Standard ports map to
// "http"/"https"; non-standard ports get the "<proto>:<port>" form so the
// audit log distinguishes scanners hitting 80 from those hitting 8080.
func protocolForHTTPPort(port int, tlsEnabled bool) string {
	if tlsEnabled {
		if port == 443 {
			return "https"
		}
		return "https:" + itoa(port)
	}
	if port == 80 {
		return "http"
	}
	return "http:" + itoa(port)
}
