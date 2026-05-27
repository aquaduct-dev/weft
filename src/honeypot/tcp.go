package honeypot

import (
	"context"
	"io"
	"net"
	"unicode"
)

// handleTCP is the catch-all per-port handler used when no protocol-specific
// handler is registered. It records a port_scan event, then reads up to
// 256 bytes of whatever the scanner sent (most scanners send a banner-grab
// payload or nothing) so the audit log has at least *some* fingerprintable
// content.
func (h *Honeypot) handleTCP(ctx context.Context, conn net.Conn) {
	srcIP, srcPort := splitHostPort(conn.RemoteAddr())
	_, dstPort := splitHostPort(conn.LocalAddr())

	detail := map[string]string{}
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if n > 0 {
		// Keep the captured banner human-grokable in the log line; raw
		// bytes will be everywhere in scanner traffic and explode the
		// audit log.
		detail["banner"] = printableASCII(buf[:n])
		detail["banner_len"] = itoa(n)
	}
	if err != nil && err != io.EOF {
		detail["read_err"] = err.Error()
	}

	h.Emitter.Emit(Event{
		SrcIP:    srcIP,
		SrcPort:  srcPort,
		DstPort:  dstPort,
		Protocol: "tcp",
		Type:     TypePortScan,
		Detail:   detail,
	})
}

// printableASCII returns a copy of p with non-printable / non-ASCII bytes
// replaced by `.`. Keeps the log line on a single line and immune to escape
// sequences scanners sometimes inject.
func printableASCII(p []byte) string {
	out := make([]byte, len(p))
	for i, b := range p {
		if b < 0x20 || b > 0x7e || !unicode.IsPrint(rune(b)) {
			out[i] = '.'
		} else {
			out[i] = b
		}
	}
	return string(out)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
