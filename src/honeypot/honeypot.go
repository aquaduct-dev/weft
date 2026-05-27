// Package honeypot runs a deliberately-exposed set of TCP listeners that
// accept abusive scanner traffic, proceed through each protocol's handshake
// far enough to capture meaningful detail (SSH username/password, HTTP
// method/path/host, TLS SNI), and emit a structured event per attempt.
//
// Events are written via zerolog and optionally POSTed to a remote ingest
// endpoint (e.g. aquaduct.dev's /api/darkforest/ingest) for fleet-wide
// aggregation.
//
// Honeypot mode is *not* a tunnel server. A weft-honeypot bastion should be
// deployed alongside (or instead of) a regular tunnel bastion: the honeypot
// owns ports 22/80/443/etc. and serves no legitimate traffic.
package honeypot

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// Honeypot is a collection of listeners on configured ports. Each connection
// is handed to the per-port handler (HTTP, HTTPS, SSH, or generic TCP) which
// captures details and emits an Event.
type Honeypot struct {
	BindIP   string
	Ports    []int
	Emitter  *Emitter
	listeners []net.Listener
	wg       sync.WaitGroup
}

// New constructs a Honeypot. The caller is expected to call Run() and then
// Shutdown() on signal.
func New(bindIP string, ports []int, emitter *Emitter) *Honeypot {
	return &Honeypot{BindIP: bindIP, Ports: ports, Emitter: emitter}
}

// portHandler dispatches each incoming connection to the right per-protocol
// handler. handlers are picked by the destination port (not by sniffing the
// stream); scanners that hit port 22 expecting SSH get the SSH greeter,
// scanners that hit 80 expecting HTTP get the HTTP reader, etc.
func (h *Honeypot) portHandler(port int) func(context.Context, net.Conn) {
	switch port {
	case 80, 8080, 8000:
		return h.handleHTTP
	case 443, 8443:
		return h.handleHTTPS
	// SSH (22, 2222) lands in a follow-up commit; falls through to TCP
	// catch-all for now.
	default:
		return h.handleTCP
	}
}

// Run starts listening on every configured port. Blocks until the context is
// cancelled. Per-port accept failures are logged but do not tear down the
// other listeners — one bad port shouldn't take the whole pot down.
func (h *Honeypot) Run(ctx context.Context) error {
	if len(h.Ports) == 0 {
		return fmt.Errorf("honeypot: no ports configured")
	}
	addr := h.BindIP
	if addr == "" {
		addr = "0.0.0.0"
	}

	for _, port := range h.Ports {
		ln, err := net.Listen("tcp", net.JoinHostPort(addr, strconv.Itoa(port)))
		if err != nil {
			log.Warn().Err(err).Int("port", port).Msg("honeypot: failed to listen — skipping port")
			continue
		}
		h.listeners = append(h.listeners, ln)
		log.Info().Int("port", port).Str("addr", ln.Addr().String()).Msg("honeypot: listening")
		handler := h.portHandler(port)
		h.wg.Add(1)
		go h.acceptLoop(ctx, ln, port, handler)
	}

	if len(h.listeners) == 0 {
		return fmt.Errorf("honeypot: no listeners bound (all ports failed)")
	}

	<-ctx.Done()
	for _, ln := range h.listeners {
		_ = ln.Close()
	}
	h.wg.Wait()
	return nil
}

func (h *Honeypot) acceptLoop(ctx context.Context, ln net.Listener, port int, handler func(context.Context, net.Conn)) {
	defer h.wg.Done()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			// Transient accept errors — log and continue. A persistent failure
			// will fill the log; that's acceptable since it surfaces the
			// problem to operators.
			if !strings.Contains(err.Error(), "use of closed network connection") {
				log.Warn().Err(err).Int("port", port).Msg("honeypot: accept failed")
			}
			return
		}
		h.wg.Add(1)
		go func(c net.Conn) {
			defer h.wg.Done()
			defer c.Close()
			// Per-connection timeout — scanners often abandon mid-stream.
			// 5s is enough for HTTP/TLS/SSH handshakes; bail otherwise.
			deadline := time.Now().Add(5 * time.Second)
			_ = c.SetDeadline(deadline)
			cctx, cancel := context.WithDeadline(ctx, deadline)
			defer cancel()
			handler(cctx, c)
		}(conn)
	}
}
