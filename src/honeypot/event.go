package honeypot

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// EventType is the small enumeration of attack shapes the dark-forest
// visualization renders distinctly. Keep in sync with the schema enum on the
// aquaduct service side (bastion_attack_events.type column).
type EventType string

const (
	TypePortScan          EventType = "port_scan"
	TypeExploitProbe      EventType = "exploit_probe"
	TypeLoginFailure      EventType = "login_failure"
	TypeBruteForce        EventType = "brute_force"
	TypeCredentialStuffing EventType = "credential_stuffing"
)

// Event is one observed attack attempt. Fields mirror what
// /api/darkforest/ingest accepts (camel-snake to match the JSON shape on the
// service side); the same value is logged via zerolog and POSTed to the
// remote ingest URL when configured.
type Event struct {
	TSMillis  int64     `json:"ts_millis"`
	SrcIP     string    `json:"src_ip"`
	SrcPort   int       `json:"src_port,omitempty"`
	DstHost   string    `json:"dst_host"` // honeypot hostname (DNS or IP)
	DstPort   int       `json:"dst_port"`
	Protocol  string    `json:"protocol"` // ssh, http, https, tcp, ...
	Type      EventType `json:"type"`
	Username  string    `json:"username,omitempty"`
	// Detail is a compact freeform string — protocol-specific captures
	// (HTTP method+path, TLS SNI, ssh client version, banner-grab string).
	// Kept here for the audit log; the ingest endpoint receives the same
	// info in the structured fields, and the service stores it in a JSONB
	// `details` column for queries.
	Detail map[string]string `json:"detail,omitempty"`
}

// Emitter writes events to zerolog and (optionally) POSTs them to a remote
// ingest endpoint. Calls to Emit are safe from any goroutine; the HTTP
// posting is fire-and-forget on a small fan-out worker pool so that slow
// ingest doesn't slow accept loops.
type Emitter struct {
	IngestURL    string
	IngestSecret string
	DstHost      string // identity for the dst_host field (defaults to os.Hostname)

	client *http.Client
	queue  chan Event
	wg     sync.WaitGroup
}

// NewEmitter builds an Emitter. If ingestURL is empty the emitter only
// writes to the log — useful for local debugging.
func NewEmitter(ingestURL, ingestSecret, dstHost string) *Emitter {
	if dstHost == "" {
		dstHost, _ = os.Hostname()
	}
	e := &Emitter{
		IngestURL:    ingestURL,
		IngestSecret: ingestSecret,
		DstHost:      dstHost,
		client:       &http.Client{Timeout: 5 * time.Second},
		queue:        make(chan Event, 256),
	}
	if ingestURL != "" {
		// Small fan-out: 4 workers is enough for our peak rate; a slow
		// ingest just backpressures into the queue, and a full queue
		// drops events with a warn log (vs slowing accept loops).
		for i := 0; i < 4; i++ {
			e.wg.Add(1)
			go e.worker()
		}
	}
	return e
}

func (e *Emitter) worker() {
	defer e.wg.Done()
	for ev := range e.queue {
		if err := e.post(ev); err != nil {
			log.Warn().Err(err).Str("src_ip", ev.SrcIP).Int("dst_port", ev.DstPort).Msg("honeypot: ingest POST failed")
		}
	}
}

// post sends a single event as a 1-event batch to the ingest endpoint. The
// remote schema currently expects {"events":[...]}; we don't yet batch
// adjacent events because honeypot rates are low and individual latency is
// fine.
func (e *Emitter) post(ev Event) error {
	body, err := json.Marshal(map[string]any{"events": []Event{ev}})
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, e.IngestURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if e.IngestSecret != "" {
		req.Header.Set("X-Darkforest-Secret", e.IngestSecret)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("ingest returned %d", resp.StatusCode)
	}
	return nil
}

// Emit logs and (best-effort) ships the event. Returns immediately.
func (e *Emitter) Emit(ev Event) {
	if ev.TSMillis == 0 {
		ev.TSMillis = time.Now().UnixMilli()
	}
	if ev.DstHost == "" {
		ev.DstHost = e.DstHost
	}
	logEvent(ev)
	if e.IngestURL == "" {
		return
	}
	select {
	case e.queue <- ev:
	default:
		log.Warn().Str("src_ip", ev.SrcIP).Msg("honeypot: ingest queue full, dropping event")
	}
}

// Shutdown drains the ingest queue and waits for workers to finish.
func (e *Emitter) Shutdown(ctx context.Context) error {
	close(e.queue)
	done := make(chan struct{})
	go func() { e.wg.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// logEvent emits one zerolog Info line per event. Keeping protocol-specific
// details in a structured nested map lets operators grep by `src_ip` or
// `dst_port` without giving up the full capture.
func logEvent(ev Event) {
	z := log.Info().
		Str("event", "honeypot_attempt").
		Str("src_ip", ev.SrcIP).
		Int("src_port", ev.SrcPort).
		Str("dst_host", ev.DstHost).
		Int("dst_port", ev.DstPort).
		Str("protocol", ev.Protocol).
		Str("type", string(ev.Type))
	if ev.Username != "" {
		z = z.Str("username", ev.Username)
	}
	if len(ev.Detail) > 0 {
		z = z.Interface("detail", ev.Detail)
	}
	z.Msg("honeypot attempt")
}

// splitHostPort safely extracts the source IP+port from a net.Addr;
// scanners using raw IPv6 or weird formats won't crash the accept loop.
func splitHostPort(addr net.Addr) (string, int) {
	host, portStr, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String(), 0
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

// ParsePorts parses a comma-separated list of port numbers, ignoring blanks.
// Returns an error if any token isn't a valid port number.
func ParsePorts(s string) ([]int, error) {
	if strings.TrimSpace(s) == "" {
		return nil, errors.New("empty port list")
	}
	out := []int{}
	for _, tok := range strings.Split(s, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		n := 0
		for i := 0; i < len(tok); i++ {
			c := tok[i]
			if c < '0' || c > '9' {
				return nil, fmt.Errorf("invalid port %q", tok)
			}
			n = n*10 + int(c-'0')
		}
		if n < 1 || n > 65535 {
			return nil, fmt.Errorf("port %d out of range", n)
		}
		out = append(out, n)
	}
	return out, nil
}
