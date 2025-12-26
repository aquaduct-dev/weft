package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// HTTPUsageReporter periodically reports tunnel usage statistics to an external
// HTTP endpoint. It implements graceful shutdown and can report usage for specific
// tunnels on demand.
type HTTPUsageReporter struct {
	url         string
	interval    time.Duration
	getCounters func() map[string]ProxyCounters
	getPeers    func() map[string]Peer
	closing     func() bool

	stopCh chan struct{}
	wg     sync.WaitGroup
}

// NewHTTPUsageReporter creates a new usage reporter that sends reports to the given URL.
// Parameters:
//   - url: the HTTP endpoint to POST usage reports to
//   - interval: how often to send periodic reports
//   - getCounters: function to retrieve current proxy traffic counters
//   - getPeers: function to retrieve current tunnel peers
//   - closing: function that returns true if the server is shutting down
func NewHTTPUsageReporter(
	url string,
	interval time.Duration,
	getCounters func() map[string]ProxyCounters,
	getPeers func() map[string]Peer,
	closing func() bool,
) *HTTPUsageReporter {
	return &HTTPUsageReporter{
		url:         url,
		interval:    interval,
		getCounters: getCounters,
		getPeers:    getPeers,
		closing:     closing,
		stopCh:      make(chan struct{}),
	}
}

// Start begins the periodic usage reporting loop in a background goroutine.
// If the URL is empty, this is a no-op.
func (r *HTTPUsageReporter) Start() {
	if r.url == "" {
		return
	}
	r.wg.Add(1)
	go r.run()
}

// Stop signals the reporter to stop and waits for it to finish.
func (r *HTTPUsageReporter) Stop() {
	if r.url == "" {
		return
	}
	close(r.stopCh)
	r.wg.Wait()
}

func (r *HTTPUsageReporter) run() {
	defer r.wg.Done()

	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()

	for {
		select {
		case <-r.stopCh:
			return
		case <-ticker.C:
			r.ReportUsage(context.Background(), nil)
		}
	}
}

// ReportUsage sends usage statistics for the specified tunnels (or all tunnels if nil).
// This can be called directly for on-demand reporting (e.g., before tunnel cleanup).
func (r *HTTPUsageReporter) ReportUsage(ctx context.Context, tunnels []string) {
	if r.url == "" {
		return
	}
	if r.closing() {
		return
	}

	proxies := r.getCounters()
	peers := r.getPeers()
	var report UsageReport

	if tunnels == nil {
		// Report all tunnels
		for name, p := range peers {
			if counters, ok := proxies[name]; ok {
				report.Tunnels = append(report.Tunnels, TunnelUsage{
					TunnelName:  name,
					InstanceId:  counters.InstanceId,
					BytesTx:     counters.Tx,
					BytesRx:     counters.Rx,
					Source:      p.ProxiedUpstream,
					Destination: p.DstURL,
				})
			}
		}
	} else {
		// Report specific tunnels
		for _, name := range tunnels {
			if counters, ok := proxies[name]; ok {
				if p, ok := peers[name]; ok {
					report.Tunnels = append(report.Tunnels, TunnelUsage{
						TunnelName:  name,
						InstanceId:  counters.InstanceId,
						BytesTx:     counters.Tx,
						BytesRx:     counters.Rx,
						Source:      p.ProxiedUpstream,
						Destination: p.DstURL,
					})
				}
			}
		}
	}

	if len(report.Tunnels) == 0 {
		return
	}

	body, err := json.Marshal(report)
	if err != nil {
		log.Error().Err(err).Msg("failed to marshal usage report")
		return
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.url, bytes.NewReader(body))
	if err != nil {
		log.Error().Err(err).Msg("failed to create usage report request")
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Error().Err(err).Msg("failed to send usage report")
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		log.Warn().Int("status", resp.StatusCode).Str("body", string(bodyBytes)).Msg("usage report failed")
	} else {
		log.Debug().Int("count", len(report.Tunnels)).Msg("usage report sent")
	}
}
