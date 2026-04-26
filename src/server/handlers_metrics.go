package server

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// MetricsHandler serves Prometheus-formatted usage metrics for all active tunnels.
func (s *Server) MetricsHandler(w http.ResponseWriter, r *http.Request) {
	user, _, ok := r.BasicAuth()
	if !ok || subtle.ConstantTimeCompare([]byte(user), []byte(s.ConnectionSecret)) != 1 {
		w.Header().Set("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	proxies := s.Dataplane.GetProxyCounters()
	tunnels := s.Store.GetAllPeers()

	var b strings.Builder
	for name, peer := range tunnels {
		if counters, ok := proxies[name]; ok {
			b.WriteString(fmt.Sprintf("weft_tunnel_bytes_transmitted_total{tunnel_id=\"%s\",src=\"%s\",dst=\"%s\"} %d\n", name, peer.ProxiedUpstream, peer.DstURL, counters.Tx))
			b.WriteString(fmt.Sprintf("weft_tunnel_bytes_received_total{tunnel_id=\"%s\",src=\"%s\",dst=\"%s\"} %d\n", name, peer.ProxiedUpstream, peer.DstURL, counters.Rx))
		}
	}

	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	w.Write([]byte(b.String()))
}

// ListHandler returns a list of all active tunnels and their current usage statistics.
func (s *Server) ListHandler(w http.ResponseWriter, r *http.Request) {

	proxies := s.Dataplane.GetProxyCounters()
	peers := s.Store.GetAllPeers()

	type tunnelInfo struct {
		Tx     uint64 `json:"tx"`
		Rx     uint64 `json:"rx"`
		SrcURL string `json:"src"`
		DstURL string `json:"dst"`
	}

	response := make(map[string]tunnelInfo)
	for name, peer := range peers {
		info := tunnelInfo{
			SrcURL: peer.ProxiedUpstream,
			DstURL: peer.DstURL,
		}
		if counters, ok := proxies[name]; ok {
			info.Tx = counters.Tx
			info.Rx = counters.Rx
		}
		response[name] = info
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
