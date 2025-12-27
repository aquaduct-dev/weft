package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/aquaduct-dev/weft/types"
	"github.com/rs/zerolog/log"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// ConnectHandler processes requests from clients to establish a new tunnel connection.
func (s *Server) ConnectHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req types.ConnectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request body: %v", err), http.StatusBadRequest)
		return
	}

	resp, err := s.Serve(&req)
	if err != nil {
		if err.Error() == "invalid connection secret" {
			http.Error(w, fmt.Sprintf("Invalid connection secret: %v", err), http.StatusUnauthorized)
			return
		}
		if strings.Contains(err.Error(), "already exists") || strings.Contains(err.Error(), "conflict") {
			http.Error(w, fmt.Sprintf("Conflict: %v", err), http.StatusConflict)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	log.Debug().Any("response", resp).Msg("ConnectHandler: sending response")
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

// Serve processes a connection request, allocates resources, and returns the tunnel configuration.
func (s *Server) Serve(req *types.ConnectRequest) (*types.ConnectResponse, error) {
	clientPublicKey, err := wgtypes.ParseKey(req.ClientPublicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid client public key")
	}

	p, created, err := s.getOrCreateTunnelPeer(req, clientPublicKey)
	if err != nil {
		return nil, err
	}

	if err := s.Dataplane.UpdateWireGuardConfig(s.Store.GetAllPeers()); err != nil {
		if created {
			s.RemoveTunnel(req.TunnelName)
		}
		return nil, err
	}

	tunnelProxyPort, err := s.Dataplane.StartProxy(req, p.IP)
	if err != nil {
		if created {
			s.RemoveTunnel(req.TunnelName)
		}
		return nil, err
	}

	pubKey := s.Dataplane.GetPrivateKey().PublicKey()

	// Update Peer with the assigned TunnelProxyPort
	p.TunnelProxyPort = tunnelProxyPort
	s.Store.SetPeer(req.TunnelName, p)

	return &types.ConnectResponse{
		ServerPublicKey: pubKey.String(),
		ClientAddress:   p.IP.String(),
		ServerWGPort:    s.Dataplane.GetWgListenPort(),
		TunnelProxyPort: tunnelProxyPort,
	}, nil
}

// getOrCreateTunnelPeer retrieves an existing peer or creates a new one, including IP allocation.
func (s *Server) getOrCreateTunnelPeer(req *types.ConnectRequest, clientPublicKey wgtypes.Key) (Peer, bool, error) {
	if p, ok := s.Store.GetPeer(req.TunnelName); ok {
		s.Store.SetLastSeen(req.TunnelName, time.Now())
		return p, false, nil
	}

	ip, err := s.Store.GetFreeIP()
	if err != nil {
		return Peer{}, false, err
	}

	p := Peer{
		IP:              ip,
		PublicKey:       clientPublicKey,
		ProxiedUpstream: req.ProxiedUpstream,
		DstURL:          fmt.Sprintf("%s://%s:%d", req.Protocol, req.Hostname, req.RemotePort),
	}
	s.Store.SetPeer(req.TunnelName, p)
	s.Store.SetLastSeen(req.TunnelName, time.Now())

	if s.CloudflareToken != "" && req.Hostname != "" && (req.Protocol == "http" || req.Protocol == "https") {
		if s.bindIP != "" && s.bindIP != "0.0.0.0" {
			updater := s.DNSUpdater
			go func(hostname, ip string) {
				if err := updater(s.CloudflareToken, hostname, ip); err != nil {
					log.Error().Err(err).Str("hostname", hostname).Msg("Failed to update Cloudflare DNS")
				}
			}(req.Hostname, s.bindIP)
		} else {
			log.Warn().Str("hostname", req.Hostname).Msg("Cloudflare token set but bindIP is invalid/empty, skipping DNS update")
		}
	}

	return p, true, nil
}

func (s *Server) ShutdownHandler(w http.ResponseWriter, r *http.Request) {
	tunnelName := s.getJWTSubjectFromRequest(r)
	s.reportUsage(r.Context(), []string{tunnelName})
	s.RemoveTunnel(tunnelName)
	w.WriteHeader(http.StatusOK)
}

// RemoveTunnel cleans up all resources associated with a tunnel name.
func (s *Server) RemoveTunnel(tunnelName string) {
	if p, ok := s.Store.GetPeer(tunnelName); ok {
		s.Dataplane.CloseProxy(tunnelName)
		s.Store.ReleaseIP(p.IP)
		s.Store.DeletePeer(tunnelName)
		s.Store.DeleteLastSeen(tunnelName)
		// Sync WireGuard config to remove the stale peer
		if err := s.Dataplane.UpdateWireGuardConfig(s.Store.GetAllPeers()); err != nil {
			log.Warn().Err(err).Str("tunnel", tunnelName).Msg("Failed to update WireGuard config after tunnel removal")
		}
	}
}
