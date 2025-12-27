package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/aquaduct-dev/weft/types"
)

// HealthcheckHandler provides an endpoint for clients to report their health status.
func (s *Server) HealthcheckHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req types.HealthcheckRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && err != io.EOF {
		http.Error(w, fmt.Sprintf("Invalid request body: %v", err), http.StatusBadRequest)
		return
	}

	proxyName := s.getJWTSubjectFromRequest(r)
	if proxyName == "" {
		http.Error(w, "Missing proxy name in token", http.StatusBadRequest)
		return
	}

	p, exists := s.Store.GetPeer(proxyName)
	if !exists {
		http.Error(w, fmt.Sprintf("Proxy '%s' not found", proxyName), http.StatusNotFound)
		return
	}

	s.Store.SetLastSeen(proxyName, time.Now())

	resp := types.HealthcheckResponse{
		Status:  "healthy",
		Message: fmt.Sprintf("Proxy '%s' is healthy. IP: %s. Request message: '%s'", proxyName, p.IP.String(), req.Message),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}
