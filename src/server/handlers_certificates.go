// handlers_certificates.go — GET /certificates lists the TLS certificates the
// bastion has obtained and cached, with their validity windows, so a user can
// see which hosts have certs and when they expire.
package server

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/rs/zerolog/log"

	"github.com/aquaduct-dev/weft/types"
)

// CertificatesHandler returns the bastion's cached certificates as JSON. It is
// JWT-gated like the other admin endpoints (see server.go mux registration).
func (s *Server) CertificatesHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	certs, err := s.Dataplane.ListCertificates()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to list certificates: %v", err), http.StatusInternalServerError)
		return
	}

	failures := s.Dataplane.ListACMEFailures()
	if len(failures) > 0 {
		log.Debug().Int("certificates", len(certs)).Int("acme_failures", len(failures)).Msg("certificates: reporting hosts with failed ACME issuance")
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(types.CertificatesResponse{Certificates: certs, ACMEFailures: failures})
}
