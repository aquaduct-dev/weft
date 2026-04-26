package server

import (
	"encoding/json"
	"net/http"

	"github.com/aquaduct-dev/weft/src/version"
)

// VersionHandler reports the build-stamped commit hash and commit date so
// clients can detect version mismatches when the login handshake fails.
// Intentionally unauthenticated: the response carries no secrets.
func (s *Server) VersionHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"commit": version.Commit,
		"date":   version.CommitDate,
	})
}
