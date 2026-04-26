package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aquaduct-dev/weft/types"
	"github.com/golang-jwt/jwt/v4"
)

func makeJWTRequest(t *testing.T, sub string, body any) *http.Request {
	t.Helper()
	bs, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/connect", bytes.NewReader(bs))
	req.Header.Set("Content-Type", "application/json")

	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": sub,
		"exp": time.Now().Add(time.Hour).Unix(),
		"nbf": time.Now().Unix(),
	})
	// Stuff the token into the context the way requireJWT does so we can call
	// the handler without going through the middleware.
	ctx := context.WithValue(req.Context(), jwtTokenKey, tok)
	return req.WithContext(ctx)
}

// TestConnectHandler_RejectsMismatchedTunnelName covers the F-3 fix: a JWT
// issued for one proxy_name must not be usable to act on a different
// tunnel_name.
func TestConnectHandler_RejectsMismatchedTunnelName(t *testing.T) {
	s := &Server{
		ConnectionSecret: "secret",
		Store:            NewInMemoryTunnelStore(),
		Dataplane:        newTestDataplane(),
	}

	body := types.ConnectRequest{
		TunnelName:      "victims-tunnel",
		ClientPublicKey: "abcdef==",
		Protocol:        "tcp",
		Hostname:        "example.com",
		RemotePort:      1234,
	}
	req := makeJWTRequest(t, "harmless", body)
	rr := httptest.NewRecorder()
	s.ConnectHandler(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 (body=%s)", rr.Code, rr.Body.String())
	}
	if _, exists := s.Store.GetPeer("victims-tunnel"); exists {
		t.Errorf("victims-tunnel must not have been created by mismatched JWT")
	}
}

// TestConnectHandler_DefaultsTunnelNameFromSub: clients that omit tunnel_name
// (e.g. older clients) get the JWT sub used implicitly. Verifies the F-3 fix
// doesn't break that compatibility shim.
func TestConnectHandler_DefaultsTunnelNameFromSub(t *testing.T) {
	s := &Server{
		ConnectionSecret: "secret",
		Store:            NewInMemoryTunnelStore(),
		Dataplane:        newTestDataplane(),
	}

	// Use an invalid public key so Serve() fails early — we only care about
	// authorization checks here, not the full happy path.
	body := types.ConnectRequest{
		ClientPublicKey: "not-a-valid-key",
		Protocol:        "tcp",
		Hostname:        "example.com",
		RemotePort:      1234,
	}
	req := makeJWTRequest(t, "alice", body)
	rr := httptest.NewRecorder()
	s.ConnectHandler(rr, req)

	if rr.Code == http.StatusForbidden {
		t.Errorf("default-name flow rejected as forbidden: %s", rr.Body.String())
	}
}

// TestConnectHandler_RejectsMissingSubject ensures the handler refuses any
// token without a usable subject claim.
func TestConnectHandler_RejectsMissingSubject(t *testing.T) {
	s := &Server{
		ConnectionSecret: "secret",
		Store:            NewInMemoryTunnelStore(),
		Dataplane:        newTestDataplane(),
	}

	body := types.ConnectRequest{
		TunnelName:      "anything",
		ClientPublicKey: "k",
		Protocol:        "tcp",
		Hostname:        "example.com",
		RemotePort:      1,
	}
	req := makeJWTRequest(t, "", body)
	rr := httptest.NewRecorder()
	s.ConnectHandler(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rr.Code)
	}
}
