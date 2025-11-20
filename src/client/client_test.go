package client_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"sync"

	"github.com/aquaduct-dev/weft/src/auth"
	"github.com/aquaduct-dev/weft/src/client"
	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/assert"
)

// Mock server for testing client interactions
type mockServer struct {
	server *httptest.Server
	secret string
	mu     sync.Mutex
	// challenges maps remote addresses to outstanding login challenges.
	challenges map[string]string
	// tunnels to list
	tunnels map[string]client.TunnelInfo
}

func newMockServer() *mockServer {
	s := &mockServer{
		secret: "test-secret",
		challenges: make(map[string]string),
		tunnels: make(map[string]client.TunnelInfo),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/login", s.loginHandler)
	mux.HandleFunc("/list", s.listHandler)
	mux.HandleFunc("/shutdown", s.shutdownHandler)

	s.server = httptest.NewTLSServer(mux)
	return s
}

func (m *mockServer) close() {
	m.server.Close()
}

func (m *mockServer) loginHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		// Simulate challenge generation
		b := make([]byte, 16)
		_, err := rand.Read(b)
		if err != nil {
			http.Error(w, "Failed to generate challenge", http.StatusInternalServerError)
			return
		}
		challenge := hex.EncodeToString(b)
		m.mu.Lock()
		m.challenges[r.RemoteAddr] = challenge
		m.mu.Unlock()

		encrypted, err := auth.Encrypt(m.secret, "server-"+challenge)
		if err != nil {
			http.Error(w, "Failed to encrypt challenge", http.StatusInternalServerError)
			return
		}
		w.Write(encrypted)
	case http.MethodPost:
		var reqBody map[string]string
		if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		encryptedChallengeBase64, ok := reqBody["challenge"]
		if !ok {
			http.Error(w, "Missing challenge in body", http.StatusBadRequest)
			return
		}
		proxyName, ok := reqBody["proxy_name"]
		if !ok {
			http.Error(w, "Missing proxy_name in body", http.StatusBadRequest)
			return
		}

		encryptedChallenge, err := base64.StdEncoding.DecodeString(encryptedChallengeBase64)
		if err != nil {
			http.Error(w, "Invalid challenge format", http.StatusBadRequest)
			return
		}

		decrypted, err := auth.Decrypt(m.secret, encryptedChallenge)
		if err != nil {
			http.Error(w, "Failed to decrypt challenge", http.StatusUnauthorized)
			return
		}

		m.mu.Lock()
		challenge, ok := m.challenges[r.RemoteAddr]
		delete(m.challenges, r.RemoteAddr)
		m.mu.Unlock()

		if !ok || string(decrypted) != challenge {
			http.Error(w, "Invalid challenge", http.StatusUnauthorized)
			return
		}

		// Generate JWT
		claims := jwt.MapClaims{
			"nbf": time.Now().Unix(),
			"exp": time.Now().Add(30 * time.Minute).Unix(),
			"aud": r.RemoteAddr,
			"sub": proxyName,
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString([]byte(m.secret))
		if err != nil {
			http.Error(w, "Failed to sign token", http.StatusInternalServerError)
			return
		}
		w.Write([]byte(tokenString))
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (m *mockServer) listHandler(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	
	// Validate JWT
	token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		return []byte(m.secret), nil
	})
	if err != nil || !token.Valid {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(m.tunnels)
}

func (m *mockServer) shutdownHandler(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	
	// Validate JWT and extract tunnelName from claims
	token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		return []byte(m.secret), nil
	})
	if err != nil || !token.Valid {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		http.Error(w, "Invalid token claims", http.StatusUnauthorized)
		return
	}
	tunnelName, ok := claims["sub"].(string)
	if !ok || tunnelName == "" {
		http.Error(w, "Missing tunnel name in token", http.StatusBadRequest)
		return
	}

	// In a real scenario, you'd mark the tunnel as shut down.
	// For this mock, we just return success.
	delete(m.tunnels, tunnelName)
	w.WriteHeader(http.StatusOK)
}

func TestListTunnels(t *testing.T) {
	server := newMockServer()
	defer server.close()

	// Add some mock tunnels
	server.tunnels["tunnel-1"] = client.TunnelInfo{Tx: 100, Rx: 200, SrcURL: "http://local1", DstURL: "https://remote1"}
	server.tunnels["tunnel-2"] = client.TunnelInfo{Tx: 300, Rx: 400, SrcURL: "http://local2", DstURL: "https://remote2"}

	weftURL := fmt.Sprintf("weft://%s@%s", server.secret, server.server.Listener.Addr().String())
	c, err := client.NewClient(weftURL, "") // No specific tunnelName for listing
	assert.NoError(t, err)

	tunnels, err := c.ListTunnels()
	assert.NoError(t, err)
	assert.Equal(t, 2, len(tunnels))
	assert.Equal(t, server.tunnels["tunnel-1"], tunnels["tunnel-1"])
	assert.Equal(t, server.tunnels["tunnel-2"], tunnels["tunnel-2"])
}

func TestShutdown(t *testing.T) {
	server := newMockServer()
	defer server.close()

	testTunnelName := "my-test-tunnel"
	server.tunnels[testTunnelName] = client.TunnelInfo{Tx: 1, Rx: 2, SrcURL: "http://local", DstURL: "https://remote"}

	weftURL := fmt.Sprintf("weft://%s@%s", server.secret, server.server.Listener.Addr().String())
	c, err := client.NewClient(weftURL, testTunnelName) // Specific tunnelName for shutdown
	assert.NoError(t, err)

	// Ensure the tunnel exists before shutdown
	_, exists := server.tunnels[testTunnelName]
	assert.True(t, exists)

	err = c.Shutdown()
	assert.NoError(t, err)

	// Verify the tunnel was removed from mock server
	_, exists = server.tunnels[testTunnelName]
	assert.False(t, exists)

	// Test shutdown of non-existent tunnel (server returns 200 currently, which is fine for mock)
	// If server returns an error code, this test needs to be updated.
	nonExistentTunnel := "non-existent-tunnel"
	cNonExistent, err := client.NewClient(weftURL, nonExistentTunnel)
	assert.NoError(t, err)
	err = cNonExistent.Shutdown()
	assert.NoError(t, err) // Server returns 200 even if tunnel doesn't exist.
}

func TestShutdownUnauthorized(t *testing.T) {
	server := newMockServer()
	defer server.close()

	testTunnelName := "my-test-tunnel"
	server.tunnels[testTunnelName] = client.TunnelInfo{}

	// Create a client with a wrong secret
	weftURL := fmt.Sprintf("weft://wrong-secret@%s", server.server.Listener.Addr().String())
	c, err := client.NewClient(weftURL, testTunnelName)
	assert.NoError(t, err)

	err = c.Shutdown()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "authentication failed")
}

func TestListTunnelsUnauthorized(t *testing.T) {
	server := newMockServer()
	defer server.close()

	server.tunnels["tunnel-1"] = client.TunnelInfo{}

	// Create a client with a wrong secret
	weftURL := fmt.Sprintf("weft://wrong-secret@%s", server.server.Listener.Addr().String())
	c, err := client.NewClient(weftURL, "")
	assert.NoError(t, err)

	_, err = c.ListTunnels()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "authentication failed")
}
