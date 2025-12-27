package server

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/aquaduct-dev/weft/src/crypto"
	"github.com/golang-jwt/jwt/v4"
	"github.com/rs/zerolog/log"
)

// LoginHandler manages the multi-step challenge-response authentication for proxies.
func (s *Server) LoginHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.getChallenge(w, r)
	case http.MethodPost:
		s.verifyChallenge(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) getChallenge(w http.ResponseWriter, r *http.Request) {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		http.Error(w, "Failed to generate challenge", http.StatusInternalServerError)
		return
	}
	challenge := hex.EncodeToString(b)
	s.mu.Lock()
	s.challenges[r.RemoteAddr] = challenge
	s.mu.Unlock()

	encrypted, err := crypto.Encrypt(s.ConnectionSecret, "server-"+challenge)
	if err != nil {
		http.Error(w, "Failed to encrypt challenge", http.StatusInternalServerError)
		return
	}
	w.Write(encrypted)
	log.Debug().Str("client", r.RemoteAddr).Msg("getChallenge: Generated login challenge")
}

func (s *Server) verifyChallenge(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusInternalServerError)
		return
	}

	var encrypted []byte
	var proxyName string

	if r.Header.Get("Content-Type") == "application/json" {
		var loginReq map[string]any
		if err := json.Unmarshal(body, &loginReq); err != nil {
			http.Error(w, "Failed to parse JSON body", http.StatusBadRequest)
			return
		}

		challengeData, ok := loginReq["challenge"]
		if !ok {
			http.Error(w, "Missing challenge in JSON body", http.StatusBadRequest)
			return
		}

		proxyData, ok := loginReq["proxy_name"]
		proxyName, _ = proxyData.(string)
		if proxyName == "" {
			http.Error(w, "Missing proxy_name in JSON body", http.StatusBadRequest)
			return
		}

		if challengeStr, ok := challengeData.(string); ok {
			var err error
			encrypted, err = base64.StdEncoding.DecodeString(challengeStr)
			if err != nil {
				http.Error(w, "Invalid challenge format", http.StatusBadRequest)
				return
			}
		} else {
			http.Error(w, "Invalid challenge format", http.StatusBadRequest)
			return
		}
	}

	decrypted, err := crypto.Decrypt(s.ConnectionSecret, encrypted)
	if err != nil {
		http.Error(w, "Failed to decrypt challenge", http.StatusUnauthorized)
		return
	}

	s.mu.Lock()
	challenge, ok := s.challenges[r.RemoteAddr]
	delete(s.challenges, r.RemoteAddr)
	s.mu.Unlock()

	if !ok {
		http.Error(w, "No challenge found for this address", http.StatusUnauthorized)
		return
	}

	if string(decrypted) != challenge {
		http.Error(w, "Invalid challenge", http.StatusUnauthorized)
		return
	}

	claims := jwt.MapClaims{
		"nbf": time.Now().Unix(),
		"exp": time.Now().Add(30 * time.Minute).Unix(),
		"aud": r.RemoteAddr,
		"sub": proxyName,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(s.ConnectionSecret))
	if err != nil {
		http.Error(w, "Failed to sign token", http.StatusInternalServerError)
		return
	}

	// Encrypt the server's TLS certificate with the connection secret.
	// This allows the client to verify they're talking to the real server.
	encryptedCert, err := crypto.Encrypt(s.ConnectionSecret, string(s.certPEM))
	if err != nil {
		http.Error(w, "Failed to encrypt certificate", http.StatusInternalServerError)
		return
	}

	// Return JSON response with token and encrypted certificate
	response := map[string]string{
		"token":       tokenString,
		"certificate": base64.StdEncoding.EncodeToString(encryptedCert),
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
	log.Debug().Str("client", r.RemoteAddr).Msg("verifyChallenge: Client passed challenge")
}

// ValidateJWT parses and validates a JSON Web Token against the server's connection secret.
func (s *Server) ValidateJWT(tokenString string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(s.ConnectionSecret), nil
	})

	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("token is not valid")
	}

	return token, nil
}
