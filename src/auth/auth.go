// Package auth: authentication helpers for the tunnel command.
//
// This file contains the extracted login flow and AES-GCM encrypt/decrypt helpers
// originally embedded inside cmd/tunnel.go. It is separated to keep cmd/tunnel.go
// focused on CLI and connection orchestration.
package auth

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/rs/zerolog/log"
)

func getCertificates(serverAddr string) ([]*x509.Certificate, error) {
	conn, err := tls.Dial("tcp", serverAddr, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		log.Err(err).Msg("Login: Error in dial")
		return nil, err
	}
	defer conn.Close()
	return conn.ConnectionState().PeerCertificates, nil
}

func GetToken(serverAddr, connectionSecret, proxyName string) (string, error) {
	client := http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	// GET /login to get the challenge
	loginURL := fmt.Sprintf("https://%s/login", serverAddr)
	log.Debug().Str("url", loginURL).Msg("Login: requesting challenge")
	resp, err := client.Get(loginURL)
	if err != nil {
		log.Error().Err(err).Msg("Login: GET /login failed")
		return "", fmt.Errorf("failed to get login challenge: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("login challenge failed with status %d: %s", resp.StatusCode, string(body))
	}

	encryptedChallenge, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Error().Err(err).Msg("Login: failed to read challenge body")
		return "", fmt.Errorf("failed to read login challenge: %w", err)
	}
	log.Debug().Int("len", len(encryptedChallenge)).Str("server", serverAddr).Msg("Login: received encrypted challenge")

	// 2. Decrypt the challenge
	decrypted, err := decrypt(connectionSecret, encryptedChallenge)
	if err != nil {
		log.Error().Err(err).Msg("Login: decrypt failed (maybe wrong connection secret)")
		return "", fmt.Errorf("failed to decrypt login challenge - is the connection secret correct? %w", err)
	}
	log.Debug().Int("len", len(decrypted)).Msg("Login: decrypted challenge")

	if !strings.HasPrefix(string(decrypted), "server-") {
		return "", fmt.Errorf("invalid server challenge")
	}

	challenge := strings.TrimPrefix(string(decrypted), "server-")

	// 3. POST the encrypted suffix back to /login
	encrypted, err := encrypt(connectionSecret, challenge)
	if err != nil {
		log.Error().Err(err).Msg("Login: encryption of response failed")
		return "", fmt.Errorf("failed to encrypt login challenge: %w", err)
	}
	log.Debug().Str("url", loginURL).Int("len", len(encrypted)).Msg("Login: posting encrypted challenge response")

	// POST JSON containing the base64-like bytes (kept as raw string) and proxy_name so the server
	// treats this as JSON. Server.loginHandler checks Content-Type == "application/json".
	// Include proxyName provided by caller so server can associate the JWT with this tunnel.
	// Encode encrypted bytes as base64 so JSON round-trip is safe.
	encodedChallenge := encodeBase64(encrypted)
	reqBodyMap := map[string]any{
		"challenge":  encodedChallenge,
		"proxy_name": proxyName,
	}
	jsonBody, jerr := json.Marshal(reqBodyMap)
	if jerr != nil {
		log.Error().Err(jerr).Msg("Login: failed to marshal login JSON")
		return "", fmt.Errorf("failed to marshal login request: %w", jerr)
	}
	resp, err = client.Post(loginURL, "application/json", bytes.NewBuffer(jsonBody))
	if err != nil {
		log.Error().Err(err).Msg("Login: POST /login failed")
		return "", fmt.Errorf("failed to post login challenge: %w", err)
	}
	defer resp.Body.Close()
	log.Debug().Int("status_code", resp.StatusCode).Msg("Login: POST /login completed")

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("login failed with status %d: %s", resp.StatusCode, string(body))
	}

	jwt, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Error().Err(err).Str("server", serverAddr).Msg("Login: failed to read JWT")
		return "", fmt.Errorf("failed to read JWT: %w", err)
	}
	log.Debug().Int("len", len(jwt)).Str("server", serverAddr).Msg("Login: obtained JWT")
	log.Info().Msg("Login: authenticated successfully!")

	return string(jwt), nil
}

// Login performs the zero-trust authentication flow with the server and returns a JWT.
func Login(serverAddr, connectionSecret, proxyName string) (*http.Client, error) {
	token, err := GetToken(serverAddr, connectionSecret, proxyName)
	if err != nil {
		return nil, err
	}

	certs, err := getCertificates(serverAddr)
	if err != nil {
		return nil, err
	}

	certPool := x509.NewCertPool()
	certPool.AddCert(certs[0])
	tlsTransport := http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs: certPool,
		},
	}
	transport := WithJWT(&tlsTransport, token, func() (string, error) {
		return GetToken(serverAddr, connectionSecret, proxyName)
	})
	client := &http.Client{Timeout: 5 * time.Second, Transport: &transport}
	return client, nil
}

type withJwt struct {
	jwt        string
	jwtRefresh func() (string, error)
	http.Header
	rt http.RoundTripper
}

func WithJWT(rt http.RoundTripper, jwt string, jwtRenewalFunction func() (string, error)) withJwt {
	if rt == nil {
		panic("Need an http.RoundTripper!")
	}

	return withJwt{jwt: jwt, rt: rt}
}

func (h withJwt) IsJWTValid() bool {
	if h.jwt == "" {
		return false
	}
	token, _, err := jwt.NewParser().ParseUnverified(h.jwt, jwt.MapClaims{})
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to parse JWT")
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		log.Fatal().Msg("Failed to get JWT claims")
	}
	exp := int64(claims["exp"].(float64))
	jwtExpiry := time.Unix(exp, 0)
	return time.Until(jwtExpiry) > 1*time.Minute

}

func (h withJwt) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	if !h.IsJWTValid() {
		log.Info().Msg("Login: refreshing JWT...")
		newJwt, err := h.jwtRefresh()
		if err != nil {
			return nil, err
		}
		h.jwt = newJwt
	}
	req.Header["Authorization"] = []string{"Bearer " + h.jwt}
	return h.rt.RoundTrip(req)
}

func encodeBase64(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}
func encrypt(key, text string) ([]byte, error) {
	hasher := sha256.New()
	hasher.Write([]byte(key))
	sha := hasher.Sum(nil)

	block, err := aes.NewCipher(sha)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aesgcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := aesgcm.Seal(nonce, nonce, []byte(text), nil)
	return ciphertext, nil
}

func decrypt(key string, ciphertext []byte) ([]byte, error) {
	hasher := sha256.New()
	hasher.Write([]byte(key))
	sha := hasher.Sum(nil)

	block, err := aes.NewCipher(sha)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := aesgcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
