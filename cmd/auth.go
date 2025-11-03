// Package cmd: authentication helpers for the tunnel command.
//
// This file contains the extracted login flow and AES-GCM encrypt/decrypt helpers
// originally embedded inside cmd/tunnel.go. It is separated to keep cmd/tunnel.go
// focused on CLI and connection orchestration.
package cmd

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
)

// Login performs the zero-trust authentication flow with the server and returns a JWT.
func Login(serverAddr, connectionSecret, proxyName string) (string, error) {
	// 1. GET /login to get the challenge
	loginURL := fmt.Sprintf("http://%s/login", serverAddr)
	log.Printf(" login: requesting challenge from %s", loginURL)
	resp, err := http.Get(loginURL)
	if err != nil {
		log.Printf(" login: GET /login failed: %v", err)
		return "", fmt.Errorf("failed to get login challenge: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("login challenge failed with status %d: %s", resp.StatusCode, string(body))
	}

	encryptedChallenge, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf(" login: failed to read challenge body: %v", err)
		return "", fmt.Errorf("failed to read login challenge: %w", err)
	}
	log.Printf(" login: received encrypted challenge (len=%d) from %s", len(encryptedChallenge), serverAddr)

	// 2. Decrypt the challenge
	decrypted, err := decrypt(connectionSecret, encryptedChallenge)
	if err != nil {
		log.Printf(" login: decrypt failed (maybe wrong connection secret): %v", err)
		return "", fmt.Errorf("failed to decrypt login challenge - is the connection secret correct? %w", err)
	}
	log.Printf(" login: decrypted challenge (len=%d)", len(decrypted))

	if !strings.HasPrefix(string(decrypted), "server-") {
		return "", fmt.Errorf("invalid server challenge")
	}

	challenge := strings.TrimPrefix(string(decrypted), "server-")

	// 3. POST the encrypted suffix back to /login
	encrypted, err := encrypt(connectionSecret, challenge)
	if err != nil {
		log.Printf(" login: encryption of response failed: %v", err)
		return "", fmt.Errorf("failed to encrypt login challenge: %w", err)
	}
	log.Printf(" login: posting encrypted challenge response to %s (len=%d)", loginURL, len(encrypted))

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
		log.Printf(" login: failed to marshal login JSON: %v", jerr)
		return "", fmt.Errorf("failed to marshal login request: %w", jerr)
	}
	resp, err = http.Post(loginURL, "application/json", bytes.NewBuffer(jsonBody))
	if err != nil {
		log.Printf(" login: POST /login failed: %v", err)
		return "", fmt.Errorf("failed to post login challenge: %w", err)
	}
	defer resp.Body.Close()
	log.Printf(" login: POST /login completed with status %d", resp.StatusCode)

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("login failed with status %d: %s", resp.StatusCode, string(body))
	}

	jwt, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf(" login: failed to read JWT from %s: %v", serverAddr, err)
		return "", fmt.Errorf("failed to read JWT: %w", err)
	}
	log.Printf(" login: obtained JWT (len=%d) from %s", len(jwt), serverAddr)

	return string(jwt), nil
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
