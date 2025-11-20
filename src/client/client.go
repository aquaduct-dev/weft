/*
Package client provides a library for communicating with the Weft server's administrative endpoints.
It allows other applications to programmatically list active tunnels and request tunnel shutdowns.
*/
package client

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"aquaduct.dev/weft/src/auth"
	"github.com/rs/zerolog/log"
)

// TunnelInfo represents the status and metrics of a tunnel.
type TunnelInfo struct {
	Tx     uint64 `json:"tx"`
	Rx     uint64 `json:"rx"`
	SrcURL string `json:"src"`
	DstURL string `json:"dst"`
}

// Client represents a Weft client that can query and manage tunnels on the server.
type Client struct {
	weftURL          *url.URL
	connectionSecret string
	tunnelName       string // Target tunnel for shutdown, or generic for listing
	httpClient       *http.Client
}

// NewClient creates a new Weft client for administrative tasks.
// weftURLStr: The URL of the Weft server (e.g., "weft://user:pass@server-ip:9092").
// tunnelName: The logical name of a specific tunnel to manage (e.g., for `Shutdown`).
// If left empty, a generic client name ("admin-client") will be used for authentication,
// suitable for operations like `ListTunnels`.
func NewClient(weftURLStr, tunnelName string) (*Client, error) {
	weftURL, err := url.Parse(weftURLStr)
	if err != nil {
		return nil, fmt.Errorf("invalid weft URL: %w", err)
	}
	// Ensure port is set if missing
	if weftURL.Port() == "" {
		weftURL.Host = weftURL.Host + ":9092"
	}

	// Extract connection secret. We rely on the same logic as cmd/tunnel.go.
	connectionSecret := weftURL.User.Username()

	return &Client{
		weftURL:          weftURL,
		connectionSecret: connectionSecret,
		tunnelName:       tunnelName,
	}, nil
}

// ensureAuth ensures the client is authenticated and has an HTTP client with a valid JWT.
// The proxyName used for authentication depends on the Client's `tunnelName` field.
// If `Client.tunnelName` is empty, a generic "admin-client" is used, suitable for `ListTunnels`.
// If `Client.tunnelName` is set, that specific tunnel name is used, making the JWT
// suitable for operations like `Shutdown` of that particular tunnel.
func (c *Client) ensureAuth() error {
	if c.httpClient != nil {
		return nil // Already authenticated
	}

	proxyName := c.tunnelName
	if proxyName == "" {
		proxyName = "admin-client" // Default for generic admin tasks like listing
	}

	client, err := auth.Login(c.weftURL.Host, c.connectionSecret, proxyName)
	if err != nil {
		return err
	}
	c.httpClient = client
	return nil
}

// ListTunnels retrieves the list of active tunnels from the server.
// The authentication for this operation will use a generic "admin-client" name
// if no specific tunnelName was provided during Client initialization.
func (c *Client) ListTunnels() (map[string]TunnelInfo, error) {
	if err := c.ensureAuth(); err != nil {
		return nil, fmt.Errorf("authentication failed: %w", err)
	}

	listUrl := fmt.Sprintf("https://%s/list", c.weftURL.Host)
	req, err := http.NewRequest(http.MethodPost, listUrl, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create list request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("list request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("server returned error (status %d): %s", resp.StatusCode, string(body))
	}

	var data map[string]TunnelInfo
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, fmt.Errorf("failed to parse list response: %w", err)
	}

	return data, nil
}

// Shutdown requests the server to shut down the tunnel specified by the Client's `tunnelName`.
// The Client must have been initialized with the specific `tunnelName` of the tunnel to be shut down.
// The authentication for this operation will use the provided `tunnelName`, which the server
// will verify against the JWT's 'sub' claim.
func (c *Client) Shutdown() error {
	if c.tunnelName == "" {
		return fmt.Errorf("cannot shutdown: tunnelName not specified in Client initialization")
	}

	if err := c.ensureAuth(); err != nil {
		return fmt.Errorf("authentication failed for tunnel '%s': %w", c.tunnelName, err)
	}

	shutdownURL := fmt.Sprintf("https://%s/shutdown", c.weftURL.Host)
	req, err := http.NewRequest(http.MethodPost, shutdownURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create shutdown request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("shutdown request failed for tunnel '%s': %w", c.tunnelName, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server returned error (status %d) for tunnel '%s': %s", resp.StatusCode, c.tunnelName, string(body))
	}
	log.Info().Str("tunnel", c.tunnelName).Msg("Successfully sent shutdown request")
	return nil
}
