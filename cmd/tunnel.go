package cmd

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"

	"strconv"
	"strings"
	"syscall"
	"time"

	server "aquaduct.dev/weft/src"
	"aquaduct.dev/weft/wireguard"

	"aquaduct.dev/weft/types"
	"github.com/spf13/cobra"
)

var tunnelCmd = &cobra.Command{
	Use:   "tunnel [weft://connection-secret@server-ip] [local url] [remote url]",
	Short: "Run the Weft tunnel",
	Args:  cobra.ExactArgs(3),
	Run: func(cmd *cobra.Command, args []string) {
		// Add tunnel-name flag (can be empty; we compute default below)
		tunnelNameFlag, _ := cmd.Flags().GetString("tunnel-name")

		// 1. Parse arguments
		weftURL, err := url.Parse(args[0])
		if err != nil {
			log.Fatalf("Invalid weft URL: %v", err)
		}
		// Extract connection secret: prefer password (user:pass@host), fall back to username (user@host).
		// Note: connection secret (if present in the URL) is no longer sent in the ConnectRequest.
		// We still read it to perform the prior login flow to obtain a JWT.
		connectionSecret := weftURL.User.Username()
		serverIP := weftURL.Host

		localURL, err := url.Parse(args[1])
		if err != nil {
			log.Fatalf("Invalid local URL: %v", err)
		}

		remoteURL, err := url.Parse(args[2])
		if err != nil {
			log.Fatalf("Invalid remote URL: %v", err)
		}
		remotePort, err := strconv.Atoi(remoteURL.Port())
		if err != nil {
			log.Fatalf("Invalid remote port: %v", err)
		}
		if remotePort == 0 {
			switch strings.ToLower(remoteURL.Scheme) {
			case "http":
				remotePort = 80
			case "https":
				remotePort = 443
			}
		}

		// If tunnel-name was not supplied by flag, compute default sha256(src|dst)
		if tunnelNameFlag == "" {
			// args[1] is local url, args[2] is remote url
			h := sha256.Sum256([]byte(args[1] + "|" + args[2]))
			tunnelNameFlag = hex.EncodeToString(h[:])
		}

		// Ensure the control API port is present. Server listens on :9092 by default.
		connectHost := serverIP
		if _, _, perr := net.SplitHostPort(serverIP); perr != nil {
			// host only (no port) -> join with default 9092
			connectHost = net.JoinHostPort(serverIP, "9092")
		}

		// Provide proxy_name (tunnel name) to login so server issues a JWT scoped to this tunnel.
		jwt, err := Login(connectHost, connectionSecret, tunnelNameFlag)
		if err != nil {
			log.Fatalf("Login failed: %v", err)
		}

		// Determine protocol and hostname to send to the control API.
		proto := strings.ToLower(localURL.Scheme)
		hostname := localURL.Hostname()
		// If localURL doesn't have a hostname (e.g., "tcp://10.0.0.1:1234"), fall back to remoteURL.
		if hostname == "" {
			hostname = remoteURL.Hostname()
		}

		// Generate a new private key.
		privateKey, err := wireguard.GeneratePrivateKey()
		if err != nil {
			log.Fatalf("Failed to generate private key: %v", err)
		}

		// Build the ConnectRequest that will be sent to the server.
		connectReq := types.ConnectRequest{
			ClientPublicKey: privateKey.PublicKey().String(),
			RemotePort:      remotePort,
			Protocol:        proto,
			Hostname:        hostname,
			Upstream:        localURL.String(),
			TunnelName:      tunnelNameFlag,
		}

		reqBody, err := json.Marshal(connectReq)
		if err != nil {
			log.Fatalf("Failed to marshal connect request: %v", err)
		}
		// Log the exact JSON payload we will send to the control API to aid debugging.
		log.Printf("Connect request payload: %s", string(reqBody))

		connectURL := fmt.Sprintf("http://%s/connect", connectHost)
		log.Printf("Posting connect request to %s", connectURL)

		httpReq, err := http.NewRequest(http.MethodPost, connectURL, bytes.NewBuffer(reqBody))
		if err != nil {
			log.Fatalf("Failed to create connect request: %v", err)
		}
		httpReq.Header.Set("Content-Type", "application/json")
		httpReq.Header.Set("Authorization", "Bearer "+jwt)

		resp, err := http.DefaultClient.Do(httpReq)
		if err != nil {
			log.Fatalf("Failed to connect to server: %v", err)
		}
		defer resp.Body.Close()

		// If the server returned a non-2xx status, read and print the raw response body so the
		// client shows the exact error string returned by the server (not the JSON decoder error).
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			body, _ := io.ReadAll(resp.Body)
			// Trim trailing newline for nicer output.
			msg := string(bytes.TrimSpace(body))
			if msg == "" {
				log.Fatalf("Server returned status %d", resp.StatusCode)
			}
			log.Fatalf("Server error (%d): %s", resp.StatusCode, msg)
		}

		var connectResp types.ConnectResponse
		if err := json.NewDecoder(resp.Body).Decode(&connectResp); err != nil {
			log.Fatalf("Failed to decode connect response: %v", err)
		}

		// 4. Create WireGuard device
		// 4. Create WireGuard device using shared helper
		_, err = server.Tunnel(serverIP, &connectResp, privateKey, []string{strings.Split(localURL.Host, ":")[0]})
		if err != nil {
			log.Fatalf("Failed to create wireguard device: %v", err)
		}

		// Start background healthchecks to the control API to keep the server-side proxy alive.
		// Send GET /healthcheck every 10s. Also register a shutdown handler to notify server on exit.
		healthURL := func() string {
			if _, _, perr := net.SplitHostPort(serverIP); perr == nil {
				return fmt.Sprintf("http://%s/healthcheck", serverIP)
			}
			return fmt.Sprintf("http://%s/healthcheck", net.JoinHostPort(serverIP, "9092"))
		}()
		done := make(chan struct{})
		go func() {
			ticker := time.NewTicker(10 * time.Second)
			defer ticker.Stop()
			client := &http.Client{Timeout: 5 * time.Second}
			for {
				select {
				case <-ticker.C:
					req, _ := http.NewRequest(http.MethodGet, healthURL, nil)
					req.Header.Set("Authorization", "Bearer "+jwt)
					resp, err := client.Do(req)
					if err != nil || resp.StatusCode != http.StatusOK {
						body := []byte("(no data)")
						statusCode := 0
						if resp != nil && resp.Body != nil {
							body, _ = io.ReadAll(resp.Body)
							statusCode = resp.StatusCode
						}
						log.Printf("Healthcheck request failed %d: %v", statusCode, string(body))
						os.Exit(1)
					}
				case <-done:
					return
				}
			}
		}()

		// Capture interrupts to allow the client to tell server to close its proxy.
		go func() {
			c := make(chan os.Signal, 1)
			signal.Notify(c, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
			<-c
			// Notify server to shutdown this tunnel
			shutdownURL := func() string {
				if _, _, perr := net.SplitHostPort(serverIP); perr == nil {
					return fmt.Sprintf("http://%s/shutdown", serverIP)
				}
				return fmt.Sprintf("http://%s/shutdown", net.JoinHostPort(serverIP, "9092"))
			}()
			req, _ := http.NewRequest(http.MethodPost, shutdownURL, nil)
			req.Header.Set("Authorization", "Bearer "+jwt)
			// Best-effort; ignore errors.
			client := &http.Client{Timeout: 3 * time.Second}
			if resp, err := client.Do(req); err == nil && resp != nil {
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
			close(done)
			os.Exit(0)
		}()
		for {
			time.Sleep(time.Minute)
		}
	},
}

func init() {
	// Register the tunnel-name flag so users can set a logical name for the tunnel.
	tunnelCmd.Flags().String("tunnel-name", "", "Logical name for the tunnel (defaults to sha256(local|remote) if not set)")
	rootCmd.AddCommand(tunnelCmd)
}
