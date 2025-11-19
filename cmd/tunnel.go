package cmd

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"

	"strconv"
	"strings"
	"syscall"
	"time"

	"aquaduct.dev/weft/src/auth"
	"aquaduct.dev/weft/src/proxy"
	"aquaduct.dev/weft/src/tunnel"
	"aquaduct.dev/weft/wireguard"

	"aquaduct.dev/weft/types"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var tunnelCmd = &cobra.Command{
	Use:   "tunnel [weft://connection-secret@server-ip] [local url] [remote url]",
	Short: "Run the Weft tunnel",
	Args:  cobra.ExactArgs(3),
	Run: func(command *cobra.Command, args []string) {
		// Add tunnel-name flag (can be empty; we compute default below)
		tunnelNameFlag, _ := command.Flags().GetString("tunnel-name")

		// 1. Parse arguments
		weftURL, err := url.Parse(args[0])
		if err != nil {
			log.Fatal().Err(err).Msg("Invalid weft URL")
		}
		if weftURL.Port() == "" {
			weftURL.Host = weftURL.Host + ":9092"
		}
		// Extract connection secret: prefer password (user:pass@host), fall back to username (user@host).
		// Note: connection secret (if present in the URL) is no longer sent in the ConnectRequest.
		// We still read it to perform the prior login flow to obtain a JWT.
		connectionSecret := weftURL.User.Username()
		serverIP := weftURL.Host

		localURL, err := url.Parse(args[1])
		if err != nil {
			log.Fatal().Err(err).Msg("Invalid local URL")
		}

		remoteURL, err := url.Parse(args[2])
		if err != nil {
			log.Fatal().Err(err).Msg("Invalid remote URL")
		}
		remotePort := 0
		switch strings.ToLower(remoteURL.Scheme) {
		case "http":
			remotePort = 80
		case "https":
			remotePort = 443
		}
		if remoteURL.Port() != "" {
			remotePort, err = strconv.Atoi(remoteURL.Port())
			if err != nil {
				log.Fatal().Err(err).Msg("Invalid remote port")
			}
		}

		// If tunnel-name was not supplied by flag, compute default sha256(src|dst)
		if tunnelNameFlag == "" {
			// args[1] is local url, args[2] is remote url
			h := sha256.Sum256([]byte(args[1] + "|" + args[2]))
			tunnelNameFlag = hex.EncodeToString(h[:10])
		}

		// Provide proxy_name (tunnel name) to login so server issues a JWT scoped to this tunnel.
		client, err := auth.Login(weftURL.Host, connectionSecret, tunnelNameFlag)
		if err != nil {
			log.Fatal().Err(err).Msg("Login failed")
		}

		// Determine protocol and hostname to send to the control API.
		proto := strings.ToLower(remoteURL.Scheme)
		hostname := remoteURL.Hostname()
		// If localURL doesn't have a hostname (e.g., "tcp://10.0.0.1:1234"), fall back to remoteURL.
		if hostname == "" {
			log.Fatal().Str("url", remoteURL.String()).Msg("URL missing hostname")
		}

		// Generate a new private key.
		privateKey, err := wireguard.GeneratePrivateKey()
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to generate private key")
		}

		// Read TLS cert/key flags (test-only) and load them into memory if provided.
		tlsCertPath, _ := command.Flags().GetString("tls-cert")
		tlsKeyPath, _ := command.Flags().GetString("tls-key")
		var tlsCertPEM []byte
		var tlsKeyPEM []byte
		if tlsCertPath != "" || tlsKeyPath != "" {
			if tlsCertPath == "" || tlsKeyPath == "" {
				log.Fatal().Msg("both --tls-cert and --tls-key must be provided together")
			}
			certBytes, err := os.ReadFile(tlsCertPath)
			if err != nil {
				log.Fatal().Err(err).Msg("failed to read tls-cert file")
			}
			keyBytes, err := os.ReadFile(tlsKeyPath)
			if err != nil {
				log.Fatal().Err(err).Msg("failed to read tls-key file")
			}
			tlsCertPEM = certBytes
			tlsKeyPEM = keyBytes
		}

		// Build the ConnectRequest that will be sent to the server.
		connectReq := types.ConnectRequest{
			ClientPublicKey: privateKey.PublicKey().String(),
			RemotePort:      remotePort,
			Protocol:        proto,
			Hostname:        hostname,
			TunnelName:      tunnelNameFlag,
			ProxiedUpstream: localURL.String(),
		}
		// If the user supplied TLS cert/key via flags (test only), include them in the
		// connect request so the server will configure the vhost with the provided certs
		// instead of attempting ACME issuance.
		if len(tlsCertPEM) > 0 && len(tlsKeyPEM) > 0 {
			connectReq.CertificatePEM = string(tlsCertPEM)
			connectReq.PrivateKeyPEM = string(tlsKeyPEM)
		}

		reqBody, err := json.Marshal(connectReq)
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to marshal connect request")
		}

		connectURL := fmt.Sprintf("https://%s/connect", weftURL.Host)
		log.Debug().Str("url", connectURL).Msg("Posting connect request")

		httpReq, err := http.NewRequest(http.MethodPost, connectURL, bytes.NewBuffer(reqBody))
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to create connect request")
		}
		httpReq.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(httpReq)
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to connect to server")
		}
		defer resp.Body.Close()

		// If the server returned a non-2xx status, read and print the raw response body so the
		// client shows the exact error string returned by the server (not the JSON decoder error).
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			body, _ := io.ReadAll(resp.Body)
			// Trim trailing newline for nicer output.
			msg := string(bytes.TrimSpace(body))
			if msg == "" {
				log.Fatal().Int("status_code", resp.StatusCode).Msg("Server returned empty error")
			}
			log.Fatal().Int("status_code", resp.StatusCode).Str("error", msg).Msg("Server error")
		}

		var connectResp types.ConnectResponse
		if err := json.NewDecoder(resp.Body).Decode(&connectResp); err != nil {
			log.Fatal().Err(err).Msg("Failed to decode connect response")
		}
		log.Info().Str("ip", connectResp.ClientAddress).Int("port", connectResp.TunnelProxyPort).Msg("Assigned IP and proxy port")

		// Create tunnel
		pm := proxy.NewProxyManager()

		// Pass any already-loaded tlsCertPEM/tlsKeyPEM (read above) into the tunnel implementation
		// so the remote proxy can present the provided certificate instead of using ACME.
		_, err = tunnel.Tunnel(serverIP, localURL, &connectResp, privateKey, pm, tunnelNameFlag, tlsCertPEM, tlsKeyPEM)
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to create tunnel")
		}

		// Start background healthchecks to the control API to keep the server-side proxy alive.
		// Send POST /healthcheck every 10s. Also register a shutdown handler to notify server on exit.
		healthURL := fmt.Sprintf("https://%s/healthcheck", weftURL.Host)
		done := make(chan struct{})
		go func() {
			ticker := time.NewTicker(5 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					healthReq := types.HealthcheckRequest{
						Message: fmt.Sprintf("Healthcheck from tunnel %s at %s", tunnelNameFlag, time.Now().Format(time.RFC3339)),
					}
					reqBody, err := json.Marshal(healthReq)
					if err != nil {
						log.Error().Err(err).Msg("Failed to marshal healthcheck request")
						continue
					}

					req, _ := http.NewRequest(http.MethodPost, healthURL, bytes.NewBuffer(reqBody))
					req.Header.Set("Content-Type", "application/json")

					resp, err := client.Do(req)
					if err != nil {
						log.Error().Err(err).Msg("Healthcheck request failed")
						os.Exit(1)
					}
					defer resp.Body.Close()

					var healthResp types.HealthcheckResponse
					if err := json.NewDecoder(resp.Body).Decode(&healthResp); err != nil {
						log.Error().Err(err).Msg("Failed to decode healthcheck response")
						os.Exit(1)
					}

					if resp.StatusCode != http.StatusOK {
						log.Error().Int("status_code", resp.StatusCode).Str("status", healthResp.Status).Str("message", healthResp.Message).Msg("Healthcheck request failed")
						os.Exit(1)
					}
					log.Debug().Str("status", healthResp.Status).Str("message", healthResp.Message).Msg("Healthcheck successful")

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
					return fmt.Sprintf("https://%s/shutdown", serverIP)
				}
				return fmt.Sprintf("https://%s/shutdown", net.JoinHostPort(serverIP, "9092"))
			}()
			req, _ := http.NewRequest(http.MethodPost, shutdownURL, nil)
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
	// TLS certificate and key to present on the remote endpoint. These are intended
	// for tests that want to present a custom certificate without relying on ACME.
	tunnelCmd.Flags().String("tls-cert", "", "Path to TLS certificate file to present on remote HTTPS endpoint (test-only)")
	tunnelCmd.Flags().String("tls-key", "", "Path to TLS private key file to present on remote HTTPS endpoint (test-only)")
	rootCmd.AddCommand(tunnelCmd)
}
