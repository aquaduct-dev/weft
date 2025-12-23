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
	"sync"

	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/aquaduct-dev/weft/src/auth"
	"github.com/aquaduct-dev/weft/src/proxy"
	"github.com/aquaduct-dev/weft/src/tunnel"
	"github.com/aquaduct-dev/weft/wireguard"

	"github.com/aquaduct-dev/weft/types"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var tunnelCmd = &cobra.Command{
	Use:   "tunnel [weft://connection-secret@server-ip] [local url] [remote url] ...",
	Short: "Run the Weft tunnel",
	Args:  cobra.MinimumNArgs(3),
	Run: func(command *cobra.Command, args []string) {
		// Validate arguments length
		if (len(args)-1)%2 != 0 {
			log.Fatal().Msg("Arguments must be: server src dst [src dst ...]")
		}

		// Add tunnel-name flag (can be empty; we compute default below)
		tunnelNameFlag, _ := command.Flags().GetString("tunnel-name")
		retriesFlag, _ := command.Flags().GetInt("retries")

		// 1. Parse server argument
		weftURL, err := url.Parse(args[0])
		if err != nil {
			log.Fatal().Err(err).Msg("Invalid weft URL")
		}
		if weftURL.Port() == "" {
			weftURL.Host = weftURL.Host + ":9092"
		}
		// Extract connection secret: prefer password (user:pass@host), fall back to username (user@host).
		connectionSecret := weftURL.User.Username()
		serverIP := weftURL.Host

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

		var cleanups []func()
		var cleanupLock sync.Mutex

		// Loop through src/dst pairs
		for i := 1; i < len(args); i += 2 {
			localStr := args[i]
			remoteStr := args[i+1]

			// Determine tunnel name
			// If explicit flag provided AND only 1 tunnel (3 args total), use it.
			// Else generate.
			thisTunnelName := tunnelNameFlag
			if len(args) > 3 {
				if tunnelNameFlag != "" && i == 1 {
					log.Warn().Msg("Ignoring --tunnel-name flag because multiple tunnels are being created")
				}
				h := sha256.Sum256([]byte(localStr + "|" + remoteStr))
				thisTunnelName = hex.EncodeToString(h[:10])
			} else if thisTunnelName == "" {
				h := sha256.Sum256([]byte(localStr + "|" + remoteStr))
				thisTunnelName = hex.EncodeToString(h[:10])
			}

			cleanup, err := startTunnel(serverIP, connectionSecret, localStr, remoteStr, thisTunnelName, retriesFlag, tlsCertPEM, tlsKeyPEM)
			if err != nil {
				log.Fatal().Err(err).Str("local", localStr).Str("remote", remoteStr).Msg("Failed to start tunnel")
			}
			
			cleanupLock.Lock()
			cleanups = append(cleanups, cleanup)
			cleanupLock.Unlock()
		}

		// Wait for interrupt
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
		<-c

		log.Info().Msg("Shutting down tunnels...")
		cleanupLock.Lock()
		defer cleanupLock.Unlock()
		for _, f := range cleanups {
			f()
		}
		os.Exit(0)
	},
}

func startTunnel(serverIP, connectionSecret, localStr, remoteStr, tunnelName string, retries int, tlsCertPEM, tlsKeyPEM []byte) (func(), error) {
	localURL, err := url.Parse(localStr)
	if err != nil {
		return nil, fmt.Errorf("invalid local URL: %w", err)
	}

	remoteURL, err := url.Parse(remoteStr)
	if err != nil {
		return nil, fmt.Errorf("invalid remote URL: %w", err)
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
			return nil, fmt.Errorf("invalid remote port: %w", err)
		}
	}

	// Provide proxy_name (tunnel name) to login so server issues a JWT scoped to this tunnel.
	// Note: serverIP here includes the port (e.g. host:9092) as processed in Run.
	// auth.Login expects just host or host:port? It uses it in URLs.
	client, err := auth.Login(serverIP, connectionSecret, tunnelName)
	if err != nil {
		return nil, fmt.Errorf("login failed: %w", err)
	}

	// Determine protocol and hostname to send to the control API.
	proto := strings.ToLower(remoteURL.Scheme)
	hostname := remoteURL.Hostname()
	// If localURL doesn't have a hostname (e.g., "tcp://10.0.0.1:1234"), fall back to remoteURL.
	if hostname == "" {
		log.Warn().Str("url", remoteURL.String()).Msg("URL missing hostname, using default")
	}

	// Generate a new private key.
	privateKey, err := wireguard.GeneratePrivateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Build the ConnectRequest that will be sent to the server.
	connectReq := types.ConnectRequest{
		ClientPublicKey: privateKey.PublicKey().String(),
		RemotePort:      remotePort,
		Protocol:        proto,
		Hostname:        hostname,
		RemotePath:      remoteURL.Path,
		RemoteQuery:     remoteURL.RawQuery,
		RemoteFragment:  remoteURL.Fragment,
		RemoteModifiers: localURL.Fragment,
		TunnelName:      tunnelName,
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
		return nil, fmt.Errorf("failed to marshal connect request: %w", err)
	}

	connectURL := fmt.Sprintf("https://%s/connect", serverIP)
	log.Debug().Str("url", connectURL).Msg("Posting connect request")

	httpReq, err := http.NewRequest(http.MethodPost, connectURL, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create connect request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to server: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		msg := string(bytes.TrimSpace(body))
		if msg == "" {
			return nil, fmt.Errorf("server returned empty error with status %d", resp.StatusCode)
		}
		return nil, fmt.Errorf("server error (status %d): %s", resp.StatusCode, msg)
	}

	var connectResp types.ConnectResponse
	if err := json.NewDecoder(resp.Body).Decode(&connectResp); err != nil {
		return nil, fmt.Errorf("failed to decode connect response: %w", err)
	}
	log.Info().Str("tunnel", tunnelName).Str("ip", connectResp.ClientAddress).Int("port", connectResp.TunnelProxyPort).Msg("Assigned IP and proxy port")

	// Create tunnel
	pm := proxy.NewProxyManager()

	// Pass any already-loaded tlsCertPEM/tlsKeyPEM (read above) into the tunnel implementation
	// so the remote proxy can present the provided certificate instead of using ACME.
	device, err := tunnel.Tunnel(serverIP, localURL, hostname, &connectResp, privateKey, pm, tunnelName, tlsCertPEM, tlsKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to create tunnel: %w", err)
	}

	// Start background healthchecks
	healthURL := fmt.Sprintf("https://%s/healthcheck", serverIP)
	done := make(chan struct{})

	// Start the healthcheck loop with adaptive intervals and sliding window
	go func() {
		// Configuration for adaptive healthcheck
		const (
			baseInterval    = 5 * time.Second
			retryInterval   = 3 * time.Second  // Faster retry on first failure
			maxInterval     = 15 * time.Second // Max backoff
			windowDuration  = 60 * time.Second // Sliding window for failure tracking
			backoffMultiplier = 1.5
		)

		// Failure tracking
		consecutiveFailures := 0
		var recentFailures []time.Time // Timestamps of failures within window
		currentInterval := baseInterval

		ticker := time.NewTicker(currentInterval)
		defer ticker.Stop()

		// Helper to count failures within the sliding window
		countRecentFailures := func() int {
			cutoff := time.Now().Add(-windowDuration)
			valid := recentFailures[:0]
			for _, t := range recentFailures {
				if t.After(cutoff) {
					valid = append(valid, t)
				}
			}
			recentFailures = valid
			return len(recentFailures)
		}

		// Helper to update ticker interval
		setInterval := func(d time.Duration) {
			if d != currentInterval {
				currentInterval = d
				ticker.Reset(currentInterval)
				log.Debug().Dur("interval", currentInterval).Str("tunnel", tunnelName).Msg("Healthcheck interval adjusted")
			}
		}

		for {
			select {
			case <-ticker.C:
				healthReq := types.HealthcheckRequest{
					Message: fmt.Sprintf("Healthcheck from tunnel %s at %s", tunnelName, time.Now().Format(time.RFC3339)),
				}
				reqBody, err := json.Marshal(healthReq)
				if err != nil {
					log.Error().Err(err).Msg("Failed to marshal healthcheck request")
					continue
				}

				req, _ := http.NewRequest(http.MethodPost, healthURL, bytes.NewBuffer(reqBody))
				req.Header.Set("Content-Type", "application/json")

				resp, err := client.Do(req)

				// Classify the failure type
				isPermanentFailure := false
				isTransientFailure := false
				var failureReason string

				if err != nil {
					// Check for permanent failures (cert issues)
					if strings.Contains(err.Error(), "x509") || strings.Contains(err.Error(), "certificate") {
						isPermanentFailure = true
						failureReason = "certificate error"
					} else {
						isTransientFailure = true
						failureReason = err.Error()
					}
				} else {
					defer resp.Body.Close()
					switch resp.StatusCode {
					case http.StatusOK:
						// Success - reset tracking
						var healthResp types.HealthcheckResponse
						if err := json.NewDecoder(resp.Body).Decode(&healthResp); err == nil {
							log.Debug().Str("status", healthResp.Status).Str("tunnel", tunnelName).Msg("Healthcheck successful")
						}
						if consecutiveFailures > 0 {
							log.Info().Str("tunnel", tunnelName).Int("recovered_after", consecutiveFailures).Msg("Healthcheck recovered")
						}
						consecutiveFailures = 0
						setInterval(baseInterval)
						continue // Skip failure handling

					case http.StatusUnauthorized, http.StatusNotFound:
						// Permanent failures - tunnel doesn't exist or auth invalid
						isPermanentFailure = true
						failureReason = fmt.Sprintf("server returned %d", resp.StatusCode)

					default:
						// Other errors are transient
						isTransientFailure = true
						var healthResp types.HealthcheckResponse
						if decodeErr := json.NewDecoder(resp.Body).Decode(&healthResp); decodeErr == nil {
							failureReason = fmt.Sprintf("status %d: %s", resp.StatusCode, healthResp.Message)
						} else {
							failureReason = fmt.Sprintf("status %d", resp.StatusCode)
						}
					}
				}

				// Handle permanent failures - exit immediately
				if isPermanentFailure {
					log.Fatal().Str("tunnel", tunnelName).Str("reason", failureReason).Msg("Healthcheck failed permanently; shutting down")
				}

				// Handle transient failures
				if isTransientFailure {
					consecutiveFailures++
					recentFailures = append(recentFailures, time.Now())
					recentCount := countRecentFailures()

					log.Warn().
						Int("consecutive", consecutiveFailures).
						Int("recent", recentCount).
						Int("max_retries", retries).
						Str("tunnel", tunnelName).
						Str("reason", failureReason).
						Msg("Healthcheck failed")

					// Adaptive interval: faster retry on first failure, then backoff
					if consecutiveFailures == 1 {
						setInterval(retryInterval)
					} else if consecutiveFailures > 1 {
						newInterval := time.Duration(float64(currentInterval) * backoffMultiplier)
						if newInterval > maxInterval {
							newInterval = maxInterval
						}
						setInterval(newInterval)
					}

					// Exit conditions:
					// 1. Too many consecutive failures (hard failure)
					// 2. Too many failures in the sliding window
					if consecutiveFailures >= retries*2 {
						log.Fatal().Str("tunnel", tunnelName).Int("consecutive", consecutiveFailures).Msg("Too many consecutive healthcheck failures; shutting down")
					}
					if recentCount >= retries {
						log.Fatal().Str("tunnel", tunnelName).Int("failures_in_window", recentCount).Msg("Too many healthcheck failures in window; shutting down")
					}
				}

			case <-done:
				return
			}
		}
	}()

	// Cleanup function
	cleanup := func() {
		log.Info().Str("tunnel", tunnelName).Msg("Stopping tunnel")
		close(done)
		
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
		
		if device != nil && device.Device != nil {
			device.Device.Close()
		}
	}

	return cleanup, nil
}

func init() {
	// Register the tunnel-name flag so users can set a logical name for the tunnel.
	tunnelCmd.Flags().String("tunnel-name", "", "Logical name for the tunnel (defaults to sha256(local|remote) if not set)")
	// Register the retries flag
	tunnelCmd.Flags().IntP("retries", "r", 3, "Maximum number of healthcheck failures in window before the tunnel shuts down")
	// TLS certificate and key to present on the remote endpoint. These are intended
	// for tests that want to present a custom certificate without relying on ACME.
	tunnelCmd.Flags().String("tls-cert", "", "Path to TLS certificate file to present on remote HTTPS endpoint (test-only)")
	tunnelCmd.Flags().String("tls-key", "", "Path to TLS private key file to present on remote HTTPS endpoint (test-only)")
	rootCmd.AddCommand(tunnelCmd)
}