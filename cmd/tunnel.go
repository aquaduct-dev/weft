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
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"aquaduct.dev/weft/types"
	"aquaduct.dev/weft/wireguard"
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

		// 2. Generate private key
		privateKey, err := wireguard.GeneratePrivateKey()
		if err != nil {
			log.Fatalf("Failed to generate private key: %v", err)
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
		// Map URL schemes like http/https -> tcp for the proxy protocol.
		proto := strings.ToLower(localURL.Scheme)
		if proto == "http" || proto == "https" {
			proto = "tcp"
		}
		hostname := localURL.Hostname()
		// If localURL doesn't have a hostname (e.g., "tcp://10.0.0.1:1234"), fall back to remoteURL.
		if hostname == "" {
			hostname = remoteURL.Hostname()
		}
		// Ensure remotePort is populated: if remote URL doesn't include a port, pick sensible defaults.
		remotePortStr := remoteURL.Port()
		if remotePortStr == "" {
			switch strings.ToLower(remoteURL.Scheme) {
			case "http":
				remotePortStr = "80"
			case "https":
				remotePortStr = "443"
			default:
				// leave as requested remotePort (already parsed above) if unknown scheme
				remotePortStr = strconv.Itoa(remotePort)
			}
		}
		if rp, err := strconv.Atoi(remotePortStr); err == nil {
			remotePort = rp
		}

		// If tunnel-name was not supplied by flag, compute default sha256(src|dst)
		if tunnelNameFlag == "" {
			// args[1] is local url, args[2] is remote url
			h := sha256.Sum256([]byte(args[1] + "|" + args[2]))
			tunnelNameFlag = hex.EncodeToString(h[:])
		}

		// Build the ConnectRequest that will be sent to the server.
		connectReq := types.ConnectRequest{
			ClientPublicKey: privateKey.PublicKey().String(),
			RemotePort:      remotePort,
			Protocol:        proto,
			Hostname:        hostname,
			TunnelName:      tunnelNameFlag,
		}
		// Debug: log the textual public key the client will send so we can compare encodings with the server.
		// This prints only the public-key textual representation (not private key material).
		log.Printf("DEBUG: client ConnectRequest.ClientPublicKey (len=%d): %s", len(connectReq.ClientPublicKey), connectReq.ClientPublicKey)

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
		clientAddress, err := netip.ParseAddr(connectResp.ClientAddress)
		if err != nil {
			log.Fatalf("Failed to parse client address: %v", err)
		}

		// Build device config with only the device's private key. We'll add the server as a peer via IpcSet
		// after creating the device to avoid placing peer keys at the top-level (invalid UAPI).
		deviceConf := fmt.Sprintf("private_key=%s\n", hex.EncodeToString(privateKey[:]))

		// Create the device first.
		device, err := wireguard.NewUserspaceDevice(deviceConf, []netip.Addr{clientAddress})
		if err != nil {
			log.Fatalf("Failed to create wireguard device: %v", err)
		}

		// Construct a proper peer config and apply it via IpcSet on the device.
		peerEndpoint := func() string {
			if _, _, perr := net.SplitHostPort(serverIP); perr == nil {
				return serverIP
			}
			return net.JoinHostPort(serverIP, "9092")
		}()

		peerConf := fmt.Sprintf("replace_peers=true\npublic_key=%s\nallowed_ip=%s\nendpoint=%s\npersistent_keepalive_interval=1",
			connectResp.ServerPublicKey,
			connectResp.AllowedIPs,
			peerEndpoint,
		)

		// Apply peer configuration using the underlying device's IpcSet.
		if err := device.Device.IpcSet(peerConf); err != nil {
			log.Fatalf("Failed to set peer config: %v", err)
		}

		log.Printf("Tunnel established. Server assigned public port %d (requested %d) -> forwarding to local service %s", connectResp.ServerPort, remotePort, localURL.String())

		// 5. Start proxying
		// Use the server-assigned port (connectResp.ServerPort) for the local WireGuard listener.
		assignedPort := connectResp.ServerPort
		listener, err := device.NetStack.ListenTCP(&net.TCPAddr{Port: assignedPort})
		if err != nil {
			log.Fatalf("Failed to listen on remote port %d: %v", assignedPort, err)
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
			// allow a brief grace period then exit process
			time.Sleep(200 * time.Millisecond)
			os.Exit(0)
		}()

		for {
			conn, err := listener.Accept()
			if err != nil {
				log.Printf("Failed to accept new connection: %v", err)
				continue
			}
			go wireguard.TCPProxy(conn, localURL.Host)
		}
	},
}

func init() {
	// Register the tunnel-name flag so users can set a logical name for the tunnel.
	tunnelCmd.Flags().String("tunnel-name", "", "Logical name for the tunnel (defaults to sha256(local|remote) if not set)")
	rootCmd.AddCommand(tunnelCmd)
}
