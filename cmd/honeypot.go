package cmd

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/aquaduct-dev/weft/src/honeypot"
)

// Default port set — common targets of opportunistic abuse scanning. Picked
// to overlap with the protocols we want to capture with dedicated handlers
// (SSH/HTTP/HTTPS) plus a handful of classic banner-grab targets.
const defaultHoneypotPorts = "22,2222,80,443,21,23,445,3306,3389,5432,6379"

var honeypotCmd = &cobra.Command{
	Use:   "honeypot",
	Short: "Run weft in honeypot mode — listen on common abused ports and emit a structured event per attempt",
	Long: `Run weft in honeypot mode.

The honeypot exposes TCP listeners on a configurable set of ports
(default: SSH/HTTP/HTTPS plus a handful of classic scanner targets) and
proceeds through each protocol's handshake far enough to capture useful
detail — SSH username/password attempts, HTTP method/path/host/UA, TLS
SNI — before closing the connection. Each attempt is emitted as a
structured zerolog event and (optionally) POSTed to a remote ingest URL.

Honeypot mode is exclusive: a weft-honeypot bastion does not serve real
tunnel traffic. Deploy it alongside (or instead of) a regular tunnel
bastion when you want to collect abuse data for visualisation.`,
	Run: func(cmd *cobra.Command, args []string) {
		bindIP, _ := cmd.Flags().GetString("bind-ip")
		portsStr, _ := cmd.Flags().GetString("ports")
		ingestURL, _ := cmd.Flags().GetString("ingest-url")
		ingestSecret, _ := cmd.Flags().GetString("ingest-secret")
		dstHost, _ := cmd.Flags().GetString("dst-host")

		if ingestSecret == "" {
			// Fall back to env so the secret doesn't have to appear in the
			// process args / k8s manifest in plaintext.
			ingestSecret = os.Getenv("WEFT_HONEYPOT_INGEST_SECRET")
		}

		ports, err := honeypot.ParsePorts(portsStr)
		if err != nil {
			log.Fatal().Err(err).Str("ports", portsStr).Msg("honeypot: invalid --ports")
		}

		if bindIP == "" {
			log.Info().Msg("honeypot: --bind-ip not set, attempting to discover public IP")
			bindIP = discoverPublicIP(false)
		}

		emitter := honeypot.NewEmitter(ingestURL, ingestSecret, dstHost)
		hp := honeypot.New(bindIP, ports, emitter)

		log.Info().
			Str("bind_ip", bindIP).
			Ints("ports", ports).
			Bool("ingest", ingestURL != "").
			Msg("honeypot: starting")

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		// Trap SIGINT/SIGTERM so the listener loop can drain.
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		go func() {
			<-sigChan
			log.Info().Msg("honeypot: signal received, shutting down")
			cancel()
		}()

		if err := hp.Run(ctx); err != nil {
			log.Error().Err(err).Msg("honeypot: run failed")
		}

		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		if err := emitter.Shutdown(shutdownCtx); err != nil {
			log.Warn().Err(err).Msg("honeypot: emitter shutdown timed out")
		}
		log.Info().Msg("honeypot: stopped")
	},
}

func init() {
	rootCmd.AddCommand(honeypotCmd)
	honeypotCmd.Flags().String("bind-ip", "", "IP to bind listeners to (default: discover public IP)")
	honeypotCmd.Flags().String("ports", defaultHoneypotPorts, "Comma-separated list of TCP ports to listen on")
	honeypotCmd.Flags().String("ingest-url", "", "Remote URL to POST events to (e.g. https://aquaduct.dev/api/darkforest/ingest); if empty, events are only logged")
	honeypotCmd.Flags().String("ingest-secret", "", "Shared secret for the ingest endpoint (X-Darkforest-Secret header). Also read from $WEFT_HONEYPOT_INGEST_SECRET.")
	honeypotCmd.Flags().String("dst-host", "", "dst_host label sent with each event (default: os.Hostname)")
}
