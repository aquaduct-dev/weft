// proxy.go — `weft proxy`: run one or more local src→dst proxies in a single
// process with no weft server or WireGuard in the path. With --tls-cert and
// --tls-key, https destinations are served with that certificate instead of
// ACME, which is how weft-operator's WeftLocalDNSReflector terminates TLS for
// public hostnames inside a cluster.
package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"syscall"

	"github.com/aquaduct-dev/weft/src/proxy"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var proxyCmd = &cobra.Command{
	Use:   "proxy [src url] [dst url] [[src url] [dst url] ...]",
	Short: "Create one-off proxies between pairs of URLs (src -> dst)",
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 2 || len(args)%2 != 0 {
			return fmt.Errorf("requires src/dst URL pairs, got %d args", len(args))
		}
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		proxyNameFlag, _ := cmd.Flags().GetString("proxy-name")
		certPEM, keyPEM, err := readTLSPair(cmd)
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to load TLS certificate")
		}

		pm := proxy.NewProxyManager()
		var names []string
		for i := 0; i < len(args); i += 2 {
			srcURL, err := url.Parse(args[i])
			if err != nil {
				log.Fatal().Err(err).Str("url", args[i]).Msg("Invalid src URL")
			}
			dstURL, err := url.Parse(args[i+1])
			if err != nil {
				log.Fatal().Err(err).Str("url", args[i+1]).Msg("Invalid dst URL")
			}

			// --proxy-name only makes sense for a single pair; with several,
			// every pair gets its own derived name so they cannot collide.
			name := proxyNameFlag
			if name == "" || len(args) > 2 {
				if proxyNameFlag != "" && i == 0 {
					log.Warn().Msg("Ignoring --proxy-name because multiple proxies are being created")
				}
				h := sha256.Sum256([]byte(args[i] + "|" + args[i+1]))
				name = hex.EncodeToString(h[:])
			}

			log.Info().Str("src", srcURL.String()).Str("dst", dstURL.String()).Str("proxy_name", name).Bool("static_tls", certPEM != nil).Msg("Starting proxy")
			if _, err := pm.StartProxy(srcURL, dstURL, name, nil, certPEM, keyPEM, "0.0.0.0"); err != nil {
				log.Fatal().Err(err).Str("proxy_name", name).Msg("Failed to start proxy")
			}
			names = append(names, name)
		}
		log.Info().Int("count", len(names)).Msg("Proxies started")

		// Run until SIGINT / SIGTERM, then close every proxy.
		shutdownCh := make(chan os.Signal, 1)
		signal.Notify(shutdownCh, syscall.SIGINT, syscall.SIGTERM)
		sig := <-shutdownCh
		log.Info().Str("signal", sig.String()).Msg("Shutdown signal received, closing proxies")
		for _, name := range names {
			pm.Close(name)
		}
		log.Info().Int("count", len(names)).Msg("Proxies stopped")
	},
}

// readTLSPair loads --tls-cert/--tls-key. Both or neither must be set; with
// neither, https destinations fall back to ACME as before. Only file paths are
// logged, never the key material.
func readTLSPair(cmd *cobra.Command) (certPEM, keyPEM []byte, err error) {
	certPath, _ := cmd.Flags().GetString("tls-cert")
	keyPath, _ := cmd.Flags().GetString("tls-key")
	if certPath == "" && keyPath == "" {
		return nil, nil, nil
	}
	if certPath == "" || keyPath == "" {
		return nil, nil, fmt.Errorf("both --tls-cert and --tls-key must be provided together")
	}
	if certPEM, err = os.ReadFile(certPath); err != nil {
		return nil, nil, fmt.Errorf("read --tls-cert %s: %w", certPath, err)
	}
	if keyPEM, err = os.ReadFile(keyPath); err != nil {
		return nil, nil, fmt.Errorf("read --tls-key %s: %w", keyPath, err)
	}
	log.Debug().Str("cert", certPath).Str("key", keyPath).Msg("Loaded static TLS certificate")
	return certPEM, keyPEM, nil
}

func init() {
	proxyCmd.Flags().String("proxy-name", "", "Logical name for the proxy (defaults to sha256(src|dst) if not set; ignored with multiple pairs)")
	proxyCmd.Flags().String("tls-cert", "", "Path to a PEM certificate to serve on https destinations instead of using ACME")
	proxyCmd.Flags().String("tls-key", "", "Path to the PEM private key for --tls-cert")
	rootCmd.AddCommand(proxyCmd)
}
