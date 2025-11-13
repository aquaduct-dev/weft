package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"os"
	"os/signal"
	"syscall"

	server "aquaduct.dev/weft/src"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var proxyCmd = &cobra.Command{
	Use:   "proxy [src url] [dst url]",
	Short: "Create a one-off proxy between two URLs (src -> dst)",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		proxyNameFlag, _ := cmd.Flags().GetString("proxy-name")

		// Parse URLs
		srcURL, err := url.Parse(args[0])
		if err != nil {
			log.Fatal().Err(err).Str("url", args[0]).Msg("Invalid src URL")
		}
		dstURL, err := url.Parse(args[1])
		if err != nil {
			log.Fatal().Err(err).Str("url", args[1]).Msg("Invalid dst URL")
		}

		// Compute default proxy name if not provided
		if proxyNameFlag == "" {
			h := sha256.Sum256([]byte(args[0] + "|" + args[1]))
			proxyNameFlag = hex.EncodeToString(h[:])
		}
		pm := server.NewProxyManager()
		log.Debug().Str("src", srcURL.String()).Str("dst", dstURL.String()).Str("proxy_name", proxyNameFlag).Msg("Starting proxy")
		if err := pm.StartProxy(srcURL, dstURL, proxyNameFlag, nil, nil, nil, "0.0.0.0"); err != nil {
			log.Fatal().Err(err).Msg("Failed to start proxy")
			os.Exit(1)
		}
		log.Info().Str("proxy_name", proxyNameFlag).Msg("Proxy started")

		// Wait for shutdown signal (SIGINT / SIGTERM) and then close the proxy.
		// This makes the proxy run until explicitly signaled to stop.
		shutdownCh := make(chan os.Signal, 1)
		signal.Notify(shutdownCh, syscall.SIGINT, syscall.SIGTERM)
		sig := <-shutdownCh
		log.Info().Str("signal", sig.String()).Str("proxy_name", proxyNameFlag).Msg("Shutdown signal received, closing proxy")
		pm.Close(proxyNameFlag)
		log.Info().Str("proxy_name", proxyNameFlag).Msg("Proxy stopped")
	},
}

func init() {
	proxyCmd.Flags().String("proxy-name", "", "Logical name for the proxy (defaults to sha256(src|dst) if not set)")
	rootCmd.AddCommand(proxyCmd)
}
