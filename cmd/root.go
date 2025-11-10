package cmd

import (
	"os"

	"aquaduct.dev/weft/src"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/spf13/cobra"

	"aquaduct.dev/weft/wireguard"
)

var rootCmd = &cobra.Command{
	Use:   "weft",
	Short: "Weft is a Layer 4/Layer 7 proxy built around wireguard-go.",
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		level := zerolog.InfoLevel
		// If the global verbose flag was set, propagate to the wireguard package.
		if b, err := cmd.Flags().GetBool("verbose"); err == nil && b {
			wireguard.Verbose = true
			level = zerolog.DebugLevel
		}
		server.Init(level)
	},
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

func init() {
	// Add a global persistent verbose flag. Users can pass --verbose to enable
	// more detailed logs (including wireguard internals).
	rootCmd.PersistentFlags().BoolP("verbose", "v", false, "Enable verbose logging")
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		log.Fatal().Err(err).Msg("failed to execute root command")
		os.Exit(1)
	}
}
