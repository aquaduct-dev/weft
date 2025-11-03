package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"aquaduct.dev/weft/wireguard"
)

var rootCmd = &cobra.Command{
	Use:   "weft",
	Short: "Weft is a Layer 4/Layer 7 proxy built around wireguard-go.",
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		// If the global verbose flag was set, propagate to the wireguard package.
		if b, err := cmd.Flags().GetBool("verbose"); err == nil && b {
			wireguard.Verbose = true
		}
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
		fmt.Println(err)
		os.Exit(1)
	}
}
