package cmd

import (
	"context"
	"os"

	"aquaduct.dev/weft/src/vhost"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/vishvananda/netlink"
)

var probeCmd = &cobra.Command{
	Use:   "probe [domain]",
	Short: "Probe if the server can answer an ACME challenge",
	Args:  cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		bindIP, _ := cmd.Flags().GetString("bind-ip")
		bindInterface, _ := cmd.Flags().GetString("bind-interface")

		var host string
		if len(args) > 0 {
			host = args[0]
		} else {
			if bindIP != "0.0.0.0" {
				host = bindIP
			} else {
				host = discoverPublicIP(false)
				if host == "" {
					log.Fatal().Msg("Could not discover public IP and no domain provided")
				}
			}
		}
		log.Info().Str("host", host).Str("bind_ip", bindIP).Str("bind_interface", bindInterface).Msg("Performing ACME probe")

		if bindInterface != "" {
			log.Info().Str("interface", bindInterface).Str("ip", bindIP).Msg("Binding IP to interface")
			link, err := netlink.LinkByName(bindInterface)
			if err != nil {
				log.Fatal().Err(err).Msg("failed to find interface")
			}
			addr, err := netlink.ParseAddr(bindIP + "/32")
			if err != nil {
				log.Fatal().Err(err).Msg("failed to parse address")
			}
			if err := netlink.AddrAdd(link, addr); err != nil {
				log.Fatal().Err(err).Msg("failed to bind IP to interface")
			}
			defer func() {
				log.Info().Str("interface", bindInterface).Str("ip", bindIP).Msg("Unbinding IP from interface")
				if err := netlink.AddrDel(link, addr); err != nil {
					log.Error().Err(err).Msg("failed to unbind IP from interface")
				}
			}()
		}

		manager := vhost.NewVHostProxyManager()
		// Create a dummy proxy context to access CanPassACMEChallenge.
		// The method uses the manager to spawn the actual probe proxy.
		// Use the provided bindIP if available, otherwise default to 127.0.0.1.
		p := manager.Proxy("0.0.0.0", 0)

		if p.CanPassACMEChallenge(context.Background(), host) {
			log.Info().Str("host", host).Msg("ACME probe succeeded")
		} else {
			log.Fatal().Str("host", host).Msg("ACME probe failed")
			os.Exit(1)
		}
	},
}

func init() {
	rootCmd.AddCommand(probeCmd)
	probeCmd.Flags().String("bind-ip", "0.0.0.0", "IP to bind the probe listener to (default is 0.0.0.0)")
	probeCmd.Flags().String("bind-interface", "", "Bind the bind-ip to the given interface")
}
