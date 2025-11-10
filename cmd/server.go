package cmd

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	server "aquaduct.dev/weft/src"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Run the Weft server",
	Run: func(cmd *cobra.Command, args []string) {
		log.Info().Msg("Server started!")
		email, _ := cmd.Flags().GetString("email")
		bindIPs, _ := cmd.Flags().GetString("bind-ips")
		useSecretPerIP, _ := cmd.Flags().GetBool("use-secret-per-ip")
		port, _ := cmd.Flags().GetInt("port")
		opentelemetryConnectionString, _ := cmd.Flags().GetString("opentelemetry-connection-string")
		secretFile, _ := cmd.Flags().GetString("secret-file")

		log.Info().Int("port", port).Msg("Starting Weft server")
		if email != "" {
			log.Info().Str("email", email).Msg("LetsEncrypt email")
		}
		if bindIPs != "" {
			log.Info().Str("bind_ips", bindIPs).Msg("Binding to IPs")
		}
		log.Info().Bool("use_secret_per_ip", useSecretPerIP).Msg("Use Secret Per IP")
		if opentelemetryConnectionString != "" {
			log.Info().Str("opentelemetry_connection_string", opentelemetryConnectionString).Msg("OpenTelemetry")
		}

		srv := server.NewServer(port)
		if email != "" {
			srv.ProxyManager.VHostProxyManager.SetACMEEmail(email)
		}

		log.Info().Str("connection_secret", srv.ConnectionSecret).Msg("Connection Secret")
		// Optionally write the connection secret to a file for automation.
		if secretFile != "" {
			if err := os.WriteFile(secretFile, []byte(srv.ConnectionSecret+"\n"), 0600); err != nil {
				log.Fatal().Err(err).Str("secret_file", secretFile).Msg("failed to write secret to file")
			}
			log.Info().Str("secret_file", secretFile).Msg("Wrote connection secret to file")
		}

		go func() {
			if err := srv.ListenAndServe(); err != nil {
				log.Fatal().Err(err).Msg("failed to serve")
			}
		}()

		// Wait for a signal to exit
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan

		log.Info().Msg("Server stopped.")
		if err := srv.Shutdown(context.Background()); err != nil {
			log.Fatal().Err(err).Msg("failed to shutdown")
		}
	},
}

func init() {
	rootCmd.AddCommand(serverCmd)
	serverCmd.Flags().String("email", "", "Email address for LetsEncrypt")
	serverCmd.Flags().String("bind-ips", "", "Comma separated list of IPs to bind to")
	serverCmd.Flags().Bool("use-secret-per-ip", false, "Use a separate secret for each IP")
	serverCmd.Flags().Int("port", 9092, "Server connection port")
	serverCmd.Flags().String("opentelemetry-connection-string", "", "OpenTelemetry connection string")
	// Write the generated connection secret to a file (optional)
	serverCmd.Flags().String("secret-file", "", "Path to write the generated connection secret")
}
