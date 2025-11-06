package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	server "aquaduct.dev/weft/src"
	"github.com/spf13/cobra"
)

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Run the Weft server",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Server started!")
		email, _ := cmd.Flags().GetString("email")
		bindIPs, _ := cmd.Flags().GetString("bind-ips")
		useSecretPerIP, _ := cmd.Flags().GetBool("use-secret-per-ip")
		port, _ := cmd.Flags().GetInt("port")
		verbose, _ := cmd.Flags().GetBool("verbose")
		opentelemetryConnectionString, _ := cmd.Flags().GetString("opentelemetry-connection-string")
		secretFile, _ := cmd.Flags().GetString("secret-file")

		fmt.Printf("Starting Weft server on port %d\n", port)
		if email != "" {
			fmt.Printf("LetsEncrypt email: %s\n", email)
		}
		if bindIPs != "" {
			fmt.Printf("Binding to IPs: %s\n", bindIPs)
		}
		fmt.Printf("Use Secret Per IP: %v\n", useSecretPerIP)
		fmt.Printf("Verbose: %v\n", verbose)
		if opentelemetryConnectionString != "" {
			fmt.Printf("OpenTelemetry: %s\n", opentelemetryConnectionString)
		}

		srv := server.NewServer(port)

		fmt.Printf("Connection Secret: %s\n", srv.ConnectionSecret)
		// Optionally write the connection secret to a file for automation.
		if secretFile != "" {
			if err := os.WriteFile(secretFile, []byte(srv.ConnectionSecret+"\n"), 0600); err != nil {
				fmt.Printf("failed to write secret to file %s: %v\n", secretFile, err)
				os.Exit(1)
			}
			fmt.Printf("Wrote connection secret to %s\n", secretFile)
		}

		go func() {
			if err := srv.ListenAndServe(); err != nil {
				fmt.Printf("failed to serve: %v\n", err)
				os.Exit(1)
			}
		}()

		// Wait for a signal to exit
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan

		fmt.Println("Server stopped.")
		if err := srv.Shutdown(context.Background()); err != nil {
			fmt.Printf("failed to shutdown: %v", err)
			os.Exit(1)
		}
	},
}

func init() {
	rootCmd.AddCommand(serverCmd)
	serverCmd.Flags().String("email", "", "Email address for LetsEncrypt")
	serverCmd.Flags().String("bind-ips", "", "Comma separated list of IPs to bind to")
	serverCmd.Flags().Bool("use-secret-per-ip", false, "Use a separate secret for each IP")
	serverCmd.Flags().Int("port", 9092, "Server connection port")
	serverCmd.Flags().Bool("verbose", false, "Enable verbose logging")
	serverCmd.Flags().String("opentelemetry-connection-string", "", "OpenTelemetry connection string")
	// Write the generated connection secret to a file (optional)
	serverCmd.Flags().String("secret-file", "", "Path to write the generated connection secret")
}
