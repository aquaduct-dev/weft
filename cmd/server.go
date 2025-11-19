package cmd

import (
	"context"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"aquaduct.dev/weft/src/server"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/vishvananda/netlink"
)

func isLikelyPublic(addr string) bool {
	// trim whitespace and lower-case for IPv6 heuristics
	a := strings.TrimSpace(addr)
	if a == "" {
		return false
	}
	// Quick leading checks for common non-routable prefixes
	switch {
	case strings.HasPrefix(a, "10."):
		return false
	case strings.HasPrefix(a, "192.168."):
		return false
	case strings.HasPrefix(a, "127."):
		return false
	case strings.HasPrefix(a, "169.254."):
		return false
	case strings.HasPrefix(a, "172."):
		parts := strings.SplitN(a, ".", 3)
		if len(parts) >= 2 {
			sec := parts[1]
			if strings.HasPrefix(sec, "1") || strings.HasPrefix(sec, "2") || strings.HasPrefix(sec, "3") {
				if n, err := strconv.Atoi(sec); err == nil && n >= 16 && n <= 31 {
					return false
				}
			}
		}
	}
	lower := strings.ToLower(a)
	if strings.HasPrefix(lower, "fe80") || strings.HasPrefix(lower, "fc") || strings.HasPrefix(lower, "fd") || strings.HasPrefix(lower, "::1") {
		return false
	}
	return true
}

func discoverPublicIP() string {
	// get all interfaces
	ifaces, err := net.Interfaces()
	if err != nil {
		log.Warn().Err(err).Msg("failed to get interfaces")
		return ""
	}

	var candidates []net.IP
	// Try asking an external service (Hetzner) for our public IP and include it as a candidate.
	// This helps on systems where the local interfaces don't expose the public IP directly.
	{
		const hetznerURL = "https://ip.hetzner.com"
		resp, err := http.Get(hetznerURL)
		if err != nil {
			log.Debug().Err(err).Msg("failed to query hetzner ip service")
		} else {
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				buf := make([]byte, 64)
				n, _ := resp.Body.Read(buf)
				ipStr := string(buf[:n])
				ipStr = strings.TrimSpace(ipStr)
				parsed := net.ParseIP(ipStr)
				if parsed != nil && parsed.To4() != nil && !parsed.IsLoopback() && !parsed.IsPrivate() {
					log.Info().Str("ip", ipStr).Msg("Hetzner service returned public IP candidate")
					candidates = append(candidates, parsed)
				} else {
					log.Debug().Str("ip", ipStr).Msg("Hetzner returned invalid or non-public IP")
				}
			} else {
				log.Debug().Int("status", resp.StatusCode).Msg("Hetzner ip service returned non-200")
			}
		}
	}
	for _, i := range ifaces {
		addrs, err := i.Addrs()
		if err != nil {
			log.Warn().Err(err).Str("interface", i.Name).Msg("failed to get addresses")
			continue
		}

		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() || ip.IsPrivate() || ip.To4() == nil {
				continue
			}

			candidates = append(candidates, ip)
		}
	}

	if len(candidates) == 0 {
		log.Warn().Msg("no candidate IPs found")
		return ""
	}

	var goodIps []string
	for _, ip := range candidates {
		if isLikelyPublic(ip.String()) {
			goodIps = append(goodIps, ip.String())
		}
	}

	if len(goodIps) == 0 {
		log.Warn().Msg("no public IPs found")
		return ""
	}

	// return a random ip
	goodIp := goodIps[rand.Intn(len(goodIps))]
	log.Info().Str("ip", goodIp).Msg("Autodetected bindIP")
	ln, err := net.Listen("tcp", net.JoinHostPort(goodIp, "0"))
	if err != nil {
		log.Warn().Err(err).Str("ip", goodIp).Msg("Failed to listen on bindIP - binding to 0.0.0.0 instead")
		log.Warn().Msg("This is likely due to a NAT and may cause unexpected behavior if your server has both publically routable and NAT addresses.")
		return "0.0.0.0"
	}
	defer ln.Close()
	return goodIp
}

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Run the Weft server",
	Run: func(cmd *cobra.Command, args []string) {
		log.Info().Msg("Server started!")
		email, _ := cmd.Flags().GetString("email")
		bindIP, _ := cmd.Flags().GetString("bind-ip")
		bindInterface, _ := cmd.Flags().GetString("bind-interface")
		useStrictBindIp, _ := cmd.Flags().GetBool("use-strict-bind-ip")
		if useStrictBindIp && (bindIP == "" || bindIP == "0.0.0.0") {
			log.Fatal().Msg("Flag --use-strict-bind-ip is set but no --bind-ip was provided!")
		}

		if bindIP == "" {
			log.Info().Msg("bind-ip not set, attempting to discover public IP")
			bindIP = discoverPublicIP()
		}

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

		port, _ := cmd.Flags().GetInt("port")
		secretFile, _ := cmd.Flags().GetString("secret-file")
		connectionSecret, _ := cmd.Flags().GetString("connection-secret")

		if email != "" {
			log.Info().Str("email", email).Msg("LetsEncrypt email")
		}

		usageReportingURL, _ := cmd.Flags().GetString("usage-reporting-url")

		log.Info().Int("port", port).Msg("Starting Weft server")
		srv := server.NewServer(port, bindIP, connectionSecret, usageReportingURL)
		if email != "" {
			srv.ProxyManager.VHostProxyManager.SetACMEEmail(email)
		}

		certsCachePath, _ := cmd.Flags().GetString("certs-cache-path")
		if certsCachePath != "" {
			srv.ProxyManager.VHostProxyManager.SetCertsCachePath(certsCachePath)
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
			if err := srv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				log.Fatal().Err(err).Msg("failed to serve HTTPS")
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
	serverCmd.Flags().String("bind-ip", "", "Comma separated list of IPs to bind to")
	serverCmd.Flags().Int("port", 9092, "Server connection port")
	serverCmd.Flags().String("secret-file", "", "Path to write the generated connection secret")
	serverCmd.Flags().String("bind-interface", "", "Bind the bind-ip to the given interface")
	serverCmd.Flags().String("certs-cache-path", "", "Path to cache certificates")
	serverCmd.Flags().String("connection-secret", "", "Connection secret to use")
	serverCmd.Flags().String("usage-reporting-url", "", "URL to post usage reports to")
}
