// Package cmd: implements the `weft list` CLI command.
//
// The `weft list [server]` command calls the server's /list endpoint and prints
// the JSON response to stdout. If the server requires authentication, an
// optional --connection-secret flag can be provided; when present the command
// will use the existing Login flow (cmd.Login) to obtain a JWT and include it
// in the Authorization header.
package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"text/tabwriter"

	"github.com/aquaduct-dev/weft/src/auth"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

// formatBytes formats bytes into human-readable format (e.g., 1.2 KB, 3.4 MB)
func formatBytes(bytes int) string {
	if bytes < 1024 {
		return fmt.Sprintf("%d B", bytes)
	}
	units := []string{"B", "KiB", "MiB", "GiB", "TiB"}
	size := float64(bytes)
	i := 0
	for size >= 1024 && i < len(units)-1 {
		size /= 1024
		i++
	}
	return fmt.Sprintf("%.1f %s", size, units[i])
}

// Note: connection secret is passed in the URL path per README: /list/<secret>
var listCmd = &cobra.Command{
	Use:   "list [server]",
	Short: "Call server /list endpoint and print the result",
	Args:  cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		weftURL, err := url.Parse(args[0])
		if weftURL.Port() == "" {
			weftURL.Host = weftURL.Host + ":9092"
		}
		if err != nil {
			log.Fatal().Err(err).Msg("Invalid weft URL")
		}
		client, err := auth.Login(weftURL.Host, weftURL.User.String(), "list-client")
		if err != nil {
			log.Fatal().Err(err).Msg("Login failed")
		}

		listUrl := weftURL.JoinPath("list")
		listUrl.Scheme = "https"
		httpReq, err := http.NewRequest(http.MethodPost, listUrl.String(), nil)
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to create connect request")
		}
		httpReq.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(httpReq)
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to connect to server")
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Fatal().Err(err).Msg("failed to read response body")
		}

		if resp.StatusCode != http.StatusOK {
			// Print the error body to stderr and exit non-zero.
			_, _ = io.Copy(os.Stderr, bytes.NewReader(body))
			log.Fatal().Int("status", resp.StatusCode).Msg("server returned non-OK status for /list")
		}

		// Parse the JSON response
		type tunnelInfo struct {
			Tx     uint64 `json:"tx"`
			Rx     uint64 `json:"rx"`
			SrcURL string `json:"src"`
			DstURL string `json:"dst"`
		}
		var data map[string]tunnelInfo
		if err := json.Unmarshal(body, &data); err != nil {
			log.Fatal().Err(err).Msg("failed to parse JSON response")
		}

		// Get keys and sort them
		keys := make([]string, 0, len(data))
		for k := range data {
			keys = append(keys, k)
		}
		sort.Sort(sort.Reverse(sort.StringSlice(keys)))

		// Print as table
		humanReadable, _ := cmd.Flags().GetBool("human-readable")
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "Tunnel ID\tSource URL\tDestination URL\tBytes Tx\tBytes Rx\tBytes Ttl")
		for _, id := range keys {
			info := data[id]
			total := info.Tx + info.Rx
			if humanReadable {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", id, info.SrcURL, info.DstURL, formatBytes(int(info.Tx)), formatBytes(int(info.Rx)), formatBytes(int(total)))
			} else {
				fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%d\t%d\n", id, info.SrcURL, info.DstURL, info.Tx, info.Rx, total)
			}
		}
		w.Flush()
	},
}

func init() {
	listCmd.Flags().String("connection-secret", "", "Connection secret appended to /list/<secret>")
	listCmd.Flags().String("proxy-name", "", "Proxy name (unused for URL form)")
	listCmd.Flags().BoolP("human-readable", "l", false, "Print bytes in human-readable format")
	rootCmd.AddCommand(listCmd)
}
