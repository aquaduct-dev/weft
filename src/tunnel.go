/*
src/tunnel.go

Implements client-side Tunnel() helper which consumes a server ConnectResponse and a client
private key, creates a userspace WireGuard device configured for the tunnel, and returns it.

This follows the tunnel construction logic previously present in cmd/tunnel.go but
is factored into a reusable package-level function so other packages can call it.
*/
package server

import (
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"aquaduct.dev/weft/types"
	"aquaduct.dev/weft/wireguard"
	"github.com/rs/zerolog/log"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Tunnel creates a userspace WireGuard device for the client side of a tunnel.
//
// It uses the information returned by the control API in types.ConnectResponse to:
//   - parse the assigned client address
//   - build a short UAPI-style WireGuard configuration that includes the client's private key
//     and the server peer (server public key, allowed IPs, endpoint, and keepalive)
//   - create and return a UserspaceDevice bound to the assigned client address.
//
// Note: endpoint is currently set to the control API loopback (127.0.0.1:9092) as a
// default placeholder to match the prior in-repo behaviour.
func Tunnel(serverIP string, localUrl *url.URL, resp *types.ConnectResponse, privateKey wgtypes.Key, p *ProxyManager, tunnelName string) (*wireguard.UserspaceDevice, error) {
	// Build peer UAPI config using server-provided values.

	// Parse and validate the client address assigned by the server.
	clientAddress, err := netip.ParseAddr(resp.ClientAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to parse client address from server response (%q): %w", resp.ClientAddress, err)
	}

	// Log the assigned client address so tests and debugging can confirm we used the server-assigned IP.
	log.Info().Str("client_ip", clientAddress.String()).Msg("Tunnel: using assigned client IP from server response")

	host, _, err := net.SplitHostPort(serverIP)
	if err != nil {
		host = serverIP
	}

	// Create device config with the client's private key.
	peerConf := fmt.Sprintf("private_key=%s\nreplace_peers=true\npublic_key=%s\nallowed_ip=%s\nendpoint=%s\npersistent_keepalive_interval=1",
		hex.EncodeToString(privateKey[:]),
		resp.ServerPublicKey,
		"0.0.0.0/0",
		// Use ServerWGPort (server WireGuard UDP listen port) as the endpoint port.
		fmt.Sprintf("%s:%d", host, resp.ServerWGPort),
	)

	// Create the userspace WireGuard device bound to the assigned client address.
	addrList := []netip.Addr{clientAddress}

	device, err := wireguard.NewUserspaceDevice(peerConf, addrList)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to create WireGuard device")
		return nil, err
	}

	log.Info().Str("server_ip", serverIP).Int("server_wg_port", resp.ServerWGPort).Str("client_ip", clientAddress.String()).Msg("Tunnel established")

	remoteUrl := &url.URL{
		Scheme: localUrl.Scheme,
		Host:   net.JoinHostPort(resp.ClientAddress, strconv.Itoa(resp.TunnelProxyPort)),
	}
	switch strings.ToLower(localUrl.Scheme) {
	case "tcp", "http", "https":
		remoteUrl.Scheme = "tcp"
		localUrl.Scheme = "tcp"
	case "udp":
		remoteUrl.Scheme = "udp"
		localUrl.Scheme = "udp"
	default:
		return nil, fmt.Errorf("unsupported protocol %q", strings.ToLower(localUrl.Scheme))
	}

	// 5. Start the proxy
	if err := p.StartProxy(localUrl, remoteUrl, tunnelName, device, nil, nil, remoteUrl.Hostname()); err != nil {
		log.Fatal().Err(err).Msg("Failed to start proxy")
	}

	return device, nil
}
