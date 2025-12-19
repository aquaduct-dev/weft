/*
src/tunnel.go

Implements client-side Tunnel() helper which consumes a server ConnectResponse and a client
private key, creates a userspace WireGuard device configured for the tunnel, and returns it.

This follows the tunnel construction logic previously present in cmd/tunnel.go but
is factored into a reusable package-level function so other packages can call it.
*/
package tunnel

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/aquaduct-dev/weft/src/internal/util"
	"github.com/aquaduct-dev/weft/src/proxy"
	"github.com/aquaduct-dev/weft/types"
	"github.com/aquaduct-dev/weft/wireguard"
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
func Tunnel(serverIP string, localUrl *url.URL, hostname string, resp *types.ConnectResponse, privateKey wgtypes.Key, p *proxy.ProxyManager, tunnelName string, tlsCertPEM []byte, tlsKeyPEM []byte) (*wireguard.UserspaceDevice, error) {
	clientAddress, err := netip.ParseAddr(resp.ClientAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to parse client address from server response (%q): %w", resp.ClientAddress, err)
	}
	log.Debug().Str("client_ip", clientAddress.String()).Msg("Tunnel: using assigned client IP from server response")

	resolvedIP, err := resolveServerIP(serverIP)
	if err != nil {
		return nil, err
	}

	peerConf, err := buildWireGuardConfig(resolvedIP, resp, privateKey)
	if err != nil {
		return nil, err
	}
	device, err := wireguard.NewUserspaceDevice(peerConf, []netip.Addr{clientAddress}, "")
	if err != nil {
		return nil, fmt.Errorf("failed to create WireGuard device: %w", err)
	}

	log.Info().Str("server_ip", serverIP).Int("server_wg_port", resp.ServerWGPort).Str("client_ip", clientAddress.String()).Msg("Tunnel established")

	remoteUrl, err := buildRemoteURL(localUrl, hostname, resp)
	if err != nil {
		device.Device.Close()
		return nil, err
	}

	if _, err := p.StartProxy(localUrl, remoteUrl, tunnelName, device, tlsCertPEM, tlsKeyPEM, resp.ClientAddress); err != nil {
		device.Device.Close()
		return nil, fmt.Errorf("failed to start proxy: %w", err)
	}

	return device, nil
}

func resolveServerIP(serverIP string) (string, error) {
	host, _, err := net.SplitHostPort(serverIP)
	if err != nil {
		host = serverIP
	}

	if _, err := netip.ParseAddr(host); err == nil {
		return host, nil
	}

	addrs, err := net.DefaultResolver.LookupNetIP(context.Background(), "ip", host)
	if err != nil {
		return "", fmt.Errorf("failed to resolve server address %q: %w", host, err)
	}
	if len(addrs) == 0 {
		return "", fmt.Errorf("no IP addresses found for host %q", host)
	}
	return addrs[0].String(), nil
}

func buildWireGuardConfig(resolvedIP string, resp *types.ConnectResponse, privateKey wgtypes.Key) (string, error) {
	serverPubKey, err := wgtypes.ParseKey(resp.ServerPublicKey)
	if err != nil {
		return "", fmt.Errorf("invalid server public key: %w", err)
	}

	endpoint, err := net.ResolveUDPAddr("udp", net.JoinHostPort(resolvedIP, strconv.Itoa(resp.ServerWGPort)))
	if err != nil {
		return "", fmt.Errorf("failed to resolve server endpoint: %w", err)
	}

	keepalive := 1 * time.Second
	cfg := wgtypes.Config{
		PrivateKey:   &privateKey,
		ReplacePeers: true,
		Peers: []wgtypes.PeerConfig{
			{
				PublicKey: serverPubKey,
				AllowedIPs: []net.IPNet{
					{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)},
				},
				Endpoint:                    endpoint,
				PersistentKeepaliveInterval: &keepalive,
			},
		},
	}

	return wireguard.ConfigToString(cfg)
}

func buildRemoteURL(localUrl *url.URL, hostname string, resp *types.ConnectResponse) (*url.URL, error) {
	remoteUrl := &url.URL{
		Scheme: localUrl.Scheme,
		Host:   net.JoinHostPort(resp.ClientAddress, strconv.Itoa(resp.TunnelProxyPort)),
	}

	if err := util.EnsurePort(localUrl); err != nil {
		return nil, err
	}

	switch strings.ToLower(localUrl.Scheme) {
	case "tcp":
		remoteUrl.Scheme = "tcp"
	case "http":
		remoteUrl.Scheme = "http"
		remoteUrl.Host = net.JoinHostPort(hostname, strconv.Itoa(resp.TunnelProxyPort))
	case "https":
		remoteUrl.Scheme = "http" // Tunnel internal remains http, local side is https
		remoteUrl.Host = net.JoinHostPort(hostname, strconv.Itoa(resp.TunnelProxyPort))
	case "udp":
		remoteUrl.Scheme = "udp"
	default:
		return nil, fmt.Errorf("unsupported protocol %q", localUrl.Scheme)
	}
	return remoteUrl, nil
}

