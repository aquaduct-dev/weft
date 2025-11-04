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
	"log"
	"net"
	"net/netip"
	"strings"

	"aquaduct.dev/weft/types"
	"aquaduct.dev/weft/wireguard"
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
func Tunnel(serverIP string, resp *types.ConnectResponse, privateKey wgtypes.Key, allowList []string) (*wireguard.UserspaceDevice, error) {
	// Build peer UAPI config using server-provided values.
	peerConf := fmt.Sprintf("replace_peers=true\npublic_key=%s\nallowed_ip=%s\nendpoint=%s\npersistent_keepalive_interval=1",
		resp.ServerPublicKey,
		"0.0.0.0/0",
		fmt.Sprintf("%s:%d", serverIP, resp.ServerPort),
	)

	// Parse and validate the client address assigned by the server.
	clientAddress, err := netip.ParseAddr(resp.ClientAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to parse client address from server response (%q): %w", resp.ClientAddress, err)
	}

	// Log the assigned client address so tests and debugging can confirm we used the server-assigned IP.
	log.Printf("Tunnel: using assigned client IP %s from server response", clientAddress.String())

	// Create device config with the client's private key.
	deviceConf := fmt.Sprintf("private_key=%s\n", hex.EncodeToString(privateKey[:]))

	// Create the userspace WireGuard device bound to the assigned client address.
	addrList := []netip.Addr{clientAddress}
	for i := range allowList {
		// validate and include each allowed IP literal; if parsing fails, log and skip it.
		resolved, err := netip.ParseAddr(allowList[i])
		if err != nil {
			resolved, err = resolveDNS(allowList[i])
			if err != nil {
				panic(err)
			}
		}
		if err == nil {
			log.Printf("Tunnel: including %s (from %s) in virtual network", resolved.String(), allowList[i])
			addrList = append(addrList, resolved)
		} else {
			log.Printf("Tunnel: skipping invalid allowList entry %q: %v", allowList[i], err)
		}
	}

	device, err := wireguard.NewUserspaceDevice(deviceConf, addrList)
	if err != nil {
		log.Fatalf("Failed to create WireGuard device: %v", err)
		return nil, err
	}

	// Apply the peer configuration (server peer) to the device.
	if err := device.Device.IpcSet(peerConf); err != nil {
		log.Fatalf("Failed to set peer config: %v", err)
	}
	// Diagnostic: attempt to read back the device IPC state (sanitized) to confirm applied state.
	if cur, err := device.Device.IpcGet(); err == nil {
		// redact private_key before logging
		var out []string
		for _, line := range strings.Split(cur, "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "private_key=") {
				out = append(out, "private_key=<redacted>")
				continue
			}
			out = append(out, line)
		}
		log.Printf("Tunnel: device IPC state configured: %s\n", strings.Join(out, "\n"))
	} else {
		log.Printf("Tunnel: failed to read device IPC state after apply: %v", err)
	}

	log.Printf("Tunnel established to server %s (server port=%d, client ip=%s)", serverIP, resp.ServerPort, clientAddress.String())

	return device, nil
}

// resolveDNS resolves a DNS name to a netip.Addr. It accepts either an IP literal
// (v4 or v6) or a hostname. For hostnames it performs a DNS lookup and returns the
// first A or AAAA result. Errors if no usable address is found.
func resolveDNS(name string) (netip.Addr, error) {
	name = strings.Split(name, ":")[0]

	// If it's already an IP literal, parse and return it directly.
	if a, err := netip.ParseAddr(name); err == nil {
		return a, nil
	}

	// Otherwise perform a DNS lookup with net.LookupIP and return the first usable address.
	addrs, err := net.LookupIP(name)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("DNS lookup failed for %q: %w", name, err)
	}
	for _, ip := range addrs {
		if ip == nil {
			continue
		}
		// prefer IPv4 if present
		if v4 := ip.To4(); v4 != nil {
			if a, ok := netip.AddrFromSlice(v4); ok {
				return a, nil
			}
			continue
		}
		if a, ok := netip.AddrFromSlice(ip); ok {
			return a, nil
		}
	}
	return netip.Addr{}, fmt.Errorf("no usable addresses found for %q", name)
}
