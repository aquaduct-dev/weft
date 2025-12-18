/*
This package provides a wrapper around the wireguard-go library.
*/
package wireguard

import (
	"encoding/hex"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// UserspaceDevice represents a WireGuard device running in userspace.
//
// This file also exposes a package-level flag `Verbose` that should be
// set by the caller when the --verbose CLI flag is present. When `Verbose` is
// true the internal wireguard logger is created at LogLevelVerbose; otherwise
// it is created at LogLevelError to suppress verbose WireGuard logs.
//
// NOTE: Keep this variable exported so cmd/tunnel.go (or main) can set it
// based on command-line flags.
var Verbose bool

// UserspaceDevice represents a WireGuard device running in userspace.
type UserspaceDevice struct {
	Device   *device.Device
	NetStack *netstack.Net
	Tun      tun.Device
}

// NewUserspaceDevice creates a new userspace WireGuard device.
func NewUserspaceDevice(conf string, addresses []netip.Addr) (*UserspaceDevice, error) {
	tun, tnet, err := netstack.CreateNetTUN(
		addresses,
		[]netip.Addr{}, // No DNS servers
		1420,           // MTU
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create TUN device: %w", err)
	}

	// Create the internal device logger at a level depending on the package-level
	// Verbose flag. When not verbose, use LogLevelError to minimize noisy output.
	logLevel := device.LogLevelError
	if Verbose {
		logLevel = device.LogLevelVerbose
	}

	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(logLevel, ""))

	err = dev.IpcSet(conf)
	if err != nil {
		return nil, fmt.Errorf("failed to set IPC config: %w", err)
	}

	err = dev.Up()
	if err != nil {
		return nil, fmt.Errorf("failed to bring up device: %w", err)
	}

	return &UserspaceDevice{
		Device:   dev,
		NetStack: tnet,
		Tun:      tun,
	}, nil
}

// GeneratePrivateKey generates a new WireGuard private key.
func GeneratePrivateKey() (wgtypes.Key, error) {
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return wgtypes.Key{}, fmt.Errorf("failed to generate private key: %w", err)
	}
	return key, nil
}

// ConfigToString converts a wgtypes.Config struct into the WireGuard UAPI string format.
func ConfigToString(cfg wgtypes.Config) (string, error) {
	var b strings.Builder

	if cfg.PrivateKey != nil {
		b.WriteString(fmt.Sprintf("private_key=%s\n", hex.EncodeToString(cfg.PrivateKey[:])))
	}

	if cfg.ListenPort != nil {
		b.WriteString(fmt.Sprintf("listen_port=%d\n", *cfg.ListenPort))
	}

	if cfg.ReplacePeers {
		b.WriteString("replace_peers=true\n")
	}

	// Emit each peer using UAPI format (flat key-value pairs, no section headers)
	for _, peer := range cfg.Peers {
		if peer.PublicKey != (wgtypes.Key{}) {
			b.WriteString(fmt.Sprintf("public_key=%s\n", hex.EncodeToString(peer.PublicKey[:])))
		}

		if len(peer.AllowedIPs) > 0 {
			for _, ipNet := range peer.AllowedIPs {
				b.WriteString(fmt.Sprintf("allowed_ip=%s\n", ipNet.String()))
			}
		}

		// Endpoint if present
		if peer.Endpoint != nil {
			b.WriteString(fmt.Sprintf("endpoint=%s\n", peer.Endpoint.String()))
		}

		// Persistent keepalive (seconds)
		if peer.PersistentKeepaliveInterval != nil && *peer.PersistentKeepaliveInterval != 0 {
			secs := max(0, int(*peer.PersistentKeepaliveInterval/time.Second))
			b.WriteString(fmt.Sprintf("persistent_keepalive_interval=%d\n", secs))
		}
	}

	// Ensure trailing newline
	if !strings.HasSuffix(b.String(), "\n") {
		b.WriteString("\n")
	}
	return b.String(), nil
}
