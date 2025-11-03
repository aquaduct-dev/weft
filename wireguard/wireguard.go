/*
This package provides a wrapper around the wireguard-go library.
*/
package wireguard

import (
	"fmt"
	"net/netip"

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
