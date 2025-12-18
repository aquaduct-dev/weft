package constants

import "net/netip"

const (
	// DefaultSubnetString is the default WireGuard subnet.
	DefaultSubnetString = "10.1.0.0/16"

	// DefaultServerIPString is the default IP assigned to the server in the WireGuard network.
	DefaultServerIPString = "10.1.0.1"

	// WGPrivateKeyRedacted is used for logging to avoid leaking secrets.
	WGPrivateKeyRedacted = "private_key=<redacted>"
)

var (
	// DefaultSubnet is the parsed DefaultSubnetString.
	DefaultSubnet = netip.MustParsePrefix(DefaultSubnetString)

	// DefaultServerIP is the parsed DefaultServerIPString.
	DefaultServerIP = netip.MustParseAddr(DefaultServerIPString)
)
