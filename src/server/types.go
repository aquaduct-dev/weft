package server

import (
	"context"
	"net/netip"
	"time"

	"github.com/aquaduct-dev/weft/types"
	"github.com/aquaduct-dev/weft/wireguard"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Peer represents a connected tunnel client, storing its WireGuard public key,
// assigned internal IP, and routing information.
type Peer struct {
	// PublicKey is the WireGuard public key of the client.
	PublicKey wgtypes.Key
	// IP is the internal IP address assigned to this client within the tunnel network.
	IP netip.Addr
	// ProxiedUpstream is the original source URL/address provided by the client.
	ProxiedUpstream string
	// DstURL is the destination URL where the traffic is being forwarded.
	DstURL string
}

// TunnelStore defines the interface for managing the state of tunnel peers and IP address allocation.
// Implementations must be thread-safe.
type TunnelStore interface {
	// GetPeer retrieves a peer by its unique tunnel name.
	GetPeer(name string) (Peer, bool)
	// SetPeer stores or updates a peer's information.
	SetPeer(name string, p Peer)
	// DeletePeer removes a peer from the store.
	DeletePeer(name string)
	// GetAllPeers returns a map of all currently registered peers.
	GetAllPeers() map[string]Peer

	// GetLastSeen retrieves the last time a tunnel was active.
	GetLastSeen(name string) (time.Time, bool)
	// SetLastSeen updates the last seen timestamp for a tunnel.
	SetLastSeen(name string, t time.Time)
	// DeleteLastSeen removes the last seen timestamp for a tunnel.
	DeleteLastSeen(name string)
	// GetAllLastSeen returns a map of all tunnel names to their last seen timestamps.
	GetAllLastSeen() map[string]time.Time

	// GetFreeIP returns an available IP address from the internal pool.
	GetFreeIP() (netip.Addr, error)
	// ReleaseIP returns an IP address to the pool.
	ReleaseIP(ip netip.Addr)
}

// Dataplane defines the interface for managing the underlying networking components,
// including WireGuard configurations and proxy listeners.
type Dataplane interface {
	// UpdateWireGuardConfig synchronizes the WireGuard device state with the provided peers.
	UpdateWireGuardConfig(peers map[string]Peer) error
	// StartProxy initializes a new proxy listener for the given connection request.
	StartProxy(req *types.ConnectRequest, peerIP netip.Addr) (int, error)
	// CloseProxy terminates the proxy listener associated with the tunnel name.
	CloseProxy(name string)
	// GetProxyCounters returns current traffic statistics for all active proxies.
	GetProxyCounters() map[string]ProxyCounters
	// GetWgListenPort returns the port where the WireGuard device is listening.
	GetWgListenPort() int
	// GetDevice returns the underlying userspace WireGuard device.
	GetDevice() *wireguard.UserspaceDevice
	// GetPrivateKey returns the WireGuard private key used by the server.
	GetPrivateKey() wgtypes.Key
	// SetACMEEmail sets the email address used for ACME certificate registration.
	SetACMEEmail(email string)
	// SetCertsCachePath sets the directory path where SSL certificates are cached.
	SetCertsCachePath(path string)
}

// ProxyCounters holds the cumulative transmission and reception statistics for a proxy.
type ProxyCounters struct {
	// Tx is the total bytes transmitted (sent to the upstream).
	Tx uint64
	// Rx is the total bytes received (from the upstream).
	Rx uint64
	// InstanceId is a unique identifier for the specific proxy instance.
	InstanceId string
}

// TunnelUsage represents the usage statistics for a specific tunnel for reporting.
type TunnelUsage struct {
	TunnelName  string `json:"tunnel_name"`
	InstanceId  string `json:"instance_id"`
	BytesTx     uint64 `json:"bytes_tx"`
	BytesRx     uint64 `json:"bytes_rx"`
	Source      string `json:"source"`
	Destination string `json:"destination"`
}

// UsageReport is a collection of usage statistics for multiple tunnels.
type UsageReport struct {
	Tunnels []TunnelUsage `json:"tunnels"`
}

// UsageReporter defines the interface for reporting tunnel usage statistics to an external service.
type UsageReporter interface {
	// ReportUsage sends the provided tunnel usage statistics.
	ReportUsage(ctx context.Context, tunnels []TunnelUsage) error
}
