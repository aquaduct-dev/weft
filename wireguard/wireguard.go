/*
This package provides a wrapper around the wireguard-go library.
*/
package wireguard

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
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

// IPBind implements conn.Bind but listens on a specific IP.
type IPBind struct {
	ip   net.IP
	mu   sync.Mutex
	conn *net.UDPConn
}

func NewIPBind(ipStr string) (conn.Bind, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, errors.New("invalid IP")
	}
	return &IPBind{ip: ip}, nil
}

type UdpEndpoint struct {
	*net.UDPAddr
}

func (e *UdpEndpoint) ClearSrc() {}
func (e *UdpEndpoint) DstIP() netip.Addr {
	ip, _ := netip.AddrFromSlice(e.IP)
	return ip.Unmap()
}
func (e *UdpEndpoint) SrcIP() netip.Addr { return netip.Addr{} }
func (e *UdpEndpoint) DstToBytes() []byte {
	if ip4 := e.IP.To4(); ip4 != nil {
		return ip4
	}
	return e.IP
}
func (e *UdpEndpoint) DstToString() string { return e.String() }
func (e *UdpEndpoint) SrcToString() string { return "" }

func (b *IPBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	a, err := net.ResolveUDPAddr("udp", s)
	if err != nil {
		return nil, err
	}
	return &UdpEndpoint{UDPAddr: a}, nil
}

func (b *IPBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.conn != nil {
		b.conn.Close()
	}

	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: b.ip, Port: int(port)})
	if err != nil {
		// handle "address already in use" gracefully if possible, but here we just error
		return nil, 0, err
	}
	b.conn = c

	// We can use a single receive func (no batching)
	var fn conn.ReceiveFunc = func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		n, addr, err := c.ReadFromUDP(bufs[0])
		if err != nil {
			return 0, err
		}
		sizes[0] = n
		eps[0] = &UdpEndpoint{UDPAddr: addr}
		return 1, nil
	}

	return []conn.ReceiveFunc{fn}, uint16(c.LocalAddr().(*net.UDPAddr).Port), nil
}

func (b *IPBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	b.mu.Lock()
	c := b.conn
	b.mu.Unlock()
	if c == nil {
		return errors.New("not open")
	}

	target := ep.(*UdpEndpoint).UDPAddr
	for _, buf := range bufs {
		_, err := c.WriteToUDP(buf, target)
		if err != nil {
			return err
		}
	}
	return nil
}

func (b *IPBind) SetMark(mark uint32) error {
	// Not easily supported in pure Go without syscalls
	return nil
}

func (b *IPBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.conn != nil {
		return b.conn.Close()
	}
	return nil
}

func (b *IPBind) BatchSize() int { return 1 }

// NewUserspaceDevice creates a new userspace WireGuard device.
func NewUserspaceDevice(conf string, addresses []netip.Addr, bindIP string) (*UserspaceDevice, error) {
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

	var bind conn.Bind
	if bindIP != "" && bindIP != "0.0.0.0" {
		bind, err = NewIPBind(bindIP)
		if err != nil {
			return nil, fmt.Errorf("failed to create IP bind: %w", err)
		}
	} else {
		bind = conn.NewDefaultBind()
	}

	dev := device.NewDevice(tun, bind, device.NewLogger(logLevel, ""))

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
