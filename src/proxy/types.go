package proxy

import (
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync/atomic"

	"github.com/aquaduct-dev/weft/src/internal/constants"
	"github.com/aquaduct-dev/weft/src/internal/util"
	"github.com/aquaduct-dev/weft/src/proxy/vhost/meter"
	"github.com/aquaduct-dev/weft/wireguard"
	"github.com/rs/zerolog/log"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
)

// Proxy defines the common interface for all types of traffic forwarders (TCP, UDP, VHost).
type Proxy interface {
	io.Closer
	// Conflicts returns true if this proxy would conflict with another (e.g., same port).
	Conflicts(other Proxy) bool
	// Name returns the unique tunnel name associated with this proxy.
	Name() string
	// Endpoint returns a string representation of the proxy's listening address.
	Endpoint() string
	// ListenAddr returns the network address the proxy is listening on.
	ListenAddr() net.Addr
	// BytesTx returns the total bytes transmitted through this proxy.
	BytesTx() uint64
	// BytesRx returns the total bytes received through this proxy.
	BytesRx() uint64
	// BytesTotal returns the sum of Tx and Rx bytes.
	BytesTotal() uint64
	// InstanceId returns a unique identifier for this specific proxy execution.
	InstanceId() string
}

// TCPProxy implements a transparent TCP layer-4 proxy.
type TCPProxy struct {
	// Listener is the underlying TCP listener.
	Listener   net.Listener
	// Addr is the address the proxy is configured to listen on.
	Addr       *net.TCPAddr
	name       string
	bytesRx    atomic.Uint64
	bytesTx    atomic.Uint64
	instanceId string
	// cleanup is called when the tunnel destination becomes unreachable.
	cleanup    func(tunnelName string)
	// dialFailures tracks consecutive upstream-dial failures so a transient
	// outage doesn't tear the tunnel down (F-9). Lazy-initialised by
	// constructProxy via newTCPProxy / inferred default in StartProxy.
	dialFailures *util.FailureTracker
}

// Close closes the TCPProxy listener.
func (p *TCPProxy) Close() error {
	if p.Listener == nil {
		return nil
	}
	log.Info().Str("proxy", p.name).Msg("TCPProxy: closing")
	return p.Listener.Close()
}

func (p *TCPProxy) Endpoint() string {
	if p.Listener != nil {
		return p.Listener.Addr().String()
	}
	if p.Addr != nil {
		return p.Addr.String()
	}
	return ""
}
func (p *TCPProxy) Name() string {
	return p.name
}

func (p *TCPProxy) InstanceId() string {
	return p.instanceId
}

func (p *TCPProxy) BytesRx() uint64 {
	return p.bytesRx.Load()
}

func (p *TCPProxy) BytesTx() uint64 {
	return p.bytesTx.Load()
}

func (p *TCPProxy) BytesTotal() uint64 {
	return p.bytesRx.Load() + p.bytesTx.Load()
}

func (p *TCPProxy) ListenAddr() net.Addr {
	if p.Listener != nil {
		return p.Listener.Addr()
	}
	return p.Addr
}

func (p *TCPProxy) Conflicts(other Proxy) bool {
	switch o := other.(type) {
	case *TCPProxy:
		pAddr := p.ListenAddr().(*net.TCPAddr)
		oAddr := o.ListenAddr().(*net.TCPAddr)
		if (pAddr.IP.IsUnspecified() || oAddr.IP.IsUnspecified()) && pAddr.Port == oAddr.Port {
			return true
		}
		return pAddr.String() == oAddr.String()
	case *VHostRouteProxy:
		pAddr := p.ListenAddr().(*net.TCPAddr)
		oAddr, ok := o.ListenAddr().(*net.TCPAddr)
		if !ok {
			return false
		}

		if (pAddr.IP.IsUnspecified() || oAddr.IP.IsUnspecified()) && pAddr.Port == oAddr.Port {
			return true
		}
		if pAddr.IP.Equal(oAddr.IP) && pAddr.Port == oAddr.Port {
			return true
		}
		return false
	default:
		return false
	}
}

// UDPProxy implements a transparent UDP layer-4 proxy.
type UDPProxy struct {
	name       string
	// Conn is the underlying UDP connection (could be WireGuard-aware).
	Conn       WGAwareUDPConn
	// Addr is the address the proxy is configured to listen on.
	Addr       *net.UDPAddr
	bytesRx    atomic.Uint64
	bytesTx    atomic.Uint64
	instanceId string
}

// Close closes the UDPProxy connection.
func (p *UDPProxy) Close() error {
	log.Info().Str("proxy", p.name).Msg("UDPProxy: closing")
	return p.Conn.Close()
}

func (p *UDPProxy) Endpoint() string {
	if p.Conn.netConn != nil || p.Conn.goNetConn != nil {
		return p.Conn.LocalAddr().String()
	}
	if p.Addr != nil {
		return p.Addr.String()
	}
	return ""
}

func (p *UDPProxy) ListenAddr() net.Addr {
	if p.Conn.netConn != nil || p.Conn.goNetConn != nil {
		return p.Conn.LocalAddr()
	}
	return p.Addr
}

func (p *UDPProxy) Conflicts(other Proxy) bool {
	if o, ok := other.(*UDPProxy); ok {
		return p.Endpoint() == o.Endpoint()
	}
	return false
}

func (p *UDPProxy) Name() string {
	return p.name
}

func (p *UDPProxy) InstanceId() string {
	return p.instanceId
}

func (p *UDPProxy) BytesRx() uint64 {
	return p.bytesRx.Load()
}

func (p *UDPProxy) BytesTx() uint64 {
	return p.bytesTx.Load()
}

func (p *UDPProxy) BytesTotal() uint64 {
	return p.BytesRx() + p.BytesTx()
}

// VHostRouteProxy implements a layer-7 HTTP/HTTPS proxy with virtual host routing.
type VHostRouteProxy struct {
	name       string
	handler    *meter.MeteredHTTPHandler
	// Closer allows shutting down the specific vhost route.
	Closer     io.Closer
	// Host is the hostname matched by this proxy.
	Host       string
	// Port is the port matched by this proxy.
	Port       int
	// BindIp is the IP address the proxy is bound to.
	BindIp     string
	// IsHTTPS indicates if the proxy expects TLS traffic.
	IsHTTPS    bool
	// Rewrite is the path prefix rewrite rule.
	Rewrite    string
	// Matchers are the rules used to select this route.
	Matchers   map[string]string
	// Modifiers are the rules used to transform requests on this route.
	Modifiers  map[string]string
	instanceId string
}

// Close closes the VHostRouteProxy.
func (p *VHostRouteProxy) Close() error {
	if p.Closer == nil {
		return nil
	}
	log.Info().Str("proxy", p.name).Msg("VHostRouteProxy: closing")
	return p.Closer.Close()
}

func (p *VHostRouteProxy) Endpoint() string {
	return fmt.Sprintf("%s:%d/%s", p.BindIp, p.Port, p.Host)
}

func (p *VHostRouteProxy) ListenAddr() net.Addr {
	addr, _ := net.ResolveTCPAddr("tcp", fmt.Sprintf("%s:%d", p.BindIp, p.Port))
	return addr
}

func (p *VHostRouteProxy) Conflicts(other Proxy) bool {
	switch o := other.(type) {
	case *TCPProxy:
		return o.Conflicts(p)
	case *VHostRouteProxy:
		// If BindIp and Port are the same, but IsHTTPS is different, it's a conflict.
		if p.BindIp == o.BindIp && p.Port == o.Port && p.IsHTTPS != o.IsHTTPS {
			return true
		}
		// If BindIp, Port, Host, IsHTTPS are same, then check Rewrite, Matchers and Modifiers
		if p.BindIp == o.BindIp && p.Port == o.Port && p.Host == o.Host && p.IsHTTPS == o.IsHTTPS {
			// Compare Rewrites
			if p.Rewrite != o.Rewrite {
				return false
			}
			// Compare Matchers
			if len(p.Matchers) != len(o.Matchers) {
				return false
			}
			for k, v := range p.Matchers {
				if ov, ok := o.Matchers[k]; !ok || ov != v {
					return false
				}
			}
			// Compare Modifiers
			if len(p.Modifiers) != len(o.Modifiers) {
				return false
			}
			for k, v := range p.Modifiers {
				if ov, ok := o.Modifiers[k]; !ok || ov != v {
					return false
				}
			}
			return true // Everything matches, so it is a conflict
		}
		return false
	default:
		return false
	}
}

func (p *VHostRouteProxy) BytesRx() uint64 {
	return p.handler.BytesRx()
}

func (p *VHostRouteProxy) BytesTx() uint64 {
	return p.handler.BytesTx()
}

func (p *VHostRouteProxy) BytesTotal() uint64 {
	return p.handler.BytesTotal()
}

func (p *VHostRouteProxy) Name() string {
	return p.name
}

func (p *VHostRouteProxy) InstanceId() string {
	return p.instanceId
}

type WGAwareUDPConn struct {
	goNetConn *gonet.UDPConn
	netConn   *net.UDPConn
}

func (w *WGAwareUDPConn) LocalAddr() net.Addr {
	if w.netConn != nil {
		return w.netConn.LocalAddr()
	}
	if w.goNetConn != nil {
		return w.goNetConn.LocalAddr()
	}
	return nil
}

func (w *WGAwareUDPConn) ReadFromUDP(b []byte) (int, *net.UDPAddr, error) {
	if w.netConn != nil {
		return w.netConn.ReadFromUDP(b)
	}
	n, addr, err := w.goNetConn.ReadFrom(b)
	return n, addr.(*net.UDPAddr), err
}

func (w *WGAwareUDPConn) Write(b []byte) (int, error) {
	if w.netConn != nil {
		return w.netConn.Write(b)
	}
	return w.goNetConn.Write(b)
}

func (w *WGAwareUDPConn) WriteToUDP(b []byte, addr *net.UDPAddr) (int, error) {
	if w.netConn != nil {
		return w.netConn.WriteToUDP(b, addr)
	}
	return w.goNetConn.WriteTo(b, addr)
}

func (w WGAwareUDPConn) Close() error {
	if w.netConn != nil {
		return w.netConn.Close()
	}
	if w.goNetConn != nil {
		return w.goNetConn.Close()
	}
	return nil
}

func isWGAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	return constants.DefaultSubnet.Contains(ip)
}

func WGAwareUDPDial(addr *net.UDPAddr, device *wireguard.UserspaceDevice) (WGAwareUDPConn, error) {
	if isWGAddr(addr.String()) {
		if device == nil {
			return WGAwareUDPConn{}, fmt.Errorf("cannot dial on WireGuard host %s without wireguard device", addr.String())
		}
		outgoingConn, err := device.NetStack.DialUDP(nil, addr)
		return WGAwareUDPConn{goNetConn: outgoingConn, netConn: nil}, err
	} else {
		outgoingConn, err := net.DialUDP("udp", nil, addr)
		return WGAwareUDPConn{goNetConn: nil, netConn: outgoingConn}, err

	}
}

func WGAwareUDPListen(addr *net.UDPAddr, device *wireguard.UserspaceDevice) (WGAwareUDPConn, error) {
	if isWGAddr(addr.String()) {
		if device == nil {
			return WGAwareUDPConn{}, fmt.Errorf("cannot listen on WireGuard host %s without wireguard device", addr.String())
		}
		rawListener, err := device.NetStack.ListenUDP(addr)
		return WGAwareUDPConn{goNetConn: rawListener, netConn: nil}, err
	} else {
		rawListener, err := net.ListenUDP("udp", addr)
		return WGAwareUDPConn{goNetConn: nil, netConn: rawListener}, err
	}
}

func WGAwareTCPDial(addr *net.TCPAddr, device *wireguard.UserspaceDevice) (net.Conn, error) {
	if isWGAddr(addr.String()) {
		if device == nil {
			return nil, fmt.Errorf("cannot dial on WireGuard host %s without wireguard device", addr.String())
		}
		return device.NetStack.DialTCP(addr)
	} else {
		return net.DialTCP("tcp", nil, addr)
	}
}

func WGAwareTCPListen(addr *net.TCPAddr, device *wireguard.UserspaceDevice) (net.Listener, error) {
	if isWGAddr(addr.String()) {
		if device == nil {
			return nil, fmt.Errorf("cannot listen on WireGuard host %s without wireguard device", addr.String())
		}
		return device.NetStack.ListenTCP(addr)
	} else {
		return net.ListenTCP("tcp", addr)
	}
}
