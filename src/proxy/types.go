package proxy

import (
	"fmt"
	"io"
	"net"
	"strings"
	"sync/atomic"

	"aquaduct.dev/weft/src/vhost/meter"
	"aquaduct.dev/weft/wireguard"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
)

// Proxy is an interface for all proxy types.
type Proxy interface {
	io.Closer
	Conflicts(other Proxy) bool
	Name() string
	Endpoint() string
	ListenAddr() net.Addr
	BytesTx() uint64
	BytesRx() uint64
	BytesTotal() uint64
}

// TCPProxy is a proxy for TCP connections.
type TCPProxy struct {
	Listener net.Listener
	Addr     *net.TCPAddr
	name     string
	bytesRx  atomic.Uint64
	bytesTx  atomic.Uint64
}

// Close closes the TCPProxy listener.
func (p *TCPProxy) Close() error {
	if p.Listener == nil {
		return nil
	}
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

// UDPProxy is a proxy for UDP connections.
type UDPProxy struct {
	name    string
	Conn    WGAwareUDPConn
	Addr    *net.UDPAddr
	bytesRx atomic.Uint64
	bytesTx atomic.Uint64
}

// Close closes the UDPProxy connection.
func (p *UDPProxy) Close() error {
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

func (p *UDPProxy) BytesRx() uint64 {
	return p.bytesRx.Load()
}

func (p *UDPProxy) BytesTx() uint64 {
	return p.bytesTx.Load()
}

func (p *UDPProxy) BytesTotal() uint64 {
	return p.BytesRx() + p.BytesTx()
}

// VHostRouteProxy is a proxy for vhost routes.
type VHostRouteProxy struct {
	name    string
	handler *meter.MeteredHTTPHandler
	Closer  io.Closer
	Host    string
	Port    int
	BindIp  string
	IsHTTPS bool
}

// Close closes the VHostRouteProxy.
func (p *VHostRouteProxy) Close() error {
	if p.Closer == nil {
		return nil
	}
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
		// If BindIp, Port, Host, and IsHTTPS are all the same, it's a duplicate conflict.
		return p.BindIp == o.BindIp && p.Port == o.Port && p.Host == o.Host && p.IsHTTPS == o.IsHTTPS
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

func WGAwareUDPDial(addr *net.UDPAddr, device *wireguard.UserspaceDevice) (WGAwareUDPConn, error) {
	if strings.HasPrefix(addr.String(), "10.1.") {
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
	if strings.HasPrefix(addr.String(), "10.1.") {
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
	if strings.HasPrefix(addr.String(), "10.1.") {
		if device == nil {
			return nil, fmt.Errorf("cannot dial on WireGuard host %s without wireguard device", addr.String())
		}
		return device.NetStack.DialTCP(addr)
	} else {
		return net.DialTCP("tcp", nil, addr)
	}
}

func WGAwareTCPListen(addr *net.TCPAddr, device *wireguard.UserspaceDevice) (net.Listener, error) {
	if strings.HasPrefix(addr.String(), "10.1.") {
		if device == nil {
			return nil, fmt.Errorf("cannot listen on WireGuard host %s without wireguard device", addr.String())
		}
		return device.NetStack.ListenTCP(addr)
	} else {
		return net.ListenTCP("tcp", addr)
	}
}
