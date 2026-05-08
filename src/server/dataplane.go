package server

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"github.com/aquaduct-dev/weft/src/internal/constants"
	proxy "github.com/aquaduct-dev/weft/src/proxy"
	"github.com/aquaduct-dev/weft/types"
	"github.com/aquaduct-dev/weft/wireguard"
	"github.com/rs/zerolog/log"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type TunnelDataplane struct {
	mu           sync.Mutex
	device       *wireguard.UserspaceDevice
	privateKey   wgtypes.Key
	wgListenPort int
	proxyManager *proxy.ProxyManager
	bindIP       string
	isClosing    func() bool
}

func NewTunnelDataplane(wgPort int, bindIP string, cleanup func(string), isClosing func() bool) (*TunnelDataplane, error) {
	device, privateKey, actualPort, err := CreateDevice(wgPort, bindIP)
	if err != nil {
		return nil, err
	}

	pm := proxy.NewProxyManager()
	if bindIP != "" {
		pm.SetBindIP(bindIP)
	}
	pm.Cleanup = cleanup
	pm.VHostProxyManager.Cleanup = cleanup

	return &TunnelDataplane{
		device:       device,
		privateKey:   privateKey,
		wgListenPort: actualPort,
		proxyManager: pm,
		bindIP:       bindIP,
		isClosing:    isClosing,
	}, nil
}

func (d *TunnelDataplane) GetWgListenPort() int {
	return d.wgListenPort
}

func (d *TunnelDataplane) GetDevice() *wireguard.UserspaceDevice {
	return d.device
}

func (d *TunnelDataplane) GetPrivateKey() wgtypes.Key {
	return d.privateKey
}

func (d *TunnelDataplane) UpdateWireGuardConfig(peers map[string]Peer) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.device == nil || d.device.Device == nil {
		return fmt.Errorf("device closed")
	}

	if d.isClosing() {
		return fmt.Errorf("server shutting down")
	}

	// Refresh wgListenPort from the device. If IpcGet fails we keep the
	// last-known port — UpdateWireGuardConfig still passes &d.wgListenPort
	// below, and a wrong port here would manifest as a peer-config error
	// downstream — but log so the silent stale-port path is at least visible.
	ipc, err := d.device.Device.IpcGet()
	if err != nil {
		log.Warn().Err(err).Msg("UpdateWireGuardConfig: IpcGet failed; using last-known wgListenPort")
	} else {
		for _, line := range strings.Split(ipc, "\n") {
			if portStr, ok := strings.CutPrefix(line, "listen_port="); ok {
				if p, parseErr := strconv.Atoi(strings.TrimSpace(portStr)); parseErr == nil && p != 0 {
					d.wgListenPort = p
				}
			}
		}
	}

	cfg := wgtypes.Config{
		ListenPort:   &d.wgListenPort,
		ReplacePeers: true,
	}
	for _, p := range peers {
		cfg.Peers = append(cfg.Peers, wgtypes.PeerConfig{
			PublicKey:  p.PublicKey,
			AllowedIPs: []net.IPNet{{IP: net.IP(p.IP.AsSlice()), Mask: net.CIDRMask(32, 32)}, {IP: net.IP(constants.DefaultServerIP.AsSlice()), Mask: net.CIDRMask(32, 32)}},
		})
	}

	newConfig, err := wireguard.ConfigToString(cfg)
	if err != nil {
		return err
	}

	currentConfig, _ := d.device.Device.IpcGet()
	if d.sanitizeConfig(currentConfig) == d.sanitizeConfig(newConfig) && currentConfig != "" {
		return nil
	}

	if err := d.device.Device.IpcSet(newConfig); err != nil {
		return err
	}

	return nil
}

func (d *TunnelDataplane) sanitizeConfig(conf string) string {
	var out []string
	for _, line := range strings.Split(conf, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "private_key=") {
			out = append(out, constants.WGPrivateKeyRedacted)
			continue
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

func (d *TunnelDataplane) StartProxy(req *types.ConnectRequest, peerIP netip.Addr) (int, error) {
	tunnelProxyPortBigInt, err := rand.Int(rand.Reader, big.NewInt(10000))
	if err != nil {
		return 0, err
	}
	tunnelProxyPort := int(tunnelProxyPortBigInt.Uint64()) + 10000

	var tunnelSource url.URL
	if strings.Contains(req.RemoteModifiers, "redirect") {
		u, err := url.Parse(req.ProxiedUpstream)
		if err == nil {
			tunnelSource = *u
		} else {
			tunnelSource = url.URL{
				Host:   fmt.Sprintf("%s:%d", peerIP.String(), tunnelProxyPort),
				Scheme: "http",
			}
		}
	} else {
		tunnelSource = url.URL{
			Host:   fmt.Sprintf("%s:%d", peerIP.String(), tunnelProxyPort),
			Scheme: "http",
		}
	}
	tunnelSource.Fragment = req.RemoteModifiers

	tunnelEnd := url.URL{
		Host:     fmt.Sprintf("%s:%d", req.Hostname, req.RemotePort),
		Scheme:   "http",
		Path:     req.RemotePath,
		RawQuery: req.RemoteQuery,
		Fragment: req.RemoteFragment,
	}

	switch req.Protocol {
	case "tcp":
		tunnelSource.Scheme = "tcp"
		tunnelEnd.Scheme = "tcp"
	case "udp":
		tunnelSource.Scheme = "udp"
		tunnelEnd.Scheme = "udp"
	case "http":
		tunnelSource.Scheme = "http"
		tunnelEnd.Scheme = "http"
	case "https":
		tunnelSource.Scheme = "http"
		tunnelEnd.Scheme = "https"
	default:
		return 0, fmt.Errorf("unknown protocol: %s", req.Protocol)
	}

	var certBytes, keyBytes []byte
	if req.Protocol == "https" {
		if req.CertificatePEM != "" || req.PrivateKeyPEM != "" {
			if req.CertificatePEM == "" || req.PrivateKeyPEM == "" {
				return 0, fmt.Errorf("missing certificate or private key for https protocol")
			}
			certBytes = []byte(req.CertificatePEM)
			keyBytes = []byte(req.PrivateKeyPEM)
		}
	}

	_, err = d.proxyManager.StartProxy(&tunnelSource, &tunnelEnd, req.TunnelName, d.device, certBytes, keyBytes, d.bindIP)
	return tunnelProxyPort, err
}

func (d *TunnelDataplane) CloseProxy(name string) {
	d.proxyManager.Close(name)
}

func (d *TunnelDataplane) GetProxyCounters() map[string]ProxyCounters {
	proxies := d.proxyManager.GetProxyCounters()
	res := make(map[string]ProxyCounters, len(proxies))
	for k, v := range proxies {
		res[k] = ProxyCounters{
			Tx:         v.Tx,
			Rx:         v.Rx,
			InstanceId: v.InstanceId,
		}
	}
	return res
}

func (d *TunnelDataplane) SetACMEEmail(email string) {
	d.proxyManager.VHostProxyManager.SetACMEEmail(email)
}

func (d *TunnelDataplane) SetCertsCachePath(path string) {
	d.proxyManager.VHostProxyManager.SetCertsCachePath(path)
}

// RegisterACMERedirect forwards the peer redirect registration to the vhost
// manager. The /acme-redirect HTTP handler must verify the peer IP is in DNS
// for host before calling this — this layer is just plumbing.
func (d *TunnelDataplane) RegisterACMERedirect(host, peerIP string) error {
	d.proxyManager.VHostProxyManager.RegisterPeerRedirect(host, peerIP)
	return nil
}
