package server

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"github.com/aquaduct-dev/weft/src/honeypot"
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

	// Reconcile the device's peers incrementally rather than with a full
	// ReplacePeers rebuild. ReplacePeers runs RemoveAllPeers() and re-adds the
	// survivors from config that carries no endpoint — which discards the
	// endpoints WireGuard learned by roaming from each client's keepalives. The
	// effect is that adding or removing one tunnel wipes the return path of
	// *every other* tunnel on this device, forcing them all to re-learn and
	// breaking any that take traffic in the meantime. Instead we add only new
	// peers and remove only departed ones, leaving live peers — and their
	// learned endpoints — untouched.
	current, err := d.device.Device.IpcGet()
	if err != nil {
		return fmt.Errorf("read current wireguard config: %w", err)
	}

	currentKeys := make(map[string]struct{})
	for _, line := range strings.Split(current, "\n") {
		if portStr, ok := strings.CutPrefix(line, "listen_port="); ok {
			if p, parseErr := strconv.Atoi(strings.TrimSpace(portStr)); parseErr == nil && p != 0 {
				d.wgListenPort = p
			}
			continue
		}
		if key, ok := strings.CutPrefix(line, "public_key="); ok {
			currentKeys[strings.TrimSpace(key)] = struct{}{}
		}
	}

	var cfg wgtypes.Config // no ReplacePeers: incremental add/remove only.

	desiredKeys := make(map[string]struct{}, len(peers))
	for _, p := range peers {
		hexKey := hex.EncodeToString(p.PublicKey[:])
		desiredKeys[hexKey] = struct{}{}
		if _, present := currentKeys[hexKey]; present {
			continue // already configured; leave its learned endpoint intact.
		}
		cfg.Peers = append(cfg.Peers, wgtypes.PeerConfig{
			PublicKey:  p.PublicKey,
			AllowedIPs: []net.IPNet{{IP: net.IP(p.IP.AsSlice()), Mask: net.CIDRMask(32, 32)}, {IP: net.IP(constants.DefaultServerIP.AsSlice()), Mask: net.CIDRMask(32, 32)}},
		})
	}

	for hexKey := range currentKeys {
		if _, want := desiredKeys[hexKey]; want {
			continue
		}
		raw, decErr := hex.DecodeString(hexKey)
		if decErr != nil || len(raw) != len(wgtypes.Key{}) {
			log.Warn().Str("public_key", hexKey).Msg("UpdateWireGuardConfig: skipping unparseable peer key during removal")
			continue
		}
		var pk wgtypes.Key
		copy(pk[:], raw)
		cfg.Peers = append(cfg.Peers, wgtypes.PeerConfig{PublicKey: pk, Remove: true})
	}

	if len(cfg.Peers) == 0 {
		return nil // device already in sync with the desired peer set.
	}

	newConfig, err := wireguard.ConfigToString(cfg)
	if err != nil {
		return err
	}

	if err := d.device.Device.IpcSet(newConfig); err != nil {
		return fmt.Errorf("apply wireguard config: %w", err)
	}

	return nil
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

// SetHoneypotEmitter installs the emitter that publishes one structured
// honeypot event per unmatched-host HTTP request and per failed TLS
// handshake across every VHost listener this dataplane manages. Pass nil to
// disable. Safe to call concurrently with traffic.
func (d *TunnelDataplane) SetHoneypotEmitter(em *honeypot.Emitter) {
	d.proxyManager.VHostProxyManager.SetHoneypotEmitter(em)
}

func (d *TunnelDataplane) SetACMEEmail(email string) {
	d.proxyManager.VHostProxyManager.SetACMEEmail(email)
}

func (d *TunnelDataplane) SetCertsCachePath(path string) {
	d.proxyManager.VHostProxyManager.SetCertsCachePath(path)
}

// ListCertificates returns a summary of the TLS certificates the bastion has
// cached, for the /certificates endpoint.
func (d *TunnelDataplane) ListCertificates() ([]types.CertInfo, error) {
	return d.proxyManager.VHostProxyManager.ListCertificates()
}

// RegisterACMERedirect forwards the peer redirect registration to the vhost
// manager. The /acme-redirect HTTP handler must verify the peer IP is in DNS
// for host before calling this — this layer is just plumbing.
func (d *TunnelDataplane) RegisterACMERedirect(host, peerIP string) error {
	d.proxyManager.VHostProxyManager.RegisterPeerRedirect(host, peerIP)
	return nil
}
