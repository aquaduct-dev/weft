package server

import (
	"net/netip"

	"github.com/aquaduct-dev/weft/types"
	"github.com/aquaduct-dev/weft/wireguard"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// testDataplane is a minimal Dataplane implementation for handler tests that do
// not exercise WireGuard or proxy plumbing.
type testDataplane struct {
	counters map[string]ProxyCounters
}

func newTestDataplane() *testDataplane {
	return &testDataplane{counters: map[string]ProxyCounters{}}
}

func (d *testDataplane) UpdateWireGuardConfig(peers map[string]Peer) error { return nil }
func (d *testDataplane) StartProxy(req *types.ConnectRequest, peerIP netip.Addr) (int, error) {
	return 0, nil
}
func (d *testDataplane) CloseProxy(name string) {}
func (d *testDataplane) GetProxyCounters() map[string]ProxyCounters {
	return d.counters
}
func (d *testDataplane) GetWgListenPort() int                  { return 0 }
func (d *testDataplane) GetDevice() *wireguard.UserspaceDevice { return nil }
func (d *testDataplane) GetPrivateKey() wgtypes.Key            { return wgtypes.Key{} }
func (d *testDataplane) SetACMEEmail(email string)             {}
func (d *testDataplane) SetCertsCachePath(path string)         {}
func (d *testDataplane) ListCertificates() ([]types.CertInfo, error) {
	return []types.CertInfo{}, nil
}
func (d *testDataplane) RegisterACMERedirect(host, peerIP string) error {
	return nil
}
