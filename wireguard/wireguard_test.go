// wireguard_test.go pins the UAPI text that ConfigToString produces for the
// configurations weft sends to its userspace WireGuard devices: an empty
// config, a private key only, peer removal, and full peers with allowed IPs,
// endpoints and keepalives. Key material in these tests is fixed test data.
package wireguard

import (
	"net"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// testKey returns a deterministic key whose bytes are all b, so the expected
// hex in the UAPI output is easy to read.
func testKey(b byte) wgtypes.Key {
	var k wgtypes.Key
	for i := range k {
		k[i] = b
	}
	return k
}

func hexOf(b byte) string {
	const digits = "0123456789abcdef"
	pair := string([]byte{digits[b>>4], digits[b&0xf]})
	out := ""
	for i := 0; i < wgtypes.KeyLen; i++ {
		out += pair
	}
	return out
}

func TestConfigToString(t *testing.T) {
	priv := testKey(0x11)
	peerA := testKey(0xaa)
	peerB := testKey(0xbb)
	port := 51820
	keepalive := 25 * time.Second
	_, allowed1, _ := net.ParseCIDR("10.1.0.2/32")
	_, allowed2, _ := net.ParseCIDR("10.2.0.0/16")
	endpoint := &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 51821}

	cases := []struct {
		name string
		cfg  wgtypes.Config
		want string
	}{
		{
			name: "empty config is a single newline",
			cfg:  wgtypes.Config{},
			want: "\n",
		},
		{
			name: "private key and listen port only",
			cfg:  wgtypes.Config{PrivateKey: &priv, ListenPort: &port, ReplacePeers: true},
			want: "private_key=" + hexOf(0x11) + "\n" +
				"listen_port=51820\n" +
				"replace_peers=true\n",
		},
		{
			name: "removed peer emits only public_key and remove",
			cfg: wgtypes.Config{Peers: []wgtypes.PeerConfig{{
				PublicKey:  peerA,
				Remove:     true,
				AllowedIPs: []net.IPNet{*allowed1},
				Endpoint:   endpoint,
			}}},
			want: "public_key=" + hexOf(0xaa) + "\n" +
				"remove=true\n",
		},
		{
			name: "mixed peers with allowed IPs, endpoint and keepalive",
			cfg: wgtypes.Config{Peers: []wgtypes.PeerConfig{
				{PublicKey: peerA, Remove: true},
				{
					PublicKey:                   peerB,
					AllowedIPs:                  []net.IPNet{*allowed1, *allowed2},
					Endpoint:                    endpoint,
					PersistentKeepaliveInterval: &keepalive,
				},
			}},
			want: "public_key=" + hexOf(0xaa) + "\n" +
				"remove=true\n" +
				"public_key=" + hexOf(0xbb) + "\n" +
				"allowed_ip=10.1.0.2/32\n" +
				"allowed_ip=10.2.0.0/16\n" +
				"endpoint=192.0.2.1:51821\n" +
				"persistent_keepalive_interval=25\n",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ConfigToString(tc.cfg)
			if err != nil {
				t.Fatalf("ConfigToString returned error: %v", err)
			}
			if got != tc.want {
				t.Errorf("ConfigToString mismatch\n got: %q\nwant: %q", got, tc.want)
			}
		})
	}
}
