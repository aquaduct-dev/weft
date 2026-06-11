/*
dataplane_endpoint_wipe_test.go

Stage 2/3 verification: removing ONE WireGuard tunnel is disruptive for ALL of
them.

UpdateWireGuardConfig (called on every /connect and every RemoveTunnel) rebuilds
the device with `replace_peers=true`, which in wireguard-go runs RemoveAllPeers()
— wiping every peer — and then re-adds the survivors from config that carries no
endpoint. WireGuard learns a client's endpoint by roaming (from the client's
keepalives), and that learned value lives only in device memory, not in weft's
config. So rebuilding the peer set to remove one tunnel collaterally erases the
roamed endpoints of every *other* tunnel, forcing each to re-learn its return
path.

This test sets endpoints on two peers (A and B), removes only B via the
production UpdateWireGuardConfig path, and asserts the innocent bystander A lost
its endpoint. It characterizes the bug: when weft switches to incremental
per-peer add/remove, A's endpoint should survive and the final assertion flips.
*/
package server

import (
	"encoding/hex"
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/aquaduct-dev/weft/wireguard"
)

// endpointFor returns the endpoint recorded for the peer with the given hex
// public key in an IpcGet dump, or "" if that peer has no endpoint.
func endpointFor(ipc, pubHex string) string {
	var cur string
	for _, line := range strings.Split(ipc, "\n") {
		if v, ok := strings.CutPrefix(line, "public_key="); ok {
			cur = v
			continue
		}
		if v, ok := strings.CutPrefix(line, "endpoint="); ok && cur == pubHex {
			return v
		}
	}
	return ""
}

func TestRemovingOneTunnelWipesBystanderEndpoints(t *testing.T) {
	dp, err := NewTunnelDataplane(0, "", func(string) {}, func() bool { return false })
	if err != nil {
		t.Fatalf("NewTunnelDataplane: %v", err)
	}
	defer dp.GetDevice().Device.Close()

	privA, err := wireguard.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("keygen A: %v", err)
	}
	privB, err := wireguard.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("keygen B: %v", err)
	}
	pubA, pubB := privA.PublicKey(), privB.PublicKey()
	hexA := hex.EncodeToString(pubA[:])
	hexB := hex.EncodeToString(pubB[:])

	// Two independent tunnels registered, exactly as two /connect calls would.
	peers := map[string]Peer{
		"tunnel-a": {PublicKey: pubA, IP: netip.MustParseAddr("10.1.0.2")},
		"tunnel-b": {PublicKey: pubB, IP: netip.MustParseAddr("10.1.0.3")},
	}
	if err := dp.UpdateWireGuardConfig(peers); err != nil {
		t.Fatalf("initial UpdateWireGuardConfig: %v", err)
	}

	// Simulate the server having learned each client's endpoint via roaming
	// (what the clients' 1s keepalives accomplish in production). This is an
	// in-place per-peer update — no replace_peers — so it only sets endpoints.
	dev := dp.GetDevice().Device
	if err := dev.IpcSet(fmt.Sprintf("public_key=%s\nendpoint=192.0.2.10:51820\n", hexA)); err != nil {
		t.Fatalf("inject endpoint A: %v", err)
	}
	if err := dev.IpcSet(fmt.Sprintf("public_key=%s\nendpoint=192.0.2.11:51820\n", hexB)); err != nil {
		t.Fatalf("inject endpoint B: %v", err)
	}

	ipc, err := dev.IpcGet()
	if err != nil {
		t.Fatalf("IpcGet (precondition): %v", err)
	}
	if got := endpointFor(ipc, hexA); got != "192.0.2.10:51820" {
		t.Fatalf("precondition: tunnel-a endpoint not learned (got %q)", got)
	}
	if got := endpointFor(ipc, hexB); got != "192.0.2.11:51820" {
		t.Fatalf("precondition: tunnel-b endpoint not learned (got %q)", got)
	}

	// Remove ONLY tunnel-b — the exact WG sync RemoveTunnel performs after a
	// peer is evicted (rebuild the device over the remaining peers).
	delete(peers, "tunnel-b")
	if err := dp.UpdateWireGuardConfig(peers); err != nil {
		t.Fatalf("UpdateWireGuardConfig after removing tunnel-b: %v", err)
	}

	ipc, err = dev.IpcGet()
	if err != nil {
		t.Fatalf("IpcGet (post-removal): %v", err)
	}

	// tunnel-a was never touched, yet removing tunnel-b should have wiped its
	// learned endpoint via replace_peers. That is the disruption.
	epA := endpointFor(ipc, hexA)
	if epA != "" {
		t.Fatalf("tunnel-a endpoint survived removal of tunnel-b (got %q): "+
			"replace_peers wipe NOT reproduced — has weft moved to incremental peer ops?", epA)
	}
	t.Logf("confirmed: removing tunnel-b wiped innocent tunnel-a's learned endpoint " +
		"(was 192.0.2.10:51820, now empty). One tunnel's teardown disrupts all peers' return paths.")
}
