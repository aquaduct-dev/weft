package server

import (
	"net/netip"
	"sync"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// TestCreatePeer_NoIPLeakUnderRace proves that racing CreatePeer() calls with
// the same tunnel name never hand out more than one IP from the pool. The
// previous check-then-act (GetPeer → GetFreeIP → SetPeer) leaked an IP per
// losing racer.
func TestCreatePeer_NoIPLeakUnderRace(t *testing.T) {
	s := NewInMemoryTunnelStore()

	const racers = 64
	results := make([]Peer, racers)
	createds := make([]bool, racers)

	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range racers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			p, created, err := s.CreatePeer("shared-name", func(ip netip.Addr) Peer {
				return Peer{IP: ip, PublicKey: wgtypes.Key{byte(i)}}
			})
			if err != nil {
				t.Errorf("CreatePeer error: %v", err)
				return
			}
			results[i] = p
			createds[i] = created
		}(i)
	}
	close(start)
	wg.Wait()

	createdCount := 0
	for _, c := range createds {
		if c {
			createdCount++
		}
	}
	if createdCount != 1 {
		t.Fatalf("expected exactly one creator, got %d", createdCount)
	}

	firstIP := results[0].IP
	for i, p := range results {
		if p.IP != firstIP {
			t.Fatalf("racer %d saw IP %s, expected %s (all racers must observe the same peer)", i, p.IP, firstIP)
		}
	}

	// Every additional IP beyond the first is a leak. Count distinct reserved IPs.
	// GetFreeIP now must hand out a different address than the one we already reserved.
	second, err := s.GetFreeIP()
	if err != nil {
		t.Fatalf("GetFreeIP after race: %v", err)
	}
	if second == firstIP {
		t.Fatal("pool handed out the same IP twice")
	}

	// Only the peer IP + the second IP should be reserved (plus the server IP).
	// usedIPs should have 3 entries: server, tunnel, second.
	if got := len(s.usedIPs); got != 3 {
		t.Fatalf("expected 3 reserved IPs (server+tunnel+second), got %d; race leaked %d IPs", got, got-3)
	}
}
