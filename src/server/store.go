package server

import (
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/aquaduct-dev/weft/src/internal/constants"
)

type InMemoryTunnelStore struct {
	mu           sync.RWMutex
	peers        map[string]Peer
	peerLastSeen map[string]time.Time
	usedIPs      map[netip.Addr]bool
	subnet       netip.Prefix
}

func NewInMemoryTunnelStore() *InMemoryTunnelStore {
	return &InMemoryTunnelStore{
		peers:        make(map[string]Peer),
		peerLastSeen: make(map[string]time.Time),
		usedIPs:      make(map[netip.Addr]bool),
		subnet:       constants.DefaultSubnet,
	}
}

func (s *InMemoryTunnelStore) GetPeer(name string) (Peer, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.peers[name]
	return p, ok
}

func (s *InMemoryTunnelStore) SetPeer(name string, p Peer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.peers[name] = p
}

func (s *InMemoryTunnelStore) DeletePeer(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.peers, name)
}

func (s *InMemoryTunnelStore) GetAllPeers() map[string]Peer {
	s.mu.RLock()
	defer s.mu.RUnlock()
	res := make(map[string]Peer, len(s.peers))
	for k, v := range s.peers {
		res[k] = v
	}
	return res
}

func (s *InMemoryTunnelStore) GetLastSeen(name string) (time.Time, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.peerLastSeen[name]
	return t, ok
}

func (s *InMemoryTunnelStore) SetLastSeen(name string, t time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.peerLastSeen[name] = t
}

func (s *InMemoryTunnelStore) DeleteLastSeen(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.peerLastSeen, name)
}

func (s *InMemoryTunnelStore) GetAllLastSeen() map[string]time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	res := make(map[string]time.Time, len(s.peerLastSeen))
	for k, v := range s.peerLastSeen {
		res[k] = v
	}
	return res
}

func (s *InMemoryTunnelStore) GetFreeIP() (netip.Addr, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.allocateIPLocked()
}

// allocateIPLocked reserves and returns the next free IP in the subnet.
// Caller must hold s.mu (write lock).
func (s *InMemoryTunnelStore) allocateIPLocked() (netip.Addr, error) {
	hostAddr := constants.DefaultServerIP
	if _, used := s.usedIPs[hostAddr]; !used {
		s.usedIPs[hostAddr] = true
	}

	addr := hostAddr
	for {
		addr = addr.Next()
		if !s.subnet.Contains(addr) {
			return netip.Addr{}, fmt.Errorf("subnet exhausted")
		}

		if !s.subnet.Contains(addr.Next()) {
			continue // skip broadcast
		}

		if _, used := s.usedIPs[addr]; !used {
			s.usedIPs[addr] = true
			return addr, nil
		}
	}
}

// CreatePeer atomically registers a new peer under name, allocating an IP
// via the supplied factory. If a peer with the same name already exists, the
// existing record is returned and created=false; no IP is allocated and the
// factory is not invoked. On (created=true), last-seen is also bumped.
func (s *InMemoryTunnelStore) CreatePeer(name string, factory func(ip netip.Addr) Peer) (Peer, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if p, ok := s.peers[name]; ok {
		s.peerLastSeen[name] = time.Now()
		return p, false, nil
	}

	ip, err := s.allocateIPLocked()
	if err != nil {
		return Peer{}, false, err
	}

	p := factory(ip)
	s.peers[name] = p
	s.peerLastSeen[name] = time.Now()
	return p, true, nil
}

func (s *InMemoryTunnelStore) ReleaseIP(ip netip.Addr) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.usedIPs, ip)
}
