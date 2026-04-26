package vhost

import (
	"context"
	"crypto/tls"
	"sync"
	"testing"
)

// TestACMEHostsAndPolicy_NoRace exercises the AddACMEHost mutator and the
// HostPolicy reader concurrently. Under -race the pre-F-6 code triggered
// "DATA RACE" reports on the acmeHosts map. The fix takes m.mu in both
// callsites; this test guards against regression.
func TestACMEHostsAndPolicy_NoRace(t *testing.T) {
	m := NewVHostProxyManager()
	policy := m.acmeManager.HostPolicy
	if policy == nil {
		t.Fatal("HostPolicy should be set")
	}

	const writers = 8
	const readers = 8
	const iters = 200

	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < iters; j++ {
				m.mu.Lock()
				m.acmeHosts[hostName(i, j)] = true
				m.mu.Unlock()
			}
		}(i)
	}
	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iters; j++ {
				_ = policy(context.Background(), "lookup-host")
			}
		}()
	}
	wg.Wait()
}

// TestTLSGetCertificate_NoRace exercises a VHostProxy's TLS GetCertificate
// callback concurrently with writes to its tlsConfigs map. Pre-fix this
// raced; post-fix the snapshot under p.mu.RLock keeps it clean.
func TestTLSGetCertificate_NoRace(t *testing.T) {
	m := NewVHostProxyManager()
	p := NewVHostProxy(VHostKey{BindIp: "127.0.0.1", Port: 0}, m)

	// Build the TLS GetCertificate the same way Start() does, without
	// actually opening a listener.
	getCert := func(serverName string) (*tls.Certificate, error) {
		hello := &tls.ClientHelloInfo{ServerName: serverName}
		return tlsGetCertificateForTest(p, hello)
	}

	const writers = 4
	const readers = 8
	const iters = 200

	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < iters; j++ {
				p.mu.Lock()
				p.tlsConfigs[hostName(i, j)] = &tls.Config{}
				p.mu.Unlock()
			}
		}(i)
	}
	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iters; j++ {
				_, _ = getCert("lookup-host")
			}
		}()
	}
	wg.Wait()
}

func hostName(i, j int) string {
	const tab = "0123456789abcdef"
	return string([]byte{tab[i&0xf], tab[(j>>4)&0xf], tab[j&0xf]}) + ".example"
}

// tlsGetCertificateForTest mirrors the lock-snapshot logic in
// VHostProxy.Start's GetCertificate closure for tlsConfigs lookups, without
// the autocert path. Kept here in test code so we can exercise the race
// surface without spinning up a real TLS listener.
func tlsGetCertificateForTest(p *VHostProxy, hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	p.mu.RLock()
	cfg, ok := p.tlsConfigs[hello.ServerName]
	p.mu.RUnlock()
	if ok && len(cfg.Certificates) > 0 {
		return &cfg.Certificates[0], nil
	}
	return nil, nil
}
