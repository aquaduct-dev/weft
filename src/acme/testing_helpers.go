// Cross-package test seams for the ACME redirect coordination logic.
//
// These helpers are exported solely so that tests living in *other* packages
// (notably src/proxy/vhost) can inject deterministic DNS and interface
// state. They have no production use and should not be called from non-test
// code.
package acme

import "net"

// SwapLookupIPForTest replaces the package-level lookupIP seam with a closure
// driven by hostsToIPs (host → list of dotted-decimal addresses). It returns
// the previous function so the caller can restore it via RestoreLookupIPForTest.
//
// Production code does not call this — it remains on net.LookupIP.
func SwapLookupIPForTest(hostsToIPs map[string][]string) func(string) ([]net.IP, error) {
	prev := lookupIP
	parsed := make(map[string][]net.IP, len(hostsToIPs))
	for h, addrs := range hostsToIPs {
		ips := make([]net.IP, 0, len(addrs))
		for _, a := range addrs {
			if ip := net.ParseIP(a); ip != nil {
				ips = append(ips, ip)
			}
		}
		parsed[h] = ips
	}
	lookupIP = func(host string) ([]net.IP, error) {
		if ips, ok := parsed[host]; ok {
			return ips, nil
		}
		return nil, &net.DNSError{Err: "no such host (test seam)", Name: host, IsNotFound: true}
	}
	return prev
}

// RestoreLookupIPForTest restores the lookupIP seam to a previously-returned
// function (typically net.LookupIP).
func RestoreLookupIPForTest(prev func(string) ([]net.IP, error)) {
	lookupIP = prev
}

// SwapInterfaceAddrsForTest replaces the interfaceAddrs seam to report the
// supplied dotted-decimal addresses as if bound to local interfaces. Returns
// the previous function for restoration via RestoreInterfaceAddrsForTest.
func SwapInterfaceAddrsForTest(localAddrs []string) func() ([]net.Addr, error) {
	prev := interfaceAddrs
	addrs := make([]net.Addr, 0, len(localAddrs))
	for _, a := range localAddrs {
		if ip := net.ParseIP(a); ip != nil {
			addrs = append(addrs, &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)})
		}
	}
	interfaceAddrs = func() ([]net.Addr, error) {
		return addrs, nil
	}
	return prev
}

// RestoreInterfaceAddrsForTest restores the interfaceAddrs seam.
func RestoreInterfaceAddrsForTest(prev func() ([]net.Addr, error)) {
	interfaceAddrs = prev
}
