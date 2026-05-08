// Package acme: peer-to-peer challenge redirect coordination.
//
// Background: a weft cluster typically has multiple nodes behind DNS round-robin
// for the same hostname. The ACME HTTP-01 validator picks a random A-record IP
// for each lookup, so it may land on a node that doesn't currently hold the
// keyAuth for an in-flight order. Without coordination, that node returns 404
// and validation fails.
//
// To bridge this, the orderer POSTs /acme-redirect to peer weft servers in the
// same A-record set. After verifying the sender IP appears in DNS for the host,
// each peer 301-redirects subsequent /.well-known/acme-challenge/* requests for
// that host to the orderer. Peers that don't receive a POST fall back to
// redirecting to the highest-IP entry in their own DNS view (the "leader" rule),
// which is the orderer in cold-start scenarios.
//
// Trust model: the IP-in-DNS check is the entire authorization story. We trust
// public DNS for the host — an attacker who can edit DNS for the host can
// already obtain a cert via plain HTTP-01, so /acme-redirect introduces no new
// attack surface. Peer-to-peer TLS uses the existing self-signed weft server
// cert; senders do NOT validate the cert (no shared trust root between weft
// nodes). The TLS layer is for transport, not authentication.
package acme

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"sort"
	"time"

	"github.com/rs/zerolog/log"
)

// Event names emitted by the redirect coordination paths. Operators should
// filter on the structured "event" field of log lines to track health.
const (
	EventRedirectRegistered    = "acme_redirect_registered"
	EventChallengeRedirected   = "acme_challenge_redirected"
	EventRedirectPostSucceeded = "acme_redirect_post_succeeded"
	EventRedirectPostFailed    = "acme_redirect_post_failed"
	EventRedirectTargetChanged = "acme_redirect_target_changed"
	EventRedirectLeaderSelf    = "acme_redirect_leader_self"
	EventRedirectRejected      = "acme_redirect_rejected"
)

// DefaultPeerPort is the default port on which weft servers expose
// /acme-redirect. It mirrors the default --port flag in cmd/server.go.
const DefaultPeerPort = 9092

// Test seams: overridden in unit tests so the logic can be exercised without
// real DNS or interface state. Production callers go through net.LookupIP /
// net.InterfaceAddrs unchanged.
var (
	lookupIP       = net.LookupIP
	interfaceAddrs = net.InterfaceAddrs
)

// PostACMERedirect connects to peerAddr (host:port of the peer's weft control
// plane) and POSTs /acme-redirect?host=<host>. The peer is expected to verify
// the source IP against DNS for host before registering the redirect.
//
// TLS is used for transport but the peer's certificate is NOT validated — weft
// servers use self-signed certs and there is no shared trust root between peer
// nodes. Authorization comes from the peer's IP-in-DNS check, not the cert.
func PostACMERedirect(peerAddr, host string) error {
	tlsConfig := &tls.Config{
		// Self-signed weft server cert; trust model is IP-in-DNS, not cert.
		InsecureSkipVerify: true, //nolint:gosec
		MinVersion:         tls.VersionTLS12,
	}
	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, peerAddr)
		},
	}
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}

	url := fmt.Sprintf("https://%s/acme-redirect?host=%s", peerAddr, host)
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(nil))
	if err != nil {
		return err
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("peer returned %d", resp.StatusCode)
	}
	return nil
}

// LocalIPs returns the non-loopback IPs bound to local network interfaces.
func LocalIPs() ([]net.IP, error) {
	addrs, err := interfaceAddrs()
	if err != nil {
		return nil, err
	}
	var ips []net.IP
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		if ipnet.IP.IsLoopback() {
			continue
		}
		ips = append(ips, ipnet.IP)
	}
	return ips, nil
}

// DescendingPeerIPs returns the A-record IPs for host, sorted descending by
// canonical byte order.
func DescendingPeerIPs(host string) ([]net.IP, error) {
	ips, err := lookupIP(host)
	if err != nil {
		return nil, err
	}
	sort.Slice(ips, func(i, j int) bool {
		return bytes.Compare(ips[i].To16(), ips[j].To16()) > 0
	})
	return ips, nil
}

// IsLocalIP reports whether ip is bound to a local network interface.
func IsLocalIP(ip net.IP, locals []net.IP) bool {
	for _, l := range locals {
		if l.Equal(ip) {
			return true
		}
	}
	return false
}

// RegisterRedirectsLoop runs until ctx is canceled. Each tick it walks the
// descending list of A-record IPs for host and tries to register with the
// first peer that responds successfully on /acme-redirect. If the registered
// peer stops responding on subsequent ticks, the loop falls down to the next
// IP. Once iteration reaches a local IP (i.e. no higher peer is reachable),
// this node is the leader and the loop goes idle until DNS or peer health
// changes.
//
// peerPort is the port on which peers expose /acme-redirect. Use
// DefaultPeerPort unless your deployment has overridden --port.
func RegisterRedirectsLoop(ctx context.Context, host string, peerPort int) {
	locals, err := LocalIPs()
	if err != nil {
		log.Warn().Err(err).Msg("acme-redirect: cannot enumerate local IPs; loop disabled")
		return
	}

	var currentTarget string
	tick := func() {
		peers, err := DescendingPeerIPs(host)
		if err != nil {
			log.Warn().Err(err).Str("host", host).Msg("acme-redirect: DNS lookup failed; cannot pick a forward target")
			return
		}
		for _, ip := range peers {
			if IsLocalIP(ip, locals) {
				if currentTarget != "self" {
					log.Info().Str("event", EventRedirectLeaderSelf).Str("host", host).Msg("acme-redirect: this node is the leader for host (no higher peer reachable)")
					currentTarget = "self"
				}
				return
			}
			peerAddr := fmt.Sprintf("%s:%d", ip.String(), peerPort)
			if err := PostACMERedirect(peerAddr, host); err != nil {
				log.Warn().Str("event", EventRedirectPostFailed).Err(err).Str("peer", ip.String()).Str("host", host).Msg("acme-redirect: peer POST failed; cannot set up forwarding through this peer")
				continue
			}
			if currentTarget != peerAddr {
				log.Info().Str("event", EventRedirectTargetChanged).Str("host", host).Str("target", peerAddr).Msg("acme-redirect: target acquired")
				currentTarget = peerAddr
			} else {
				log.Debug().Str("event", EventRedirectPostSucceeded).Str("peer", peerAddr).Str("host", host).Msg("acme-redirect: registration refreshed")
			}
			return
		}
		if currentTarget != "" {
			log.Warn().Str("host", host).Msg("acme-redirect: no eligible peer or self in DNS; cannot forward")
			currentTarget = ""
		}
	}

	tick()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			tick()
		}
	}
}
