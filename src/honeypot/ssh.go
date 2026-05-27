package honeypot

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"sync"

	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/ssh"
)

// honeypotSSHHostKey is the SSH server identity presented to scanners. One
// generated key reused across all connections is fine — the key fingerprint
// isn't pinned by any legitimate operator and we don't accept any session.
var (
	honeypotSSHHostKeyOnce sync.Once
	honeypotSSHHostKey     ssh.Signer
)

func honeypotSSHHostSigner() ssh.Signer {
	honeypotSSHHostKeyOnce.Do(func() {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			log.Fatal().Err(err).Msg("honeypot: failed to generate SSH host key")
		}
		signer, err := ssh.NewSignerFromKey(priv)
		if err != nil {
			log.Fatal().Err(err).Msg("honeypot: failed to wrap SSH host key")
		}
		honeypotSSHHostKey = signer
	})
	return honeypotSSHHostKey
}

// errSSHReject is the canonical rejection used in every auth callback. SSH
// servers don't differentiate per-method failures over the wire — the
// scanner just sees a generic authentication failure and (usually) retries
// another username/password combo, which we also capture.
var errSSHReject = errors.New("authentication failed")

// handleSSH accepts a TCP connection, runs the SSH handshake against the
// scanner with always-failing auth callbacks, captures every credential the
// scanner offers, and emits a single event summarising the attempt.
//
// Common SSH-scanner shapes this catches:
//   - libssh brute-forcers cycling through (user, password) combos
//   - publickey-only scanners probing default usernames with random keys
//   - keyboard-interactive auth attempts (Mirai-shaped)
//
// The scanner's client_version (often something identifying like
// "SSH-2.0-libssh_0.10.4" or "SSH-2.0-Go") is captured from the
// ConnMetadata in the first callback that runs.
func (h *Honeypot) handleSSH(ctx context.Context, conn net.Conn) {
	srcIP, srcPort := splitHostPort(conn.RemoteAddr())
	_, dstPort := splitHostPort(conn.LocalAddr())

	var (
		captureMu     sync.Mutex
		attempts      int
		usernames     []string
		passwords     []string
		pubkeyFPs     []string
		clientVersion string
		authMethods   []string
	)

	record := func(c ssh.ConnMetadata, method string) {
		captureMu.Lock()
		defer captureMu.Unlock()
		attempts++
		if clientVersion == "" {
			clientVersion = string(c.ClientVersion())
		}
		if u := c.User(); u != "" && !contains(usernames, u) {
			usernames = append(usernames, u)
		}
		if !contains(authMethods, method) {
			authMethods = append(authMethods, method)
		}
	}

	cfg := &ssh.ServerConfig{
		// Look like a freshly-installed Ubuntu sshd; scanners will happily
		// attempt their default-credential lists against this banner.
		ServerVersion: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1",
		PasswordCallback: func(c ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			record(c, "password")
			captureMu.Lock()
			if len(passwords) < 32 { // cap so a brute-forcer doesn't balloon the audit log
				passwords = append(passwords, string(password))
			}
			captureMu.Unlock()
			return nil, errSSHReject
		},
		PublicKeyCallback: func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			record(c, "publickey")
			captureMu.Lock()
			if len(pubkeyFPs) < 32 {
				pubkeyFPs = append(pubkeyFPs, ssh.FingerprintSHA256(key))
			}
			captureMu.Unlock()
			return nil, errSSHReject
		},
		KeyboardInteractiveCallback: func(c ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			record(c, "keyboard-interactive")
			// One trivial round-trip captures the password most kbd-int
			// scanners are willing to send.
			answers, err := client("", "Password: ", []string{"Password: "}, []bool{false})
			if err == nil && len(answers) > 0 {
				captureMu.Lock()
				if len(passwords) < 32 {
					passwords = append(passwords, answers[0])
				}
				captureMu.Unlock()
			}
			return nil, errSSHReject
		},
	}
	cfg.AddHostKey(honeypotSSHHostSigner())

	// NewServerConn drives the full SSH handshake including auth. With
	// always-rejecting callbacks it never returns a usable session — we
	// just want the auth round-trips for capture, after which it returns
	// an error and we close.
	//
	// A separate watchdog closes the underlying conn if the parent ctx
	// expires (e.g. accept-loop deadline elapsed); that unblocks the
	// handshake goroutine. We then ALWAYS wait for doneCh so the captured
	// state is stable before we read it below.
	doneCh := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			conn.Close()
		case <-doneCh:
		}
	}()
	func() {
		defer close(doneCh)
		sshConn, _, _, _ := ssh.NewServerConn(conn, cfg)
		if sshConn != nil {
			sshConn.Close()
		}
	}()

	captureMu.Lock()
	defer captureMu.Unlock()

	detail := map[string]string{"attempts": itoa(attempts)}
	if clientVersion != "" {
		detail["client_version"] = clientVersion
	}
	if len(authMethods) > 0 {
		detail["auth_methods"] = joinComma(authMethods)
	}
	if len(usernames) > 0 {
		detail["usernames"] = joinComma(usernames)
	}
	if len(passwords) > 0 {
		detail["passwords"] = joinComma(passwords)
	}
	if len(pubkeyFPs) > 0 {
		detail["pubkey_fps"] = joinComma(pubkeyFPs)
	}

	// Pick the most specific username for the top-level Username field
	// (helps the dark-forest log render). If multiple were tried, the
	// detail map still carries all of them.
	username := ""
	if len(usernames) > 0 {
		username = usernames[0]
	}

	// Classification: a single SSH attempt looks like a port_scan / probe;
	// repeated credential attempts on one connection are textbook brute
	// force. The threshold is intentionally low — most legitimate clients
	// try one method, then succeed or give up.
	evType := TypePortScan
	if len(passwords) > 0 || len(pubkeyFPs) > 1 {
		evType = TypeBruteForce
	}

	h.Emitter.Emit(Event{
		SrcIP:    srcIP,
		SrcPort:  srcPort,
		DstPort:  dstPort,
		Protocol: "ssh",
		Type:     evType,
		Username: username,
		Detail:   detail,
	})
}

func contains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}

func joinComma(xs []string) string {
	if len(xs) == 0 {
		return ""
	}
	n := len(xs) - 1
	for _, s := range xs {
		n += len(s)
	}
	out := make([]byte, 0, n)
	for i, s := range xs {
		if i > 0 {
			out = append(out, ',')
		}
		out = append(out, s...)
	}
	return string(out)
}
