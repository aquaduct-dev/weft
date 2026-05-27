package honeypot

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// honeypotCertOnce makes the self-signed cert generation a one-time cost.
// Reusing a single cert across all HTTPS handshakes is fine — scanners
// don't care whether the certificate is valid (they pin nothing) and the
// log of presented SNIs is what matters here, not cert details.
var (
	honeypotCertOnce sync.Once
	honeypotCert     tls.Certificate
)

// honeypotSelfSignedCert returns a long-lived self-signed certificate
// suitable for the HTTPS honeypot. Subject CN is a vanilla "nginx"-ish
// string so that opportunistic scanners can't trivially fingerprint
// the honeypot off the cert metadata.
func honeypotSelfSignedCert() tls.Certificate {
	honeypotCertOnce.Do(func() {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			log.Fatal().Err(err).Msg("honeypot: failed to generate TLS key")
		}
		serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		tpl := x509.Certificate{
			SerialNumber: serial,
			Subject:      pkix.Name{CommonName: "default"},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			DNSNames:     []string{"localhost"},
		}
		der, err := x509.CreateCertificate(rand.Reader, &tpl, &tpl, &priv.PublicKey, priv)
		if err != nil {
			log.Fatal().Err(err).Msg("honeypot: failed to issue self-signed cert")
		}
		honeypotCert = tls.Certificate{
			Certificate: [][]byte{der},
			PrivateKey:  priv,
		}
	})
	return honeypotCert
}

// tlsConfigWithCapture builds a tls.Config whose GetCertificate callback
// records the client-presented SNI and ALPN list before returning the
// honeypot's self-signed cert. The captured values are written through
// the pointers and read by handleHTTPS after the handshake.
func tlsConfigWithCapture(snOut, alpnOut *string) *tls.Config {
	cert := honeypotSelfSignedCert()
	return &tls.Config{
		MinVersion: tls.VersionTLS10, // accept old scanners on purpose; the
		// dark-forest visualization wants to see them
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if snOut != nil {
				*snOut = hello.ServerName
			}
			if alpnOut != nil && len(hello.SupportedProtos) > 0 {
				*alpnOut = strings.Join(hello.SupportedProtos, ",")
			}
			return &cert, nil
		},
	}
}
