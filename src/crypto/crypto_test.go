package crypto_test

import (
	"bytes"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"aquaduct.dev/weft/src/crypto"
)

// Ginkgo entrypoint for the crypto suite.
func TestCryptoSuite(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Crypto Suite")
}

var _ = Describe("Encrypt/Decrypt", func() {
	It("round-trips for several inputs", func() {
		cases := []struct {
			key  string
			text string
		}{
			{"key1", "hello"},
			{"very-long-secret-key-that-is-used-for-testing", "this is a longer piece of plaintext used for testing AES-GCM encryption/decryption correctness"},
			{"some-key", ""},
			{"unicode-key", "こんにちは、世界! 🌍"},
		}
		for _, c := range cases {
			ct, err := crypto.Encrypt(c.key, c.text)
			Expect(err).ToNot(HaveOccurred())
			Expect(len(ct)).To(BeNumerically(">", 0))

			pt, err := crypto.Decrypt(c.key, ct)
			Expect(err).ToNot(HaveOccurred())
			Expect(pt).To(Equal([]byte(c.text)))
		}
	})
})

var _ = Describe("Decrypt failures", func() {
	It("fails with wrong key", func() {
		ct, err := crypto.Encrypt("correct-key", "secret message")
		Expect(err).ToNot(HaveOccurred())

		_, err = crypto.Decrypt("incorrect-key", ct)
		Expect(err).To(HaveOccurred())
	})

	It("fails with corrupted ciphertext", func() {
		key := "test-key"
		ct, err := crypto.Encrypt(key, "another secret")
		Expect(err).ToNot(HaveOccurred())

		// flip last byte
		ct[len(ct)-1] ^= 0xFF
		_, err = crypto.Decrypt(key, ct)
		Expect(err).To(HaveOccurred())
	})
})

var _ = Describe("GenerateCert", func() {
	It("returns valid PEM blocks", func() {
		certPEM, keyPEM, err := crypto.GenerateCert("example.test", []string{})
		Expect(err).ToNot(HaveOccurred())
		Expect(len(certPEM)).To(BeNumerically(">", 0))
		Expect(len(keyPEM)).To(BeNumerically(">", 0))

		Expect(bytes.Contains(certPEM, []byte("BEGIN CERTIFICATE"))).To(BeTrue())
		Expect(bytes.Contains(keyPEM, []byte("BEGIN RSA PRIVATE KEY")) || bytes.Contains(keyPEM, []byte("BEGIN PRIVATE KEY"))).To(BeTrue())
	})
})
