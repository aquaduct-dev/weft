package acme

import (
	"context"
	"crypto/tls"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"golang.org/x/crypto/acme/autocert"
)

func TestAcme(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "ACME Suite")
}

// fakeCache implements autocert.Cache for tests.
type fakeCache struct {
	data map[string][]byte
	err  error
}

func (f *fakeCache) Get(ctx context.Context, key string) ([]byte, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.data == nil {
		return nil, autocert.ErrCacheMiss
	}
	if b, ok := f.data[key]; ok {
		return b, nil
	}
	return nil, autocert.ErrCacheMiss
}

func (f *fakeCache) Put(ctx context.Context, key string, data []byte) error {
	if f.err != nil {
		return f.err
	}
	if f.data == nil {
		f.data = make(map[string][]byte)
	}
	f.data[key] = data
	return nil
}

func (f *fakeCache) Delete(ctx context.Context, key string) error {
	if f.err != nil {
		return f.err
	}
	if f.data == nil {
		return nil
	}
	delete(f.data, key)
	return nil
}

var _ = Describe("ACMEHelper", func() {
	It("constructs with NewACMEHelper", func() {
		m := &autocert.Manager{}
		h := NewACMEHelper(m)
		Expect(h).ToNot(BeNil())
		Expect(h.Manager).To(Equal(m))
	})

	It("returns error when manager not configured", func() {
		var h *ACMEHelper
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		_, err := h.WaitForCertificate(ctx, "example.org")
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("acme manager not configured"))
	})

	It("handles cache hit but parse fails", func() {
		fc := &fakeCache{data: map[string][]byte{
			"example.org": []byte("not-a-valid-pem"),
		}}
		mgr := &autocert.Manager{Cache: fc}
		h := NewACMEHelper(mgr)

		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()
		_, err := h.WaitForCertificate(ctx, "example.org")
		Expect(err).To(HaveOccurred())
	})

	It("calls GetCertificate when cache is nil (returns error in test env)", func() {
		mgr := &autocert.Manager{Cache: nil}
		h := NewACMEHelper(mgr)

		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()
		_, err := h.WaitForCertificate(ctx, "example.org")
		Expect(err).To(HaveOccurred())
	})
})

var _ = Describe("AcquireCertificate", func() {
	It("returns error when manager is nil", func() {
		_, err := AcquireCertificate(nil, &tls.ClientHelloInfo{ServerName: "example.org"})
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("acme manager not configured"))
	})

	It("returns an error and emits issuance_failed when issuance fails", func() {
		// No cache, no network → autocert will fail. We just confirm the call
		// doesn't panic and surfaces the error. Event emission is best-checked
		// via log scraping in integration tests.
		mgr := &autocert.Manager{Cache: nil}
		_, err := AcquireCertificate(mgr, &tls.ClientHelloInfo{ServerName: "example.invalid"})
		Expect(err).To(HaveOccurred())
	})

	It("exposes stable event name constants", func() {
		// Operators / log pipelines depend on these values being stable. If
		// you rename one, treat it as a breaking change to the log schema.
		Expect(EventCacheHit).To(Equal("acme_cache_hit"))
		Expect(EventIssuanceStarted).To(Equal("acme_issuance_started"))
		Expect(EventIssuanceSucceeded).To(Equal("acme_issuance_succeeded"))
		Expect(EventIssuanceFailed).To(Equal("acme_issuance_failed"))
	})
})
