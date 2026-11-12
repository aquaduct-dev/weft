package acme

import (
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	xacme "golang.org/x/crypto/acme"
)

// TestRateLimitHold: only the CA's rate limit is remembered, and only until
// the time the CA gave; every other failure is retried on the next request.
func TestRateLimitHold(t *testing.T) {
	now := time.Date(2026, 11, 12, 9, 0, 0, 0, time.UTC)

	// Retry-After header, wrapped the way autocert wraps errors.
	h := http.Header{}
	h.Set("Retry-After", "3600")
	withHeader := fmt.Errorf("acme/autocert: %w", &xacme.Error{StatusCode: 429, ProblemType: "urn:ietf:params:acme:error:rateLimited", Header: h})
	if until, ok := rateLimitEnd(withHeader, now); !ok || !until.Equal(now.Add(time.Hour)) {
		t.Fatalf("header: %v %v", until, ok)
	}

	// No header: the time Let's Encrypt writes into the detail.
	detail := "too many certificates (5) already issued for this exact set of identifiers in the last 168h0m0s, retry after 2026-11-12 13:30:00 UTC: see https://letsencrypt.org/docs/rate-limits/"
	inDetail := &xacme.Error{StatusCode: 429, ProblemType: "urn:ietf:params:acme:error:rateLimited", Detail: detail}
	if until, ok := rateLimitEnd(inDetail, now); !ok || !until.Equal(time.Date(2026, 11, 12, 13, 30, 0, 0, time.UTC)) {
		t.Fatalf("detail: %v %v", until, ok)
	}
	// Only the message survived (wrapped with %v): still read from the text.
	flat := errors.New("acme/autocert: 429 urn:ietf:params:acme:error:rateLimited: " + detail)
	if _, ok := rateLimitEnd(flat, now); !ok {
		t.Fatal("flattened rate limit not recognized")
	}

	// Anything else is not held: not a DNS failure, not a failed challenge,
	// not a rate limit that names no end.
	for _, err := range []error{
		errors.New("host x not reachable for ACME HTTP-01 challenge"),
		&xacme.Error{StatusCode: 403, ProblemType: "urn:ietf:params:acme:error:unauthorized", Detail: "invalid response"},
		&xacme.Error{StatusCode: 429, ProblemType: "urn:ietf:params:acme:error:rateLimited", Detail: "slow down"},
	} {
		if _, ok := rateLimitEnd(err, now); ok {
			t.Fatalf("held %v", err)
		}
	}

	// A hold lasts exactly until the CA's time, then is gone.
	holdRateLimit("a.example", now.Add(time.Minute))
	if _, ok := rateLimitedUntil("a.example", now); !ok {
		t.Fatal("hold not in force")
	}
	if _, ok := rateLimitedUntil("b.example", now); ok {
		t.Fatal("hold leaked to another host")
	}
	if _, ok := rateLimitedUntil("a.example", now.Add(time.Minute)); ok {
		t.Fatal("hold outlived the CA's retry-after")
	}
	if _, ok := rateLimits["a.example"]; ok {
		t.Fatal("expired hold not dropped")
	}
}
