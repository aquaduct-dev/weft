// tunnel_test.go covers resolveServerIP, which turns the weft server address a
// user passes (IP, IP:port, hostname or hostname:port) into the IP used as the
// WireGuard peer endpoint, including how lookup failures are reported.
package tunnel

import (
	"strings"
	"testing"
)

func TestResolveServerIP(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    string // exact IP expected; empty means "any loopback"
		wantErr string // substring of the expected error; empty means success
	}{
		{name: "ipv4 literal", in: "192.0.2.10", want: "192.0.2.10"},
		{name: "ipv4 with port", in: "192.0.2.10:9092", want: "192.0.2.10"},
		{name: "ipv6 literal", in: "2001:db8::1", want: "2001:db8::1"},
		{name: "bracketed ipv6 with port", in: "[2001:db8::1]:9092", want: "2001:db8::1"},
		{name: "hostname with port", in: "localhost:9092"},
		{name: "unresolvable hostname", in: "weft-test.invalid:9092", wantErr: `failed to resolve server address "weft-test.invalid"`},
		{name: "empty input", in: "", wantErr: "failed to resolve server address"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveServerIP(tc.in)
			t.Logf("resolveServerIP(%q) = %q, err=%v", tc.in, got, err)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got IP %q", tc.wantErr, got)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error %q does not contain %q", err.Error(), tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.want != "" {
				if got != tc.want {
					t.Fatalf("got %q, want %q", got, tc.want)
				}
				return
			}
			if got != "127.0.0.1" && got != "::1" {
				t.Fatalf("localhost resolved to %q, want a loopback address", got)
			}
		})
	}
}
