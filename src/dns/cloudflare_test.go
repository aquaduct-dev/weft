// cloudflare_test.go covers findZone, the zone-selection step of UpdateRecord:
// longest-suffix wins, matches respect label boundaries, and case and a
// trailing dot do not matter. It needs no Cloudflare API access.
package dns

import (
	"testing"

	"github.com/cloudflare/cloudflare-go"
)

func TestFindZone(t *testing.T) {
	zones := []cloudflare.Zone{
		{ID: "z-com", Name: "com"},
		{ID: "z-example", Name: "example.com"},
		{ID: "z-sub", Name: "sub.example.com"},
		{ID: "z-other", Name: "other.org"},
	}

	cases := []struct {
		name     string
		hostname string
		wantID   string
	}{
		{name: "exact zone apex", hostname: "example.com", wantID: "z-example"},
		{name: "host in zone", hostname: "app.example.com", wantID: "z-example"},
		{name: "longest suffix wins", hostname: "app.sub.example.com", wantID: "z-sub"},
		{name: "label boundary respected", hostname: "notexample.com", wantID: "z-com"},
		{name: "trailing dot and case ignored", hostname: "App.Example.COM.", wantID: "z-example"},
		{name: "no matching zone", hostname: "app.example.net", wantID: ""},
		{name: "suffix without dot boundary", hostname: "brother.org", wantID: ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotID, gotName := findZone(zones, tc.hostname)
			t.Logf("findZone(%q) = (%q, %q)", tc.hostname, gotID, gotName)
			if gotID != tc.wantID {
				t.Fatalf("findZone(%q) id = %q, want %q", tc.hostname, gotID, tc.wantID)
			}
		})
	}
}
