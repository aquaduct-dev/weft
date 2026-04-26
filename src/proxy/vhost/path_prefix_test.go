package vhost

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func mustReq(t *testing.T, p string) *http.Request {
	t.Helper()
	return httptest.NewRequest(http.MethodGet, "http://example.com"+p, nil)
}

// TestPathMatcher_SegmentAware proves the F-7 fix: "/api" must NOT match
// "/apifoo", and a traversal sequence ("/api/../admin") is normalised before
// the match decision so it doesn't sneak through as a literal-prefix hit.
func TestPathMatcher_SegmentAware(t *testing.T) {
	m := &PathMatcher{Prefix: "/api"}

	cases := []struct {
		path   string
		expect bool
	}{
		// Legitimate matches.
		{"/api", true},
		{"/api/", true},
		{"/api/users", true},
		{"/api/users/123", true},
		// Sibling paths that share the prefix textually but not by segment.
		{"/apifoo", false},
		{"/apifoo/x", false},
		{"/api2", false},
		// Unrelated.
		{"/admin", false},
		{"/", false},
		// Traversal: /api/../admin normalises to /admin → not matched.
		{"/api/../admin", false},
		// Trailing-slash + traversal still resolves cleanly.
		{"/api/./users", true},
	}
	for _, c := range cases {
		got := m.Matches(mustReq(t, c.path))
		if got != c.expect {
			t.Errorf("path=%q: matches=%v, want %v", c.path, got, c.expect)
		}
	}
}

// TestPathPrefixModifier_SegmentAware proves the F-7 fix on the strip side:
// "/apifoo/x" no longer becomes "/foo/x", and "/api/../admin" doesn't reach
// upstream as "/../admin".
func TestPathPrefixModifier_SegmentAware(t *testing.T) {
	mod := &PathPrefixModifier{Prefix: "/api"}

	cases := []struct {
		in, want string
	}{
		{"/api", "/"},
		{"/api/", "/"},
		{"/api/users", "/users"},
		{"/api/users/123", "/users/123"},
		// Sibling: don't strip a non-segment prefix.
		{"/apifoo/x", "/apifoo/x"},
		// Traversal: normalised so the upstream sees /admin (not /../admin)
		// and "/api" is no longer at the front, so we don't strip.
		{"/api/../admin", "/admin"},
		// Already-clean dot-segment.
		{"/api/./users", "/users"},
	}
	for _, c := range cases {
		req := mustReq(t, c.in)
		mod.Apply(nil, req)
		if req.URL.Path != c.want {
			t.Errorf("in=%q: out=%q, want %q", c.in, req.URL.Path, c.want)
		}
	}
}
