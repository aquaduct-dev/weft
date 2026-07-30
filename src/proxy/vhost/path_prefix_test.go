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

// TestFindRoute_LongestPrefixWins proves Gateway-API precedence: among routes
// on one host, the longest matching PathPrefix wins REGARDLESS of the order the
// tunnels registered — so a "/charts" route is chosen over a "/" catch-all
// whether it registered first or last. Ties fall back to registration order.
func TestFindRoute_LongestPrefixWins(t *testing.T) {
	p := &VHostProxy{}
	app := &Route{Matchers: []Matcher{&PathMatcher{Prefix: "/"}}}
	charts := &Route{Matchers: []Matcher{&PathMatcher{Prefix: "/charts/"}}}

	cases := []struct {
		name   string
		routes []*Route
		path   string
		want   *Route
	}{
		// The bug repro: catch-all registered FIRST must not shadow /charts.
		{"appFirst_chartsPath", []*Route{app, charts}, "/charts/9/1/1.png", charts},
		{"chartsFirst_chartsPath", []*Route{charts, app}, "/charts/9/1/1.png", charts},
		{"exactCharts", []*Route{app, charts}, "/charts", charts},
		// Non-/charts paths still fall to the catch-all, either order.
		{"appFirst_otherPath", []*Route{app, charts}, "/courses/x", app},
		{"chartsFirst_health", []*Route{charts, app}, "/healthz", app},
		// Sibling that shares the prefix textually but not by segment → catch-all.
		{"chartsSibling", []*Route{charts, app}, "/chartsabc", app},
	}
	for _, c := range cases {
		got := p.findRoute(mustReq(t, c.path), c.routes)
		if got != c.want {
			t.Errorf("%s: findRoute(%q) picked the wrong route", c.name, c.path)
		}
	}
	// A single-route host is unaffected (backward compatibility).
	if got := p.findRoute(mustReq(t, "/anything"), []*Route{app}); got != app {
		t.Error("single catch-all route should still match")
	}
	if got := p.findRoute(mustReq(t, "/other"), []*Route{charts}); got != nil {
		t.Error("a non-matching single route should return nil, not a false match")
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
