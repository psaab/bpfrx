package config

import (
	"strings"
	"testing"
)

// TestRPMHTTPGetSchemeStrictRejects pins the #2495 commit-time gate: an
// http-get target carrying a scheme other than http/https (ftp://,
// gopher://) is hard-rejected on the strict path (commit / commit-check).
// Such a scheme makes http.NewRequestWithContext error before any packet
// is sent, so the probe never runs and publishes a permanent FAIL into
// event-options / ip-monitoring failover.
//
// This FAILS against master, which has no scheme gate and silently
// accepts the unprobeable target.
func TestRPMHTTPGetSchemeStrictRejects(t *testing.T) {
	cases := []struct {
		name   string
		target string
		scheme string
	}{
		{"ftp", "ftp://host.example.com/health", "ftp"},
		{"gopher", "gopher://h.example.com", "gopher"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lines := []string{
				"set services rpm probe P test t probe-type http-get",
				"set services rpm probe P test t target " + tc.target,
			}
			tree := buildTree(t, lines)
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("CompileConfig accepted http-get target %q with scheme %q; want strict reject",
					tc.target, tc.scheme)
			}
			if !strings.Contains(err.Error(), "unsupported scheme") {
				t.Fatalf("err = %v, want substring %q", err, "unsupported scheme")
			}
		})
	}
}

// TestRPMHTTPGetSchemeLenientWarns pins the no-brick contract (#1960
// doctrine): the bad scheme the strict path rejects is TOLERATED on the
// lenient load / peer-sync path — downgraded to a warning so an
// already-persisted or peer-synced config still boots. The runtime
// canonicalizeHTTPTarget guard then returns the same error and the test
// holds state.
func TestRPMHTTPGetSchemeLenientWarns(t *testing.T) {
	lines := []string{
		"set services rpm probe P test t probe-type http-get",
		"set services rpm probe P test t target ftp://host.example.com",
	}
	tree := buildTree(t, lines)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient must not fail on bad http-get scheme (brick-on-restart): %v", err)
	}
	if !hasWarningSubstr(cfg.Warnings, "rpm http-get scheme") {
		t.Fatalf("expected a downgraded rpm http-get-scheme warning, warnings=%v", cfg.Warnings)
	}
}

// TestRPMHTTPGetSchemeAccepts confirms NO regression and the bug-fix
// coverage: bare hostnames (including h-prefixed ones, the #2495 bug),
// host:port, and explicit http:// / https:// targets are all accepted.
func TestRPMHTTPGetSchemeAccepts(t *testing.T) {
	targets := []string{
		"server.example.com",      // bare host, non-'h'
		"host.example.com",        // bare host starting with 'h' — the bug
		"h2.lan",                  // bare h-prefixed host
		"host.example.com:8080",   // bare host:port (must not parse "host..." as scheme)
		"http://host.example.com", // explicit http
		"https://h.example.com",   // explicit https
		"203.0.113.5",             // bare IPv4 literal
	}
	for _, target := range targets {
		t.Run(target, func(t *testing.T) {
			lines := []string{
				"set services rpm probe P test t probe-type http-get",
				"set services rpm probe P test t target " + target,
			}
			tree := buildTree(t, lines)
			if _, err := CompileConfig(tree); err != nil {
				t.Fatalf("http-get target %q must be accepted: %v", target, err)
			}
		})
	}
}

// TestRPMHTTPGetSchemeOnlyAppliesToHTTPGet confirms the scheme gate is
// scoped to http-get tests: an icmp-ping/tcp-ping test is never inspected
// for a URL scheme (its target is a host/IP, never a URL).
func TestRPMHTTPGetSchemeOnlyAppliesToHTTPGet(t *testing.T) {
	// A non-http-get test with an IP-literal target is accepted as today.
	lines := []string{
		"set services rpm probe P test t probe-type tcp-ping",
		"set services rpm probe P test t target 8.8.8.8",
	}
	tree := buildTree(t, lines)
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("tcp-ping test must be unaffected by the http-get scheme gate: %v", err)
	}
}
