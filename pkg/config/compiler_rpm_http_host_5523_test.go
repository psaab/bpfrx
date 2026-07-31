package config

import (
	"strings"
	"testing"
)

// C179-042 (codex-179): a hostless http-get RPM target ("http://",
// "https://", a schemeless ":8080") passes the #2495 scheme gate but
// canonicalizes to a URL the client cannot dial — the probe never sends a
// packet and its permanent no-run is counted as path loss into event-options
// / ip-monitoring failover. The strict commit path must reject the empty host;
// the lenient load / peer-sync path downgrades to a warning (#1960 no-brick).
//
// FAIL-ON-REVERT: dropping the u.Hostname()=="" checks in
// validateRPMHTTPGetSchemeStrict makes these targets compile clean again.
func TestRPMHTTPGetHostlessStrictRejects_5523(t *testing.T) {
	for _, target := range []string{"http://", "https://", ":8080", "http://:80/health"} {
		t.Run(target, func(t *testing.T) {
			lines := []string{
				"set services rpm probe P test t probe-type http-get",
				"set services rpm probe P test t target " + target,
			}
			tree := buildTree(t, lines)
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("hostless http-get target %q compiled clean; want strict reject (no host)", target)
			}
			if !strings.Contains(err.Error(), "no host") {
				t.Fatalf("err = %v, want substring %q", err, "no host")
			}
		})
	}
}

// The lenient path must not brick (#1960): the hostless target is downgraded
// to a warning so an already-persisted / peer-synced config still boots (the
// runtime canonicalizeHTTPTarget guard returns the same no-host error, so the
// test holds state instead of actuating off a dead probe).
func TestRPMHTTPGetHostlessLenientWarns_5523(t *testing.T) {
	lines := []string{
		"set services rpm probe P test t probe-type http-get",
		"set services rpm probe P test t target http://",
	}
	tree := buildTree(t, lines)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient must not brick on a hostless http-get target: %v", err)
	}
	if !hasWarningSubstr(cfg.Warnings, "no host") {
		t.Fatalf("expected a downgraded rpm http-get no-host warning, warnings=%v", cfg.Warnings)
	}
}

// No over-reject: valid hosts (bare, host:port, IPv4, scheme'd) are still
// accepted. Bracketed / bare IPv6 handling is covered directly at the runtime
// canonicalizer (pkg/rpm) to avoid the flat-set lexer's bracket stripping.
func TestRPMHTTPGetHostAcceptedNoRegression_5523(t *testing.T) {
	for _, target := range []string{
		"server.example.com",
		"host.example.com:8080",
		"203.0.113.5",
		"http://host.example.com",
		"https://h.example.com/health",
	} {
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
