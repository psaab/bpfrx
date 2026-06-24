package config

import (
	"strings"
	"testing"
)

// TestRPMScopedHostnameStrictRejects pins the #2493 commit-time gate: a
// HOSTNAME target on a SCOPED test (routing-instance, destination-interface,
// or next-hop) is hard-rejected on the strict path (commit / commit-check).
// DNS resolution is not VRF/device-scoped — the SO_BINDTODEVICE bind is
// applied per-connection, AFTER name resolution — so the probe would
// resolve out-of-context and measure resolver health, not path health.
//
// This FAILS against master, which accepts the scoped hostname and silently
// leaks the DNS lookup out of the configured scope.
func TestRPMScopedHostnameStrictRejects(t *testing.T) {
	cases := []struct {
		name  string
		scope string // the scoping set-line tail
	}{
		{"routing-instance", "set services rpm probe P test t routing-instance ISP-B"},
		{"destination-interface", "set services rpm probe P test t destination-interface ge-0/0/1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lines := []string{
				"set services rpm probe P test t probe-type icmp-ping",
				"set services rpm probe P test t target example.com",
				tc.scope,
			}
			tree := buildTree(t, lines)
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("CompileConfig accepted scoped hostname target; want strict reject")
			}
			if !strings.Contains(err.Error(), "hostname on a scoped test") {
				t.Fatalf("err = %v, want substring %q", err, "hostname on a scoped test")
			}
		})
	}
}

// TestRPMScopedHostnameNextHopRejected covers the next-hop-pinned scope.
// (validateRPMTest already rejects a hostname under next-hop because the
// pin route needs an IP-literal target; this confirms the scoped-hostname
// gate also treats next-hop as scoped, so the two gates agree.)
func TestRPMScopedHostnameNextHopRejected(t *testing.T) {
	lines := []string{
		"set services rpm probe P test t probe-type icmp-ping",
		"set services rpm probe P test t target example.com",
		"set services rpm probe P test t destination-interface ge-0/0/1",
		"set services rpm probe P test t next-hop 10.0.0.1",
	}
	tree := buildTree(t, lines)
	if _, err := CompileConfig(tree); err == nil {
		t.Fatalf("CompileConfig accepted scoped+next-hop hostname target; want reject")
	}
}

// TestRPMScopedHostnameLenientWarns pins the no-brick contract (#1960
// doctrine): the same scoped hostname that the strict path rejects is
// TOLERATED on the lenient load / peer-sync path — downgraded to a warning
// so an already-persisted or peer-synced config still boots. The runtime
// executeProbe guard then holds the test's state.
func TestRPMScopedHostnameLenientWarns(t *testing.T) {
	lines := []string{
		"set services rpm probe P test t probe-type icmp-ping",
		"set services rpm probe P test t target example.com",
		"set services rpm probe P test t routing-instance ISP-B",
	}
	tree := buildTree(t, lines)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient must not fail on scoped hostname (brick-on-restart): %v", err)
	}
	if !hasWarningSubstr(cfg.Warnings, "rpm scoped hostname") {
		t.Fatalf("expected a downgraded rpm scoped-hostname warning, warnings=%v", cfg.Warnings)
	}
}

// TestRPMScopedIPLiteralAccepted confirms an IP-literal target on a scoped
// test is accepted (no resolution, no leak) — the legitimate scoped-probe
// shape used for multi-WAN path health.
func TestRPMScopedIPLiteralAccepted(t *testing.T) {
	t.Run("routing-instance + IP literal accepted", func(t *testing.T) {
		lines := []string{
			"set services rpm probe P test t probe-type icmp-ping",
			"set services rpm probe P test t target 8.8.8.8",
			"set services rpm probe P test t routing-instance ISP-B",
		}
		tree := buildTree(t, lines)
		if _, err := CompileConfig(tree); err != nil {
			t.Fatalf("scoped IP-literal target must be accepted: %v", err)
		}
	})

	t.Run("destination-interface + IPv6 literal accepted", func(t *testing.T) {
		lines := []string{
			"set services rpm probe P test t probe-type icmp-ping",
			"set services rpm probe P test t target 2001:db8::1",
			"set services rpm probe P test t destination-interface ge-0/0/1",
		}
		tree := buildTree(t, lines)
		if _, err := CompileConfig(tree); err != nil {
			t.Fatalf("scoped IPv6-literal target must be accepted: %v", err)
		}
	})
}

// TestRPMUnscopedHostnameAccepted confirms NO regression: a hostname target
// on an UNSCOPED (default-context) test resolves in the same context it
// probes, so it stays accepted (today's behavior).
func TestRPMUnscopedHostnameAccepted(t *testing.T) {
	lines := []string{
		"set services rpm probe P test t probe-type icmp-ping",
		"set services rpm probe P test t target example.com",
	}
	tree := buildTree(t, lines)
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("unscoped hostname target must be accepted (no regression): %v", err)
	}
}
