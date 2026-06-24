package config

import (
	"strings"
	"testing"
)

// TestRPMLinkLocalNoScopeStrictRejects pins the #2494 commit-time gate: an
// IPv6 link-local target (fe80::/10) with NO scope — neither an explicit
// %zone on the literal nor a destination-interface — is hard-rejected on
// the strict path. A link-local address is unprobeable without an egress
// link; the kernel cannot pick one, so the ICMP echo goes nowhere.
//
// This FAILS against master, which accepts the scopeless link-local and
// silently runs a dead probe into ip-monitoring failover.
func TestRPMLinkLocalNoScopeStrictRejects(t *testing.T) {
	lines := []string{
		"set services rpm probe P test t probe-type icmp-ping",
		"set services rpm probe P test t target fe80::1",
	}
	tree := buildTree(t, lines)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatalf("CompileConfig accepted a scopeless link-local target; want strict reject")
	}
	if !strings.Contains(err.Error(), "link-local") {
		t.Fatalf("err = %v, want substring %q", err, "link-local")
	}
}

// TestRPMLinkLocalWithDestInterfaceAccepted confirms a link-local target
// scoped by a destination-interface is accepted — the zone is derivable
// from the egress device, so the probe can pick the link.
func TestRPMLinkLocalWithDestInterfaceAccepted(t *testing.T) {
	lines := []string{
		"set services rpm probe P test t probe-type icmp-ping",
		"set services rpm probe P test t target fe80::1",
		"set services rpm probe P test t destination-interface ge-0/0/3",
	}
	tree := buildTree(t, lines)
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("link-local + destination-interface must be accepted: %v", err)
	}
}

// TestRPMLinkLocalWithExplicitZoneAccepted confirms a link-local literal
// carrying an explicit %zone is accepted with no destination-interface.
func TestRPMLinkLocalWithExplicitZoneAccepted(t *testing.T) {
	lines := []string{
		"set services rpm probe P test t probe-type icmp-ping",
		"set services rpm probe P test t target fe80::1%ge-0/0/3",
	}
	tree := buildTree(t, lines)
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("link-local with explicit %%zone must be accepted: %v", err)
	}
}

// TestRPMLinkLocalNoScopeLenientWarns pins the no-brick contract (#1960
// doctrine): the same scopeless link-local the strict path rejects is
// TOLERATED on the lenient load / peer-sync path — downgraded to a warning
// so an already-persisted or peer-synced config still boots. The runtime
// probeICMP guard then holds the test's state with ErrProbeSetup.
func TestRPMLinkLocalNoScopeLenientWarns(t *testing.T) {
	lines := []string{
		"set services rpm probe P test t probe-type icmp-ping",
		"set services rpm probe P test t target fe80::1",
	}
	tree := buildTree(t, lines)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient must not fail on scopeless link-local (brick-on-restart): %v", err)
	}
	if !hasWarningSubstr(cfg.Warnings, "rpm link-local zone") {
		t.Fatalf("expected a downgraded rpm link-local-zone warning, warnings=%v", cfg.Warnings)
	}
}

// TestRPMGlobalV6TargetUnaffected confirms a non-link-local IPv6 target is
// not touched by the link-local gate (no regression).
func TestRPMGlobalV6TargetUnaffected(t *testing.T) {
	lines := []string{
		"set services rpm probe P test t probe-type icmp-ping",
		"set services rpm probe P test t target 2001:db8::10",
	}
	tree := buildTree(t, lines)
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("global IPv6 target must be unaffected: %v", err)
	}
}
