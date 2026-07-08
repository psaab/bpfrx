package config

import (
	"strings"
	"testing"
)

// #4559 (ps-034 M-01): deterministic CGNAT (`port deterministic block-size <n>
// host address <cidr>`) is typed + validated and commits CLEAN. The
// IPv4-subscriber path (mode 1) is now ENFORCED on the userspace dataplane —
// the Go builder carries the block/host params and the Rust allocator maps each
// subscriber to a fixed external IP + port block. Only the IPv6-subscriber path
// (mode 2 / NAT64) remains deferred, so the accepted-but-inert commit-time
// ADVISORY is now scoped to IPv6-host pools (mirroring the #4291/#4292
// accepted-only NAT doctrine). An IPv4-host pool must NOT warn.

// deterministicAdvisoryPresent reports whether cfg carries the #4559
// accepted-but-inert advisory for deterministic source NAT.
func deterministicAdvisoryPresent(cfg *Config) bool {
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#4559") &&
			strings.Contains(w, "deterministic") &&
			strings.Contains(w, "NOT enforced by the userspace dataplane") {
			return true
		}
	}
	return false
}

// TestDeterministicNATIPv6EmitsInertAdvisory is the #4559 FAIL-ON-REVERT proof
// for the still-deferred IPv6 (NAT64) path: an IPv6-subscriber deterministic
// pool COMMITS CLEAN (valid Junos) but MUST surface the accepted-but-inert
// advisory so the operator knows the userspace dataplane still round-robins it
// (mode 2 is not yet implemented). On revert (advisory removed) cfg.Warnings has
// no such entry and this fails.
func TestDeterministicNATIPv6EmitsInertAdvisory(t *testing.T) {
	cfg, err := CompileConfig(buildTree(t, deterministicNATLines("2016", "2001:db8::/64")))
	if err != nil {
		t.Fatalf("IPv6 deterministic pool is valid Junos and must commit clean (advisory, not reject); got: %v", err)
	}
	// Sanity: the pool really is deterministic (guards against the test
	// silently passing because the config never parsed the field).
	_ = poolDeterministic(t, cfg, "CGNAT-POOL")
	if !deterministicAdvisoryPresent(cfg) {
		t.Fatalf("IPv6 (NAT64) deterministic source NAT pool must emit the #4559 accepted-but-inert advisory; got warnings: %v", cfg.Warnings)
	}
}

// TestDeterministicNATIPv4NoAdvisory is the #4559 enforcement proof: an
// IPv4-subscriber deterministic pool is now enforced by the userspace dataplane
// (deterministicSourceNATFields builds the mode-1 block params, the Rust
// allocator honours them), so it must NOT emit the accepted-but-inert advisory.
// On revert of the narrowing (advisory fires for every deterministic pool)
// cfg.Warnings would carry the entry and this fails.
func TestDeterministicNATIPv4NoAdvisory(t *testing.T) {
	cfg, err := CompileConfig(buildTree(t, deterministicNATLines("2016", "100.64.0.0/25")))
	if err != nil {
		t.Fatalf("IPv4 deterministic pool must commit clean; got: %v", err)
	}
	// Precondition: the pool really is deterministic (mode 1, IPv4 host).
	_ = poolDeterministic(t, cfg, "CGNAT-POOL")
	if deterministicAdvisoryPresent(cfg) {
		t.Fatalf("IPv4-subscriber deterministic NAT is enforced and must NOT emit the #4559 advisory; got warnings: %v", cfg.Warnings)
	}
}

// TestNonDeterministicNATNoInertAdvisory proves the advisory is scoped: a plain
// (non-deterministic) source NAT pool must NOT carry the #4559 warning, so the
// advisory does not cry wolf on every SNAT pool.
func TestNonDeterministicNATNoInertAdvisory(t *testing.T) {
	// deterministicNATLines("", "") builds the same pool WITHOUT any
	// `port deterministic ...` line, so pool.Deterministic stays nil.
	cfg, err := CompileConfig(buildTree(t, deterministicNATLines("", "")))
	if err != nil {
		t.Fatalf("plain source NAT pool must compile clean; got: %v", err)
	}
	if p := sourcePool(t, cfg, "CGNAT-POOL"); p.Deterministic != nil {
		t.Fatalf("test precondition: non-deterministic pool must have nil Deterministic, got %+v", p.Deterministic)
	}
	if deterministicAdvisoryPresent(cfg) {
		t.Fatalf("non-deterministic pool must NOT emit the #4559 advisory; got warnings: %v", cfg.Warnings)
	}
}
