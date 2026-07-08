package config

import (
	"strings"
	"testing"
)

// #4559 (ps-034 M-01): deterministic CGNAT (`port deterministic block-size <n>
// host address <cidr>`) is typed + validated and commits CLEAN, but the block
// allocator was only ever wired into the retired eBPF plane and was never
// ported to the userspace dataplane (the only runtime after #1373/#1476). A
// deterministic pool therefore silently falls back to round-robin/sticky SNAT.
// The honest-fix (mirroring the #4291/#4292 accepted-only NAT doctrine) is an
// accepted-but-inert commit-time ADVISORY so the operator is not silently
// misled — NOT a hard reject (deterministic is valid Junos syntax). Full block
// allocation in userspace-dp remains a follow-up (#4559).

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

// TestDeterministicNATEmitsInertAdvisory is the #4559 FAIL-ON-REVERT proof: a
// well-formed deterministic pool COMMITS CLEAN (no error — it is valid Junos)
// but MUST surface the accepted-but-inert advisory so the operator knows the
// userspace dataplane does not enforce deterministic block allocation. On
// revert (advisory removed) cfg.Warnings has no such entry and this fails.
func TestDeterministicNATEmitsInertAdvisory(t *testing.T) {
	cfg, err := CompileConfig(buildTree(t, deterministicNATLines("2016", "100.64.0.0/25")))
	if err != nil {
		t.Fatalf("deterministic pool is valid Junos and must commit clean (advisory, not reject); got: %v", err)
	}
	// Sanity: the pool really is deterministic (guards against the test
	// silently passing because the config never parsed the field).
	_ = poolDeterministic(t, cfg, "CGNAT-POOL")
	if !deterministicAdvisoryPresent(cfg) {
		t.Fatalf("deterministic source NAT pool must emit the #4559 accepted-but-inert advisory; got warnings: %v", cfg.Warnings)
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
