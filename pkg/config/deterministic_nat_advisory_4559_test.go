package config

import (
	"strings"
	"testing"
)

// #4559 (ps-034 M-01): deterministic CGNAT (`port deterministic block-size <n>
// host address <cidr>`) is typed + validated and commits CLEAN. BOTH the
// IPv4-subscriber path (mode 1) and the IPv6-subscriber / NAPT64 path (mode 2)
// are now ENFORCED on the userspace dataplane — mode 1 via the source-NAT
// snapshot + allocate_deterministic_v4, mode 2 via the NAT64 forward path
// (allocate_deterministic_v6) when the pool is referenced by a `security nat
// nat64` rule-set with a supported /32 or /64 subscriber prefix. The
// accepted-but-inert commit-time ADVISORY is now scoped to the residual
// UNENFORCEABLE cases (an IPv6-host pool not referenced by nat64, or an
// unsupported prefix length), mirroring the #4291/#4292 accepted-only doctrine.
// An enforced pool must NOT warn.

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

// napt64DeterministicLines builds a deterministic source pool with an IPv6
// (NAPT64) subscriber host, plus (when refByNat64) a `security nat nat64`
// rule-set referencing that pool as its source-pool — the wiring that makes the
// mode-2 block allocator actually enforce the mapping (#4559).
func napt64DeterministicLines(hostPrefix string, refByNat64 bool) []string {
	base := "set security nat source pool CGNAT-POOL "
	lines := []string{
		"set security zones security-zone trust",
		base + "address 203.0.113.1/32 to 203.0.113.4/32",
		base + "port range low 1024 high 65535",
		base + "port deterministic block-size 512",
		base + "port deterministic host address " + hostPrefix,
	}
	if refByNat64 {
		lines = append(lines,
			"set security nat nat64 rule-set rs1 prefix 64:ff9b::/96",
			"set security nat nat64 rule-set rs1 source-pool CGNAT-POOL",
		)
	}
	return lines
}

// TestDeterministicNAPT64EnforcedNoAdvisory is the #4559 mode-2 enforcement
// proof: an IPv6-subscriber deterministic pool that IS referenced by a NAT64
// rule-set with a supported /64 prefix is now enforced by the userspace
// dataplane (buildNAT64Snapshots carries the block/host params, the Rust NAT64
// allocator maps each subscriber to a fixed external IPv4 + port block), so it
// must NOT emit the accepted-but-inert advisory. On revert (advisory fires for
// every IPv6-host pool) cfg.Warnings would carry the entry and this fails.
func TestDeterministicNAPT64EnforcedNoAdvisory(t *testing.T) {
	cfg, err := CompileConfig(buildTree(t, napt64DeterministicLines("2001:db8::/64", true)))
	if err != nil {
		t.Fatalf("NAPT64 deterministic pool referenced by a nat64 rule-set must commit clean; got: %v", err)
	}
	_ = poolDeterministic(t, cfg, "CGNAT-POOL")
	if deterministicAdvisoryPresent(cfg) {
		t.Fatalf("a /64 IPv6 deterministic pool referenced by a nat64 rule-set is ENFORCED (mode 2) and must NOT emit the #4559 advisory; got warnings: %v", cfg.Warnings)
	}
}

// TestDeterministicNAPT64UnreferencedEmitsAdvisory proves the mode-2 enforcement
// is gated on the NAT64 wiring: an IPv6-host deterministic pool NOT referenced
// by any nat64 rule-set cannot translate a v6 subscriber to a v4 pool (the plain
// source-NAT path has no v6→v4 mode), so it still round-robins and MUST keep the
// advisory.
func TestDeterministicNAPT64UnreferencedEmitsAdvisory(t *testing.T) {
	cfg, err := CompileConfig(buildTree(t, napt64DeterministicLines("2001:db8::/64", false)))
	if err != nil {
		t.Fatalf("IPv6 deterministic pool must commit clean; got: %v", err)
	}
	_ = poolDeterministic(t, cfg, "CGNAT-POOL")
	if !deterministicAdvisoryPresent(cfg) {
		t.Fatalf("an IPv6 deterministic pool NOT referenced by a nat64 rule-set stays inert and must emit the #4559 advisory; got warnings: %v", cfg.Warnings)
	}
}

// (An unsupported IPv6 subscriber-prefix length — e.g. /48 — is HARD-REJECTED
// at commit by the compiler_nat.go validator "IPv6 host prefix must be /32 or
// /64", so it never reaches ValidateConfig. The advisory's unsupported-prefix
// branch and deterministicNAPT64Enforced's prefix-len gate are defense-in-depth
// for the lenient / HA-sync load path only.)

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
