package config

import (
	"strings"
	"testing"
)

// Tests for #5144: overlapping / duplicate source-NAT and NAT64 pools own
// SEPARATE allocator domains and can mint identical public tuples (reply
// misdelivery). The Rust dataplane keys the source-NAT PortAllocator by pool
// name + address vector (userspace-dp/src/nat/source.rs) and the NAT64 allocator
// by (prefix_bytes, pool_v4) (userspace-dp/src/nat64.rs), so differently-named
// overlapping source pools, a source pool that also backs a NAT64 rule-set, two
// NAT64 rule-sets sharing a pool under different prefixes, and duplicate members
// within one pool each own an independent occupancy bitmap. Independent bitmaps
// share no ownership word → two flows can be handed the same (family, translated
// IP, port) and the reverse (1:N) NAT index cannot disambiguate the return
// packet. The commit-time detection (material choice S1: reject independently
// owned overlap) lives in validateNATPoolExternalTupleOverlapStrict, wired into
// runTailGates next to the #2241 NPTv6 overlap gate.
//
// FAIL-ON-REVERT: neutralizing the gate (making
// validateNATPoolExternalTupleOverlapStrict `return nil, nil`, or dropping its
// dispatch in compiler_tailgates.go) turns every "must reject" case below GREEN
// — the overlap is accepted — so those assertions go RED.

// natOverlapTree builds a ConfigTree from flat-set `set` commands using the
// production ParseSetCommand + SetPath path (never NewParser — the flat-set
// testing gotcha in CLAUDE.md).
func natOverlapTree(t *testing.T, cmds ...string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	return tree
}

// assertNATOverlapRejected asserts the strict commit path rejects the config
// with a #5144 diagnostic containing want, AND the tolerant load / peer-sync
// path (#1960 no-brick) downgrades it to a #5144 warning instead of failing.
func assertNATOverlapRejected(t *testing.T, want string, cmds ...string) {
	t.Helper()
	if _, err := CompileConfig(natOverlapTree(t, cmds...)); err == nil {
		t.Fatalf("strict commit must reject the overlap (want %q)", want)
	} else {
		msg := err.Error()
		if !strings.Contains(msg, "#5144") {
			t.Fatalf("strict error must cite #5144, got: %v", err)
		}
		if !strings.Contains(msg, want) {
			t.Fatalf("strict error %q does not contain %q", msg, want)
		}
	}

	cfg, err := CompileConfigLenient(natOverlapTree(t, cmds...))
	if err != nil {
		t.Fatalf("lenient compile must not brick on an overlapping config: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#5144") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("lenient compile must record a #5144 overlap warning; warnings = %v", cfg.Warnings)
	}
}

// assertNATOverlapAccepted asserts the strict commit path accepts the config (no
// false positive).
func assertNATOverlapAccepted(t *testing.T, cmds ...string) {
	t.Helper()
	if _, err := CompileConfig(natOverlapTree(t, cmds...)); err != nil {
		t.Fatalf("config must compile clean (no #5144 false positive): %v", err)
	}
}

// srcRule references pool from a source-nat rule-set (from trust to untrust).
func srcRule(ruleset, rule, pool string) []string {
	return []string{
		"set security nat source rule-set " + ruleset + " from zone trust",
		"set security nat source rule-set " + ruleset + " to zone untrust",
		"set security nat source rule-set " + ruleset + " rule " + rule + " match source-address 10.0.0.0/24",
		"set security nat source rule-set " + ruleset + " rule " + rule + " then source-nat pool " + pool,
	}
}

// TestNAT5144ExactDuplicateSourcePools: two differently-named source pools with
// the SAME address, both referenced — the canonical "differently-named
// overlapping source pools" case.
func TestNAT5144ExactDuplicateSourcePools(t *testing.T) {
	cmds := []string{
		"set security nat source pool A address 203.0.113.5",
		"set security nat source pool B address 203.0.113.5",
	}
	cmds = append(cmds, srcRule("RSA", "r1", "A")...)
	cmds = append(cmds, srcRule("RSB", "r1", "B")...)
	assertNATOverlapRejected(t, "independent NAT allocators", cmds...)
}

// TestNAT5144PartialOverlapSourcePools: two source pools whose CIDRs partially
// overlap (a /24 nesting a /25) — the partial-overlap case, distinct from exact
// duplicate.
func TestNAT5144PartialOverlapSourcePools(t *testing.T) {
	cmds := []string{
		"set security nat source pool A address 203.0.113.0/24",
		"set security nat source pool B address 203.0.113.128/25",
	}
	cmds = append(cmds, srcRule("RSA", "r1", "A")...)
	cmds = append(cmds, srcRule("RSB", "r1", "B")...)
	assertNATOverlapRejected(t, "independent NAT allocators", cmds...)
}

// TestNAT5144SourceNAT64SamePool: one pool referenced by BOTH a source-nat rule
// AND a NAT64 rule-set. The source allocator (keyed by pool name) and the NAT64
// allocator (keyed by prefix+pool) are independent even over the identical pool
// addresses — the cross-feature case.
func TestNAT5144SourceNAT64SamePool(t *testing.T) {
	cmds := []string{
		"set security nat source pool P address 100.64.0.7/32",
		"set security nat nat64 rule-set N64 prefix 64:ff9b::/96",
		"set security nat nat64 rule-set N64 source-pool P",
	}
	cmds = append(cmds, srcRule("RS", "r1", "P")...)
	assertNATOverlapRejected(t, "independent NAT allocators", cmds...)
}

// TestNAT5144SourceNAT64DifferentOverlappingPools: a source-nat pool and a
// DIFFERENT NAT64 source-pool whose addresses overlap — the cross-feature
// address-overlap case (not the same pool).
func TestNAT5144SourceNAT64DifferentOverlappingPools(t *testing.T) {
	cmds := []string{
		"set security nat source pool S address 100.64.0.7/32",
		"set security nat source pool N address 100.64.0.7/32",
		"set security nat nat64 rule-set N64 prefix 64:ff9b::/96",
		"set security nat nat64 rule-set N64 source-pool N",
	}
	cmds = append(cmds, srcRule("RS", "r1", "S")...)
	assertNATOverlapRejected(t, "independent NAT allocators", cmds...)
}

// TestNAT5144NAT64DifferentPrefixesSamePool: two NAT64 rule-sets sharing one
// source pool under DIFFERENT prefixes. The Rust nat64 allocator keys by
// (prefix, pool_v4), so the two are independent allocators over the same pool
// address.
func TestNAT5144NAT64DifferentPrefixesSamePool(t *testing.T) {
	cmds := []string{
		"set security nat source pool P address 100.64.0.7/32",
		"set security nat nat64 rule-set A prefix 64:ff9b::/96",
		"set security nat nat64 rule-set A source-pool P",
		"set security nat nat64 rule-set B prefix 64:ff9b:1::/96",
		"set security nat nat64 rule-set B source-pool P",
	}
	assertNATOverlapRejected(t, "independent NAT allocators", cmds...)
}

// TestNAT5144WithinPoolOverlap: a single referenced pool whose members overlap
// (a /24 nesting a host). Duplicate members within one pool each own an
// independent occupancy bitmap.
func TestNAT5144WithinPoolOverlap(t *testing.T) {
	cmds := []string{
		"set security nat source pool A address 203.0.113.0/24",
		"set security nat source pool A address 203.0.113.7",
	}
	cmds = append(cmds, srcRule("RS", "r1", "A")...)
	assertNATOverlapRejected(t, "overlapping or duplicate pool members", cmds...)
}

// TestNAT5144WithinPoolDuplicateHost: the same host expressed as a bare IP and a
// /32 — a duplicate member, caught within one pool.
func TestNAT5144WithinPoolDuplicateHost(t *testing.T) {
	cmds := []string{
		"set security nat source pool A address 203.0.113.7",
		"set security nat source pool A address 203.0.113.7/32",
	}
	cmds = append(cmds, srcRule("RS", "r1", "A")...)
	assertNATOverlapRejected(t, "overlapping or duplicate pool members", cmds...)
}

// TestNAT5144IPv6Overlap: two source pools sharing an IPv6 address — proves the
// v6 sweep path detects overlap (v6 pools use a separate 16-byte comparison).
func TestNAT5144IPv6Overlap(t *testing.T) {
	cmds := []string{
		"set security nat source pool A address 2001:db8::5",
		"set security nat source pool B address 2001:db8::5",
	}
	cmds = append(cmds, srcRule("RSA", "r1", "A")...)
	cmds = append(cmds, srcRule("RSB", "r1", "B")...)
	assertNATOverlapRejected(t, "independent NAT allocators", cmds...)
}

// --- Negative cases: no false positive ---

// TestNAT5144DistinctPoolsAccepted: two source pools with disjoint addresses
// compile clean.
func TestNAT5144DistinctPoolsAccepted(t *testing.T) {
	cmds := []string{
		"set security nat source pool A address 203.0.113.1",
		"set security nat source pool B address 203.0.113.2",
	}
	cmds = append(cmds, srcRule("RSA", "r1", "A")...)
	cmds = append(cmds, srcRule("RSB", "r1", "B")...)
	assertNATOverlapAccepted(t, cmds...)
}

// TestNAT5144SharedPoolMultiZoneAccepted: ONE pool referenced by two rule-sets in
// different zones is a SINGLE allocator (pool-name-keyed) — the "different-zones,
// same match" case must NOT false-positive.
func TestNAT5144SharedPoolMultiZoneAccepted(t *testing.T) {
	cmds := []string{"set security nat source pool A address 203.0.113.5"}
	cmds = append(cmds, srcRule("RS1", "r1", "A")...)
	cmds = append(cmds,
		"set security nat source rule-set RS2 from zone dmz",
		"set security nat source rule-set RS2 to zone untrust",
		"set security nat source rule-set RS2 rule r1 match source-address 10.0.0.0/24",
		"set security nat source rule-set RS2 rule r1 then source-nat pool A",
	)
	assertNATOverlapAccepted(t, cmds...)
}

// TestNAT5144CrossFamilyNoOverlapAccepted: a v4 pool and a v6 pool that share the
// same numeric suffix are DIFFERENT families and never collide (the v4/v6 case).
func TestNAT5144CrossFamilyNoOverlapAccepted(t *testing.T) {
	cmds := []string{
		"set security nat source pool A address 203.0.113.5",
		"set security nat source pool B address 2001:db8::5",
	}
	cmds = append(cmds, srcRule("RSA", "r1", "A")...)
	cmds = append(cmds, srcRule("RSB", "r1", "B")...)
	assertNATOverlapAccepted(t, cmds...)
}

// TestNAT5144NAT64SamePrefixSamePoolAccepted: two NAT64 rule-sets sharing the
// SAME (prefix, pool) resolve to one allocator (deduped), so they must not
// false-positive.
func TestNAT5144NAT64SamePrefixSamePoolAccepted(t *testing.T) {
	cmds := []string{
		"set security nat source pool P address 100.64.0.7/32",
		"set security nat nat64 rule-set A prefix 64:ff9b::/96",
		"set security nat nat64 rule-set A source-pool P",
		"set security nat nat64 rule-set B prefix 64:ff9b::/96",
		"set security nat nat64 rule-set B source-pool P",
	}
	assertNATOverlapAccepted(t, cmds...)
}

// TestNAT5144UnreferencedOverlapAccepted: two pools with the SAME address but
// NEITHER referenced build no allocator, so they are out of scope (mirrors the
// aggregate gate's referenced-pool scoping).
func TestNAT5144UnreferencedOverlapAccepted(t *testing.T) {
	cmds := []string{
		"set security nat source pool A address 203.0.113.5",
		"set security nat source pool B address 203.0.113.5",
	}
	assertNATOverlapAccepted(t, cmds...)
}
