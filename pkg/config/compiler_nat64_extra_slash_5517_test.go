package config

import (
	"strings"
	"testing"
)

// #5517: commit-accepts / runtime-drops divergence for a NAT64 rule-set
// `prefix` with a trailing extra slash.
//
// The Rust dataplane loader (Nat64State::from_snapshots,
// userspace-dp/src/nat64.rs) splits the prefix on '/' and requires EXACTLY two
// parts: `if parts.len() != 2 { ...; continue }` SKIPS any rule whose prefix
// does not split into exactly two slash-separated parts. So a prefix with an
// extra slash — "64:ff9b::/96/garbage" → ["64:ff9b::", "96", "garbage"] — is
// silently omitted from the forwarding snapshot (the Rust regression test
// `extra_slash_prefix_skips_rule` pins this skip).
//
// Pre-#5517, validateNAT64PrefixStrict used `if len(parts) >= 2` and indexed
// parts[0]/parts[1], disregarding the rest, so it ACCEPTED "64:ff9b::/96/garbage"
// (parts[1]=="96" parses, parts[0]=="64:ff9b::" is a valid IPv6 address). Commit
// SUCCEEDED but the runtime dropped the rule → IPv6→IPv4 translation for that
// rule never happened (silent blackhole, no error).
//
// The gate now requires `len(parts) == 2`, rejecting exactly what the runtime
// skips. RED-on-revert: change `== 2` back to `>= 2` in
// validateNAT64PrefixStrict and the two reject tests below go GREEN-accept
// (commit succeeds), i.e. the tests fail.
//
// All tests use the production ParseSetCommand + SetPath path (buildTree),
// never NewParser (the flat-set gotcha in CLAUDE.md).

func TestNAT64PrefixRejectsExtraSlash_5517(t *testing.T) {
	// The exact issue case: a valid-looking /96 with trailing garbage after a
	// second slash. Rust splits into three parts and skips the rule; the strict
	// commit gate must reject it so the two agree.
	tree := buildTree(t, nat64Set("64:ff9b::/96/garbage"))
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("NAT64 prefix 64:ff9b::/96/garbage (extra slash) must be rejected at commit; the dataplane skips it (silent blackhole) otherwise")
	}
	msg := err.Error()
	if !strings.Contains(msg, "rs1") ||
		!strings.Contains(msg, "64:ff9b::/96/garbage") ||
		!strings.Contains(msg, "/96") {
		t.Fatalf("error must name the rule-set + offending prefix + /96 requirement, got: %v", err)
	}
}

func TestNAT64PrefixRejectsBareTrailingSlashAfterMask_5517(t *testing.T) {
	// A bare trailing slash after the mask — "64:ff9b::/96/" splits into
	// ["64:ff9b::", "96", ""] → three parts → the runtime skips it. Must reject
	// at commit.
	tree := buildTree(t, nat64Set("64:ff9b::/96/"))
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("NAT64 prefix 64:ff9b::/96/ (bare trailing slash after mask) must be rejected at commit")
	}
}

func TestNAT64PrefixValidStillCommits_5517(t *testing.T) {
	// Control: the exact-two-parts well-known prefix must still compile on the
	// strict path (the tightened `== 2` split must not over-reject a valid rule).
	tree := buildTree(t, nat64Set("64:ff9b::/96"))
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("valid 64:ff9b::/96 must still commit after the #5517 tightening, got: %v", err)
	}
}

// Lenient path (#1960 / #1979 doctrine) must skip the extra-slash prefix
// consistently: an already-persisted or peer-synced config with the bad prefix
// must NOT hard-fail the compile, but MUST emit a warning naming it (mirroring
// the runtime skip, which keeps the previous live state).
func TestNAT64PrefixExtraSlashLenientWarns_5517(t *testing.T) {
	for _, p := range []string{"64:ff9b::/96/garbage", "64:ff9b::/96/"} {
		tree := buildTree(t, nat64Set(p))
		cfg, err := CompileConfigLenient(tree)
		if err != nil {
			t.Fatalf("lenient compile must NOT hard-fail on extra-slash NAT64 prefix %q, got: %v", p, err)
		}
		found := false
		for _, w := range cfg.Warnings {
			if strings.Contains(w, "rs1") && strings.Contains(w, p) && strings.Contains(w, "nat64") {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("lenient compile must warn naming the extra-slash NAT64 prefix %q, warnings: %v", p, cfg.Warnings)
		}
	}
}
