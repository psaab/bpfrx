package userspace

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #6812 F1 round 4 — the UPGRADE and PEER-SYNC regression tests for the
// leading-zero pool member, driving the real TOLERANT path.
//
// WHAT MOVED, AND WHY THE MOVEMENT IS DELIBERATE.
//
// A pool member spelled `010.0.0.0/24` changes disposition across this branch,
// and the round-3 claim that "no pool changes disposition" was false on the one
// path that matters. Measured, same config, both trees:
//
//	merge base : PoolUnusable=false  -> ipnet read it as 10.0.0.0/24, allocator
//	                                    built, flows TRANSLATED
//	this branch: PoolUnusable=true   -> reason "invalid_pool", Rust returns
//	                                    Unavailable, packets DROPPED
//
// The movement is NOT from the round-3 Rust narrowing. `SourceNATPoolUnusableReason`
// does not exist at the merge base; the membership-grammar clause that stamps
// `invalid_pool` arrived in round 2 (`bc1329ae0`), and round 3 only made the
// RUNTIME agree with a poison Go had already begun applying. So the question
// this test settles is not "should Rust be narrowed" but "should the shared
// verdict refuse a non-canonical literal" — and the answer is yes, kept
// deliberately, for three reasons:
//
//  1. #5875 already settled the structurally identical case in this same
//     subsystem and chose REJECT over rewrite: "stripping the %zone silently
//     would change the modeled address, so the fix rejects rather than
//     rewrites". A leading zero is the WEAKER case — `010` has two readings
//     (decimal 10, octal 8) where `fe80::1%eth0` has exactly one.
//  2. Normalizing would install a NAT pool on a guess that is invisible:
//     `show configuration` would print `010.0.0.0/24` while the dataplane
//     translated from `10.0.0.0/24`. A stopped pool is loud; a silently
//     reinterpreted pool is quiet and wrong, which is the worse failure for a
//     firewall.
//  3. The merge base ALREADY warned that "the dataplane marks the pool unusable
//     (InvalidPool) and drops it at runtime, silently stopping translation".
//     That was aspirational there. This branch makes the code match the
//     promise the operator was already being given.
//
// What the movement costs, and what these tests therefore pin: the operator
// meets it as a NAT outage after an upgrade rather than as a commit error, so
// the diagnostic has to name the one-character fix and has to reach them on
// BOTH tolerant entries.

const leadingZeroPoolMember = "010.0.0.0/24"

func leadingZeroPoolTree(t *testing.T) *config.ConfigTree {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, cmd := range []string{
		"set security nat source pool p1 address " + leadingZeroPoolMember,
		"set security nat source rule-set rs1 from zone trust",
		"set security nat source rule-set rs1 to zone untrust",
		"set security nat source rule-set rs1 rule r1 match source-address 10.0.0.0/24",
		"set security nat source rule-set rs1 rule r1 then source-nat pool p1",
	} {
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	return tree
}

// assertLeadingZeroDiagnostic checks the compiler produced an operator-visible
// warning that names BOTH the offending spelling and the canonical one. The
// warning list is the field the daemon logs at apply
// (`slog.Warn("config validation", ...)`, pkg/daemon/daemon_apply.go), so this
// is the channel an upgrading operator actually reads.
func assertLeadingZeroDiagnostic(t *testing.T, cfg *config.Config, path string) {
	t.Helper()
	var hit string
	for _, w := range cfg.Warnings {
		if strings.Contains(w, leadingZeroPoolMember) && strings.Contains(w, "leading zero") {
			hit = w
			break
		}
	}
	if hit == "" {
		t.Fatalf("%s: no warning named the leading-zero member; warnings = %v", path, cfg.Warnings)
	}
	if !strings.Contains(hit, `"10.0.0.0/24"`) {
		t.Fatalf("%s: the warning does not name the canonical spelling, so the operator "+
			"cannot see that the fix is one character: %q", path, hit)
	}
	if !strings.Contains(hit, "translates nothing") {
		t.Fatalf("%s: the warning does not say the pool stopped translating: %q", path, hit)
	}
}

// TestLeadingZeroPoolMemberUpgradeIsDiagnosable_6812 drives the TOLERANT LOAD
// entry (config.CompileConfigLenient — what configstore's compileTolerantTree
// calls for a standalone node) on a config that was committed before the #5627
// grammar gate existed.
//
// FAIL-ON-REVERT: drop the canonicalPoolAddressHint branch in
// sourceNATPoolAddressReason and the reason falls back to the generic "is not a
// valid CIDR", which names neither the cause nor the fix — this test reds.
func TestLeadingZeroPoolMemberUpgradeIsDiagnosable_6812(t *testing.T) {
	tree := leadingZeroPoolTree(t)

	// #1960 no-brick: the tolerant path must still COMPILE. An upgrade that
	// refuses to boot on a persisted config is the failure this path exists to
	// prevent, and it is not what this branch does.
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("tolerant load must not fail on a persisted config: %v", err)
	}
	assertLeadingZeroDiagnostic(t, cfg, "tolerant load")

	// The behaviour that MOVED, asserted so it can never move back silently.
	out := buildSourceNATSnapshots(cfg, nil)
	if len(out) != 1 {
		t.Fatalf("expected one emitted rule, got %d", len(out))
	}
	if !out[0].PoolUnusable || out[0].PoolUnusableReason != "invalid_pool" {
		t.Fatalf("pool unusable=%v reason=%q, want true/invalid_pool — the leading-zero "+
			"member must poison the pool on the tolerant path too, matching the runtime",
			out[0].PoolUnusable, out[0].PoolUnusableReason)
	}
	// The raw literal is still what ships: the control plane REPORTS the
	// canonical spelling and never substitutes it (#5875 doctrine).
	if len(out[0].PoolAddresses) != 1 || out[0].PoolAddresses[0] != leadingZeroPoolMember {
		t.Fatalf("PoolAddresses = %v, want the raw literal — the compiler must not "+
			"silently rewrite a pool address", out[0].PoolAddresses)
	}
}

// TestLeadingZeroPoolMemberPeerSyncIsDiagnosable_6812 drives the PEER-SYNC
// entry (config.CompileConfigForNodeLenient — what configstore's
// compileTolerantTree calls when this box has a node id), the path a config
// arriving from an OLDER primary takes. An HA standby that silently stops
// translating after the primary syncs it a legacy pool is the same outage with
// no operator at the keyboard, so the diagnostic is owed here too.
func TestLeadingZeroPoolMemberPeerSyncIsDiagnosable_6812(t *testing.T) {
	for _, nodeID := range []int{0, 1} {
		cfg, err := config.CompileConfigForNodeLenient(leadingZeroPoolTree(t), nodeID)
		if err != nil {
			t.Fatalf("node %d: peer-sync compile must not fail: %v", nodeID, err)
		}
		assertLeadingZeroDiagnostic(t, cfg, "peer-sync")

		out := buildSourceNATSnapshots(cfg, nil)
		if len(out) != 1 || !out[0].PoolUnusable {
			t.Fatalf("node %d: the synced pool must be poisoned like the local one", nodeID)
		}
	}
}

// TestLeadingZeroPoolMemberStrictRejectionNamesTheFix_6812 pins the same
// diagnostic on the STRICT path, where an operator authoring the config meets
// it. Same message on both paths means the upgrade warning and the commit
// error are recognisably the same problem.
func TestLeadingZeroPoolMemberStrictRejectionNamesTheFix_6812(t *testing.T) {
	_, err := config.CompileConfig(leadingZeroPoolTree(t))
	if err == nil {
		t.Fatal("strict commit must reject a leading-zero pool member")
	}
	msg := err.Error()
	for _, want := range []string{leadingZeroPoolMember, `"10.0.0.0/24"`, "leading zero"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("strict error does not contain %q: %s", want, msg)
		}
	}
}
