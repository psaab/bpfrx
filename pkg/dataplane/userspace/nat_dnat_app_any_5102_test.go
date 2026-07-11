// #5102 (Codex audit 177 A6-b2-F3): a DNAT rule with `match application any`
// (the Junos application wildcard) is UNCONSTRAINED — it must match every
// application, exactly like a DNAT rule with no application configured. SNAT's
// buildSourceNATAppTerms already collapses a sole "any"/empty reference to no
// constraint; before this fix the DNAT builder treated `any` as a
// configured-but-unresolvable application (appConfigured = len(list) > 0 was
// true, ResolveApplication("any") returned not-found, "any" is not an
// application-set) and emitted the #3434 never-match source-port sentinel
// ({Low:1, High:0}), silently disabling a valid, strict-commit-accepted rule.
//
// RED-on-revert: restoring `appConfigured := len(rule.Match.ApplicationList())
// > 0` makes `any` configured-but-unresolvable, so MatchSourcePorts carries the
// {1,0} never-match sentinel instead of staying empty. This test asserts the
// UNCONSTRAINED shape, which the never-match sentinel fails.
//
// The never-match-for-a-real-but-unresolvable-app no-regression (a typo, a
// dangling reference, or a defined-but-empty application-set) is guarded by the
// existing #3434 tests (TestBuildDNATSnapshotUndefinedApplicationFailsClosed /
// TestBuildDNATSnapshotEmptyApplicationSetFailsClosed): those names are NOT
// "any"/"" so they still set appConfigured=true and still fail closed. A real
// application alongside "any" is likewise preserved — the resolve loop (which
// this fix does NOT touch) skips the unresolvable "any" and adds the real
// terms, so appTerms is non-empty and the rule stays application-scoped.
package userspace

import "testing"

// A DNAT `match application any` must lower to an UNCONSTRAINED term — empty
// MatchSourcePorts and a zero (any-port) DestinationPort — identical to the
// no-application control (TestBuildDNATSnapshotNoApplicationStillWildcards),
// NOT the {1,0} never-match sentinel that a real-but-unresolvable app gets.
func TestBuildDNATSnapshotApplicationAnyIsUnconstrained_5102(t *testing.T) {
	cfg := dnatAppRefConfig("any")
	snaps := buildDestinationNATSnapshots(cfg, nil)
	if len(snaps) != 1 {
		t.Fatalf("len(snaps) = %d, want 1", len(snaps))
	}
	if len(snaps[0].MatchSourcePorts) != 0 {
		t.Fatalf("MatchSourcePorts = %+v, want empty (match application any is "+
			"unconstrained, NOT the never-match {1,0} sentinel)", snaps[0].MatchSourcePorts)
	}
	if snaps[0].DestinationPort != 0 {
		t.Fatalf("DestinationPort = %d, want 0 (any-port DNAT)", snaps[0].DestinationPort)
	}
}
