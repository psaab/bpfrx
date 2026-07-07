package daemon

import "testing"

// TestIPsecSASyncAdvertise pins the #4385 empty-set advertise decision made by
// syncIPsecSAPeriodic.
//
// The bug: syncIPsecSAPeriodic guarded the push with `if len(names) > 0`, so
// when the primary's active SA set dropped to zero (a tunnel was
// administratively downed / all its SAs torn down) the empty set was NEVER
// advertised. The standby overwrites its peer set wholesale, so it retained the
// last non-empty snapshot and, on RG0 takeover, reinitiateIPsecSAs re-initiated
// each stale name -> the downed tunnel was resurrected on the new primary.
//
// The fix advertises the empty set once on the drop-to-zero transition so the
// standby clears its stale peer set, while never churning an empty heartbeat on
// a node that never brought an SA up, and still re-pushing a live set every
// tick for reconnect-safety.
//
// RED-on-revert: restoring the `len(names) > 0` guard (return `len(names) > 0`
// unconditionally from ipsecSASyncAdvertise) fails the "downed tunnel" case
// below — the empty set is no longer advertised and the standby keeps the
// stale SA.
func TestIPsecSASyncAdvertise(t *testing.T) {
	// never-up: an empty set from the start is never advertised (no churn; the
	// standby's default peer set is already empty).
	if push, fp := ipsecSASyncAdvertise(nil, ""); push || fp != "" {
		t.Fatalf("never-up: got push=%v fp=%q, want push=false fp=\"\"", push, fp)
	}

	// SAs come up: the non-empty set is advertised and its fingerprint is
	// remembered so the NEXT drop-to-zero is detected as a transition.
	push, up := ipsecSASyncAdvertise([]string{"vpn-a", "vpn-b"}, "")
	if !push || up == "" {
		t.Fatalf("SA up: got push=%v fp=%q, want push=true fp!=\"\"", push, up)
	}

	// steady live set: heartbeat re-push every tick. This is the ONLY mechanism
	// that seeds a freshly reconnected/restarted standby, so it must keep
	// pushing even when the set is unchanged (reconnect-safety, unchanged from
	// pre-#4385 behavior).
	if push, _ := ipsecSASyncAdvertise([]string{"vpn-a", "vpn-b"}, up); !push {
		t.Fatal("live set: heartbeat re-push required for reconnect-safety")
	}

	// tunnel downed: the active set drops to zero AFTER being non-empty -> the
	// empty set MUST be advertised once so the standby clears stale SAs. This is
	// the #4385 fix and is RED on revert of the len(names)>0 guard.
	push, fp := ipsecSASyncAdvertise(nil, up)
	if !push {
		t.Fatal("downed tunnel: empty set must be advertised to clear stale peer SAs (#4385)")
	}
	if fp != "" {
		t.Fatalf("downed tunnel: advertised-empty fingerprint got %q, want \"\"", fp)
	}

	// steady empty after the clear: the empty set is not re-advertised (no 30s
	// empty-heartbeat churn on the sync channel).
	if push, _ := ipsecSASyncAdvertise(nil, ""); push {
		t.Fatal("steady empty: repeated empty set must not churn the sync channel")
	}

	// the fingerprint is set-identity, not slice-order, so a reordered
	// swanctl --list-sas result does not look like a change.
	if a, b := ipsecSAFingerprint([]string{"a", "b"}), ipsecSAFingerprint([]string{"b", "a"}); a != b {
		t.Fatalf("fingerprint not order-independent: %q vs %q", a, b)
	}
}
