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
	if push, fp := ipsecSASyncAdvertise(nil, "", false); push || fp != "" {
		t.Fatalf("never-up: got push=%v fp=%q, want push=false fp=\"\"", push, fp)
	}

	// SAs come up: the non-empty set is advertised and its fingerprint is
	// remembered so the NEXT drop-to-zero is detected as a transition.
	push, up := ipsecSASyncAdvertise([]string{"vpn-a", "vpn-b"}, "", false)
	if !push || up == "" {
		t.Fatalf("SA up: got push=%v fp=%q, want push=true fp!=\"\"", push, up)
	}

	// steady live set: heartbeat re-push every tick. This is the ONLY mechanism
	// that seeds a freshly reconnected/restarted standby's peer set, so it must
	// keep pushing even when the set is unchanged (reconnect-safety, unchanged
	// from pre-#4385 behavior).
	if push, _ := ipsecSASyncAdvertise([]string{"vpn-a", "vpn-b"}, up, false); !push {
		t.Fatal("live set: heartbeat re-push required for reconnect-safety")
	}

	// tunnel downed: the active set drops to zero AFTER being non-empty -> the
	// empty set MUST be advertised once so the standby clears stale SAs. This is
	// the #4385 fix and is RED on revert of the len(names)>0 guard.
	push, fp := ipsecSASyncAdvertise(nil, up, false)
	if !push {
		t.Fatal("downed tunnel: empty set must be advertised to clear stale peer SAs (#4385)")
	}
	if fp != "" {
		t.Fatalf("downed tunnel: advertised-empty fingerprint got %q, want \"\"", fp)
	}

	// steady empty after the clear: the empty set is not re-advertised (no 30s
	// empty-heartbeat churn on the sync channel).
	if push, _ := ipsecSASyncAdvertise(nil, "", false); push {
		t.Fatal("steady empty: repeated empty set must not churn the sync channel")
	}

	// the fingerprint is set-identity, not slice-order, so a reordered
	// swanctl --list-sas result does not look like a change.
	if a, b := ipsecSAFingerprint([]string{"a", "b"}), ipsecSAFingerprint([]string{"b", "a"}); a != b {
		t.Fatalf("fingerprint not order-independent: %q vs %q", a, b)
	}
}

// TestIPsecSASyncForceReadvertise pins the #4385 peer-connect re-advertise: on a
// forced pass (a peer sync connection was (re)established) the CURRENT set is
// advertised regardless of change — empty or not — so a reconnected standby
// converges to our actual state. RED-on-revert: without the force branch,
// ipsecSASyncAdvertise(nil, "", true) returns push=false and a standby that
// missed the one-shot empty stays stale until the set next changes.
func TestIPsecSASyncForceReadvertise(t *testing.T) {
	// force + current set empty: re-advertise empty so a stale standby (missed
	// the one-shot empty, or retained its set across a blip) clears.
	push, fp := ipsecSASyncAdvertise(nil, "", true)
	if !push {
		t.Fatal("force: an empty current set must be re-advertised to clear a stale standby (#4385)")
	}
	if fp != "" {
		t.Fatalf("force empty: fingerprint got %q, want \"\"", fp)
	}

	// force + current set non-empty: re-advertise the set to re-seed a freshly
	// reconnected/restarted standby.
	push, fp = ipsecSASyncAdvertise([]string{"vpn-a"}, "", true)
	if !push || fp == "" {
		t.Fatalf("force non-empty: got push=%v fp=%q, want push=true fp!=\"\"", push, fp)
	}
}

// TestIPsecSAMissedEmptyRetries pins the #4385 confirmed-send retry: the
// last-sent fingerprint advances ONLY on a confirmed send, so an empty
// advertisement that no-ops on a nil/dropped conn (a reconnect gap) is retried
// on the next tick and eventually clears the standby.
//
// RED-on-revert: if ipsecSANextFP advanced lastFP even on an UNCONFIRMED send
// (return fp whenever push), the missed empty would mark lastFP="" and the next
// tick would see ipsecSASyncAdvertise(nil, "") -> push=false -> the empty is
// NEVER retried, leaving the standby holding the stale set that resurrects the
// tunnel on takeover.
func TestIPsecSAMissedEmptyRetries(t *testing.T) {
	// Primary brought {vpn-a} up and advertised it (confirmed).
	push, fp := ipsecSASyncAdvertise([]string{"vpn-a"}, "", false)
	up := ipsecSANextFP(push, true, fp, "")
	if up == "" {
		t.Fatalf("setup: live set must leave a non-empty last-sent fingerprint, got %q", up)
	}

	// Tunnel downed during a reconnect gap: the empty push is DUE, but the send
	// no-ops on a nil conn (sendConfirmed=false). lastFP MUST stay non-empty so
	// the empty advertisement is retried, not silently lost.
	push, fp = ipsecSASyncAdvertise(nil, up, false)
	if !push {
		t.Fatal("downed tunnel: empty advertisement must be DUE")
	}
	lastFP := ipsecSANextFP(push, false /* send did not reach an active conn */, fp, up)
	if lastFP != up {
		t.Fatalf("missed send: lastFP must NOT advance (retry-on-next-tick); got %q want %q", lastFP, up)
	}

	// Next tick, the conn is restored: the empty is STILL due (lastFP unchanged)
	// and the send is now confirmed -> lastFP advances to empty (standby
	// cleared, no further churn).
	push, fp = ipsecSASyncAdvertise(nil, lastFP, false)
	if !push {
		t.Fatal("retry: empty advertisement must still be DUE after the missed send")
	}
	lastFP = ipsecSANextFP(push, true, fp, lastFP)
	if lastFP != "" {
		t.Fatalf("retry: after a confirmed empty send lastFP must be empty, got %q", lastFP)
	}

	// Steady empty after the clear: no further churn.
	if push, _ := ipsecSASyncAdvertise(nil, lastFP, false); push {
		t.Fatal("steady empty after clear: empty set must not churn")
	}
}
