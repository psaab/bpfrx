package cluster

import (
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// #6031 coverage salvage: an EMPTY table-truth snapshot must still frame a REAL
// authoritative window.
//
// This is the one shape the merged #6031 tests do not drive. All four of them
// hand BulkSnapshotSource a non-empty snapshot or an error, so nothing pins what
// happens when the snapshot is legitimately empty — and empty is not a corner
// case here, it is the steady state of a node that is primary for NO redundancy
// group. `kick_owner_rg_export` short-circuits on an empty owner-RG list
// (userspace-dp afxdp/ha/export.rs), the helper drains nothing, and
// userspaceBulkSnapshot correctly returns an empty snapshot with no error. A
// fully-secondary node cold-priming its peer therefore takes exactly this path.
//
// An empty snapshot is an ASSERTION — "I own nothing to sync" — and #5085
// requires the receiver to act on it by reconciling away every eligible session
// it still holds for us. Short-circuiting the window because there is nothing to
// send is the #5085 empty-bulk skip, reintroduced one layer down: the receiver
// never sees a BulkStart, `bulkInProgress` stays false, and #5272 drops the
// (never sent) BulkEnd as spurious, so the stale sessions survive forever.
//
// RED-on-revert: add the plausible optimisation
//
//	if walk.len() == 0 { return nil }
//
// to bulkSyncWindow (or `if snap.Len() == 0 { return nil }` to BulkSyncSnapshot)
// and staleOnStandby survives — this test fires on the first assertion.
func TestBulkSyncSnapshotEmptyIsStillAnAuthoritativeWindow6031(t *testing.T) {
	senderSS, _ := newBulk6031Primary(t)
	receiverSS, receiverDP := newBulk6031Standby(t)

	// Table truth says this node owns nothing — the shape a node that is
	// secondary for every RG reports. Its mirror is NOT empty (the primary
	// fixture holds the host-inbound row), so a window framed from the store
	// walk would carry a session and this would pass for the wrong reason.
	senderSS.BulkSnapshotSource = func() (BulkSnapshot, error) {
		return BulkSnapshot{}, nil
	}

	pumpBulk(t, senderSS, receiverSS)

	for _, tc := range []struct {
		key  dataplane.SessionKey
		name string
	}{
		{staleOnStandby, "stale peer-owned"},
		{transitLive, "live peer-owned"},
	} {
		if _, ok := receiverDP.v4sessions[tc.key]; ok {
			t.Fatalf("#6031/#5085: the %s session survived an EMPTY authoritative window — "+
				"an empty snapshot asserts the peer owns nothing, so every eligible session "+
				"must be reconciled away; a short-circuit that skips framing the window "+
				"reintroduces the #5085 empty-bulk skip one layer down", tc.name)
		}
	}
	// The standby's OWN session is in an RG it owns, so it is not
	// reconcile-eligible and must be untouched — this is what separates
	// "reconciled correctly" from "deleted everything".
	if _, ok := receiverDP.v4sessions[standbyOwnLocal]; !ok {
		t.Fatal("the standby's own session (our RG) must never be reconciled by a peer's window")
	}
	// A real transfer happened: the peer counted a bulk. Without this the
	// assertions above would also pass if the window were never framed AND the
	// receiver had been wiped by something else.
	if got := senderSS.stats.BulkSyncs.Load(); got != 1 {
		t.Fatalf("BulkSyncs = %d, want 1 — an empty snapshot must still complete a real window", got)
	}
}
