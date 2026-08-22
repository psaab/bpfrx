package daemon

import (
	"testing"

	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #6031 coverage salvage: an empty OWNED-RG set is a determinate answer, not a
// precondition failure.
//
// Every merged fail-closed test pins the other direction — a nil exporter, a nil
// session sync, a nil config and a failing export must each be an ERROR rather
// than an empty authoritative window, because an empty window makes the peer
// delete every session it holds for us. That direction is right, and it is
// exactly what makes THIS case easy to break on the next edit: "empty means
// error" is one guard away, sitting next to four guards that already have that
// shape, and it is the wrong guard here.
//
// A node primary for no redundancy group has not FAILED to determine ownership.
// It owns nothing to sync, and the peer should reconcile away what it still
// holds for us — the steady state of a standby cold-priming its primary.
// Erroring would make doBulkSync fail closed on every attempt, leaving the
// obligation armed forever: handleNewConnection's needColdPrime latch, the #4090
// survivor re-drive and the #82 sweep re-drive all merely retry. The standby
// would never reconcile, on a path that runs on every reconnect.
//
// The helper agrees by construction: kick_owner_rg_export short-circuits on an
// empty owner-RG list (userspace-dp afxdp/ha/export.rs:27, `skip: true`,
// sequence 0) and drains nothing, so an empty snapshot is what table truth
// actually reports for this node.
//
// RED-on-revert: add `if len(rgIDs) == 0 { return cluster.BulkSnapshot{},
// errors.New("no owned redundancy groups") }` to
// userspaceBulkSnapshotWithConfig and the error assertion fires.
//
// Deliberately NOT asserted here: that the returned snapshot is empty. The
// exporter is a fake, and this fake — like the merged recordingExporter —
// returns its canned deltas regardless of the RG list. Asserting emptiness would
// therefore be asserting the fake's own behaviour, not the daemon's. What the
// daemon actually owes is below: pass the determinate empty set THROUGH, and do
// not turn it into an error. Emptiness of the result is the helper's half of the
// contract, pinned on the Rust side.
func TestUserspaceBulkSnapshotEmptyOwnedRGSetIsNotAnError6031(t *testing.T) {
	d, ss, cfg := snapshot6031Daemon()
	exporter := &recordingExporter{deltas: []dpuserspace.SessionDeltaInfo{transitDelta6031(39906)}}

	if _, err := d.userspaceBulkSnapshotWithConfig(exporter, ss, cfg, nil); err != nil {
		t.Fatalf("#6031: a node primary for no redundancy group must NOT be an error — "+
			"doBulkSync fails closed on one, so every cold prime from a fully-secondary node "+
			"would be abandoned and its obligation re-armed forever; got %v", err)
	}
}

// TestUserspaceBulkSnapshotPassesTheOwnedRGSetThrough6031 pins the other half:
// the RG list reaches the export verbatim, and an empty one is NOT widened into
// a default.
//
// The dangerous "fix" for the case above is not an error but a substitution —
// `if len(rgIDs) == 0 { rgIDs = allConfiguredRGs(cfg) }` — which asks the helper
// for every RG's sessions, including the ones this node holds only as peer
// imports. Today the per-delta owner-RG filter would still drop them, so the
// window would come out empty anyway; that is a second line of defence, not a
// reason to let the first one go unbound.
func TestUserspaceBulkSnapshotPassesTheOwnedRGSetThrough6031(t *testing.T) {
	d, ss, cfg := snapshot6031Daemon()

	exporter := &recordingExporter{}
	if _, err := d.userspaceBulkSnapshotWithConfig(exporter, ss, cfg, nil); err != nil {
		t.Fatalf("userspaceBulkSnapshotWithConfig() error = %v", err)
	}
	if len(exporter.gotRGIDs) != 0 {
		t.Fatalf("export requested RGs %v for a node that owns none — an empty owned set must "+
			"reach the helper verbatim, not be widened into a default that asks for the "+
			"peer's sessions too", exporter.gotRGIDs)
	}

	// Positive control: a non-empty set is passed through unchanged, so the
	// assertion above is about the EMPTY case and not about the argument being
	// dropped on every call.
	owned := &recordingExporter{}
	if _, err := d.userspaceBulkSnapshotWithConfig(owned, ss, cfg, []int{1, 4}); err != nil {
		t.Fatalf("userspaceBulkSnapshotWithConfig() error = %v", err)
	}
	if len(owned.gotRGIDs) != 2 || owned.gotRGIDs[0] != 1 || owned.gotRGIDs[1] != 4 {
		t.Fatalf("export requested RGs %v, want [1 4] passed through verbatim", owned.gotRGIDs)
	}
}
