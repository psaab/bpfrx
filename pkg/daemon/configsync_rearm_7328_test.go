package daemon

import (
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
)

// #7328 — a config generation the peer did not apply must become re-pushable.
//
// Two shipped features stated opposite contracts about the same event, and the
// later one won silently:
//
//   - #4151 pins the receiver's lastAppliedConfigGen on a FAILED apply
//     SPECIFICALLY so the same generation stays eligible for a re-push
//     ("keeps the standby eligible for the primary's re-push so it
//     re-converges instead of being silently stranded"), and
//     errConfigSyncRejectedPrimary's doc says the dual-active window "must heal
//     via the peer's re-push".
//   - #5863's reconciler claims its (epoch x generation) marker BEFORE sending
//     and nothing ever cleared it, so no trigger on the live connection ever
//     pushed that generation again. Convergence waited for a new commit (new
//     generation) or a reconnect (new epoch).
//
// #6387's own comment records the same mechanism from the receiver's side —
// "the sender pushes a generation at most once per connection, so a stable
// connection with a persistent apply failure would otherwise never re-enter
// this edge" — and answered it with an alarm rather than convergence.
//
// The fix is receiver-driven: the peer nacks the generation it failed on and
// the sender re-arms the marker. These tests pin BOTH directions of the
// asymmetry, which is the whole design problem — the marker must still suppress
// a redundant push on SUCCESS (that is what #5863 exists to prevent) while no
// longer suppressing the retry on FAILURE.

// TestConfigSyncRearmsAfterPeerApplyFailure7328 is the fail-on-revert case.
//
// FAIL-ON-REVERT: drop the invalidateConfigSyncPushed() call from the
// OnPeerConfigApplyFailed wiring in wireSessionSyncConfigCallbacks (or delete
// the assignment entirely) and this reds — the reconcile ticks go back to
// producing zero re-pushes.
func TestConfigSyncRearmsAfterPeerApplyFailure7328(t *testing.T) {
	d, pushes := newReconcileDaemon(t, true /*primary*/, 60*time.Second)

	// The authority pushes the active config once and claims the marker.
	d.reconcileConfigSyncToPeer("rg0-promotion")
	if got := pushes.Load(); got != 1 {
		t.Fatalf("setup: authority must push once; got %d", got)
	}

	// Every trigger that changes neither the connection epoch nor the config
	// generation is deduped — this is #5863 working as designed, and it is the
	// state the peer's failed apply gets stuck behind.
	for i := 0; i < 5; i++ {
		d.reconcileConfigSyncToPeer("reconcile-loop")
	}
	if got := pushes.Load(); got != 1 {
		t.Fatalf("same epoch+generation must dedupe; got %d pushes", got)
	}

	// The peer reports it did not apply that generation. The sender re-arms.
	d.invalidateConfigSyncPushed()

	// The very next ordinary reconcile tick must now re-push. No new commit,
	// no reconnect — the same config text on the same connection.
	d.reconcileConfigSyncToPeer("reconcile-loop")
	if got := pushes.Load(); got != 2 {
		t.Fatalf("after a peer apply-failure the next reconcile tick MUST re-push the same "+
			"generation (M-2/#4151 keeps the peer eligible for exactly that); got %d pushes", got)
	}

	// And the re-push re-claims the marker, so the retry stays bounded to the
	// reconciler's cadence rather than becoming a push storm.
	for i := 0; i < 5; i++ {
		d.reconcileConfigSyncToPeer("reconcile-loop")
	}
	if got := pushes.Load(); got != 2 {
		t.Fatalf("the re-push must re-claim the marker so the retry is bounded to the "+
			"reconcile cadence; got %d pushes", got)
	}
}

// TestConfigSyncDoesNotRearmOnSuccess7328 is the OTHER direction of the
// asymmetry, and it is the storm guard.
//
// The fix must fire ONLY on a failed apply. A successful apply sends no nack,
// so nothing re-arms the marker and a healthy connection still pushes a
// generation exactly once. A fix that re-armed unconditionally — on a timer, on
// every tick, or on any push regardless of outcome — would reintroduce the push
// storm #5863's marker exists to prevent, on a control socket CLAUDE.md
// requires be kept quiet.
//
// FAIL-ON-REVERT: make the re-arm unconditional (e.g. call
// invalidateConfigSyncPushed from the reconcile path itself, or clear the
// marker on a timer) and this reds immediately.
func TestConfigSyncDoesNotRearmOnSuccess7328(t *testing.T) {
	d, pushes := newReconcileDaemon(t, true /*primary*/, 60*time.Second)

	d.reconcileConfigSyncToPeer("rg0-promotion")
	if got := pushes.Load(); got != 1 {
		t.Fatalf("setup: authority must push once; got %d", got)
	}

	// A healthy peer applies it and nacks nothing. Drive far more ticks than a
	// real 30s reconciler would fire in a long-lived connection.
	for i := 0; i < 50; i++ {
		d.reconcileConfigSyncToPeer("reconcile-loop")
	}
	// Plus the other two production triggers, neither of which changes the key.
	d.reconcileConfigSyncToPeer("rg0-promotion")
	d.reconcileConfigSyncToPeer("peer-connect")

	if got := pushes.Load(); got != 1 {
		t.Fatalf("NO re-arm may happen without a peer apply-failure — a successful push must "+
			"stay deduped (#5863 no-storm); got %d pushes", got)
	}
}

// TestConfigApplyFailedWiringReArmsMarker7328 binds the production WIRING, not
// the function it calls.
//
// Nothing in production calls invalidateConfigSyncPushed directly. The re-arm
// is live only because wireSessionSyncConfigCallbacks ASSIGNS
// ss.OnPeerConfigApplyFailed, and the cluster read loop invokes that field. A
// re-arm that was implemented but never wired would leave every direct test
// above green while the defect shipped unchanged.
//
// FAIL-ON-REVERT: delete the `ss.OnPeerConfigApplyFailed = ...` assignment from
// wireSessionSyncConfigCallbacks and this reds on the nil check; make the
// closure a no-op and it reds on the marker assertion.
func TestConfigApplyFailedWiringReArmsMarker7328(t *testing.T) {
	d, pushes := newReconcileDaemon(t, true /*primary*/, 60*time.Second)
	ss := cluster.NewSessionSync(":0", "10.0.0.2:4785", nil)

	d.wireSessionSyncConfigCallbacks(ss)

	if ss.OnPeerConfigApplyFailed == nil {
		t.Fatal("wireSessionSyncConfigCallbacks must install OnPeerConfigApplyFailed — " +
			"the cluster read loop has no other source for it, so an unwired re-arm " +
			"leaves the #7328 defect shipping unchanged")
	}

	// Claim the marker, exactly as a real push does.
	d.reconcileConfigSyncToPeer("rg0-promotion")
	if got := pushes.Load(); got != 1 {
		t.Fatalf("setup: authority must push once; got %d", got)
	}
	d.reconcileConfigSyncToPeer("reconcile-loop")
	if got := pushes.Load(); got != 1 {
		t.Fatalf("setup: marker must be claimed; got %d pushes", got)
	}

	// Drive the callback the way the cluster read loop does on a nack.
	ss.OnPeerConfigApplyFailed(1234)

	d.reconcileConfigSyncToPeer("reconcile-loop")
	if got := pushes.Load(); got != 2 {
		t.Fatalf("the wired OnPeerConfigApplyFailed callback must re-arm the push marker; "+
			"got %d pushes after invoking it", got)
	}
}
