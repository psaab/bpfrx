// #6557: rolling step 7 REQUESTED the rejoin and reported "cut complete"
// without confirming it.
//
//	if err := cl.ResetFailover(); err != nil { ... }
//	logf("rolling: local node rejoined election; cut complete for this node")
//	return nil
//
// ResetFailover only requests the reset, per RG. A call that returned nil is
// not proof any RG left the ForceSecondary drain, and a client that could not
// enumerate an RG never issued its reset at all. Step 6's SyncEstablished does
// not close the gap: PeerAlive and SyncEstablished are GLOBAL predicates that
// hold while one RG is still pinned at weight 0.
//
// The #5138 per-RG readback (LocalRejoinComplete) was DECLARED on the
// RollingCluster interface in rolling.go itself and wired only into
// kernel_drain.go's RejoinAndConfirm. fakeCluster has carried the
// rejoinIncomplete / rejoinErr seams since #5138 and no rolling test ever set
// them, so the gap was invisible: TestRolling_HappyPath asserts only that
// ResetFailover was CALLED.
//
// Consequence: a reset that is ACKed but not effected (e.g. a post-upgrade
// interface monitor holding an RG at weight 0) leaves node 0 silently
// ineligible; the driver advances to node 1, whose ForceSecondary then leaves
// that RG with NO PRIMARY ON EITHER NODE until node 1's DrainDeadline expires.
//
// FAIL-ON-REVERT: restore the bare `cl.ResetFailover()` in step 7 and all
// three tests below go RED — the incomplete rejoin returns nil, the
// enumeration error is swallowed, and LocalRejoinComplete is never consulted.
package upgrade

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// rejoinRC bounds the rejoin wait tightly. RejoinAndConfirm polls at the
// package's drainPollInterval (1s), so the default 2s fastRC deadline would
// make every negative case a multi-second test for no added coverage.
func rejoinRC() RollingConfig {
	return RollingConfig{
		DrainDeadline:  2 * time.Second,
		RejoinDeadline: 10 * time.Millisecond,
		PollInterval:   time.Millisecond,
	}
}

// healthyRollingCluster is the cluster state every case below starts from: the
// cut itself succeeds, so the ONLY thing under test is step 7.
func healthyRollingCluster() *fakeCluster {
	return &fakeCluster{peerAlive: true, synced: true, compatible: true, peerReady: true, drainAfter: 2}
}

// TestRolling_RefusesWhenRejoinIncomplete6557 is the issue's scenario: the
// reset is ACKed but a configured RG is still held in the drain.
func TestRolling_RefusesWhenRejoinIncomplete6557(t *testing.T) {
	fs := newFakeSystem(t, "2.0.0")
	r, cfg := testEnv(t, fs)
	seedInitialCurrent(t, r, cfg, "1.0.0")

	cl := healthyRollingCluster()
	cl.rejoinIncomplete = true // a configured RG never left weight 0

	err := runRollingWith(r, cl, rejoinRC())
	if err == nil {
		t.Fatal("runRollingWith reported the cut COMPLETE while a configured redundancy " +
			"group was still held in the ForceSecondary drain. The external driver would " +
			"now advance to the peer and drain the node that still owns that RG, leaving " +
			"it with no primary on either node (#6557).")
	}
	if !strings.Contains(err.Error(), "rejoin") {
		t.Errorf("error does not identify the rejoin as the failure: %v", err)
	}
	// The operator must be told the node is left secondary and the roll must
	// stop — a bare "rejoin failed" does not say what NOT to do next.
	if !strings.Contains(err.Error(), "MUST NOT advance to the peer") {
		t.Errorf("error does not tell the driver to stop before the peer: %v", err)
	}
	// The reset must still have been REQUESTED: this is a confirmation
	// failure, not a refusal to try.
	if !cl.resetCalled {
		t.Error("ResetFailover was never called — step 7 must still request the rejoin")
	}
}

// TestRolling_SurfacesLocalRejoinEnumerationError6557 covers the fail-closed
// half. LocalRejoinComplete fails closed on an enumeration/transport error, and
// that error must reach the operator: "rejoin not confirmed" without the cause
// sends them to syslog to find out it was a refused gRPC dial.
func TestRolling_SurfacesLocalRejoinEnumerationError6557(t *testing.T) {
	fs := newFakeSystem(t, "2.0.0")
	r, cfg := testEnv(t, fs)
	seedInitialCurrent(t, r, cfg, "1.0.0")

	wantCause := errors.New("enumerate redundancy groups: connection refused")
	cl := healthyRollingCluster()
	cl.rejoinErr = wantCause

	err := runRollingWith(r, cl, rejoinRC())
	if err == nil {
		t.Fatal("runRollingWith reported the cut complete despite being unable to " +
			"determine whether the node rejoined (#6557 fail-closed)")
	}
	if !strings.Contains(err.Error(), wantCause.Error()) {
		t.Errorf("the underlying rejoin error is not surfaced.\n got: %v\nwant it to contain: %v",
			err, wantCause)
	}
}

// TestRolling_HappyPathConsultsTheRejoinReadback6557 binds the WIRING, and it
// is the test that would have caught the original defect.
//
// The two cases above are behavioural: they set a seam and observe a refusal.
// But a step 7 that confirms only on some branch — or one that calls
// ResetFailover twice and never reads back — could still satisfy them. This
// asserts the readback is consulted on the SUCCESS path, which is the path the
// pre-#6557 code took while reporting "cut complete".
//
// RED-on-revert: restore the bare `cl.ResetFailover()` and rejoinChecks stays
// 0 while the run returns nil — exactly the shipped behaviour, and exactly
// what TestRolling_HappyPath's `resetCalled` assertion could not see.
func TestRolling_HappyPathConsultsTheRejoinReadback6557(t *testing.T) {
	fs := newFakeSystem(t, "2.0.0")
	r, cfg := testEnv(t, fs)
	seedInitialCurrent(t, r, cfg, "1.0.0")

	cl := healthyRollingCluster()
	if err := runRollingWith(r, cl, rejoinRC()); err != nil {
		t.Fatalf("healthy rolling cut: %v", err)
	}
	if !cl.resetCalled {
		t.Fatal("ResetFailover not called")
	}
	if cl.rejoinChecks == 0 {
		t.Fatal("step 7 reported the cut COMPLETE without ever calling " +
			"LocalRejoinComplete. ResetFailover having returned nil is not proof any " +
			"redundancy group left the drain — that is precisely the #5138 readback " +
			"this interface declares and step 7 never used (#6557).")
	}
}
