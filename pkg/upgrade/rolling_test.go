package upgrade

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// fakeCluster is an in-memory RollingCluster for orchestration tests.
type fakeCluster struct {
	peerAlive    bool
	synced       bool
	compatible   bool
	peerReady    bool
	localPri     bool
	drainAfter   int // become drained after this many DrainComplete polls
	drainPolls   int
	syncErrPolls int // SyncEstablished returns a transient error for this many polls
	syncPolls    int
	forced       bool
	resetCalled  bool
}

func (f *fakeCluster) PeerAlive() (bool, error) { return f.peerAlive, nil }
func (f *fakeCluster) SyncEstablished() (bool, error) {
	f.syncPolls++
	// Poll #1 is the PRE-cut precondition check (daemon up) — always OK.
	// Polls #2..#(1+syncErrPolls) model the POST-cut gRPC-startup gap: the
	// local socket refuses connections while xpfd restarts. After that the
	// daemon is up and sync re-establishes.
	if f.syncPolls > 1 && f.syncPolls-1 <= f.syncErrPolls {
		return false, errors.New("dial xpfd gRPC 127.0.0.1:50051: connection refused")
	}
	return f.synced, nil
}
func (f *fakeCluster) HAProtocolCompatible() (bool, error) { return f.compatible, nil }
func (f *fakeCluster) PeerTakeoverReady() (bool, error)    { return f.peerReady, nil }
func (f *fakeCluster) ForceSecondary() error               { f.forced = true; return nil }
func (f *fakeCluster) DrainComplete() (bool, error) {
	f.drainPolls++
	return f.drainPolls >= f.drainAfter, nil
}
func (f *fakeCluster) ResetFailover() error        { f.resetCalled = true; return nil }
func (f *fakeCluster) LocalPrimary() (bool, error) { return f.localPri, nil }

func fastRC() RollingConfig {
	return RollingConfig{
		DrainDeadline:  2 * time.Second,
		RejoinDeadline: 2 * time.Second,
		PollInterval:   time.Millisecond,
	}
}

func TestRolling_HappyPath(t *testing.T) {
	fs := newFakeSystem(t, "2.0.0")
	r, _ := testEnv(t, fs)
	cl := &fakeCluster{peerAlive: true, synced: true, compatible: true, peerReady: true, drainAfter: 2}

	if err := runRollingWith(r, cl, fastRC()); err != nil {
		t.Fatalf("rolling: %v", err)
	}
	if !cl.forced {
		t.Error("ForceSecondary not called")
	}
	if !cl.resetCalled {
		t.Error("ResetFailover (failback) not called")
	}
	// The cut must have completed (current -> 2.0.0).
	if fs.dropinContent == "" {
		t.Error("no cut happened (no drop-in)")
	}
}

func TestRolling_AbortsIfPeerDead(t *testing.T) {
	fs := newFakeSystem(t, "2.0.0")
	r, _ := testEnv(t, fs)
	cl := &fakeCluster{peerAlive: false, synced: true, compatible: true, peerReady: true, drainAfter: 1}

	err := runRollingWith(r, cl, fastRC())
	if err == nil || !strings.Contains(err.Error(), "peer is not alive") {
		t.Fatalf("expected peer-dead abort, got %v", err)
	}
	if cl.forced {
		t.Error("ForceSecondary called despite dead peer — would strand the only forwarding node")
	}
	if fs.dropinContent != "" {
		t.Error("cut happened despite dead peer")
	}
}

func TestRolling_AbortsIfProtocolIncompatible(t *testing.T) {
	fs := newFakeSystem(t, "2.0.0")
	r, _ := testEnv(t, fs)
	cl := &fakeCluster{peerAlive: true, synced: true, compatible: false, peerReady: true, drainAfter: 1}

	err := runRollingWith(r, cl, fastRC())
	if err == nil || !strings.Contains(err.Error(), "not rolling-upgradable") {
		t.Fatalf("expected protocol-incompatible abort, got %v", err)
	}
	if cl.forced {
		t.Error("ForceSecondary called despite incompatible protocol")
	}
}

func TestRolling_RefusesDemoteIfPeerNotReady(t *testing.T) {
	fs := newFakeSystem(t, "2.0.0")
	r, _ := testEnv(t, fs)
	cl := &fakeCluster{peerAlive: true, synced: true, compatible: true, peerReady: false, drainAfter: 1}

	err := runRollingWith(r, cl, fastRC())
	if err == nil || !strings.Contains(err.Error(), "takeover-ready") {
		t.Fatalf("expected peer-not-ready abort, got %v", err)
	}
	if cl.forced {
		t.Error("ForceSecondary called despite peer not takeover-ready — VIP stranding risk")
	}
	if fs.dropinContent != "" {
		t.Error("cut happened despite peer not ready")
	}
}

func TestRolling_AbortsAndFailsBackIfDrainTimesOut(t *testing.T) {
	fs := newFakeSystem(t, "2.0.0")
	r, _ := testEnv(t, fs)
	// drainAfter huge so the predicate never holds within the deadline.
	cl := &fakeCluster{peerAlive: true, synced: true, compatible: true, peerReady: true, drainAfter: 1 << 30}

	err := runRollingWith(r, cl, RollingConfig{DrainDeadline: 20 * time.Millisecond, PollInterval: time.Millisecond})
	if err == nil || !strings.Contains(err.Error(), "drain predicate not satisfied") {
		t.Fatalf("expected drain-timeout abort, got %v", err)
	}
	if !cl.forced {
		t.Error("ForceSecondary should have been called before the drain wait")
	}
	if !cl.resetCalled {
		t.Error("ResetFailover (failback) not called after drain timeout — node left half-drained")
	}
	if fs.dropinContent != "" {
		t.Error("cut happened despite drain timeout (node was still forwarding)")
	}
}

// TestRolling_RejoinToleratesTransientSyncErr proves the post-cut rejoin
// wait survives the gRPC-startup gap. The cut restarts xpfd, so the local
// gRPC socket refuses connections for the first several polls; the wait
// must treat that as "not ready yet" and keep polling until the daemon is
// up — NOT abort on the first dial error. Regression for the live #1933
// rolling-upgrade false-negative abort ("connection refused on
// 127.0.0.1:50051" surfaced ~immediately, never using RejoinDeadline).
func TestRolling_RejoinToleratesTransientSyncErr(t *testing.T) {
	fs := newFakeSystem(t, "2.0.0")
	r, _ := testEnv(t, fs)
	// SyncEstablished errors (connection refused) for the first 5 polls,
	// then succeeds — mimicking the daemon coming up ~6 polls after the cut.
	cl := &fakeCluster{peerAlive: true, synced: true, compatible: true, peerReady: true, drainAfter: 2, syncErrPolls: 5}

	if err := runRollingWith(r, cl, fastRC()); err != nil {
		t.Fatalf("rolling aborted on a transient post-cut sync error (should tolerate until RejoinDeadline): %v", err)
	}
	if cl.syncPolls <= cl.syncErrPolls {
		t.Errorf("rejoin wait did not keep polling past the transient errors: syncPolls=%d, syncErrPolls=%d", cl.syncPolls, cl.syncErrPolls)
	}
	if !cl.resetCalled {
		t.Error("ResetFailover (failback) not called — rejoin must complete after sync re-establishes")
	}
	if fs.dropinContent == "" {
		t.Error("cut did not happen")
	}
}

// TestRolling_RejoinTimesOutSurfacesLastErr proves a PERSISTENT rejoin
// error still aborts at RejoinDeadline (tolerance is bounded) and surfaces
// the last observed error for operator diagnosis.
func TestRolling_RejoinTimesOutSurfacesLastErr(t *testing.T) {
	fs := newFakeSystem(t, "2.0.0")
	r, _ := testEnv(t, fs)
	// Never re-establishes sync (huge syncErrPolls), short RejoinDeadline.
	cl := &fakeCluster{peerAlive: true, synced: true, compatible: true, peerReady: true, drainAfter: 2, syncErrPolls: 1 << 30}

	err := runRollingWith(r, cl, RollingConfig{DrainDeadline: 2 * time.Second, RejoinDeadline: 20 * time.Millisecond, PollInterval: time.Millisecond})
	if err == nil {
		t.Fatal("expected rejoin timeout, got nil")
	}
	if !strings.Contains(err.Error(), "re-establish session sync") {
		t.Errorf("expected rejoin-timeout wrapper, got %v", err)
	}
	if !strings.Contains(err.Error(), "connection refused") {
		t.Errorf("expected the last observed error surfaced, got %v", err)
	}
	// The cut DID happen (we are past it); the node is left secondary, not
	// failed back — ResetFailover (rejoin election) must NOT have run.
	if cl.resetCalled {
		t.Error("ResetFailover (failback) ran despite the rejoin never completing — node should be left secondary")
	}
}
