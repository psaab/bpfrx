package upgrade

import (
	"strings"
	"testing"
	"time"
)

// fakeCluster is an in-memory RollingCluster for orchestration tests.
type fakeCluster struct {
	peerAlive   bool
	synced      bool
	compatible  bool
	peerReady   bool
	localPri    bool
	drainAfter  int // become drained after this many DrainComplete polls
	drainPolls  int
	forced      bool
	resetCalled bool
}

func (f *fakeCluster) PeerAlive() (bool, error)            { return f.peerAlive, nil }
func (f *fakeCluster) SyncEstablished() (bool, error)      { return f.synced, nil }
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
