package upgrade

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type fakeSRCluster struct {
	drained    bool
	drainedErr error
	peerOK     bool
	peerErr    error
	resets     int
	resetErr   error
}

func (f *fakeSRCluster) LocalDrained() (bool, error)       { return f.drained, f.drainedErr }
func (f *fakeSRCluster) PeerHealthyPrimary() (bool, error) { return f.peerOK, f.peerErr }
func (f *fakeSRCluster) ResetFailover() error              { f.resets++; return f.resetErr }

func newSR(t *testing.T, cl *fakeSRCluster, now *time.Time, grace time.Duration) *KernelSelfRecovery {
	t.Helper()
	return NewKernelSelfRecovery(SelfRecoveryConfig{
		NodeID:    0,
		LeasePath: filepath.Join(t.TempDir(), "kernel-roll.lease"),
		Grace:     grace,
		Now:       func() time.Time { return *now },
	}, cl)
}

func writeLease(t *testing.T, path string, l KernelRollLease) {
	t.Helper()
	b, _ := json.Marshal(l)
	if err := os.WriteFile(path, b, 0644); err != nil {
		t.Fatalf("write lease: %v", err)
	}
}

// Drained + no lease + healthy peer, held for Grace -> auto-ResetFailover.
func TestSelfRecoveryRecoversAfterGrace(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	cl := &fakeSRCluster{drained: true, peerOK: true}
	sr := newSR(t, cl, &now, 90*time.Second)

	if did, err := sr.Tick(); err != nil || did {
		t.Fatalf("first tick should only START the timer (did=%v err=%v)", did, err)
	}
	if cl.resets != 0 {
		t.Fatal("must not reset within grace")
	}
	// advance past grace
	now = now.Add(91 * time.Second)
	did, err := sr.Tick()
	if err != nil {
		t.Fatalf("tick: %v", err)
	}
	if !did || cl.resets != 1 {
		t.Fatalf("expected auto-ResetFailover after grace (did=%v resets=%d)", did, cl.resets)
	}
}

// An UNEXPIRED lease for THIS node suppresses self-recovery (real roll ongoing).
func TestSelfRecoverySuppressedByActiveLease(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	cl := &fakeSRCluster{drained: true, peerOK: true}
	sr := newSR(t, cl, &now, 1*time.Second)
	writeLease(t, sr.cfg.LeasePath, KernelRollLease{NodeID: 0, ExpiresAt: now.Add(10 * time.Minute)})

	now = now.Add(5 * time.Minute) // well past grace, but lease still valid
	if did, err := sr.Tick(); err != nil || did {
		t.Fatalf("active lease must suppress recovery (did=%v err=%v)", did, err)
	}
	if cl.resets != 0 {
		t.Fatal("must not reset while a valid lease names this node")
	}
}

// An EXPIRED lease does NOT suppress (orchestrator crashed) -> recovers.
func TestSelfRecoveryExpiredLeaseDoesNotSuppress(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	cl := &fakeSRCluster{drained: true, peerOK: true}
	sr := newSR(t, cl, &now, 10*time.Second)
	writeLease(t, sr.cfg.LeasePath, KernelRollLease{NodeID: 0, ExpiresAt: now.Add(-1 * time.Minute)}) // expired

	_, _ = sr.Tick() // starts timer
	now = now.Add(11 * time.Second)
	did, _ := sr.Tick()
	if !did || cl.resets != 1 {
		t.Fatalf("expired lease should not suppress recovery (did=%v resets=%d)", did, cl.resets)
	}
}

// A lease for the OTHER node does not suppress THIS node.
func TestSelfRecoveryOtherNodeLeaseDoesNotSuppress(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	cl := &fakeSRCluster{drained: true, peerOK: true}
	sr := newSR(t, cl, &now, 10*time.Second)
	writeLease(t, sr.cfg.LeasePath, KernelRollLease{NodeID: 1, ExpiresAt: now.Add(10 * time.Minute)})

	_, _ = sr.Tick()
	now = now.Add(11 * time.Second)
	did, _ := sr.Tick()
	if !did || cl.resets != 1 {
		t.Fatalf("a lease for node 1 must not suppress node 0 recovery (did=%v resets=%d)", did, cl.resets)
	}
}

// Not drained -> never recovers (the normal case).
func TestSelfRecoveryNoOpWhenNotDrained(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	cl := &fakeSRCluster{drained: false, peerOK: true}
	sr := newSR(t, cl, &now, 1*time.Second)
	now = now.Add(10 * time.Second)
	if did, _ := sr.Tick(); did || cl.resets != 0 {
		t.Fatal("must not recover when not drained")
	}
}

// Drained but peer NOT a healthy primary -> do NOT auto-recover (dual-down).
func TestSelfRecoveryNoOpWhenPeerUnhealthy(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	cl := &fakeSRCluster{drained: true, peerOK: false}
	sr := newSR(t, cl, &now, 1*time.Second)
	now = now.Add(10 * time.Second)
	if did, _ := sr.Tick(); did || cl.resets != 0 {
		t.Fatal("must not auto-recover when the peer is not a healthy primary")
	}
}

// The timer RESETS if the condition lapses (e.g. peer flaps), so a transient
// blip doesn't accumulate toward the grace deadline.
func TestSelfRecoveryTimerResetsOnConditionLapse(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	cl := &fakeSRCluster{drained: true, peerOK: true}
	sr := newSR(t, cl, &now, 60*time.Second)
	_, _ = sr.Tick() // start timer
	now = now.Add(40 * time.Second)
	cl.drained = false // condition lapses
	_, _ = sr.Tick()   // resets timer
	cl.drained = true
	now = now.Add(40 * time.Second) // 80s total but only 40s since re-observe
	if did, _ := sr.Tick(); did {
		t.Fatal("timer should have reset on the lapse; not yet past grace")
	}
}
