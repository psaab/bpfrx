package userspace

import (
	"errors"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// #6165 (follow-up to #6163/#5648): the ~1s desired-state forwarding reconcile
// (syncDesiredForwardingStateLocked / desiredForwardingArmedLocked) must honor
// the SAME required-generation protocol gate that #6163 added to
// SetForwardingArmed. desiredForwardingArmedLocked() returns true whenever
// ForwardingSupported — it never consults the accepted-snapshot protocol
// version — so after a compile/scheduler-path protocol disarm the reconcile
// would otherwise re-arm the stale accepted image on the next tick (fail-OPEN).
//
// The reachable trace: a config with a scheduler-driven policy (or persistent
// source NAT) is committed while the helper protocol is current, so
// m.lastSnapshot.Config REQUIRES ProtocolVersion. The helper is then behind
// (mixed-base HA deploy / in-place upgrade / older restarted binary). A
// scheduler tick (UpdatePolicyScheduleState) disarms the helper (fail-closed)
// and — unlike an operator commit — does NOT revert the active config, so
// m.lastSnapshot keeps requiring the protocol while the helper is disarmed +
// protocol-stale. The next reconcile tick must refuse to re-arm.

// TestSyncDesiredForwardingRefusesStaleProtocolMismatch is the #6165
// fail-on-revert gate: the reconcile must REFUSE to re-arm a helper whose
// accepted image is behind the required snapshot protocol (returning the
// required-protocol sentinel) and must NOT send set_forwarding_state{Armed:true}.
//
// RED-on-revert: neutralize the guard in syncDesiredForwardingStateLocked
// (`if desired && m.lastSnapshot != nil && m.lastSnapshot.Config != nil {` →
// `if false && ...`). The gate is skipped, the reconcile arms the stale image,
// and the returned error is nil / a control-plane bookkeeping error rather than
// ErrPolicySchedulerProtocolIncompatible — both assertions below flip RED.
func TestSyncDesiredForwardingRefusesStaleProtocolMismatch(t *testing.T) {
	sock, reqCh := recordingControlServer(t)
	m := New()
	m.proc = &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}
	m.cfg.ControlSocket = sock
	// Standalone: desiredForwardingArmedLocked() == true whenever forwarding is
	// supported. The helper is currently DISARMED (a compile/scheduler-path
	// disarmSnapshotProtocolFailureLocked just fired) and its accepted image is
	// STALE — below the required snapshot protocol version.
	m.lastStatus.Capabilities.ForwardingSupported = true
	m.lastStatus.ForwardingArmed = false
	// #6648: BELOW THE FEATURE'S FLOOR. This used to say `ProtocolVersion - 1`,
	// which only produced ErrPolicySchedulerProtocolIncompatible because every
	// gate compared against the shared constant. Policy-scheduler state has
	// been representable since v2 (MinProtocolPolicyScheduler), so a helper one
	// version behind the constant CAN carry this snapshot's scheduler content
	// and the scheduler gate is the wrong thing to name for it. Retargeted, not
	// relaxed: the assertion below is unchanged and now runs against a helper
	// that genuinely cannot represent the feature it names.
	m.lastStatus.ConfigSnapshotProtocolVersion = MinProtocolPolicyScheduler - 1
	// Last-applied config carries scheduler-driven policy, so it REQUIRES at
	// least MinProtocolPolicyScheduler.
	m.lastSnapshot, _ = buildSnapshot(scheduledPolicyCfg(), config.UserspaceConfig{ControlSocket: sock}, 5, 0)

	// Guard the premise: absent the gate the reconcile WOULD arm — it only
	// sends when desired != current and desired is true.
	if !m.desiredForwardingArmedLocked() {
		t.Fatal("test setup: desiredForwardingArmedLocked() must be true so an ungated reconcile would arm")
	}
	if m.lastStatus.ForwardingArmed {
		t.Fatal("test setup: helper must be disarmed so the reconcile detects an arm delta")
	}

	err := m.syncDesiredForwardingStateLocked()
	if !errors.Is(err, ErrPolicySchedulerProtocolIncompatible) {
		t.Fatalf("syncDesiredForwardingStateLocked() err = %v, want %v (reconcile must refuse a stale accepted image)",
			err, ErrPolicySchedulerProtocolIncompatible)
	}

	// The security-critical behavior: NO set_forwarding_state{Armed:true} was
	// sent by the reconcile. The gate's protocol re-poll issues a benign
	// "status" request; the arm request must never appear.
	deadline := time.After(300 * time.Millisecond)
	for {
		select {
		case req := <-reqCh:
			if req.Type == "set_forwarding_state" {
				t.Fatalf("reconcile must NOT arm on a protocol mismatch; got request %+v", req)
			}
		case <-deadline:
			return
		}
	}
}

// TestSyncDesiredForwardingArmsWhenProtocolMatches is the scoped-not-blanket
// control: the gate must NOT block a legitimate reconcile arm when the helper's
// accepted image satisfies the required protocol. Proves the fix refuses ONLY
// the stale case, so it is not a regression that refuses all reconcile arming.
func TestSyncDesiredForwardingArmsWhenProtocolMatches(t *testing.T) {
	sock, reqCh := recordingControlServer(t)
	m := New()
	m.proc = &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}
	m.cfg.ControlSocket = sock
	m.lastStatus.Capabilities.ForwardingSupported = true
	m.lastStatus.ForwardingArmed = false
	// Helper's accepted image is CURRENT — satisfies the required protocol.
	m.lastStatus.ConfigSnapshotProtocolVersion = ProtocolVersion
	// Same protocol-requiring config as the mismatch test.
	m.lastSnapshot, _ = buildSnapshot(scheduledPolicyCfg(), config.UserspaceConfig{ControlSocket: sock}, 5, 0)

	// applyHelperStatusLocked touches a BPF map absent in a unit test, so the
	// call may return that local-bookkeeping error AFTER the wire arm request
	// is issued; that env artifact must not mask the assertion that the arm was
	// actually sent (mirrors the #5648 SetForwardingArmed control).
	_ = m.syncDesiredForwardingStateLocked()

	select {
	case req := <-reqCh:
		if req.Type != "set_forwarding_state" || req.Forwarding == nil || !req.Forwarding.Armed {
			t.Fatalf("got request %+v, want set_forwarding_state{Armed:true}", req)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no arm request sent when helper protocol satisfies the requirement")
	}
}

// TestSyncDesiredForwardingDisarmNotBlockedByGate proves the gate is scoped to
// the ARM direction only: a disarm (desired==false) must proceed even when the
// last-applied config requires a protocol the stale helper cannot honor.
// Blocking a disarm here would strand a helper ARMED on a config it cannot
// represent — the opposite fail-open. The scenario: forwarding is no longer
// desired (e.g. an HA node with no active data RG) while the helper is
// currently armed and protocol-stale; the reconcile must still send
// set_forwarding_state{Armed:false}.
//
// RED-on-revert: dropping the `desired &&` scope from the guard
// (`if m.lastSnapshot != nil && m.lastSnapshot.Config != nil {`) makes the gate
// return the protocol sentinel on the disarm path too, so no disarm request is
// sent and this test's arm-delta assertion flips RED.
func TestSyncDesiredForwardingDisarmNotBlockedByGate(t *testing.T) {
	sock, reqCh := recordingControlServer(t)
	m := New()
	m.proc = &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}
	m.cfg.ControlSocket = sock
	// clusterHA node with no data RG and no active local-only RG:
	// desiredForwardingArmedLocked() == false, so desired disarm.
	m.clusterHA = true
	m.lastStatus.Capabilities.ForwardingSupported = true
	m.lastStatus.ForwardingArmed = true
	m.lastStatus.ConfigSnapshotProtocolVersion = ProtocolVersion - 1
	m.lastSnapshot, _ = buildSnapshot(scheduledPolicyCfg(), config.UserspaceConfig{ControlSocket: sock}, 5, 0)

	if m.desiredForwardingArmedLocked() {
		t.Fatal("test setup: desiredForwardingArmedLocked() must be false so the reconcile disarms")
	}

	_ = m.syncDesiredForwardingStateLocked()

	select {
	case req := <-reqCh:
		if req.Type != "set_forwarding_state" || req.Forwarding == nil || req.Forwarding.Armed {
			t.Fatalf("got request %+v, want set_forwarding_state{Armed:false} (disarm must never be gated)", req)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no disarm request sent — the protocol gate must not block the disarm direction")
	}
}
