package userspace

import (
	"errors"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// #5648 (M43b): SetForwardingArmed must fail closed on a required-generation
// protocol mismatch. When the last-applied config REQUIRES a newer config
// snapshot protocol (policy schedulers, persistent source NAT) than the
// helper's accepted image reports, the compile/publish paths disarm the
// helper. An explicit arm request (operator `request`/gRPC) must honor the
// SAME gate — otherwise it re-arms the stale accepted image and forwards on a
// config the helper cannot represent (fail-OPEN).

// scheduledPolicyCfg returns a config that REQUIRES ProtocolVersion because it
// carries a scheduler-driven policy (configHasScheduledPolicy → true).
func scheduledPolicyCfg() *config.Config {
	cfg := &config.Config{}
	cfg.Security.Policies = []*config.ZonePairPolicies{{
		FromZone: "trust",
		ToZone:   "untrust",
		Policies: []*config.Policy{{
			Name:          "scheduled-allow",
			SchedulerName: "workhours",
			Match: config.PolicyMatch{
				SourceAddresses:      []string{"any"},
				DestinationAddresses: []string{"any"},
				Applications:         []string{"any"},
			},
			Action: config.PolicyPermit,
		}},
	}}
	cfg.Schedulers = map[string]*config.SchedulerConfig{
		"workhours": {Name: "workhours"},
	}
	return cfg
}

// TestSetForwardingArmedRefusesStaleProtocolMismatch is the #5648 fail-on-revert
// gate: arming a helper whose accepted image is behind the required snapshot
// protocol must be REFUSED with the required-protocol sentinel, and must NOT
// send set_forwarding_state{Armed:true}.
//
// RED-on-revert: neutralize the guard in SetForwardingArmed
// (`if armed && m.lastSnapshot != nil && m.lastSnapshot.Config != nil {` →
// `if false && ...`). The guard is skipped, the arm request is sent, and the
// returned error is a control-plane error rather than
// ErrPolicySchedulerProtocolIncompatible — both assertions below flip RED.
func TestSetForwardingArmedRefusesStaleProtocolMismatch(t *testing.T) {
	sock, reqCh := recordingControlServer(t)
	m := New()
	m.proc = &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}
	m.cfg.ControlSocket = sock
	// Isolate the NEW guard from the pre-existing ForwardingSupported gate:
	// forwarding IS supported, helper is currently disarmed, but its accepted
	// config snapshot protocol version is STALE (below the required version).
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
	m.lastSnapshot = mustBuildSnapshot(t, scheduledPolicyCfg(), config.UserspaceConfig{ControlSocket: sock}, 5, 0)

	_, err := m.SetForwardingArmed(true)
	if !errors.Is(err, ErrPolicySchedulerProtocolIncompatible) {
		t.Fatalf("SetForwardingArmed(true) err = %v, want %v (must refuse a stale accepted image)",
			err, ErrPolicySchedulerProtocolIncompatible)
	}

	// The security-critical behavior: NO set_forwarding_state{Armed:true} was
	// sent. The gate's protocol re-poll issues a benign "status" request; the
	// arm request must never appear.
	deadline := time.After(300 * time.Millisecond)
	for {
		select {
		case req := <-reqCh:
			if req.Type == "set_forwarding_state" {
				t.Fatalf("guard must NOT arm on a protocol mismatch; got request %+v", req)
			}
		case <-deadline:
			return
		}
	}
}

// TestSetForwardingArmedArmsWhenProtocolMatches is the scoped-not-blanket
// control: the guard must NOT block a legitimate arm when the helper's accepted
// image satisfies the required protocol. Proves the fix refuses ONLY the stale
// case, so it is not a regression that refuses all arming.
func TestSetForwardingArmedArmsWhenProtocolMatches(t *testing.T) {
	sock, reqCh := recordingControlServer(t)
	m := New()
	m.proc = &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}
	m.cfg.ControlSocket = sock
	m.lastStatus.Capabilities.ForwardingSupported = true
	m.lastStatus.ForwardingArmed = false
	// Helper's accepted image is CURRENT — satisfies the required protocol.
	m.lastStatus.ConfigSnapshotProtocolVersion = ProtocolVersion
	// Same protocol-requiring config as the mismatch test.
	m.lastSnapshot = mustBuildSnapshot(t, scheduledPolicyCfg(), config.UserspaceConfig{ControlSocket: sock}, 5, 0)

	// applyHelperStatusLocked touches a BPF map absent in a unit test, so the
	// call may return that local-bookkeeping error AFTER the wire arm request
	// is issued; that env artifact must not mask the assertion that the arm was
	// actually sent (mirrors protocol_failopen_2124_test.go).
	_, _ = m.SetForwardingArmed(true)

	select {
	case req := <-reqCh:
		if req.Type != "set_forwarding_state" || req.Forwarding == nil || !req.Forwarding.Armed {
			t.Fatalf("got request %+v, want set_forwarding_state{Armed:true}", req)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no arm request sent when helper protocol satisfies the requirement")
	}
}
