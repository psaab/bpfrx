package userspace

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"

	"github.com/psaab/xpf/pkg/config"
	"testing"
)

// #6722 round 10: what a v5 control plane ACTUALLY does when it finds a v4
// helper — measured on the wire, not read off the call graph.
//
// The bump's whole value claim is that a mixed window becomes a LOUD abort
// instead of a silent mis-forward. An earlier revision of this work stated the
// consequence as "the running helper keeps forwarding its previous-good image".
// THAT IS WRONG for the gated path and the correction matters, because the two
// outcomes have opposite availability profiles:
//
//   - Bump with NO gate: the helper refuses the snapshot at its own
//     exact-equality version check and keeps forwarding its previous-good
//     image. Availability preserved, failure legible only as a generic apply
//     error.
//   - Bump WITH the gate (what this PR does): the control plane refuses first,
//     DISARMS the helper, and aborts the commit with a named sentinel. Transit
//     drops to the kernel path — fail-CLOSED, per the #2138 required-protocol
//     contract that ErrEgressZoneProtocolIncompatible joins.
//
// This test pins the second, which is what the code does. What it measures:
//
//  1. the returned error carries the sentinel, so ApplyConfig treats it as a
//     required-protocol failure and the commit ABORTS (#2138);
//  2. a `set_forwarding_state` with Armed=false REACHED the helper — the
//     fail-closed disarm actually happened rather than being merely intended;
//  3. NO `apply_snapshot` reached the helper. This is the "nothing half-applied"
//     property; before this cell it was an argument from reading five call
//     sites, which is not evidence.

type recordedRequest6722 struct {
	kind  string
	armed bool
	// hasForwarding distinguishes "set_forwarding_state{Armed:false}" from a
	// request that simply carries no Forwarding block. Recording the two in
	// PARALLEL SLICES was the first shape of this and it was wrong: `armed` was
	// appended only for requests that carry the block, so index i in one slice
	// did not describe entry i in the other and the disarm assertion read a
	// different request than the one it named.
	hasForwarding bool
}

type recordedHelper6722 struct {
	mu   sync.Mutex
	reqs []recordedRequest6722
}

// startRecordingHelper6722 answers every control request OK and records what it
// was asked to do. The client blocks on the response, so by the time the call
// under test returns, everything it sent is already recorded.
func startRecordingHelper6722(t *testing.T, sockPath string, version int) *recordedHelper6722 {
	t.Helper()
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen control socket: %v", err)
	}
	r := &recordedHelper6722{}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				var req ControlRequest
				if err := json.NewDecoder(conn).Decode(&req); err != nil {
					return
				}
				rec := recordedRequest6722{kind: req.Type}
				if req.Forwarding != nil {
					rec.hasForwarding = true
					rec.armed = req.Forwarding.Armed
				}
				r.mu.Lock()
				r.reqs = append(r.reqs, rec)
				r.mu.Unlock()
				_ = json.NewEncoder(conn).Encode(ControlResponse{
					OK: true,
					Status: &ProcessStatus{
						ConfigSnapshotProtocolVersion: version,
					},
				})
			}()
		}
	}()
	return r
}

func (r *recordedHelper6722) sawType(want string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, got := range r.reqs {
		if got.kind == want {
			return true
		}
	}
	return false
}

func (r *recordedHelper6722) sawDisarm() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, got := range r.reqs {
		if got.kind == "set_forwarding_state" && got.hasForwarding && !got.armed {
			return true
		}
	}
	return false
}

func (r *recordedHelper6722) seen() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, 0, len(r.reqs))
	for _, got := range r.reqs {
		if got.hasForwarding {
			out = append(out, fmt.Sprintf("%s{armed:%v}", got.kind, got.armed))
			continue
		}
		out = append(out, got.kind)
	}
	return out
}

func TestEgressZoneProtocolAbortDisarmsAndPublishesNothing_6722(t *testing.T) {
	// A SHORT temp-dir prefix: t.TempDir()'s long sub-test name pushes the
	// AF_UNIX path past the 108-byte sun_path limit.
	dir, err := os.MkdirTemp("", "x6722")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "c.sock")

	// A helper that answers every request but advertises the PRE-v5 contract.
	helper := startRecordingHelper6722(t, sock, preV5SnapshotProtocolVersion)

	m := New()
	m.cfg.ControlSocket = sock
	// A live process, so the disarm path is not short-circuited by the
	// `m.proc == nil` guard in disarmSnapshotProtocolFailureLocked.
	m.proc = &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}
	m.lastStatus.ConfigSnapshotProtocolVersion = preV5SnapshotProtocolVersion
	m.pendingWorkerArm = true
	m.lastSnapshot = &ConfigSnapshot{
		Version:      ProtocolVersion,
		Generation:   7,
		DeferWorkers: true,
		Config:       &config.Config{},
	}

	err = m.retryDeferredWorkerArmLocked()

	if err == nil {
		t.Fatalf("the publish path ACCEPTED a v%d helper; a v5 control plane must "+
			"not report a successful commit against a helper that will refuse the "+
			"snapshot", preV5SnapshotProtocolVersion)
	}
	if !errors.Is(err, ErrEgressZoneProtocolIncompatible) {
		t.Fatalf("error %v does not wrap ErrEgressZoneProtocolIncompatible; without "+
			"the sentinel ApplyConfig does not classify this as a required-protocol "+
			"failure and the commit is promoted against a dataplane that never got "+
			"the snapshot (#2138)", err)
	}

	// (2) The fail-closed disarm REACHED the helper.
	if !helper.sawDisarm() {
		t.Errorf("no set_forwarding_state{Armed:false} reached the helper; the "+
			"required-protocol contract is to DISARM on the failure edge, so an "+
			"abort without it would leave the helper armed on an image the control "+
			"plane has just declared it cannot honour. Requests seen: %v",
			helper.seen())
	}

	// (3) NOTHING was published. This is the property the bump's value claim
	// rests on, and the reason this cell exists rather than a call-graph
	// argument: if apply_snapshot were sent first and refused, the abort would
	// be a second-order effect of the helper's own gate rather than a decision
	// the control plane made before touching it.
	if helper.sawType("apply_snapshot") {
		t.Errorf("apply_snapshot was sent to a v%d helper before the gate aborted; "+
			"the gate must run BEFORE the publish so nothing is half-applied. "+
			"Requests seen: %v", preV5SnapshotProtocolVersion, helper.seen())
	}

	// The debt must survive so a later tick re-tries against an upgraded helper
	// rather than silently dropping the deferred arm.
	if !m.pendingWorkerArm {
		t.Errorf("the deferred-worker-arm debt was cleared by a FAILED publish; " +
			"the next tick would then never retry, leaving workers unarmed after " +
			"the helper is upgraded")
	}
}

// The positive control. Without it the cell above passes for a helper that
// refuses everything, and "no apply_snapshot was sent" would be evidence of
// nothing.
func TestEgressZoneProtocolMatchedHelperPublishes_6722(t *testing.T) {
	dir, err := os.MkdirTemp("", "x6722ok")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "c.sock")

	helper := startRecordingHelper6722(t, sock, ProtocolVersion)

	m := New()
	m.cfg.ControlSocket = sock
	m.proc = &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}
	m.lastStatus.ConfigSnapshotProtocolVersion = ProtocolVersion
	m.pendingWorkerArm = true
	m.lastSnapshot = &ConfigSnapshot{
		Version:      ProtocolVersion,
		Generation:   7,
		DeferWorkers: true,
		Config:       &config.Config{},
	}

	// The matched path runs PAST the gate and publishes, then fails later on the
	// BPF classifier maps this unit context does not load. That later failure is
	// expected and is not what the control is about: what it shows is that the
	// gate did not fence the ordinary case, and that apply_snapshot really is
	// reachable on this path — which is what makes "no apply_snapshot" in the
	// sibling cell evidence rather than an artefact of the harness.
	err = m.retryDeferredWorkerArmLocked()
	if errors.Is(err, ErrEgressZoneProtocolIncompatible) {
		t.Fatalf("a MATCHED helper was fenced by the egress-zone gate (%v); the "+
			"gate must not fire on the ordinary case", err)
	}
	if !helper.sawType("apply_snapshot") {
		t.Fatalf("no apply_snapshot reached a matched helper — this control is what "+
			"makes the \"nothing was published\" assertion in the sibling cell "+
			"meaningful rather than vacuous. Requests seen: %v", helper.seen())
	}
	if helper.sawDisarm() {
		t.Errorf("a matched helper was DISARMED; the fail-closed edge must not fire "+
			"on the ordinary path. Requests seen: %v", helper.seen())
	}
}

// The gate is UNCONDITIONAL IN THE CONFIG DIMENSION, and both arm-side callers
// route through it (#6722).
//
// `ensureRequiredSnapshotProtocolLocked` is a chain of four gates. Its first
// three fire only for a config that USES the feature they name — policy
// schedulers, persistent source NAT, scoped global zone sets — and the comments
// at both call sites below were written for that family: they say the gate "is a
// no-op unless the last-applied config requires the protocol". Since #6722 that
// is no longer true of the chain as a whole. Every snapshot carries
// `EgressZone`, so `ensureEgressZoneProtocolLocked` takes no config at all and
// fires for ANY last-applied config, including an empty one.
//
// The direction is fail-closed and intended — a version-mismatched helper
// cannot honour a v5 snapshot at all, so arming it forwards on whatever stale
// image it holds — but it is a widening of what these two call sites refuse, so
// it is pinned here rather than left to the comments. Both cells drive an EMPTY
// `config.Config{}`: nothing in it requires any of the three feature gates, so
// the only thing that can produce the sentinel is the unconditional one.
//
// The two controls are what keep this from being a test that a Manager refuses
// everything: a DISARM must still reach a mismatched helper (the fail-closed
// edge itself needs it), and a MATCHED helper must arm.
//
// FAIL-ON-REVERT, measured per hunk:
//
//	drop the ensureRequiredSnapshotProtocolLocked call in SetForwardingArmed
//	  (manager_status.go)                   -> the explicit-arm sub-test only
//	drop it in syncDesiredForwardingStateLocked
//	  (manager_ha.go)                       -> the reconcile sub-test only
func TestEgressZoneProtocolGatesBothArmPaths_6722(t *testing.T) {
	// newManager6722 wires a Manager to a recording helper advertising `version`
	// and gives it an EMPTY last-applied config — the point of the cell.
	newManager6722 := func(t *testing.T, prefix string, version int) (*Manager, *recordedHelper6722) {
		t.Helper()
		dir, err := os.MkdirTemp("", prefix)
		if err != nil {
			t.Fatalf("mkdtemp: %v", err)
		}
		t.Cleanup(func() { os.RemoveAll(dir) })
		sock := filepath.Join(dir, "c.sock")
		helper := startRecordingHelper6722(t, sock, version)

		m := New()
		m.cfg.ControlSocket = sock
		m.proc = &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}
		m.lastStatus.ConfigSnapshotProtocolVersion = version
		// Both gates sit BEHIND a ForwardingSupported check, so without this the
		// call returns early and the cell would pass without reaching the gate.
		m.lastStatus.Capabilities.ForwardingSupported = true
		m.lastSnapshot = &ConfigSnapshot{
			Version: ProtocolVersion,
			// EMPTY. Not a config that requires schedulers, persistent source
			// NAT or a scoped global zone set — if any of those were populated,
			// a sibling gate could produce an error and this cell would not be
			// measuring the egress-zone one.
			Config: &config.Config{},
		}
		return m, helper
	}
	sawArm := func(helper *recordedHelper6722) bool {
		for _, got := range helper.seen() {
			if got == "set_forwarding_state{armed:true}" {
				return true
			}
		}
		return false
	}

	t.Run("explicit-operator-arm", func(t *testing.T) {
		m, helper := newManager6722(t, "x6722arm", preV5SnapshotProtocolVersion)
		_, err := m.SetForwardingArmed(true)
		if !errors.Is(err, ErrEgressZoneProtocolIncompatible) {
			t.Fatalf("SetForwardingArmed(true) against a v%d helper returned %v; "+
				"want ErrEgressZoneProtocolIncompatible. This is the `request "+
				"chassis` / gRPC arm path (cli_request_chassis.go, "+
				"server_diag_system_action.go): arming a helper that cannot decode "+
				"a v5 snapshot forwards on whatever image it already holds",
				preV5SnapshotProtocolVersion, err)
		}
		if sawArm(helper) {
			t.Errorf("a set_forwarding_state{armed:true} reached the v%d helper "+
				"anyway; the gate must refuse BEFORE the request, or the refusal is "+
				"only a return value. Requests seen: %v",
				preV5SnapshotProtocolVersion, helper.seen())
		}
	})

	t.Run("ha-reconcile-tick", func(t *testing.T) {
		m, helper := newManager6722(t, "x6722ha", preV5SnapshotProtocolVersion)
		// The ~1s reconcile only acts when desired != current, so the helper must
		// start DISARMED for the arm direction to be the one under test.
		m.lastStatus.ForwardingArmed = false
		err := m.syncDesiredForwardingStateLocked()
		if !errors.Is(err, ErrEgressZoneProtocolIncompatible) {
			t.Fatalf("syncDesiredForwardingStateLocked() against a v%d helper "+
				"returned %v; want ErrEgressZoneProtocolIncompatible. This tick runs "+
				"unattended roughly once a second, so an ungated one re-arms a "+
				"version-stale helper without an operator ever asking",
				preV5SnapshotProtocolVersion, err)
		}
		if sawArm(helper) {
			t.Errorf("the reconcile armed the v%d helper anyway. Requests seen: %v",
				preV5SnapshotProtocolVersion, helper.seen())
		}
	})

	// Control 1. The fail-closed contract DISARMS on the failure edge, so a
	// blanket refusal would defeat the very thing the gate exists to do.
	t.Run("control-disarm-is-never-fenced", func(t *testing.T) {
		m, helper := newManager6722(t, "x6722dis", preV5SnapshotProtocolVersion)
		m.lastStatus.ForwardingArmed = true
		// The later error here is the classifier-map load this unit context
		// cannot do; what matters is that the request REACHED the helper.
		_, _ = m.SetForwardingArmed(false)
		if !helper.sawDisarm() {
			t.Errorf("no set_forwarding_state{armed:false} reached a v%d helper; a "+
				"gate that also blocked disarms would strand an armed helper on an "+
				"image the control plane has declared it cannot honour. Requests "+
				"seen: %v", preV5SnapshotProtocolVersion, helper.seen())
		}
	})

	// Control 2. Without it, both assertions above are satisfied by a Manager
	// that refuses every arm for any reason.
	t.Run("control-matched-helper-arms", func(t *testing.T) {
		m, helper := newManager6722(t, "x6722ok", ProtocolVersion)
		m.lastStatus.ForwardingArmed = false
		_, err := m.SetForwardingArmed(true)
		if errors.Is(err, ErrEgressZoneProtocolIncompatible) {
			t.Fatalf("a MATCHED v%d helper was fenced by the egress-zone gate (%v)",
				ProtocolVersion, err)
		}
		if !sawArm(helper) {
			t.Fatalf("no set_forwarding_state{armed:true} reached a MATCHED v%d "+
				"helper, so the two refusals above are not evidence of a gate. "+
				"Requests seen: %v", ProtocolVersion, helper.seen())
		}
	})

	// Control 3 — the SECOND LOOK. `ensureEgressZoneProtocolLocked` re-polls the
	// helper before failing, because `lastStatus` may predate a helper restart
	// onto a matching build. Without that block the gate would refuse every
	// commit and every arm made between "the helper restarted" and "the ~1s poll
	// noticed", which for an operator looks like an upgrade that took effect and
	// then would not arm. Nothing bound it before this sub-test; the cached view
	// and the wire answer agreed in every other cell, which is exactly the
	// condition under which a re-ask is invisible.
	t.Run("stale-lastStatus-re-asks-the-helper", func(t *testing.T) {
		m, helper := newManager6722(t, "x6722reask", ProtocolVersion)
		// The helper on the wire is CURRENT; only the cached view is stale.
		m.lastStatus.ConfigSnapshotProtocolVersion = preV5SnapshotProtocolVersion
		m.lastStatus.ForwardingArmed = false
		_, err := m.SetForwardingArmed(true)
		if errors.Is(err, ErrEgressZoneProtocolIncompatible) {
			t.Fatalf("the gate refused a helper that answers v%d on the wire "+
				"because the CACHED lastStatus still said v%d (%v). The re-poll in "+
				"ensureEgressZoneProtocolLocked exists so a helper that has since "+
				"upgraded arms without waiting for the next status tick",
				ProtocolVersion, preV5SnapshotProtocolVersion, err)
		}
		if !sawArm(helper) {
			t.Fatalf("no arm reached the helper after the re-ask should have "+
				"cleared the gate. Requests seen: %v", helper.seen())
		}
	})
}
