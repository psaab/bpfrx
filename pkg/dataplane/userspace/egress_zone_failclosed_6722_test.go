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
