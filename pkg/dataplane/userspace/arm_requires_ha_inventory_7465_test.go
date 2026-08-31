package userspace

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// arm_requires_ha_inventory_7465_test.go pins the #7465 gate: a chassis-cluster
// helper must not be ARMED before it has been sent an HA inventory.
//
// Why the window exists at all — arming and inventory publication are
// INDEPENDENT. desiredForwardingArmedLocked never reads the helper's HA state;
// on a clustered node it returns true whenever any RG with ID>0 is configured.
// The 1 Hz status poll calls syncDesiredForwardingStateLocked unconditionally
// while the HA publish above it is gated on an active signature, a 2s
// post-activation hold and a 5s throttle. So a helper holding a snapshot but no
// inventory gets armed, and the Rust per-packet gate reads an empty ha_state as
// "not clustered" and delivers LocalDelivery traffic ungated.
//
// It is reachable because an ORDINARY apply failure does not disarm or stop the
// helper (#5679): the daemon records a deferred commit error and continues, and
// compileErrorMustAbortApply is true only for the required-protocol gate.
//
// NOTE TO ANYONE EXTENDING THIS FILE: no cell here creates a real BPF map, and
// that is deliberate. ebpf.NewMap fails on a host without MEMLOCK headroom
// ("operation not permitted"), so a map-backed cell SKIPS and `go test` still
// prints `ok` — a skipped cell is indistinguishable from a passing one in
// aggregate output, so the property would be asserted by a test that never ran.
// Every cell below asserts on manager state and executes unconditionally. If you
// need a map-backed property, put it beside
// TestHAMapsDeclaredAsFullArrays7465 in pkg/dataplane, where the load-bearing
// assertion is on the DECLARATION and the map-backed half is explicitly a bonus.

// newArmGateManager7465 builds the minimum Manager the arm path reads. No helper
// process is contacted: every cell here stops at the gate, which sits before any
// request, and m.proc is present only because the arm path requires a live
// process to consider sending anything.
func newArmGateManager7465(t *testing.T, clustered bool) *Manager {
	t.Helper()
	m := New()
	m.proc = &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}
	// The gate sits behind a ForwardingSupported check; without this the call
	// returns early and a cell would pass without ever reaching the gate.
	m.lastStatus.Capabilities.ForwardingSupported = true
	// Currently disarmed, so `desired != current` and the arm direction is live.
	m.lastStatus.ForwardingArmed = false
	m.clusterHA = clustered
	cfg := &config.Config{}
	if clustered {
		cfg.Chassis.Cluster = &config.ClusterConfig{
			RedundancyGroups: []*config.RedundancyGroup{{ID: 1}},
		}
	}
	// lastSnapshot drives configHasDataRGLocked, which is what makes `desired`
	// true on a clustered node without any group being active.
	m.lastSnapshot = &ConfigSnapshot{Config: cfg}
	return m
}

// FAIL-ON-REVERT: delete the `desired && m.clusterHA && !m.helperHAStatePublished`
// gate in syncDesiredForwardingStateLocked and this cell reds.
func TestArmRefusedBeforeHAInventoryPublished7465(t *testing.T) {
	m := newArmGateManager7465(t, true)

	// Precondition: without the gate this WOULD arm. Asserting it makes the cell
	// fail loudly if a future change makes `desired` false for another reason —
	// which would leave the gate untested while the cell still passed.
	if !m.desiredForwardingArmedLocked() {
		t.Fatal("setup: desired must be true, or this cell never reaches the arm gate")
	}
	if m.helperHAStatePublished {
		t.Fatal("setup: a fresh manager must not claim the helper was told anything")
	}

	err := m.syncDesiredForwardingStateLocked()
	if err == nil {
		t.Fatal("armed a clustered helper with no HA inventory. The helper reads an " +
			"empty ha_state as \"not clustered\" and delivers host-destined traffic " +
			"without gating it on redundancy-group ownership (#7465)")
	}
	if !strings.Contains(err.Error(), "HA inventory") {
		t.Errorf("error %q should name the missing HA inventory, so an operator "+
			"reading a non-forwarding cluster node knows what is missing", err)
	}
}

// CONTROL: once the inventory has been published, the same manager arms.
// Without this the cell above passes against a build that never arms anything.
func TestArmAllowedAfterHAInventoryPublished7465(t *testing.T) {
	m := newArmGateManager7465(t, true)
	m.helperHAStatePublished = true

	// The gate must be the ONLY thing that changed. This still fails later (no
	// real helper to send to), so assert on the gate's own message being absent
	// rather than on success — asserting nil here would test the socket, not the
	// gate.
	err := m.syncDesiredForwardingStateLocked()
	if err != nil && strings.Contains(err.Error(), "HA inventory") {
		t.Errorf("gate still refused after a successful publish: %v", err)
	}
}

// CONTROL: a STANDALONE node must be unaffected. This is the direction that
// carries real risk — clearHelperHAStateLocked drives the helper's map empty on
// purpose for standalone, and a gate that fired there would refuse to arm every
// non-cluster firewall, which is a total forwarding outage (#1928's shape).
func TestArmUnaffectedOnStandalone7465(t *testing.T) {
	m := newArmGateManager7465(t, false)
	if !m.desiredForwardingArmedLocked() {
		t.Fatal("setup: a standalone node with forwarding supported must want to arm")
	}
	if m.helperHAStatePublished {
		t.Fatal("setup: nothing published yet")
	}
	err := m.syncDesiredForwardingStateLocked()
	if err != nil && strings.Contains(err.Error(), "HA inventory") {
		t.Errorf("the #7465 gate fired on a STANDALONE node: %v. Standalone helpers "+
			"are driven to an empty ha_state deliberately, so gating them would "+
			"refuse to arm every non-cluster firewall", err)
	}
}

// The DISARM direction must never be blocked. A gate that also blocked disarms
// would strand an armed helper that must stop forwarding — the fail-OPEN
// direction, and the reason the sibling #6165 gate is arm-only too.
func TestDisarmNeverBlockedByHAInventoryGate7465(t *testing.T) {
	m := newArmGateManager7465(t, true)
	// Currently ARMED, and no longer desired: forwarding unsupported flips
	// desired to false without touching the cluster fields.
	m.lastStatus.ForwardingArmed = true
	m.lastStatus.Capabilities.ForwardingSupported = false
	if m.desiredForwardingArmedLocked() {
		t.Fatal("setup: desired must be false so this is a DISARM")
	}
	err := m.syncDesiredForwardingStateLocked()
	if err != nil && strings.Contains(err.Error(), "HA inventory") {
		t.Errorf("the gate blocked a DISARM: %v. A disarm must never be refused — "+
			"blocking it leaves a helper forwarding when it must not", err)
	}
}

// A restarted helper must not inherit the previous process's publication. The
// new helper starts with an empty inventory, so the flag has to be cleared with
// the rest of the per-process state.
//
// FAIL-ON-REVERT: drop the `m.helperHAStatePublished = false` line in
// resetAfterHelperGoneLocked and this cell reds.
func TestHelperRestartClearsHAInventoryPublished7465(t *testing.T) {
	m := newArmGateManager7465(t, true)
	m.helperHAStatePublished = true

	m.resetAfterHelperGoneLocked()

	if m.helperHAStatePublished {
		t.Error("a restarted helper inherited the previous process's HA-inventory " +
			"publication. The new helper's inventory is EMPTY, so the gate would " +
			"pass on exactly the state it exists to refuse (#7465)")
	}
}

// The flag must be set ONLY by a real publish. syncHAStateLocked returns nil
// EARLY when the manager's inventory is empty — a silent no-publish that reads
// as success — so setting the flag anywhere but after the update_ha_state
// request would mark it on exactly the case the gate exists to catch, and the
// gate would then pass while the helper still knows nothing.
//
// This binds the PLACEMENT decision, which the other cells cannot see: they set
// helperHAStatePublished by hand, so they would all stay green with the
// assignment moved to the early return.
//
// FAIL-ON-REVERT: move `m.helperHAStatePublished = true` above the
// `if len(m.haGroups) == 0 { return nil }` early return and this cell reds.
func TestEmptyInventoryDoesNotCountAsPublished7465(t *testing.T) {
	m := newArmGateManager7465(t, true)
	// No bpfShim: refreshHAWatchdogOnlyFromMapsLocked returns nil when the map
	// is absent, so control reaches the empty-inventory early return rather than
	// erroring out before it — the cell must exercise the RETURN, not a failure
	// on the way to it.
	m.haGroups = map[int]HAGroupStatus{}

	if err := m.syncHAStateLocked(); err != nil {
		t.Fatalf("syncHAStateLocked with an empty inventory should no-op, got: %v", err)
	}

	if m.helperHAStatePublished {
		t.Error("an empty-inventory no-op was recorded as a publish. syncHAStateLocked " +
			"returned without sending update_ha_state, so the helper knows nothing — " +
			"marking it published lets the arm gate pass on precisely the state it " +
			"exists to refuse (#7465)")
	}

	// And the gate must still refuse, which is the consequence that matters.
	if err := m.syncDesiredForwardingStateLocked(); err == nil ||
		!strings.Contains(err.Error(), "HA inventory") {
		t.Errorf("after a no-op publish the arm gate did not refuse: %v", err)
	}
}

// A FAILED publish must not count as a publish.
//
// This is the keying question, and no other cell in this file can see it: they
// all set helperHAStatePublished by hand, and the cluster smoke cannot see it
// either because its publishes succeed. It matters because the poll path
// SWALLOWS publish errors — process_status.go only slog.Warns on
// syncHAWatchdogOnlyLocked (which is syncHAStateLocked) and discards
// refreshHAStateFromMapsLocked's error with `_ =`. So a tick whose publish
// FAILED still falls through to the arm. If the flag were set on "we attempted
// a publish" rather than "the helper acknowledged one", that fall-through would
// re-open the exact window this gate closes, on the error path.
//
// FAIL-ON-REVERT: move `m.helperHAStatePublished = true` above the
// `if err := m.requestLocked(req, &status); err != nil { return err }` in
// syncHAStateLocked and this cell reds while every other cell stays green.
func TestFailedPublishDoesNotCountAsPublished7465(t *testing.T) {
	m := newArmGateManager7465(t, true)
	// Non-empty inventory so syncHAStateLocked gets past the empty early return
	// and actually attempts the update_ha_state request.
	m.haGroups = map[int]HAGroupStatus{1: {RGID: 1}}
	// No control socket is listening, so requestLocked fails: a publish that the
	// helper never acknowledged.
	m.cfg.ControlSocket = "/nonexistent/xpf-7465-no-such.sock"

	err := m.syncHAStateLocked()
	if err == nil {
		t.Fatal("setup: the publish was expected to fail with no socket listening; " +
			"without a failure this cell proves nothing")
	}

	if m.helperHAStatePublished {
		t.Error("a FAILED update_ha_state was recorded as a publish. The helper never " +
			"acknowledged the inventory, so it still reads an empty ha_state as " +
			"\"not clustered\" — and because the poll swallows publish errors and arms " +
			"anyway, the gate would pass on the error path it exists to close (#7465)")
	}

	// The consequence that matters: the gate must still refuse to arm.
	armErr := m.syncDesiredForwardingStateLocked()
	if armErr == nil || !strings.Contains(armErr.Error(), "HA inventory") {
		t.Errorf("after a failed publish the arm gate did not refuse: %v", armErr)
	}
}
