package daemon

import (
	"context"
	"os"
	"strings"
	"testing"
)

// #7072: stopClusterComms must clear `activeClusterTransport`, so the field
// stops naming the transport of an epoch that has been torn down.
//
// This is a STATE claim, so it is asserted as one: the field's VALUE after
// teardown. "Teardown ran" is not the property — the epoch generation already
// binds that, and it advances whether or not the field is cleared.
//
// The fixture has to make the seed NON-ZERO or the assertion is zero == zero and
// passes against a build with the clear removed. `clusterTransportFromConfig`
// derives the key from ControlInterface / PeerAddress / the fabric fields, and
// the pre-existing #6290 fixture sets none of them; `clusteredStore7066` sets
// control-interface, which yields a non-zero key while starting no goroutines
// (the heartbeat needs control-interface AND peer-address, and
// clusterSyncTransport falls back to the empty fabric pair when either is
// missing).
func TestStopClusterCommsClearsTheActiveTransport_7072(t *testing.T) {
	store := clusteredStore7066(t)
	d := &Daemon{store: store, opts: Options{NoDataplane: true}}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d.startClusterComms(ctx)

	seeded := d.activeTransport()
	if seeded == (clusterTransportKey{}) {
		t.Fatalf("premise broken: the transport key is the ZERO value after " +
			"startClusterComms, so the assertion below is zero == zero and would pass " +
			"against a build that never clears it")
	}

	d.stopClusterComms()

	if got := d.activeTransport(); got != (clusterTransportKey{}) {
		t.Errorf("stopClusterComms left activeClusterTransport naming a torn-down "+
			"transport: %+v (seeded %+v).\nThe field is part of the epoch tuple — "+
			"sessionSync, fabricRefreshCh, fabricRefreshCh1 and the comms context are "+
			"all nilled in the same locked section — and #6290 joined it to the epoch on "+
			"the PUBLISH side only. Left stale, activeTransport() reports a live-looking "+
			"key for comms that are stopped", got, seeded)
	}
}

// #7072, the CONSEQUENCE — and it corrects the issue's stated rationale.
//
// The issue says a stale field means "step 20 would compare the next commit
// against a dead baseline and skip a restart it should perform". That is only
// half true, and the half it misses matters for anyone who later adds the
// stop-only path the issue is written against.
//
// Step 20's guard is `active != zero && newTransport != active`. Read it as what
// it is — RESTART-ON-CHANGE, not START-IF-STOPPED:
//
//	stale field: config unchanged -> no restart (comms stay down)
//	             config changed   -> restart    (comms come back)
//	cleared:     either way       -> no restart, first conjunct is false
//
// So clearing does not rescue a stop-only path; it changes WHICH restart is
// skipped. What it buys is that the field stops LYING, which is the precondition
// for reasoning about such a path — not a substitute for giving it a start.
//
// This binds the half that is now load-bearing: with the field cleared, step 20
// takes no action, so a future stop-only path cannot be built on the assumption
// that step 20 will notice and restart for it.
func TestStepTwentyDoesNotRestartOnAClearedTransport_7072(t *testing.T) {
	store := clusteredStore7066(t)
	d := &Daemon{store: store, opts: Options{NoDataplane: true}}
	d.daemonCtx = context.Background()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d.startClusterComms(ctx)
	d.stopClusterComms()

	if got := d.activeTransport(); got != (clusterTransportKey{}) {
		t.Fatalf("premise: the teardown must leave a ZERO transport, or this cell is "+
			"about the stale-field path instead of the cleared one (got %+v)", got)
	}

	restarts := 0
	d.startClusterCommsFn = func(context.Context) { restarts++ }

	// A config whose transport DIFFERS from the (now zero) baseline. Under the
	// stale-field behaviour this is the case that restarted.
	moved := store.ActiveConfig()
	moved.Chassis.Cluster.PeerAddress = "10.99.0.9"

	gen := func() uint64 {
		d.clusterCommsMu.Lock()
		defer d.clusterCommsMu.Unlock()
		return d.clusterCommsGen
	}
	before := gen()
	_ = d.applyTailReconciles(moved, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)

	if restarts != 0 || gen() != before {
		t.Errorf("step 20 restarted comms off a CLEARED transport baseline "+
			"(restarts=%d, gen %d -> %d). The `active != zero` conjunct exists to mean "+
			"\"comms were previously started\"; firing on a zero baseline would restart "+
			"comms that were never up, and would make the #7072 clear a behaviour change "+
			"rather than a truthfulness fix", restarts, before, gen())
	}
}

// #7071 CALL-SITE guard — and it exists because my first attempt at binding
// this was measured GREEN under the revert.
//
// `TestSupersededEpochPublishIsRefused_7071` below asserts that
// setActiveTransportIfCurrent REFUSES a superseded epoch. That is true with the
// fix and true without it: the gate is unchanged either way. Reverting the call
// site to `d.setActiveTransportIfCurrent(...)` with the result discarded left
// the whole pkg/daemon suite green — 2192 collected, 0 named failures. The test
// was adjacent to the property, not on it.
//
// The property is that the CALL SITE consumes the bool, and it cannot be driven
// behaviourally without a seam: the drop needs the epoch to advance between
// `beginClusterCommsEpoch` and the publish on the next line, a window no test
// can schedule. Rather than add a production seam whose only consumer is a test,
// this asserts the call site's SHAPE — the same instrument
// `TestDaemonPassesRethBeforeCycleHook_5103` uses for "programRethMemberMAC has
// exactly one call site and its result is assigned back", and
// `TestCompileRoutesPublishThroughFailClosedHelper4959` uses for "this publish
// goes through the fail-closed helper".
//
// Comments are stripped before matching. A source-scanning guard that reads its
// own explanatory prose is satisfied by the sentence describing the thing it is
// meant to find.
func TestStartClusterCommsConsumesTheDropSignal_7071(t *testing.T) {
	src, err := os.ReadFile("daemon_ha_sync.go")
	if err != nil {
		t.Fatalf("read daemon_ha_sync.go: %v", err)
	}
	const fn = "func (d *Daemon) startClusterComms("
	start := strings.Index(string(src), fn)
	if start < 0 {
		t.Fatalf("startClusterComms not found — this guard is scanning for a name that " +
			"no longer exists, which is not evidence that the call site is correct")
	}
	rest := string(src)[start+len(fn):]
	if end := strings.Index(rest, "\nfunc "); end >= 0 {
		rest = rest[:end]
	}
	var code []string
	for _, line := range strings.Split(rest, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "//") {
			continue
		}
		code = append(code, line)
	}
	body := strings.Join(code, "\n")

	// Non-vacuity: the call must be in there at all. Without this the shape
	// assertion below would pass for free on a body that never publishes.
	if !strings.Contains(body, "setActiveTransportIfCurrent(") {
		t.Fatalf("startClusterComms no longer calls setActiveTransportIfCurrent at all, " +
			"so the transport is never published and step 20's `active != zero` guard " +
			"never passes")
	}
	if !strings.Contains(body, "if !d.setActiveTransportIfCurrent(") {
		t.Errorf("startClusterComms DISCARDS setActiveTransportIfCurrent's drop signal.\n"+
			"Both sibling publishers gate on theirs (publishSessionSyncIfCurrent, "+
			"publishFabricRefreshChansIfCurrent). A false return means this epoch was "+
			"superseded, so everything below wires a DEAD epoch onto `commsCtx` — whose "+
			"cancel the newer epoch has already overwritten in clusterCommsCancel, so "+
			"nothing can cancel those goroutines and they outlive the epoch that spawned "+
			"them.\nbody:\n%s", body)
	}
	if !strings.Contains(body, "commsCancel()") {
		t.Errorf("the drop path does not cancel its own sub-context. Returning without " +
			"it leaks the context — nothing else holds that cancel, since the field now " +
			"names the newer epoch's — and cancelling here is safe precisely because " +
			"nothing has been launched on it yet")
	}
}

// #7071: startClusterComms must CONSUME the drop signal from
// setActiveTransportIfCurrent, as both sibling publishers already do.
//
// A false return means this epoch was superseded between the epoch opening and
// the publish, so everything below would wire a DEAD epoch. The wasted work is
// the smaller half. The goroutines are the larger one: they capture `commsCtx`,
// whose cancel the NEWER epoch has already overwritten in `clusterCommsCancel`,
// so nothing can cancel them — stopClusterComms would call the newer epoch's
// cancel — and they survive until the daemon context dies.
//
// Driving the race directly would be a timing test. This instead constructs the
// superseded state deterministically: open an epoch, advance the generation
// behind it, and assert the publish is refused. That is the exact condition the
// call site now returns on, and it is the property that makes the early return
// correct rather than arbitrary.
func TestSupersededEpochPublishIsRefused_7071(t *testing.T) {
	store := clusteredStore7066(t)
	d := &Daemon{store: store, opts: Options{NoDataplane: true}}
	want := clusterTransportFromConfig(store.ActiveConfig())
	if want == (clusterTransportKey{}) {
		t.Fatal("premise: a zero transport key cannot distinguish a refused publish " +
			"from an accepted one — both leave the field zero")
	}

	_, staleGen, staleCancel := d.beginClusterCommsEpoch(context.Background())
	defer staleCancel()

	// A newer epoch opens behind the first one — exactly what a concurrent
	// restart does between the two lines at the call site.
	_, newGen, newCancel := d.beginClusterCommsEpoch(context.Background())
	defer newCancel()
	if newGen == staleGen {
		t.Fatalf("premise: beginClusterCommsEpoch must advance the generation "+
			"(stale=%d new=%d)", staleGen, newGen)
	}

	if d.setActiveTransportIfCurrent(staleGen, want) {
		t.Error("the superseded epoch's publish was ACCEPTED. The call site returns " +
			"early on false, so accepting here would let a dead epoch wire the VRF " +
			"resolve, the HA watchdog, the heartbeat goroutine and the session-sync " +
			"constructor onto a context nothing can cancel")
	}
	if got := d.activeTransport(); got != (clusterTransportKey{}) {
		t.Errorf("a refused publish still wrote the field: %+v", got)
	}

	// And the live epoch's publish is still accepted — without this the test
	// passes against a setActiveTransportIfCurrent that refuses everything.
	if !d.setActiveTransportIfCurrent(newGen, want) {
		t.Error("the CURRENT epoch's publish was refused; the gate must drop only " +
			"superseded epochs")
	}
}
