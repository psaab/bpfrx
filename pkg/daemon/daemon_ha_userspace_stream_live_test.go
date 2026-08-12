package daemon

import (
	"context"
	"net"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #2114 (Codex PR #6743 r7-F5): behavioural binders for the event-stream
// fallback loop's per-tick resolution.
//
// r6-F4 made the EventStream provider and the stream instance per-tick but
// bound neither: deleting the `es != wired` re-install block, or reverting
// the provider resolution to a capture-once local, left the whole
// pkg/daemon suite green. The only r6-F4 test called
// wireUserspaceEventStreamCallbacks directly, so reverting THAT hunk was a
// build break rather than an assertion — which does not count as a binder.
// r7-F1 then found the third resolution (the session-delta drainer) was
// still captured at loop entry.
//
// These two tests drive eventStreamFallbackLoop itself, which is what the
// production goroutine at daemon_ha_sync.go runs.

// countingDeltaDrainerDP is a publishable backend that counts
// DrainSessionDeltas calls. It deliberately does NOT implement
// userspaceEventStreamProvider, so the loop sees no stream, reports
// disconnected, and takes the FAST 100 ms fallback branch — the branch on
// which a captured drainer kept polling a disowned backend at 10 Hz.
type countingDeltaDrainerDP struct {
	runtimeOnlyApplyTestDP
	drains atomic.Int64
}

func (c *countingDeltaDrainerDP) DrainSessionDeltas(uint32) ([]dpuserspace.SessionDeltaInfo, dpuserspace.ProcessStatus, error) {
	c.drains.Add(1)
	return nil, dpuserspace.ProcessStatus{}, nil
}

// connectedSyncPairForDrainTest returns a SessionSync whose IsConnected()
// is true, built from a real loopback peer. The fallback loop's drain is
// gated on IsConnected(), so a disconnected stub would make the whole test
// vacuous (it would never reach the drain in EITHER direction).
func connectedSyncPairForDrainTest(t *testing.T, ctx context.Context) *cluster.SessionSync {
	t.Helper()

	// Two free loopback ports; the pair dials each other.
	lnA, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port A: %v", err)
	}
	addrA := lnA.Addr().String()
	lnB, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port B: %v", err)
	}
	addrB := lnB.Addr().String()
	if err := lnA.Close(); err != nil {
		t.Fatalf("release port A: %v", err)
	}
	if err := lnB.Close(); err != nil {
		t.Fatalf("release port B: %v", err)
	}

	local := cluster.NewSessionSync(addrA, addrB, nil)
	peer := cluster.NewSessionSync(addrB, addrA, nil)
	if err := local.Start(ctx); err != nil {
		t.Fatalf("start local session sync: %v", err)
	}
	t.Cleanup(local.Stop)
	if err := peer.Start(ctx); err != nil {
		t.Fatalf("start peer session sync: %v", err)
	}
	t.Cleanup(peer.Stop)

	deadline := time.Now().Add(20 * time.Second)
	for !local.IsConnected() {
		if time.Now().After(deadline) {
			t.Fatal("session sync pair never connected: the drain gate this test " +
				"depends on would never open, so a green run would say nothing")
		}
		time.Sleep(10 * time.Millisecond)
	}
	return local
}

// storeWithActiveConfigForDrainTest returns a store whose ActiveConfig() is
// non-nil (the loop's last gate before the drain).
func storeWithActiveConfigForDrainTest(t *testing.T) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "config.db"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := store.SetFromInput("system host-name drain-binder"); err != nil {
		t.Fatalf("SetFromInput: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if store.ActiveConfig() == nil {
		t.Fatal("test setup: ActiveConfig() is nil, the drain is unreachable")
	}
	return store
}

func waitForDrainsForDrainTest(t *testing.T, dp *countingDeltaDrainerDP, what string) int64 {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		if n := dp.drains.Load(); n > 0 {
			return n
		}
		if time.Now().After(deadline) {
			t.Fatalf("no DrainSessionDeltas call %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestEventStreamFallbackLoop_DrainerReresolvedPerTick is the F1 binder, in
// BOTH directions.
//
// Fail-on-revert: hoist the `drainer, hasDrainer := d.currentSessionDeltaDrainer()`
// resolutions in eventStreamFallbackLoop back to a single capture at loop
// entry and this test fails on the FIRST assertion — the disowned backend
// keeps being drained at 10 Hz for the goroutine's life, because the loop's
// commsCtx is cancelled only by stopClusterComms, never by a dataplane
// disown. The second assertion covers the reverse arm the same revert also
// breaks: a backend published AFTER loop entry is never picked up, because
// the capture-once shape latched hasDrainer=false.
func TestEventStreamFallbackLoop_DrainerReresolvedPerTick(t *testing.T) {
	runDrainerReresolutionBinder(t, func(d *Daemon, ctx context.Context) {
		d.eventStreamFallbackLoop(ctx, nil)
	})
}

// TestSyncUserspaceSessionDeltas_DrainerReresolvedPerTick is the SECOND
// instance of the same F1 defect. syncUserspaceSessionDeltas is the polling
// path taken when the published backend exposes no event stream
// (runUserspaceEventStream), and it carried the identical capture-at-entry
// shape — worse, its miss arm RETURNED rather than continued, so an empty
// cell at entry killed the goroutine outright.
//
// Fail-on-revert: restore `drainer, ok := d.dataplane().(...)` plus the
// `!ok ||` entry gate and drop the per-tick resolution, and this fails the
// same way its eventStreamFallbackLoop sibling does. Fixing only one of the
// two functions leaves this test RED.
func TestSyncUserspaceSessionDeltas_DrainerReresolvedPerTick(t *testing.T) {
	runDrainerReresolutionBinder(t, func(d *Daemon, ctx context.Context) {
		d.syncUserspaceSessionDeltas(ctx)
	})
}

// runDrainerReresolutionBinder drives loop across a disown and a
// republication, asserting the drain follows the #2114 cell in BOTH
// directions.
func runDrainerReresolutionBinder(t *testing.T, loop func(*Daemon, context.Context)) {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	d := &Daemon{
		cluster: clusterManagerPrimaryForRGs(0),
		store:   storeWithActiveConfigForDrainTest(t),
	}
	if !d.cluster.IsLocalPrimaryAny() {
		t.Fatal("test setup: node must be primary for some RG or the drain is unreachable")
	}
	d.sessionSync = connectedSyncPairForDrainTest(t, ctx)

	first := &countingDeltaDrainerDP{}
	d.setDataplane(first)

	loopDone := make(chan struct{})
	go func() {
		defer close(loopDone)
		loop(d, ctx)
	}()

	waitForDrainsForDrainTest(t, first, "against the published backend: the loop never reached its drain")

	// Arm 1: the daemon disowns the backend (the bootstrap-exit re-arm
	// failure at daemon_run_naming.go). The drain must stop.
	d.setDataplane(nil)
	settle := first.drains.Load()
	// 1.5 s is 15 ticks of the 100 ms fast cadence — the cadence both loops
	// run at here, since no backend means no stream and connected==false.
	time.Sleep(1500 * time.Millisecond)
	if got := first.drains.Load(); got != settle {
		t.Fatalf("DrainSessionDeltas ran %d more times on the DISOWNED backend after "+
			"setDataplane(nil) (%d -> %d): the loop captured the drainer instead of "+
			"re-resolving it from the #2114 cell", got-settle, settle, got)
	}

	// Arm 2: a healthy backend is republished (the corrected commit's
	// re-arm). The drain must resume against the NEW object.
	second := &countingDeltaDrainerDP{}
	d.setDataplane(second)
	waitForDrainsForDrainTest(t, second, "against the REPUBLISHED backend: the loop latched "+
		"\"no drainer\" at entry and stayed dead for the goroutine's life")

	// The disowned backend must still be untouched.
	if got := first.drains.Load(); got != settle {
		t.Fatalf("the disowned backend was drained again (%d -> %d) after a new one was published",
			settle, got)
	}

	cancel()
	<-loopDone
}

// replaceableStreamDP publishes a swappable EventStream, standing in for the
// commit-confirmed rollback that CLOSES the armed backend's stream and
// constructs a new one on the corrected re-arm.
type replaceableStreamDP struct {
	runtimeOnlyApplyTestDP
	es atomic.Pointer[dpuserspace.EventStream]
}

func (r *replaceableStreamDP) EventStream() *dpuserspace.EventStream { return r.es.Load() }

// startEventStreamForRewireTest starts an EventStream on a private socket
// and returns it with that socket path (EventStream exposes no getter).
func startEventStreamForRewireTest(t *testing.T, ctx context.Context, name string) (*dpuserspace.EventStream, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	es := dpuserspace.NewEventStream(path)
	// Start binds the listener synchronously, so a nil error means the
	// socket is connectable (#6038).
	if err := es.Start(ctx); err != nil {
		t.Fatalf("start event stream %s: %v", name, err)
	}
	t.Cleanup(es.Close)
	return es, path
}

// TestEventStreamFallbackLoop_RewiresReplacementStream binds the r6-F4
// re-install hunk, and ONLY that hunk.
//
// Fail-on-revert: delete the `if es != nil && es != wired { ... }` block in
// eventStreamFallbackLoop and no ACK ever comes back — the replacement
// stream's events sit in the callback-not-ready queue, which is exactly the
// post-rollback symptom r6-F4 describes.
//
// It deliberately does NOT bind the per-tick PROVIDER resolution: the
// backend is published BEFORE the loop starts, so a capture-once provider
// would resolve to the same object and reach the same stream. That arm is
// TestEventStreamFallbackLoop_ProviderResolvedPerTick, which is
// correspondingly built so this hunk's removal does not disturb it — one
// fixture, one arm, in each direction.
func TestEventStreamFallbackLoop_RewiresReplacementStream(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	wired, _ := startEventStreamForRewireTest(t, ctx, "wired.sock")
	replacement, replacementPath := startEventStreamForRewireTest(t, ctx, "replacement.sock")

	// A cluster that is primary for NOTHING: handleEventStreamDelta then
	// takes its "ignored (not primary for any RG)" arm and ACKs, so the ACK
	// proves only that the CALLBACK ran — which is the property under test.
	d := &Daemon{
		cluster:     cluster.NewManager(0, 1),
		sessionSync: cluster.NewSessionSync(":0", "127.0.0.1:1", nil),
		store:       storeWithActiveConfigForDrainTest(t),
	}
	if d.cluster.IsLocalPrimaryAny() {
		t.Fatal("test setup: the cluster must not be primary for any RG")
	}

	backend := &replaceableStreamDP{}
	backend.es.Store(replacement)
	d.setDataplane(backend)

	loopDone := make(chan struct{})
	go func() {
		defer close(loopDone)
		// wired is the stream the callbacks were installed on at startup;
		// the published backend now exposes a DIFFERENT instance.
		d.eventStreamFallbackLoop(ctx, wired)
	}()

	conn, err := dialEventStreamForRewireTest(t, replacementPath)
	if err != nil {
		t.Fatalf("dial replacement event stream: %v", err)
	}
	defer conn.Close()

	writeEventFrameForWiringTest(t, conn, dpuserspace.EventTypeSessionOpen, 1,
		buildSessionOpenFrameV4PayloadForWiringTest())
	// SetOnEvent flushes the callback-not-ready queue, so this does not race
	// the loop's first tick: the ACK arrives whenever the re-install lands.
	waitForAckSeqForWiringTest(t, conn, 1)

	cancel()
	<-loopDone
}

// TestEventStreamFallbackLoop_ProviderResolvedPerTick binds the r6-F4
// per-tick PROVIDER resolution in isolation.
//
// The loop is handed the SAME stream instance it will later observe
// (wired == the published backend's stream), so the `es != wired`
// re-install block is a no-op throughout and deleting it changes nothing
// here. The only thing under test is whether a backend published AFTER
// loop entry is seen at all: the observable is d.eventStreamConnected,
// which the loop sets from `es != nil && es.IsConnected()`.
//
// Fail-on-revert: hoist `d.currentEventStreamProvider()` back out of the
// tick into a loop-entry capture and this fails — the cell is EMPTY when
// the loop starts (the production shape after a bootstrap-arm failure, or
// simply before the helper is armed), so the captured provider is nil for
// the goroutine's life and the stream is never observed.
func TestEventStreamFallbackLoop_ProviderResolvedPerTick(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	es, path := startEventStreamForRewireTest(t, ctx, "late.sock")

	// A live client, so es.IsConnected() is true once the loop looks at it.
	conn, err := dialEventStreamForRewireTest(t, path)
	if err != nil {
		t.Fatalf("dial event stream: %v", err)
	}
	defer conn.Close()

	d := &Daemon{
		cluster:     cluster.NewManager(0, 1),
		sessionSync: cluster.NewSessionSync(":0", "127.0.0.1:1", nil),
		store:       storeWithActiveConfigForDrainTest(t),
	}

	loopDone := make(chan struct{})
	go func() {
		defer close(loopDone)
		// Nothing is published yet. `wired` is the stream that will later
		// appear, so the re-install block never fires and this test is
		// blind to it.
		d.eventStreamFallbackLoop(ctx, es)
	}()

	// Let the loop take several ticks against the empty cell first.
	time.Sleep(300 * time.Millisecond)
	if d.eventStreamConnected.Load() {
		t.Fatal("eventStreamConnected is true with an EMPTY cell: the loop is not " +
			"reading the stream out of the #2114 cell at all")
	}

	backend := &replaceableStreamDP{}
	backend.es.Store(es)
	d.setDataplane(backend)

	deadline := time.Now().Add(20 * time.Second)
	for !d.eventStreamConnected.Load() {
		if time.Now().After(deadline) {
			t.Fatal("the loop never observed the stream of a backend published AFTER " +
				"loop entry: the event-stream provider was captured once instead of " +
				"being re-resolved from the #2114 cell every tick")
		}
		time.Sleep(10 * time.Millisecond)
	}

	cancel()
	<-loopDone
}

// dialEventStreamForRewireTest dials the stream's socket, retrying until the
// listener is up.
func dialEventStreamForRewireTest(t *testing.T, socketPath string) (net.Conn, error) {
	t.Helper()
	deadline := wiringTestDeadline(t)
	var lastErr error
	for time.Now().Before(deadline) {
		conn, err := net.Dial("unix", socketPath)
		if err == nil {
			return conn, nil
		}
		lastErr = err
		time.Sleep(10 * time.Millisecond)
	}
	return nil, lastErr
}

// Compile-time reminders that the fakes above really do carry the optional
// capabilities the loop probes for; a signature drift would otherwise turn
// both tests into vacuous no-ops (the loop would simply `continue`).
var (
	_ dataplane.RuntimeDataPlane   = (*countingDeltaDrainerDP)(nil)
	_ userspaceSessionDeltaDrainer = (*countingDeltaDrainerDP)(nil)
	_ dataplane.RuntimeDataPlane   = (*replaceableStreamDP)(nil)
	_ userspaceEventStreamProvider = (*replaceableStreamDP)(nil)
)
