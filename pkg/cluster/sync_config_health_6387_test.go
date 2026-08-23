package cluster

import (
	"context"
	"errors"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// #6387 — persistent config-sync APPLY failure surfaced as a CF monitor-failure
// / degraded health.
//
// Root cause recap: config-sync apply hard-fails on the standby (e.g. a missing
// host-inbound enforcement dependency), so configApplyLoop bumps
// ConfigsApplyFailed and leaves the config high-water pinned (M-2/#4151) — the
// node is stuck `Transfer ready: no`, `applied gen=0`, but looks "healthy" in
// the summary. These tests prove the time-based CF signal makes that stranded
// standby operator-visible without perturbing election.
//
// The two defects these tests pin (PR #6398 MERGE-NEEDS-MAJOR):
//   - the raise must not depend on a SECOND delivery: the sender pushes a
//     generation at most once per connection/generation, so a STABLE connection
//     with one persistent apply failure gets no re-delivery edge — an
//     independent grace-expiry TIMER, armed on the first failure, must raise CF
//     on its own; and
//   - the CLEAR must be manager-driven and idempotent: a comms transport change
//     tears down the SessionSync but keeps the cluster Manager, so a CF raised by
//     the OLD instance must be cleared by the REPLACEMENT instance's first
//     successful apply (not gated on the old instance's local raised flag).

// healthClk is a deterministic monotonic clock for driving the stale-duration
// grace without wall-clock sleeps.
type healthClk struct{ nanos atomic.Int64 }

func (c *healthClk) now() int64              { return c.nanos.Load() }
func (c *healthClk) set(ns int64)            { c.nanos.Store(ns) }
func (c *healthClk) advance(d time.Duration) { c.nanos.Add(int64(d)) }

// fakeAfterFunc is a deterministic stand-in for time.AfterFunc that captures the
// armed callback and the requested delay instead of scheduling on the wall
// clock, so a test can assert the grace-expiry timer was armed and fire it on
// demand. It spawns NO goroutine and returns an already-stopped real timer, so
// the SessionSync's Stop() calls on the handle are safe no-ops.
type fakeAfterFunc struct {
	mu    sync.Mutex
	calls int
	lastD time.Duration
	last  func()
}

func (f *fakeAfterFunc) schedule(d time.Duration, fn func()) *time.Timer {
	f.mu.Lock()
	f.calls++
	f.lastD = d
	f.last = fn
	f.mu.Unlock()
	tm := time.NewTimer(time.Hour)
	tm.Stop()
	return tm
}

func (f *fakeAfterFunc) armed() (int, time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls, f.lastD
}

// fire invokes the most recently armed callback, simulating the grace-expiry
// timer firing. A no-op if nothing was ever armed (so a neutralized arm leaves
// this inert and the raise assertion fails RED).
func (f *fakeAfterFunc) fire() {
	f.mu.Lock()
	fn := f.last
	f.mu.Unlock()
	if fn != nil {
		fn()
	}
}

func mgrConfigSyncFailing(m *Manager) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.configSyncFailing
}

// flushClusterEvents empties the manager event channel so a later assertion can prove
// that a subsequent call emitted (or, for CF, did NOT emit) an election event.
func flushClusterEvents(m *Manager) {
	for {
		select {
		case <-m.Events():
		case <-time.After(50 * time.Millisecond):
			return
		}
	}
}

// TestConfigSyncHealthTimerRaisesWithoutSecondDelivery is the primary
// RED-on-revert test for BUG 1. It wires OnConfigReceived to hard-fail, delivers
// the config exactly ONCE (a STABLE connection — the sender does not re-push),
// advances the stale-duration clock past the grace, fires the armed grace-expiry
// timer, and asserts:
//   - lastAppliedConfigGen stays pinned at 0 (existing #4151 behavior),
//   - ConfigsApplyFailed increments,
//   - the grace-expiry timer was ARMED on the first failure (with the grace),
//   - configSyncFailing raises when that timer fires — NO second delivery →
//     FormatStatus renders CF and FormatInformation renders degraded health +
//     "Config sync: failing",
//   - the flag SURVIVES an intervening UpdateConfig (the reconcileMonitorDebts
//     hazard — the key regression), and
//   - one successful apply CLEARS it.
//
// Neutralizing armConfigApplyGraceTimerLocked (the timer arm) leaves fakeAfterFunc
// uncalled → fire() is inert → CF never raises → this test goes RED.
func TestConfigSyncHealthTimerRaisesWithoutSecondDelivery(t *testing.T) {
	const grace = 5 * time.Second
	clk := &healthClk{}
	clk.set(1_000_000_000) // arbitrary non-zero monotonic base
	af := &fakeAfterFunc{}

	m := NewManager(0, 22)
	// Two configured RGs so the CF column render is exercised on multiple rows.
	cfg := makeConfig(
		makeRG(0, false, map[int]int{0: 200, 1: 100}),
		makeRG(1, false, map[int]int{0: 200, 1: 100}),
	)
	m.UpdateConfig(cfg)
	flushClusterEvents(m)

	s := NewSessionSync("127.0.0.1:0", "127.0.0.1:0", nil)
	s.nowMonoFn = clk.now
	s.configApplyFailGrace = grace
	s.afterFuncFn = af.schedule
	// Fail only the first apply; the eventual clear-path apply succeeds. Crucially
	// the SAME generation is NOT re-delivered — the raise must come from the timer.
	rec := &configRecorder{failN: 1}
	s.OnConfigReceived = rec.record
	s.OnConfigApplyHealth = func(failing bool, reason string) {
		m.SetConfigSyncHealth(failing, reason)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.configApplyLoop(ctx)

	// (1) Single push of gen 7 fails. The streak starts and the grace-expiry
	// timer is armed, but the timer has not fired, so CF must NOT raise yet.
	s.configApplyCh <- configApplyItem{gen: 7, text: "config-C7"}
	drainConfigApply(t, s)
	if got := s.lastAppliedConfigGen.Load(); got != 0 {
		t.Fatalf("apply failure must NOT advance the high-water, got %d", got)
	}
	if got := s.stats.ConfigsApplyFailed.Load(); got != 1 {
		t.Fatalf("ConfigsApplyFailed should be 1 after first failure, got %d", got)
	}
	if calls, d := af.armed(); calls != 1 || d != grace {
		t.Fatalf("grace-expiry timer must be armed exactly once with the grace on the first failure, got calls=%d d=%s", calls, d)
	}
	if mgrConfigSyncFailing(m) {
		t.Fatal("CF must NOT raise before the grace-expiry timer fires")
	}

	// (2) Advance past the grace and fire the ARMED timer — no second delivery.
	// This is the stranded-standby scenario: a stable connection, one persistent
	// apply failure, and only the timer to surface it.
	clk.advance(grace + time.Second)
	af.fire()
	if got := s.lastAppliedConfigGen.Load(); got != 0 {
		t.Fatalf("high-water must still be pinned at 0, got %d", got)
	}
	if !mgrConfigSyncFailing(m) {
		t.Fatal("the armed grace-expiry timer must raise CF with no second delivery")
	}

	// Rendering: FormatStatus folds CF into the Monitor-failures column (the
	// legend line already contains one "CF", so > 1 proves a row picked it up).
	status := m.FormatStatus()
	if strings.Count(status, "CF") <= 1 {
		t.Fatalf("FormatStatus must render CF in a Monitor-failures column:\n%s", status)
	}
	info := m.FormatInformation()
	if !strings.Contains(info, "Local node: degraded") {
		t.Fatalf("FormatInformation must degrade node health:\n%s", info)
	}
	if !strings.Contains(info, "Config sync: failing") {
		t.Fatalf("FormatInformation must render a Config sync: failing line:\n%s", info)
	}

	// (3) KEY REGRESSION: an intervening UpdateConfig runs
	// reconcileMonitorDebtsLocked, which wipes any non-interface/non-IP
	// MonitorFails entry. A dedicated manager field must survive it.
	m.UpdateConfig(cfg)
	flushClusterEvents(m)
	if !mgrConfigSyncFailing(m) {
		t.Fatal("CF must survive UpdateConfig — a MonitorFails sentinel would be wiped by reconcileMonitorDebtsLocked")
	}
	if strings.Count(m.FormatStatus(), "CF") <= 1 {
		t.Fatal("FormatStatus must still render CF after UpdateConfig")
	}

	// (4) A successful apply of a newer generation clears CF and advances the
	// high-water.
	s.configApplyCh <- configApplyItem{gen: 8, text: "config-C8"}
	drainConfigApply(t, s)
	if got := s.lastAppliedConfigGen.Load(); got != 8 {
		t.Fatalf("successful apply must advance the high-water to 8, got %d", got)
	}
	if mgrConfigSyncFailing(m) {
		t.Fatal("CF must clear on the first successful apply")
	}
	if strings.Count(m.FormatStatus(), "CF") != 1 {
		t.Fatalf("FormatStatus must drop the CF column entry once cleared:\n%s", m.FormatStatus())
	}
}

// TestConfigSyncHealthClearsAcrossCommsRestart is the RED-on-revert test for
// BUG 2. A comms transport change tears down the SessionSync (daemon
// stopClusterComms) but KEEPS the cluster Manager, so the "clear-required"
// state cannot live only in the SessionSync: instance A raises CF on the shared
// Manager, A is torn down, and a fresh instance B — whose local raised flag was
// never set — must clear the Manager CF on its first successful apply.
//
// Reverting the UNCONDITIONAL clear (gating it back on the instance's own
// configApplyHealthRaised) leaves B unable to clear the Manager → CF stuck →
// this test goes RED.
func TestConfigSyncHealthClearsAcrossCommsRestart(t *testing.T) {
	const grace = 5 * time.Second

	m := NewManager(0, 22)
	m.UpdateConfig(makeConfig(makeRG(0, false, map[int]int{0: 200, 1: 100})))
	flushClusterEvents(m)

	// --- instance A: raises CF via its grace-expiry timer, then is torn down ---
	clkA := &healthClk{}
	clkA.set(1_000_000_000)
	afA := &fakeAfterFunc{}
	a := NewSessionSync("127.0.0.1:0", "127.0.0.1:0", nil)
	a.nowMonoFn = clkA.now
	a.configApplyFailGrace = grace
	a.afterFuncFn = afA.schedule
	recA := &configRecorder{failN: 1}
	a.OnConfigReceived = recA.record
	a.OnConfigApplyHealth = func(failing bool, reason string) {
		m.SetConfigSyncHealth(failing, reason)
	}

	ctxA, cancelA := context.WithCancel(context.Background())
	go a.configApplyLoop(ctxA)
	a.configApplyCh <- configApplyItem{gen: 5, text: "config-A5"}
	drainConfigApply(t, a)
	clkA.advance(grace + time.Second)
	afA.fire()
	if !mgrConfigSyncFailing(m) {
		t.Fatal("precondition: instance A must raise CF on the shared manager")
	}

	// Tear down A the way stopClusterComms does: stop its loop and Stop() the
	// instance. Teardown alone must NOT clear the manager CF — the whole point
	// of the bug is that the CF outlives the SessionSync.
	cancelA()
	a.Stop()
	if !mgrConfigSyncFailing(m) {
		t.Fatal("tearing down instance A must not clear the manager CF (it outlives the SessionSync)")
	}

	// --- instance B: a fresh SessionSync on the SAME manager; its first
	// successful apply must clear the stale CF even though B never raised it. ---
	b := NewSessionSync("127.0.0.1:0", "127.0.0.1:0", nil)
	b.OnConfigReceived = (&configRecorder{}).record // succeeds
	b.OnConfigApplyHealth = func(failing bool, reason string) {
		m.SetConfigSyncHealth(failing, reason)
	}
	ctxB, cancelB := context.WithCancel(context.Background())
	defer cancelB()
	go b.configApplyLoop(ctxB)

	b.configApplyCh <- configApplyItem{gen: 6, text: "config-B6"}
	drainConfigApply(t, b)
	if got := b.lastAppliedConfigGen.Load(); got != 6 {
		t.Fatalf("instance B's apply must advance its high-water to 6, got %d", got)
	}
	if mgrConfigSyncFailing(m) {
		t.Fatal("instance B's first successful apply must clear the manager CF raised by instance A")
	}
}

// TestConfigSyncHealthTransientFailureWithinGraceNoFlap proves a transient apply
// failure that resolves WITHIN the grace never raises CF — a transient
// RG0-primary rejection must not flap the flag — AND that the grace-expiry timer
// is cancelled on the intervening success so a late fire cannot raise a stale CF
// (the cancelled-but-already-firing race) and no timer is leaked.
func TestConfigSyncHealthTransientFailureWithinGraceNoFlap(t *testing.T) {
	const grace = 30 * time.Second
	clk := &healthClk{}
	clk.set(5_000_000_000)
	af := &fakeAfterFunc{}

	var mu sync.Mutex
	var raisedTrue int
	m := NewManager(0, 22)
	m.UpdateConfig(makeConfig(makeRG(0, false, map[int]int{0: 200, 1: 100})))
	flushClusterEvents(m)

	goroutinesBefore := runtime.NumGoroutine()

	s := NewSessionSync("127.0.0.1:0", "127.0.0.1:0", nil)
	s.nowMonoFn = clk.now
	s.configApplyFailGrace = grace
	s.afterFuncFn = af.schedule
	rec := &configRecorder{failN: 1} // one transient failure, then success
	s.OnConfigReceived = rec.record
	s.OnConfigApplyHealth = func(failing bool, reason string) {
		mu.Lock()
		if failing {
			raisedTrue++
		}
		mu.Unlock()
		m.SetConfigSyncHealth(failing, reason)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.configApplyLoop(ctx)

	// Failure at t0 (streak starts, timer armed, grace not elapsed).
	s.configApplyCh <- configApplyItem{gen: 3, text: "config-A"}
	drainConfigApply(t, s)
	if calls, _ := af.armed(); calls != 1 {
		t.Fatalf("timer must be armed on the transient failure, got calls=%d", calls)
	}
	// A short time later (well within the grace) the re-push succeeds — this
	// cancels the timer.
	clk.advance(2 * time.Second)
	s.configApplyCh <- configApplyItem{gen: 3, text: "config-A"}
	drainConfigApply(t, s)

	if got := s.lastAppliedConfigGen.Load(); got != 3 {
		t.Fatalf("the eventual apply must advance the high-water to 3, got %d", got)
	}
	if mgrConfigSyncFailing(m) {
		t.Fatal("a failure resolving within the grace must NOT leave CF raised")
	}

	// The success must have cancelled the timer (no dangling handle) and bumped
	// the epoch. Simulate a late fire of the already-cancelled timer: the epoch
	// guard must make it a no-op, so CF stays clear (no flap).
	s.configApplyMu.Lock()
	timerNil := s.configApplyFailTimer == nil
	s.configApplyMu.Unlock()
	if !timerNil {
		t.Fatal("the grace-expiry timer must be cancelled (handle dropped) on the intervening success")
	}
	af.fire() // stale late fire — must be swallowed by the epoch guard
	if mgrConfigSyncFailing(m) {
		t.Fatal("a stale late timer fire after a success must NOT raise CF (epoch guard)")
	}

	mu.Lock()
	if raisedTrue != 0 {
		mu.Unlock()
		t.Fatalf("CF must never have flapped to failing within the grace, raised=%d", raisedTrue)
	}
	mu.Unlock()

	// No leaked timer goroutine: fakeAfterFunc spawns none and the real path is
	// stopped, so the goroutine count returns to its baseline once the loop exits.
	cancel()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if runtime.NumGoroutine() <= goroutinesBefore {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if after := runtime.NumGoroutine(); after > goroutinesBefore {
		t.Fatalf("goroutine leak: before=%d after=%d", goroutinesBefore, after)
	}
}

// TestConfigSyncHealthRaiseClearReorderSerialized is the RED-on-revert test for
// the PR #6398 callback-reorder race. The grace-expiry timer raise and the
// success clear both publish OnConfigApplyHealth; if the raise callback is
// delivered OUTSIDE configApplyMu it can be preempted between deciding-to-raise
// and delivering, so a concurrent success's clear(false) can land FIRST and the
// late raise(true) overtakes it — leaving the Manager stuck
// configSyncFailing=true after a SUCCESSFUL apply (the epoch guard only covers
// decision-time staleness, not the two out-of-lock callback deliveries).
//
// The fix delivers every OnConfigApplyHealth publish while STILL HOLDING
// configApplyMu, serializing raise vs clear. This test forces the exact hostile
// interleaving deterministically using the callback itself as the seam: the
// raise callback announces it is mid-delivery and then blocks, and the test only
// releases it AFTER a concurrent success has had its chance to run.
//
//   - With the fix (callback under lock): the raise callback holds configApplyMu
//     while blocked, so the success goroutine cannot acquire the lock and cannot
//     clear early; once released, the raise publishes, the lock drops, and the
//     success then clears LAST → final state cleared.
//   - Without the fix (callback outside lock): the raise has already released the
//     lock before delivering, so the success runs to completion and clears FIRST;
//     the test then releases the late raise, which sets CF true LAST → final
//     state stuck-true → RED.
func TestConfigSyncHealthRaiseClearReorderSerialized(t *testing.T) {
	const grace = 5 * time.Second
	clk := &healthClk{}
	clk.set(1_000_000_000)
	af := &fakeAfterFunc{}

	m := NewManager(0, 22)
	m.UpdateConfig(makeConfig(makeRG(0, false, map[int]int{0: 200, 1: 100})))
	flushClusterEvents(m)

	s := NewSessionSync("127.0.0.1:0", "127.0.0.1:0", nil)
	s.nowMonoFn = clk.now
	s.configApplyFailGrace = grace
	s.afterFuncFn = af.schedule

	raiseDelivering := make(chan struct{}) // closed when the raise callback starts delivering
	letRaiseFinish := make(chan struct{})  // closed by the test to release the blocked raise
	var raiseOnce sync.Once
	s.OnConfigApplyHealth = func(failing bool, reason string) {
		if failing {
			// The raise delivery — hold it open until the test says go, so a
			// concurrent success clear has a chance to be reordered ahead of it.
			raiseOnce.Do(func() {
				close(raiseDelivering)
				<-letRaiseFinish
			})
		}
		m.SetConfigSyncHealth(failing, reason)
	}

	// (1) First failure arms the grace-expiry timer (no raise yet — elapsed 0).
	s.noteConfigApplyFailure(errors.New("host-inbound apply failed: dependency missing"))
	if calls, d := af.armed(); calls != 1 || d != grace {
		t.Fatalf("grace-expiry timer must be armed once with the grace, got calls=%d d=%s", calls, d)
	}
	if mgrConfigSyncFailing(m) {
		t.Fatal("CF must not raise before the grace elapses")
	}

	// (2) Grace elapses; fire the armed timer on its own goroutine. The raise
	// callback blocks mid-delivery (raiseDelivering closed, waiting on letRaiseFinish).
	clk.advance(grace + time.Second)
	raiseReturned := make(chan struct{})
	go func() {
		af.fire()
		close(raiseReturned)
	}()
	<-raiseDelivering

	// (3) A successful apply runs concurrently while the raise is mid-delivery.
	successDone := make(chan struct{})
	go func() {
		s.noteConfigApplySuccess(0)
		close(successDone)
	}()

	// Give the success a chance to complete. Without the fix it runs to
	// completion here (raise already released the lock) and clears CF first;
	// with the fix it blocks on configApplyMu (held by the raise) and cannot.
	select {
	case <-successDone:
		// Success cleared already — only reachable when the raise was delivered
		// outside the lock (the bug). Releasing the raise now makes it overtake.
	case <-time.After(250 * time.Millisecond):
		// Success is blocked on the lock (the fix) — expected.
	}

	// (4) Release the blocked raise and let both callbacks settle.
	close(letRaiseFinish)
	<-successDone
	<-raiseReturned

	// The final state after a SUCCESSFUL apply must be cleared — a late raise
	// must never be able to land after the clear.
	if mgrConfigSyncFailing(m) {
		t.Fatal("callback-reorder race: a late raise overtook the success clear — CF stuck raised after a successful apply")
	}
}

// TestConfigSyncHealthElectionNeutral proves SetConfigSyncHealth is a pure
// health annotation: it does not change Weight / State / priority / failover
// count, it emits no election event, and it is not wired into the
// manual-failover readiness gate (ReadyForManualFailover stays a pure function
// of ConfigStale()).
func TestConfigSyncHealthElectionNeutral(t *testing.T) {
	m := NewManager(0, 22)
	m.UpdateConfig(makeConfig(
		makeRG(0, false, map[int]int{0: 200, 1: 100}),
		makeRG(1, false, map[int]int{0: 100, 1: 200}),
	))
	flushClusterEvents(m)

	before := m.GroupStates()

	// Setting CF must not perturb election state nor emit an event.
	m.SetConfigSyncHealth(true, "host-inbound apply failed: nft not found")

	select {
	case ev := <-m.Events():
		t.Fatalf("SetConfigSyncHealth must not emit an election event, got %+v", ev)
	case <-time.After(100 * time.Millisecond):
	}

	after := m.GroupStates()
	if len(before) != len(after) {
		t.Fatalf("RG count changed: %d -> %d", len(before), len(after))
	}
	for i := range before {
		b, a := before[i], after[i]
		if b.Weight != a.Weight || b.State != a.State ||
			b.LocalPriority != a.LocalPriority || b.FailoverCount != a.FailoverCount {
			t.Fatalf("rg %d election state perturbed by CF: before=%+v after=%+v", b.GroupID, b, a)
		}
	}

	// CF is NOT a second failover gate: a standby whose config is up to date
	// (not stale) is still manual-failover-ready even with CF set.
	snap := TransferReadinessSnapshot{PeerConfigGen: 42, AppliedConfigGen: 42}
	if snap.ConfigStale() {
		t.Fatal("precondition: an up-to-date snapshot must not be config-stale")
	}
	if !snap.ReadyForManualFailover() {
		t.Fatal("ReadyForManualFailover must stay gated solely by ConfigStale(); CF must not gate it")
	}
}
