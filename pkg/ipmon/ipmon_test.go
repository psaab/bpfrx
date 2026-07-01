package ipmon

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/rpm"
)

func testPolicyConfig() *config.IPMonitoringConfig {
	return &config.IPMonitoringConfig{Policies: map[string]*config.IPMonitoringPolicy{
		"wan-failover": {
			Name:          "wan-failover",
			MatchRPMProbe: "WAN",
			PreferredRoutes: []*config.PreferredRoute{
				{Destination: "0.0.0.0/0", NextHop: "172.16.80.1", PreferredMetric: 10},
				{RoutingInstance: "ISP-B", Destination: "0.0.0.0/0", NextHop: "172.16.80.1"},
			},
		},
	}}
}

func passResults() []*rpm.ProbeResult {
	return []*rpm.ProbeResult{
		{ProbeName: "WAN", TestName: "wan-a", LastStatus: "pass"},
		{ProbeName: "WAN", TestName: "wan-b", LastStatus: "pass"},
	}
}

// fakeClock drives the engine deterministically.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

func newTestEngine(actuate func() bool) (*Engine, *fakeClock) {
	e := New(actuate)
	clock := &fakeClock{now: time.Unix(1000000, 0)}
	e.now = clock.Now
	return e, clock
}

// transition builds an rpm.Transition with a coherent results snapshot.
func transition(probe, test, status string, results []*rpm.ProbeResult) rpm.Transition {
	for _, r := range results {
		if r.ProbeName == probe && r.TestName == test {
			r.LastStatus = status
		}
	}
	return rpm.Transition{ProbeName: probe, TestName: test, Status: status, Results: results}
}

// TestProbeFailInjectsAndRecoverWithdraws is the core state machine
// test: probe-fail → inject; probe-recover → withdraw.
func TestProbeFailInjectsAndRecoverWithdraws(t *testing.T) {
	e, clock := newTestEngine(nil)
	e.Apply(testPolicyConfig(), passResults())

	if got := e.ActiveOverlay(); got != nil {
		t.Fatalf("overlay = %+v before any failure, want nil", got)
	}

	// ANY test failing flips the policy to FAIL (Junos semantics).
	e.HandleTransition(transition("WAN", "wan-a", "fail", passResults()))
	overlay := e.ActiveOverlay()
	if len(overlay) != 2 {
		t.Fatalf("overlay = %+v, want both preferred routes injected", overlay)
	}
	if overlay[0].RoutingInstance != "" || overlay[0].Destination != "0.0.0.0/0" ||
		overlay[0].NextHop != "172.16.80.1" {
		t.Fatalf("overlay[0] = %+v", overlay[0])
	}
	if overlay[1].RoutingInstance != "ISP-B" {
		t.Fatalf("overlay[1] = %+v", overlay[1])
	}

	// Recovery of the failing test (hold-down 0) withdraws immediately.
	clock.Advance(10 * time.Second)
	e.HandleTransition(transition("WAN", "wan-a", "pass", passResults()))
	if got := e.ActiveOverlay(); got != nil {
		t.Fatalf("overlay = %+v after recovery, want nil", got)
	}

	st := e.Status()
	if len(st) != 1 || st[0].Transitions != 2 {
		t.Fatalf("status = %+v, want one policy with 2 transitions", st)
	}
}

func TestAnyTestFailedKeepsPolicyFailed(t *testing.T) {
	e, _ := newTestEngine(nil)
	e.Apply(testPolicyConfig(), passResults())

	results := passResults()
	e.HandleTransition(transition("WAN", "wan-a", "fail", results))
	e.HandleTransition(transition("WAN", "wan-b", "fail", results))
	// One of two failing tests recovers — policy stays FAIL.
	e.HandleTransition(transition("WAN", "wan-a", "pass", results))
	if got := e.ActiveOverlay(); len(got) == 0 {
		t.Fatal("overlay withdrawn while one test still FAILED")
	}
	e.HandleTransition(transition("WAN", "wan-b", "pass", results))
	if got := e.ActiveOverlay(); got != nil {
		t.Fatalf("overlay = %+v after full recovery", got)
	}
}

// TestRecoveryHoldDown verifies hold-down damps recovery (and ONLY
// recovery: failure re-arms instantly).
func TestRecoveryHoldDown(t *testing.T) {
	cfg := testPolicyConfig()
	cfg.Policies["wan-failover"].HoldDownSecs = 5
	e, clock := newTestEngine(nil)
	e.Apply(cfg, passResults())

	e.HandleTransition(transition("WAN", "wan-a", "fail", passResults()))
	if len(e.ActiveOverlay()) == 0 {
		t.Fatal("no overlay after failure")
	}

	// Recovery starts the hold-down; the overlay must persist.
	e.HandleTransition(transition("WAN", "wan-a", "pass", passResults()))
	if len(e.ActiveOverlay()) == 0 {
		t.Fatal("overlay withdrawn before hold-down expiry")
	}
	st := e.Status()
	if st[0].PendingRecoveryAt.IsZero() {
		t.Fatal("no pending recovery deadline during hold-down")
	}

	// A re-failure during hold-down cancels the recovery.
	clock.Advance(2 * time.Second)
	e.HandleTransition(transition("WAN", "wan-a", "fail", passResults()))
	if !e.Status()[0].PendingRecoveryAt.IsZero() {
		t.Fatal("pending recovery survived a re-failure")
	}
	if len(e.ActiveOverlay()) == 0 {
		t.Fatal("overlay lost on flap during hold-down")
	}

	// Recover again; advance past hold-down; evaluate withdraws.
	e.HandleTransition(transition("WAN", "wan-a", "pass", passResults()))
	clock.Advance(6 * time.Second)
	e.mu.Lock()
	e.evaluateLocked(e.now())
	e.mu.Unlock()
	if got := e.ActiveOverlay(); got != nil {
		t.Fatalf("overlay = %+v after hold-down expiry", got)
	}
}

// TestWinnerResolution verifies the §4.1 corrected semantics: among
// multiple injected routes for the same prefix, lowest preferred-metric
// wins; tie-break lexicographic policy name; withdrawal of the winner
// re-exposes the loser (not the config route, which the overlay only
// shadows downstream).
func TestWinnerResolution(t *testing.T) {
	cfg := &config.IPMonitoringConfig{Policies: map[string]*config.IPMonitoringPolicy{
		"b-policy": {
			Name: "b-policy", MatchRPMProbe: "P1",
			PreferredRoutes: []*config.PreferredRoute{
				{Destination: "0.0.0.0/0", NextHop: "10.0.0.1", PreferredMetric: 10},
			},
		},
		"a-policy": {
			Name: "a-policy", MatchRPMProbe: "P2",
			PreferredRoutes: []*config.PreferredRoute{
				{Destination: "0.0.0.0/0", NextHop: "10.0.0.2", PreferredMetric: 20},
			},
		},
		"c-policy": {
			Name: "c-policy", MatchRPMProbe: "P3",
			PreferredRoutes: []*config.PreferredRoute{
				{Destination: "0.0.0.0/0", NextHop: "10.0.0.3", PreferredMetric: 10},
			},
		},
	}}
	results := []*rpm.ProbeResult{
		{ProbeName: "P1", TestName: "t", LastStatus: "pass"},
		{ProbeName: "P2", TestName: "t", LastStatus: "pass"},
		{ProbeName: "P3", TestName: "t", LastStatus: "pass"},
	}
	e, _ := newTestEngine(nil)
	e.Apply(cfg, results)

	// All three fail: lowest metric (10) wins; tie between b-policy and
	// c-policy broken lexicographically → b-policy.
	for _, r := range results {
		r.LastStatus = "fail"
	}
	e.HandleTransition(rpm.Transition{ProbeName: "P1", TestName: "t", Status: "fail", Results: results})
	overlay := e.ActiveOverlay()
	if len(overlay) != 1 {
		t.Fatalf("overlay = %+v, want single winner per prefix", overlay)
	}
	if overlay[0].NextHop != "10.0.0.1" || overlay[0].Policy != "b-policy" {
		t.Fatalf("winner = %+v, want b-policy via 10.0.0.1", overlay[0])
	}

	// Winner's probe recovers → c-policy (same metric) takes over.
	results[0].LastStatus = "pass"
	e.HandleTransition(rpm.Transition{ProbeName: "P1", TestName: "t", Status: "pass", Results: results})
	overlay = e.ActiveOverlay()
	if len(overlay) != 1 || overlay[0].Policy != "c-policy" {
		t.Fatalf("overlay = %+v, want c-policy after winner recovery", overlay)
	}

	// All recover → empty overlay.
	results[1].LastStatus = "pass"
	results[2].LastStatus = "pass"
	e.HandleTransition(rpm.Transition{ProbeName: "P2", TestName: "t", Status: "pass", Results: results})
	if got := e.ActiveOverlay(); got != nil {
		t.Fatalf("overlay = %+v, want nil", got)
	}
}

// TestDebounceCoalescing: N rapid transitions collapse to one actuation
// per throttle window (§4.3 coalescing).
func TestDebounceCoalescing(t *testing.T) {
	var actuations atomic.Int32
	e := New(func() bool { actuations.Add(1); return true })
	e.debounce = 20 * time.Millisecond
	e.throttle = 60 * time.Millisecond
	e.Apply(testPolicyConfig(), passResults())
	e.Start()
	defer e.Stop()

	// Storm: 10 fail/recover flaps in quick succession.
	results := passResults()
	for i := 0; i < 5; i++ {
		e.HandleTransition(transition("WAN", "wan-a", "fail", results))
		e.HandleTransition(transition("WAN", "wan-a", "pass", results))
	}
	time.Sleep(40 * time.Millisecond)
	first := actuations.Load()
	if first < 1 {
		t.Fatal("no actuation after debounce window")
	}
	if first > 2 {
		t.Fatalf("actuations = %d within one window, want coalesced (<= 2: config-apply + storm)", first)
	}

	// Sustained flapping stays bounded: ≤ 1 actuation per throttle
	// window (plus one carry-over).
	start := actuations.Load()
	deadline := time.Now().Add(200 * time.Millisecond)
	for time.Now().Before(deadline) {
		e.HandleTransition(transition("WAN", "wan-a", "fail", results))
		e.HandleTransition(transition("WAN", "wan-a", "pass", results))
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(80 * time.Millisecond)
	total := actuations.Load() - start
	// 280ms elapsed / 60ms throttle ≈ 4.6 windows; allow slack to 6.
	if total > 6 {
		t.Fatalf("sustained flap produced %d actuations in ~280ms with 60ms throttle, want bounded", total)
	}
}

// TestActuationFailureStaysDirtyUntilConverged is the #3757
// M1/H1/H2/H3 regression: when the actuator reports failure the engine
// must KEEP the state dirty and retry autonomously (throttle-paced),
// then go quiescent once the actuation converges. On revert (dirty
// cleared before/independent of the actuation result) a failing
// actuator would fire exactly once — attempts stays 1 — and this goes
// RED.
func TestActuationFailureStaysDirtyUntilConverged(t *testing.T) {
	var attempts atomic.Int32
	var succeed atomic.Bool // false ⇒ actuation fails; flipped to self-heal
	e := New(func() bool {
		attempts.Add(1)
		return succeed.Load()
	})
	e.debounce = 5 * time.Millisecond
	e.throttle = 20 * time.Millisecond
	e.Apply(testPolicyConfig(), passResults())
	e.Start()
	defer e.Stop()

	// A probe failure marks the overlay dirty and actuates — but the
	// actuator keeps failing, so the engine must retry on the next sweep.
	e.HandleTransition(transition("WAN", "wan-a", "fail", passResults()))

	deadline := time.Now().Add(400 * time.Millisecond)
	for attempts.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := attempts.Load(); got < 2 {
		t.Fatalf("attempts = %d while actuation kept failing, want autonomous retry (>=2)", got)
	}

	// Let the actuation converge; the retry loop must settle once the
	// dirty bit clears.
	succeed.Store(true)
	time.Sleep(80 * time.Millisecond) // a few throttle windows to land + clear
	settled := attempts.Load()
	time.Sleep(160 * time.Millisecond) // several more windows
	if extra := attempts.Load() - settled; extra > 1 {
		t.Fatalf("actuation kept firing after convergence: +%d attempts, want quiescent", extra)
	}
}

// TestSuccessfulActuationClearsDirty: a single stable failure with a
// succeeding actuator actuates exactly once (the dirty bit clears on the
// converged actuation and the loop parks) — no retry churn.
func TestSuccessfulActuationClearsDirty(t *testing.T) {
	var attempts atomic.Int32
	e := New(func() bool { attempts.Add(1); return true })
	e.debounce = 5 * time.Millisecond
	e.throttle = 20 * time.Millisecond
	e.Apply(testPolicyConfig(), passResults())
	e.Start()
	defer e.Stop()

	e.HandleTransition(transition("WAN", "wan-a", "fail", passResults()))
	time.Sleep(60 * time.Millisecond)
	first := attempts.Load()
	if first < 1 {
		t.Fatal("no actuation after a failure")
	}
	time.Sleep(200 * time.Millisecond) // ~10 throttle windows
	if extra := attempts.Load() - first; extra > 0 {
		t.Fatalf("converged actuation kept retrying: +%d attempts, want 0 (dirty cleared)", extra)
	}
}

// TestLifecycleIdempotent is the #3762 regression: the exported engine
// lifecycle must be idempotent. A second Start must be a no-op (H9 — on
// revert it spawns a second run() goroutine whose deferred close(e.done)
// panics after Stop), and Stop must be safe before/without Start (H10 —
// on revert it blocks forever on <-e.done because no run loop exists to
// close it).
func TestLifecycleIdempotent(t *testing.T) {
	// H9: double Start does not spawn a second goroutine (no double
	// close(done) panic), and repeated Stop is safe.
	e := New(func() bool { return true })
	e.debounce = time.Millisecond
	e.throttle = time.Millisecond
	e.Start()
	e.Start() // no-op; on revert a second run() → panic on Stop
	time.Sleep(10 * time.Millisecond)
	e.Stop()
	e.Stop() // idempotent, no panic

	// H10: Stop before Start must return promptly, not deadlock.
	e2 := New(func() bool { return true })
	stopReturned := make(chan struct{})
	go func() {
		e2.Stop()
		close(stopReturned)
	}()
	select {
	case <-stopReturned:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop before Start deadlocked (H10)")
	}
	// A Start after Stop must be a no-op (no run loop, no panic) and a
	// further Stop stays safe.
	e2.Start()
	e2.Stop()
}

// TestPublishGatingBaseline: standby gating returns a nil overlay
// (baseline) and re-enables on takeover.
func TestPublishGatingBaseline(t *testing.T) {
	var actuations atomic.Int32
	e := New(func() bool { actuations.Add(1); return true })
	e.Apply(testPolicyConfig(), passResults())
	e.HandleTransition(transition("WAN", "wan-a", "fail", passResults()))
	if len(e.ActiveOverlay()) == 0 {
		t.Fatal("no overlay after failure")
	}

	e.SetPublishEnabled(false)
	if got := e.ActiveOverlay(); got != nil {
		t.Fatalf("overlay = %+v on standby, want nil (baseline)", got)
	}
	// State machine still tracks underneath the gate.
	if st := e.Status(); !st[0].Failed {
		t.Fatal("policy state lost under publication gate")
	}

	e.SetPublishEnabled(true)
	if len(e.ActiveOverlay()) == 0 {
		t.Fatal("overlay not restored on takeover")
	}
}

func TestApplyPreservesFailedStateAcrossCommit(t *testing.T) {
	e, _ := newTestEngine(nil)
	e.Apply(testPolicyConfig(), passResults())
	e.HandleTransition(transition("WAN", "wan-a", "fail", passResults()))
	if len(e.ActiveOverlay()) == 0 {
		t.Fatal("no overlay after failure")
	}

	// An unrelated commit re-applies the same policy config with a
	// results snapshot that still shows the failing test: FAIL state
	// (and the overlay) must survive.
	results := passResults()
	results[0].LastStatus = "fail"
	e.Apply(testPolicyConfig(), results)
	if len(e.ActiveOverlay()) == 0 {
		t.Fatal("overlay wiped by an unrelated commit (AGY r2-2 scenario)")
	}
	if !e.Status()[0].Failed {
		t.Fatal("FAIL state lost across Apply")
	}

	// Removing the policy clears everything.
	e.Apply(&config.IPMonitoringConfig{}, results)
	if got := e.ActiveOverlay(); got != nil {
		t.Fatalf("overlay = %+v after policy removal", got)
	}
}

// TestFilterOverlayForConfig is the Codex PR #1843 HIGH-1 regression
// test: a commit that removes a policy or edits its preferred-route
// spec must not republish the stale overlay entries on the commit's
// own publish; an unrelated commit preserves the overlay.
func TestFilterOverlayForConfig(t *testing.T) {
	e, _ := newTestEngine(nil)
	e.Apply(testPolicyConfig(), passResults())
	e.HandleTransition(transition("WAN", "wan-a", "fail", passResults()))
	overlay := e.ActiveOverlay()
	if len(overlay) != 2 {
		t.Fatalf("setup: overlay = %+v", overlay)
	}

	// Unrelated commit: identical policy spec → preserved verbatim.
	kept := FilterOverlayForConfig(overlay, testPolicyConfig())
	if len(kept) != 2 {
		t.Fatalf("unrelated commit dropped overlay entries: %+v", kept)
	}

	// Commit removes the policy → overlay entries absent.
	if got := FilterOverlayForConfig(overlay, &config.IPMonitoringConfig{}); got != nil {
		t.Fatalf("removed policy still riding the commit: %+v", got)
	}
	if got := FilterOverlayForConfig(overlay, nil); got != nil {
		t.Fatalf("nil ip-monitoring config still riding the commit: %+v", got)
	}

	// Commit edits the master route's next-hop → the OLD hop is
	// dropped; the untouched ISP-B entry survives.
	edited := testPolicyConfig()
	edited.Policies["wan-failover"].PreferredRoutes[0].NextHop = "172.16.80.99"
	kept = FilterOverlayForConfig(overlay, edited)
	if len(kept) != 1 || kept[0].RoutingInstance != "ISP-B" {
		t.Fatalf("edited next-hop: kept = %+v, want only the ISP-B entry", kept)
	}
	for _, entry := range kept {
		if entry.NextHop == "172.16.80.1" && entry.RoutingInstance == "" {
			t.Fatalf("stale master next-hop survived the edit: %+v", kept)
		}
	}

	// Commit edits the preferred-metric → spec changed → dropped.
	edited = testPolicyConfig()
	edited.Policies["wan-failover"].PreferredRoutes[0].PreferredMetric = 99
	kept = FilterOverlayForConfig(overlay, edited)
	if len(kept) != 1 || kept[0].RoutingInstance != "ISP-B" {
		t.Fatalf("edited metric: kept = %+v, want only the ISP-B entry", kept)
	}

	// Non-canonical but equivalent prefix spelling still matches.
	equiv := testPolicyConfig()
	equiv.Policies["wan-failover"].PreferredRoutes[0].Destination = "0.0.0.0/0"
	kept = FilterOverlayForConfig(overlay, equiv)
	if len(kept) != 2 {
		t.Fatalf("canonical-equivalent prefix dropped: %+v", kept)
	}
}

// TestApplyWithoutOverlayChangeDoesNotActuate (Codex PR #1843 MED):
// a commit with zero policies — or any commit that leaves the
// effective overlay unchanged — must not schedule a routes-only
// actuation (one spurious frr-reload per commit otherwise).
func TestApplyWithoutOverlayChangeDoesNotActuate(t *testing.T) {
	var actuations atomic.Int32
	e := New(func() bool { actuations.Add(1); return true })
	e.debounce = 5 * time.Millisecond
	e.throttle = 5 * time.Millisecond
	e.Start()
	defer e.Stop()

	// No-policy commits: nothing to actuate.
	e.Apply(&config.IPMonitoringConfig{}, nil)
	e.Apply(nil, nil)
	// Policies present but all passing (overlay nil before and after).
	e.Apply(testPolicyConfig(), passResults())
	e.Apply(testPolicyConfig(), passResults())
	time.Sleep(60 * time.Millisecond)
	if got := actuations.Load(); got != 0 {
		t.Fatalf("actuations = %d after overlay-neutral commits, want 0", got)
	}

	// A real failure still actuates...
	e.HandleTransition(transition("WAN", "wan-a", "fail", passResults()))
	time.Sleep(60 * time.Millisecond)
	if got := actuations.Load(); got == 0 {
		t.Fatal("real failure did not actuate")
	}

	// ...and an unrelated re-Apply with the overlay active (same
	// spec, still-failing results) stays quiet.
	before := actuations.Load()
	results := passResults()
	results[0].LastStatus = "fail"
	e.Apply(testPolicyConfig(), results)
	time.Sleep(60 * time.Millisecond)
	if got := actuations.Load(); got != before {
		t.Fatalf("unrelated commit actuated: %d -> %d", before, got)
	}

	// A spec edit while FAILED changes the overlay → actuates (the
	// HIGH-1 re-injection path).
	edited := testPolicyConfig()
	edited.Policies["wan-failover"].PreferredRoutes[0].NextHop = "172.16.80.99"
	e.Apply(edited, results)
	time.Sleep(60 * time.Millisecond)
	if got := actuations.Load(); got == before {
		t.Fatal("overlay-changing spec edit did not actuate")
	}
}
