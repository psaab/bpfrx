package cluster

import (
	"context"
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

// healthClk is a deterministic monotonic clock for driving the stale-duration
// grace without wall-clock sleeps.
type healthClk struct{ nanos atomic.Int64 }

func (c *healthClk) now() int64              { return c.nanos.Load() }
func (c *healthClk) set(ns int64)            { c.nanos.Store(ns) }
func (c *healthClk) advance(d time.Duration) { c.nanos.Add(int64(d)) }

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

// TestConfigSyncHealthRaisesAfterGraceAndClearsOnSuccess is the primary
// RED-on-revert test. It wires OnConfigReceived to hard-fail, drives
// configApplyLoop, advances the stale-duration clock past the grace, and
// asserts:
//   - lastAppliedConfigGen stays pinned at 0 (existing #4151 behavior),
//   - ConfigsApplyFailed increments,
//   - configSyncFailing raises once the grace elapses → FormatStatus renders CF
//     and FormatInformation renders "Node health: degraded" + "Config sync:
//     failing",
//   - the flag SURVIVES an intervening UpdateConfig (the reconcileMonitorDebts
//     hazard — the key regression), and
//   - one successful apply CLEARS it.
func TestConfigSyncHealthRaisesAfterGraceAndClearsOnSuccess(t *testing.T) {
	const grace = 5 * time.Second
	clk := &healthClk{}
	clk.set(1_000_000_000) // arbitrary non-zero monotonic base

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
	// Fail the first two applies (the initial push + the post-grace re-push),
	// then succeed — mirroring the primary re-pushing the same generation.
	rec := &configRecorder{failN: 2}
	s.OnConfigReceived = rec.record
	s.OnConfigApplyHealth = func(failing bool, reason string) {
		m.SetConfigSyncHealth(failing, reason)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.configApplyLoop(ctx)

	// (1) First push of gen 7 fails. The streak starts but the grace has not
	// elapsed, so CF must NOT raise yet.
	s.configApplyCh <- configApplyItem{gen: 7, text: "config-C7"}
	drainConfigApply(t, s)
	if got := s.lastAppliedConfigGen.Load(); got != 0 {
		t.Fatalf("apply failure must NOT advance the high-water, got %d", got)
	}
	if got := s.stats.ConfigsApplyFailed.Load(); got != 1 {
		t.Fatalf("ConfigsApplyFailed should be 1 after first failure, got %d", got)
	}
	if mgrConfigSyncFailing(m) {
		t.Fatal("CF must NOT raise before the stale-duration grace elapses")
	}

	// (2) Advance past the grace and re-push the SAME generation (re-admitted
	// because the high-water never advanced). This failure edge crosses the
	// grace → CF raises.
	clk.advance(grace + time.Second)
	s.configApplyCh <- configApplyItem{gen: 7, text: "config-C7"}
	drainConfigApply(t, s)
	if got := s.lastAppliedConfigGen.Load(); got != 0 {
		t.Fatalf("high-water must still be pinned at 0, got %d", got)
	}
	if got := s.stats.ConfigsApplyFailed.Load(); got != 2 {
		t.Fatalf("ConfigsApplyFailed should be 2, got %d", got)
	}
	if !mgrConfigSyncFailing(m) {
		t.Fatal("CF must raise once the un-applied streak persists past the grace")
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

// TestConfigSyncHealthTransientFailureWithinGraceNoFlap proves a transient apply
// failure that resolves WITHIN the grace never raises CF — a transient
// RG0-primary rejection must not flap the flag.
func TestConfigSyncHealthTransientFailureWithinGraceNoFlap(t *testing.T) {
	const grace = 30 * time.Second
	clk := &healthClk{}
	clk.set(5_000_000_000)

	var mu sync.Mutex
	var raisedTrue int
	m := NewManager(0, 22)
	m.UpdateConfig(makeConfig(makeRG(0, false, map[int]int{0: 200, 1: 100})))
	flushClusterEvents(m)

	s := NewSessionSync("127.0.0.1:0", "127.0.0.1:0", nil)
	s.nowMonoFn = clk.now
	s.configApplyFailGrace = grace
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

	// Failure at t0 (streak starts, grace not elapsed).
	s.configApplyCh <- configApplyItem{gen: 3, text: "config-A"}
	drainConfigApply(t, s)
	// A short time later (well within the grace) the re-push succeeds.
	clk.advance(2 * time.Second)
	s.configApplyCh <- configApplyItem{gen: 3, text: "config-A"}
	drainConfigApply(t, s)

	if got := s.lastAppliedConfigGen.Load(); got != 3 {
		t.Fatalf("the eventual apply must advance the high-water to 3, got %d", got)
	}
	if mgrConfigSyncFailing(m) {
		t.Fatal("a failure resolving within the grace must NOT leave CF raised")
	}
	mu.Lock()
	defer mu.Unlock()
	if raisedTrue != 0 {
		t.Fatalf("CF must never have flapped to failing within the grace, raised=%d", raisedTrue)
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
