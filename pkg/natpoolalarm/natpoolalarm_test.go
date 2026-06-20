package natpoolalarm

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// emitRec is a thread-safe recorder for emitted syslog lines, used as the
// mutation seam: if the emit call is removed from a transition path, the
// corresponding assertion fails.
type emitRec struct {
	mu    sync.Mutex
	lines []recLine
}

type recLine struct {
	sev int
	msg string
}

func (r *emitRec) emit(sev int, msg string) {
	r.mu.Lock()
	r.lines = append(r.lines, recLine{sev: sev, msg: msg})
	r.mu.Unlock()
}

func (r *emitRec) snapshot() []recLine {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]recLine, len(r.lines))
	copy(out, r.lines)
	return out
}

func (r *emitRec) reset() {
	r.mu.Lock()
	r.lines = nil
	r.mu.Unlock()
}

func countMatch(lines []recLine, substr string) int {
	n := 0
	for _, l := range lines {
		if strings.Contains(l.msg, substr) {
			n++
		}
	}
	return n
}

const (
	raisedTag  = "NAT_POOL_UTILIZATION_ALARM_RAISED"
	clearedTag = "NAT_POOL_UTILIZATION_ALARM_CLEARED"
)

// cfgWith builds a config with a single source pool referenced by one
// source-NAT rule, with the given alarm thresholds. deterministic marks the
// pool deterministic. If poolMissing is true the rule references a name that
// does not exist in SourcePools.
func cfgWith(raise, clear int, deterministic bool) *config.Config {
	cfg := &config.Config{}
	cfg.Security.NAT.PoolUtilizationAlarm = &config.PoolUtilizationAlarmConfig{
		RaiseThreshold: raise,
		ClearThreshold: clear,
	}
	pool := &config.NATPool{Name: "p1", PortLow: 1, PortHigh: 100, Addresses: []string{"1.1.1.1"}}
	if deterministic {
		pool.Deterministic = &config.DeterministicNATConfig{BlockSize: 10, HostAddress: "10.0.0.0/24"}
	}
	cfg.Security.NAT.SourcePools = map[string]*config.NATPool{"p1": pool}
	cfg.Security.NAT.Source = []*config.NATRuleSet{
		{Name: "rs1", Rules: []*config.NATRule{
			{Name: "r1", Then: config.NATThen{Type: config.NATSource, PoolName: "p1"}},
		}},
	}
	return cfg
}

// poolStatus builds a deduped pool sample with capacity = addr*(high-low+1).
func poolStatus(name string, addr int, low, high uint16, used uint64) PoolStatus {
	return PoolStatus{PoolName: name, AddressCount: addr, PortLow: low, PortHigh: high, UsedPorts: used}
}

// newMon makes a monitor with a controllable sampler and recorder. The sampler
// reads *view under a mutex so tests can mutate it between evaluate() calls.
func newMon() (*Monitor, *emitRec, *viewBox) {
	rec := &emitRec{}
	vb := &viewBox{}
	m := New(vb.get, rec.emit)
	return m, rec, vb
}

type viewBox struct {
	mu sync.Mutex
	v  View
}

func (b *viewBox) set(v View) {
	b.mu.Lock()
	b.v = v
	b.mu.Unlock()
}

func (b *viewBox) get() View {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.v
}

// coherentView wraps a config + pools into an Available+Coherent view.
func coherentView(cfg *config.Config, pools ...PoolStatus) View {
	pm := map[string]PoolStatus{}
	for _, p := range pools {
		pm[p.PoolName] = p
	}
	return View{Config: cfg, Pools: pm, HelperCoherent: true, Available: true}
}

// --- Tests ---

// TestRaiseFiresOnce: crossing up raises exactly one alarm and one raise line.
func TestRaiseFiresOnce(t *testing.T) {
	m, rec, vb := newMon()
	cfg := cfgWith(80, 70, false) // capacity 100; raise at >=80
	// 85 used / 100 cap = 85% >= 80 → raise.
	vb.set(coherentView(cfg, poolStatus("p1", 1, 1, 100, 85)))

	m.evaluate()
	if got := countMatch(rec.snapshot(), raisedTag); got != 1 {
		t.Fatalf("expected 1 raise line, got %d", got)
	}
	if alarms := m.ActiveAlarms(); len(alarms) != 1 || alarms[0].PoolName != "p1" {
		t.Fatalf("expected p1 active, got %+v", alarms)
	}

	// Re-evaluate while still above raise: NO second raise (hold).
	rec.reset()
	m.evaluate()
	if got := countMatch(rec.snapshot(), raisedTag); got != 0 {
		t.Fatalf("expected no duplicate raise, got %d", got)
	}
	if len(m.ActiveAlarms()) != 1 {
		t.Fatal("alarm should still be active")
	}
}

// TestClearFiresOnce: dropping below clear clears exactly once.
func TestClearFiresOnce(t *testing.T) {
	m, rec, vb := newMon()
	cfg := cfgWith(80, 70, false)
	vb.set(coherentView(cfg, poolStatus("p1", 1, 1, 100, 85)))
	m.evaluate() // raise
	rec.reset()

	// 65% < clear(70) → clear once.
	vb.set(coherentView(cfg, poolStatus("p1", 1, 1, 100, 65)))
	m.evaluate()
	if got := countMatch(rec.snapshot(), clearedTag); got != 1 {
		t.Fatalf("expected 1 clear line, got %d", got)
	}
	if len(m.ActiveAlarms()) != 0 {
		t.Fatal("alarm should be cleared")
	}

	// Re-evaluate below clear with no alarm: no duplicate clear.
	rec.reset()
	m.evaluate()
	if got := countMatch(rec.snapshot(), clearedTag); got != 0 {
		t.Fatalf("expected no duplicate clear, got %d", got)
	}
}

// TestHysteresisNoFlap: in the band [clear,raise) an unraised alarm stays
// unraised and a raised alarm stays raised — no emissions either way.
func TestHysteresisNoFlap(t *testing.T) {
	m, rec, vb := newMon()
	cfg := cfgWith(80, 70, false)

	// Start in the band, never raised: 75% — no raise.
	vb.set(coherentView(cfg, poolStatus("p1", 1, 1, 100, 75)))
	m.evaluate()
	if len(rec.snapshot()) != 0 || len(m.ActiveAlarms()) != 0 {
		t.Fatal("band-below-raise must not raise")
	}

	// Raise, then drop into the band: must stay raised (no clear).
	vb.set(coherentView(cfg, poolStatus("p1", 1, 1, 100, 85)))
	m.evaluate() // raise
	rec.reset()
	vb.set(coherentView(cfg, poolStatus("p1", 1, 1, 100, 75)))
	m.evaluate()
	if got := countMatch(rec.snapshot(), clearedTag); got != 0 {
		t.Fatalf("band-above-clear must not clear, got %d clears", got)
	}
	if len(m.ActiveAlarms()) != 1 {
		t.Fatal("alarm must remain active in hysteresis band")
	}
}

// TestBoundaryComparators: at exactly raise → raises; at exactly clear → does
// NOT clear (strict <); just below clear → clears.
func TestBoundaryComparators(t *testing.T) {
	m, _, vb := newMon()
	cfg := cfgWith(80, 70, false)

	// Exactly 80% → raise (>=).
	vb.set(coherentView(cfg, poolStatus("p1", 1, 1, 100, 80)))
	m.evaluate()
	if len(m.ActiveAlarms()) != 1 {
		t.Fatal("pct == raise must raise")
	}
	// Exactly 70% → does NOT clear (strict <).
	vb.set(coherentView(cfg, poolStatus("p1", 1, 1, 100, 70)))
	m.evaluate()
	if len(m.ActiveAlarms()) != 1 {
		t.Fatal("pct == clear must NOT clear (strict <)")
	}
	// 69% → clears.
	vb.set(coherentView(cfg, poolStatus("p1", 1, 1, 100, 69)))
	m.evaluate()
	if len(m.ActiveAlarms()) != 0 {
		t.Fatal("pct < clear must clear")
	}
}

// TestActiveAlarmsRegistry: the show-alarms registry is populated on raise and
// emptied on clear.
func TestActiveAlarmsRegistry(t *testing.T) {
	m, _, vb := newMon()
	cfg := cfgWith(80, 70, false)
	vb.set(coherentView(cfg, poolStatus("p1", 1, 1, 100, 90)))
	m.evaluate()
	alarms := m.ActiveAlarms()
	if len(alarms) != 1 || alarms[0].PoolName != "p1" || alarms[0].CurrentPct != 90 || alarms[0].RaiseThreshold != 80 {
		t.Fatalf("registry not populated correctly: %+v", alarms)
	}
	if alarms[0].FirstSeen.IsZero() {
		t.Fatal("FirstSeen should be set")
	}
	vb.set(coherentView(cfg, poolStatus("p1", 1, 1, 100, 10)))
	m.evaluate()
	if len(m.ActiveAlarms()) != 0 {
		t.Fatal("registry not cleared")
	}
}

// TestEligibilityRuleReferenced: a pool whose LAST referencing rule is removed
// (pool still in SourcePools) is cleared by the prune. Mutation: if eligibility
// iterated SourcePools instead of rule-references, the alarm would stick.
func TestEligibilityRuleReferenced(t *testing.T) {
	m, rec, vb := newMon()
	cfg := cfgWith(80, 70, false)
	vb.set(coherentView(cfg, poolStatus("p1", 1, 1, 100, 90)))
	m.evaluate() // raise
	if len(m.ActiveAlarms()) != 1 {
		t.Fatal("precondition: p1 raised")
	}
	rec.reset()

	// Remove the only referencing rule; pool p1 STAYS in SourcePools.
	cfg2 := cfgWith(80, 70, false)
	cfg2.Security.NAT.Source = []*config.NATRuleSet{{Name: "rs1", Rules: nil}}
	// Keep p1 present in the snapshot (still configured) to prove it is the
	// un-reference, not snapshot absence, that clears it.
	vb.set(coherentView(cfg2, poolStatus("p1", 1, 1, 100, 90)))
	m.evaluate()
	if len(m.ActiveAlarms()) != 0 {
		t.Fatal("un-referenced pool alarm must be pruned/cleared")
	}
	if got := countMatch(rec.snapshot(), clearedTag); got != 1 {
		t.Fatalf("un-reference must emit a clear, got %d", got)
	}
}

// TestEligibleButAbsentHolds: a rule-referenced non-deterministic pool with an
// active alarm but NO snapshot entry this tick HOLDS (not cleared). Mutation:
// snapshot-derived eligibility (the r4 bug) would clear it.
func TestEligibleButAbsentHolds(t *testing.T) {
	m, rec, vb := newMon()
	cfg := cfgWith(80, 70, false)
	vb.set(coherentView(cfg, poolStatus("p1", 1, 1, 100, 90)))
	m.evaluate() // raise
	rec.reset()

	// Same config (p1 still referenced + configured) but NO pool sample.
	vb.set(coherentView(cfg)) // empty Pools
	m.evaluate()
	if len(m.ActiveAlarms()) != 1 {
		t.Fatal("referenced-but-absent pool must HOLD, not clear")
	}
	if got := countMatch(rec.snapshot(), clearedTag); got != 0 {
		t.Fatalf("HOLD must emit nothing, got %d clears", got)
	}
}

// TestTransientUncomputableHolds: an already-raised alarm with a transient
// uncomputable sample (AddressCount==0 / PortHigh<PortLow / capacity 0) HOLDS.
func TestTransientUncomputableHolds(t *testing.T) {
	cases := []struct {
		name string
		s    PoolStatus
	}{
		{"addr0", poolStatus("p1", 0, 1, 100, 90)},
		{"badports", poolStatus("p1", 1, 100, 1, 90)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, rec, vb := newMon()
			cfg := cfgWith(80, 70, false)
			vb.set(coherentView(cfg, poolStatus("p1", 1, 1, 100, 90)))
			m.evaluate() // raise
			rec.reset()
			vb.set(coherentView(cfg, tc.s))
			m.evaluate()
			if len(m.ActiveAlarms()) != 1 {
				t.Fatal("uncomputable sample must HOLD a raised alarm")
			}
			if got := countMatch(rec.snapshot(), clearedTag); got != 0 {
				t.Fatalf("HOLD must not clear, got %d", got)
			}
		})
	}
}

// TestDeterministicSkipped: a deterministic pool is never raised; if referenced
// while raised becomes deterministic, the alarm is pruned/cleared.
func TestDeterministicSkipped(t *testing.T) {
	m, _, vb := newMon()
	detCfg := cfgWith(80, 70, true)
	vb.set(coherentView(detCfg, poolStatus("p1", 1, 1, 100, 95)))
	m.evaluate()
	if len(m.ActiveAlarms()) != 0 {
		t.Fatal("deterministic pool must not raise")
	}

	// Non-deterministic raise, then convert to deterministic → prune clears.
	m2, rec2, vb2 := newMon()
	cfg := cfgWith(80, 70, false)
	vb2.set(coherentView(cfg, poolStatus("p1", 1, 1, 100, 95)))
	m2.evaluate() // raise
	rec2.reset()
	vb2.set(coherentView(cfgWith(80, 70, true), poolStatus("p1", 1, 1, 100, 95)))
	m2.evaluate()
	if len(m2.ActiveAlarms()) != 0 {
		t.Fatal("convert-to-deterministic must clear the alarm")
	}
	if got := countMatch(rec2.snapshot(), clearedTag); got != 1 {
		t.Fatalf("det-convert must emit a clear, got %d", got)
	}
}

// TestNoDoubleCount: two rules sharing one pool report identical UsedPorts; the
// View is deduped (one entry per pool), so the pct is from one entry, not the
// sum. Capacity 100, used 50 → 50%, below raise(80): must NOT raise. (If summed
// to 100 used → 100% → would raise.)
func TestNoDoubleCount(t *testing.T) {
	m, _, vb := newMon()
	cfg := cfgWith(80, 70, false)
	// Add a second rule referencing the same pool.
	cfg.Security.NAT.Source = []*config.NATRuleSet{
		{Name: "rs1", Rules: []*config.NATRule{
			{Name: "r1", Then: config.NATThen{Type: config.NATSource, PoolName: "p1"}},
			{Name: "r2", Then: config.NATThen{Type: config.NATSource, PoolName: "p1"}},
		}},
	}
	// View deduped: ONE entry for p1 (50 used of 100 → 50%).
	vb.set(coherentView(cfg, poolStatus("p1", 1, 1, 100, 50)))
	m.evaluate()
	if len(m.ActiveAlarms()) != 0 {
		t.Fatal("deduped 50% must not raise; summing would (false alarm)")
	}
}

// TestNilConfigClearsAll: a nil config clears every active alarm (and emits the
// clears), no panic.
func TestNilConfigClearsAll(t *testing.T) {
	m, rec, vb := newMon()
	cfg := cfgWith(80, 70, false)
	vb.set(coherentView(cfg, poolStatus("p1", 1, 1, 100, 90)))
	m.evaluate() // raise
	rec.reset()

	vb.set(View{Config: nil, HelperCoherent: true, Available: true})
	m.evaluate()
	if len(m.ActiveAlarms()) != 0 {
		t.Fatal("nil config must clear all alarms")
	}
	if got := countMatch(rec.snapshot(), clearedTag); got != 1 {
		t.Fatalf("nil config must emit clear for the active alarm, got %d", got)
	}
}

// TestFeatureDisabledClearsAll: disabling the alarm (config present, alarmCfg
// nil) clears every active alarm and emits the clears.
func TestFeatureDisabledClearsAll(t *testing.T) {
	m, rec, vb := newMon()
	cfg := cfgWith(80, 70, false)
	vb.set(coherentView(cfg, poolStatus("p1", 1, 1, 100, 90)))
	m.evaluate() // raise
	rec.reset()

	cfgDisabled := cfgWith(80, 70, false)
	cfgDisabled.Security.NAT.PoolUtilizationAlarm = nil
	vb.set(coherentView(cfgDisabled, poolStatus("p1", 1, 1, 100, 90)))
	m.evaluate()
	if len(m.ActiveAlarms()) != 0 {
		t.Fatal("disabling the feature must clear all alarms")
	}
	if got := countMatch(rec.snapshot(), clearedTag); got != 1 {
		t.Fatalf("feature-disable must emit clear, got %d", got)
	}
}

// TestUnavailableHoldsAll: !Available (dp nil / helper down) HOLDs every alarm,
// emits nothing. Mutation: clearing on unavailable fails this test.
func TestUnavailableHoldsAll(t *testing.T) {
	m, rec, vb := newMon()
	cfg := cfgWith(80, 70, false)
	vb.set(coherentView(cfg, poolStatus("p1", 1, 1, 100, 90)))
	m.evaluate() // raise
	rec.reset()

	vb.set(View{Available: false})
	m.evaluate()
	if len(m.ActiveAlarms()) != 1 {
		t.Fatal("unavailable view must HOLD all alarms (no clear)")
	}
	if len(rec.snapshot()) != 0 {
		t.Fatal("unavailable view must emit nothing")
	}
}

// TestNotCoherentHoldsAll: Available but !HelperCoherent (mid-apply) HOLDs.
func TestNotCoherentHoldsAll(t *testing.T) {
	m, rec, vb := newMon()
	cfg := cfgWith(80, 70, false)
	vb.set(coherentView(cfg, poolStatus("p1", 1, 1, 100, 90)))
	m.evaluate() // raise
	rec.reset()

	// Available but counters belong to a different generation than config.
	vb.set(View{Config: cfg, Pools: map[string]PoolStatus{}, Available: true, HelperCoherent: false})
	m.evaluate()
	if len(m.ActiveAlarms()) != 1 {
		t.Fatal("mid-apply (not coherent) must HOLD all alarms")
	}
	if len(rec.snapshot()) != 0 {
		t.Fatal("mid-apply must emit nothing")
	}
}

// TestUpdatePctNoSyslog: a raised pool whose utilization changes but stays
// above clear gets its displayed pct refreshed WITHOUT emitting a line.
// Mutation: dropping updatePct leaves the pct stuck → this fails.
func TestUpdatePctNoSyslog(t *testing.T) {
	m, rec, vb := newMon()
	cfg := cfgWith(80, 70, false)
	vb.set(coherentView(cfg, poolStatus("p1", 1, 1, 100, 90)))
	m.evaluate() // raise at 90
	if a := m.ActiveAlarms(); len(a) != 1 || a[0].CurrentPct != 90 {
		t.Fatalf("expected pct 90, got %+v", a)
	}
	rec.reset()

	// Still above clear (95), changed: refresh pct, no syslog.
	vb.set(coherentView(cfg, poolStatus("p1", 1, 1, 100, 95)))
	m.evaluate()
	if a := m.ActiveAlarms(); len(a) != 1 || a[0].CurrentPct != 95 {
		t.Fatalf("expected refreshed pct 95, got %+v", a)
	}
	if len(rec.snapshot()) != 0 {
		t.Fatalf("updatePct must NOT emit a syslog line, got %v", rec.snapshot())
	}
}

// TestRaiseSeverityAndShape: the raise/clear lines carry the right severity and
// RT_NAT shape (formatter contract).
func TestRaiseSeverityAndShape(t *testing.T) {
	m, rec, vb := newMon()
	cfg := cfgWith(80, 70, false)
	vb.set(coherentView(cfg, poolStatus("p1", 1, 1, 100, 90)))
	m.evaluate()
	lines := rec.snapshot()
	if len(lines) != 1 {
		t.Fatalf("expected 1 line, got %d", len(lines))
	}
	if lines[0].sev != severityRaise {
		t.Fatalf("raise severity = %d, want %d", lines[0].sev, severityRaise)
	}
	if !strings.HasPrefix(lines[0].msg, "RT_NAT") || !strings.Contains(lines[0].msg, "pool-name=\"p1\"") {
		t.Fatalf("raise line shape wrong: %q", lines[0].msg)
	}

	rec.reset()
	vb.set(coherentView(cfg, poolStatus("p1", 1, 1, 100, 10)))
	m.evaluate()
	lines = rec.snapshot()
	if len(lines) != 1 || lines[0].sev != severityClear {
		t.Fatalf("clear severity wrong: %+v", lines)
	}
}

// TestStartStopNoSampler: Start with a nil sampler does not block Stop.
func TestStartStopNoSampler(t *testing.T) {
	m := New(nil, nil)
	m.Start()
	done := make(chan struct{})
	go func() { m.Stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop blocked with nil sampler")
	}
}

// TestStopWithoutStart: Stop must not block when Start was never called.
func TestStopWithoutStart(t *testing.T) {
	vb := &viewBox{}
	m := New(vb.get, nil) // valid sampler, but never Start()ed
	done := make(chan struct{})
	go func() { m.Stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop blocked when Start was never called")
	}
}

// TestDoubleStartStop: Start twice + Stop twice must not panic or block.
func TestDoubleStartStop(t *testing.T) {
	vb := &viewBox{}
	m := New(vb.get, nil)
	m.tick = time.Hour
	m.Start()
	m.Start() // second Start is a no-op
	done := make(chan struct{})
	go func() {
		m.Stop()
		m.Stop() // second Stop is a no-op
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("double Start/Stop blocked or deadlocked")
	}
}

// TestStartTriggersEvaluate: Start runs an immediate evaluation so an
// already-over-threshold pool surfaces without waiting a full tick.
func TestStartTriggersEvaluate(t *testing.T) {
	rec := &emitRec{}
	vb := &viewBox{}
	cfg := cfgWith(80, 70, false)
	vb.set(coherentView(cfg, poolStatus("p1", 1, 1, 100, 90)))
	m := New(vb.get, rec.emit)
	m.tick = time.Hour // ensure only the startup evaluate runs
	m.Start()
	defer m.Stop()

	deadline := time.After(2 * time.Second)
	for {
		if len(m.ActiveAlarms()) == 1 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("startup evaluate did not raise within deadline")
		case <-time.After(10 * time.Millisecond):
		}
	}
	if got := countMatch(rec.snapshot(), raisedTag); got != 1 {
		t.Fatalf("expected 1 raise from startup evaluate, got %d", got)
	}
}
