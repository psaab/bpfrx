// Package natpoolalarm implements the runtime consumer for the Junos
// `set security nat source pool-utilization-alarm raise-threshold/clear-threshold`
// stanza (#2079). The stanza was parsed and stored but had no consumer, so an
// operator who configured it got silent no-op behaviour — contrary to vSRX,
// where crossing the raise threshold raises a system alarm visible in
// `show security alarms` and emits a NAT syslog event, and dropping below the
// clear threshold clears it.
//
// This monitor closes that gap entirely in the control plane: a slow (10s)
// daemon-resident loop reads the helper's LAST-APPLIED NAT pool snapshot
// (config + same-generation pool counters) via an injected sampler, computes
// per-pool port utilization, applies raise/clear hysteresis, maintains an
// in-memory active-alarm set surfaced by both `show security alarms` render
// sites, and emits ONE structured RT_NAT syslog line per raise/clear
// transition (never per tick).
//
// Design constraints (see docs/research/2079-nat-pool-util-alarm/plan.md):
//   - No Rust / wire change: the helper already echoes 1 Hz pool counters and
//     last_snapshot_generation; this is pure Go.
//   - No new control-socket request: the sampler reads the manager's cached
//     status + applied snapshot (AppliedNATView), no socket I/O (CLAUDE.md
//     control-socket-contention rule).
//   - Generation coherency: all raise/clear/prune logic runs only when the
//     sampled view is Available AND HelperCoherent (config and counters are
//     the same applied generation); otherwise the monitor HOLDs all alarms.
package natpoolalarm

import (
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// DefaultTickInterval is the slow evaluation cadence. The alarm is not
// latency-critical and the sampler reads only cached in-memory state, so 10s
// keeps overhead negligible and damps flap near the threshold band.
const DefaultTickInterval = 10 * time.Second

// Syslog severity levels (RFC 3164 numeric) used for transition lines. Raise
// is warning (4, "minor" in Junos alarm terms); clear is notice (5).
const (
	severityRaise = 4
	severityClear = 5
)

// PoolStatus is one source-NAT pool's deduplicated live utilization sample,
// already keyed by pool name (rules sharing a pool report identical UsedPorts
// via a shared allocator, so the sampler takes one entry per pool — never
// summed). It is a dataplane-package-free projection so this package does not
// depend on pkg/dataplane/userspace.
type PoolStatus struct {
	PoolName     string
	AddressCount int
	PortLow      uint16
	PortHigh     uint16
	UsedPorts    uint64
}

// View is one generation-coherent sample for the monitor. Config and Pools
// both belong to the helper's last-applied generation.
type View struct {
	// Config is the helper's currently applied configuration; may be nil
	// before the first apply lands.
	Config *config.Config
	// Pools is deduplicated by pool name (one entry per pool).
	Pools map[string]PoolStatus
	// HelperCoherent is true when the cached pool counters belong to the same
	// applied generation as Config (no in-flight apply). When false the
	// monitor HOLDs numeric raise/clear for this tick.
	HelperCoherent bool
	// Available is false when the dataplane helper is not running or no apply
	// has landed. When false the monitor HOLDs ALL alarms (no clear): no data
	// is not a decision to clear.
	Available bool
}

// Sampler returns the current generation-coherent NAT view. It must read only
// cached in-memory state (no control-socket I/O).
type Sampler func() View

// Emitter sends one pre-formatted structured syslog line at the given numeric
// severity to all configured syslog streams and local writers. The daemon
// wires this to logging.EventReader.ForwardLogMsg; tests inject a recorder.
type Emitter func(severity int, msg string)

// ActiveAlarm is a thread-safe snapshot of one active NAT pool alarm for the
// `show security alarms` render sites.
type ActiveAlarm struct {
	PoolName       string
	CurrentPct     uint64
	RaiseThreshold int
	FirstSeen      time.Time
}

// alarmState is the per-pool internal record while raised.
type alarmState struct {
	pct       uint64
	raiseThr  int
	firstSeen time.Time
}

// Monitor evaluates NAT pool utilization on a slow tick and maintains the
// active-alarm set.
type Monitor struct {
	sample Sampler
	emit   Emitter
	tick   time.Duration
	nowFn  func() time.Time

	mu      sync.Mutex
	active  map[string]*alarmState
	started bool // run() launched (guards Stop against an unstarted monitor)

	stop chan struct{}
	done chan struct{}
}

// New constructs a Monitor. sample and emit are dependency-injected so the
// monitor is unit-testable without a live dataplane or syslog client. A nil
// emit is tolerated (alarms still surface in `show security alarms`).
func New(sample Sampler, emit Emitter) *Monitor {
	return &Monitor{
		sample: sample,
		emit:   emit,
		tick:   DefaultTickInterval,
		nowFn:  time.Now,
		active: make(map[string]*alarmState),
		stop:   make(chan struct{}),
		done:   make(chan struct{}),
	}
}

// SetTickForTest overrides the evaluation cadence. It MUST be called before
// Start (the running loop captures m.tick once). Intended only for tests that
// need the sampler to fire rapidly — e.g. the #2114 daemon race regression
// test, which drives the monitor's d.dp sampler against a concurrent
// bootstrap-exit d.dp transition under the race detector.
func (m *Monitor) SetTickForTest(d time.Duration) {
	if m == nil || d <= 0 {
		return
	}
	m.mu.Lock()
	if !m.started {
		m.tick = d
	}
	m.mu.Unlock()
}

// Start launches the evaluation loop. It is a no-op if the monitor is nil or
// the sampler is nil, and is safe to call at most once.
func (m *Monitor) Start() {
	if m == nil || m.sample == nil {
		return
	}
	m.mu.Lock()
	if m.started {
		m.mu.Unlock()
		return
	}
	m.started = true
	m.mu.Unlock()
	go m.run()
}

// Stop terminates the evaluation loop and waits for it to exit. It is safe to
// call whether or not Start was ever called (an unstarted monitor's loop never
// ran, so there is no goroutine to join) and is idempotent.
func (m *Monitor) Stop() {
	if m == nil {
		return
	}
	m.mu.Lock()
	started := m.started
	m.mu.Unlock()
	select {
	case <-m.stop:
		// already stopped
	default:
		close(m.stop)
	}
	if started {
		<-m.done // join the run() goroutine
	}
}

func (m *Monitor) run() {
	defer close(m.done)
	t := time.NewTicker(m.tick)
	defer t.Stop()
	// Evaluate once promptly so an alarm that is already over threshold at
	// startup surfaces within the first tick rather than after a full period.
	m.evaluate()
	for {
		select {
		case <-t.C:
			m.evaluate()
		case <-m.stop:
			return
		}
	}
}

// evaluate runs one tick of the raise/clear/hysteresis/prune logic. It is the
// unit-test entry point (drive it directly with a synthetic Sampler).
func (m *Monitor) evaluate() {
	view := m.sample()

	// dp nil / helper down → HOLD all alarms (no clear): no data is not a
	// decision to clear.
	if !view.Available {
		return
	}
	// Mid-apply (status gen != applied gen) → counters/config transiently
	// mismatched → HOLD all this tick.
	if !view.HelperCoherent {
		return
	}

	cfg := view.Config
	// Fail-closed nil config: clear every active alarm and return.
	if cfg == nil {
		m.clearAll("alarm config unavailable")
		return
	}
	alarmCfg := cfg.Security.NAT.PoolUtilizationAlarm
	if alarmCfg == nil ||
		alarmCfg.RaiseThreshold <= 0 || alarmCfg.RaiseThreshold > 100 ||
		alarmCfg.ClearThreshold <= 0 || alarmCfg.ClearThreshold >= alarmCfg.RaiseThreshold {
		// Feature disabled / unset: clear every active alarm and return.
		m.clearAll("pool-utilization-alarm disabled")
		return
	}

	// Eligibility is RULE-REFERENCED config: a pool is eligible only if a
	// configured source-NAT rule references it AND the pool exists AND it is
	// non-deterministic. The status producer is rule-derived, so a pool with
	// no referencing rule never appears in the snapshot — iterating
	// SourcePools directly would HOLD its alarm forever (the prune never
	// fires). Mirror buildSourceNATSnapshots' defensive nil skips.
	referenced := map[string]bool{}
	for _, rs := range cfg.Security.NAT.Source {
		if rs == nil {
			continue
		}
		for _, rule := range rs.Rules {
			if rule == nil {
				continue
			}
			if rule.Then.PoolName != "" {
				referenced[rule.Then.PoolName] = true
			}
		}
	}

	eligible := map[string]bool{}
	for poolName := range referenced {
		p, ok := cfg.Security.NAT.SourcePools[poolName]
		if !ok || p == nil {
			continue // rule references a missing pool → not eligible
		}
		if p.Deterministic != nil {
			continue // deterministic pools are skipped in r1
		}
		eligible[poolName] = true

		s, present := view.Pools[poolName]
		if !present {
			continue // eligible but absent this tick → HOLD
		}
		if s.AddressCount == 0 || uint64(s.PortHigh) < uint64(s.PortLow) {
			continue // bad sample → HOLD
		}
		// Cast operands to uint64 BEFORE the arithmetic so the uint16 port
		// range cannot underflow before promotion.
		capacity := uint64(s.AddressCount) * (uint64(s.PortHigh) - uint64(s.PortLow) + 1)
		if capacity == 0 {
			continue // uncomputable → HOLD (NOT a clear)
		}
		pct := s.UsedPorts * 100 / capacity

		raised := m.isRaised(poolName)
		switch {
		case !raised && pct >= uint64(alarmCfg.RaiseThreshold):
			m.raise(poolName, pct, alarmCfg.RaiseThreshold)
		case raised && pct < uint64(alarmCfg.ClearThreshold):
			m.clear(poolName, "utilization below clear-threshold")
		case raised:
			// Held above clear: refresh the displayed pct only, no syslog.
			m.updatePct(poolName, pct)
		}
	}

	// Prune alarms for any pool no longer ELIGIBLE (rule-unreferenced,
	// config-removed, or converted to deterministic). Snapshot the key set
	// under the mutex first, then emit clears WITHOUT holding the mutex across
	// the (blocking) syslog write. This runs unconditionally (eligibility is
	// config-derived) — but here it is already gated behind Available +
	// HelperCoherent, which makes cfg the applied config.
	for _, poolName := range m.activeKeys() {
		if !eligible[poolName] {
			m.clear(poolName, "pool no longer eligible")
		}
	}
}

// isRaised reports whether the pool currently has an active alarm.
func (m *Monitor) isRaised(poolName string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.active[poolName]
	return ok
}

// activeKeys returns a snapshot of active-alarm pool names taken under the
// mutex, so callers can iterate and emit clears without holding the lock.
func (m *Monitor) activeKeys() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	keys := make([]string, 0, len(m.active))
	for k := range m.active {
		keys = append(keys, k)
	}
	return keys
}

// raise records a new active alarm and emits one raise syslog line.
func (m *Monitor) raise(poolName string, pct uint64, raiseThr int) {
	m.mu.Lock()
	if _, ok := m.active[poolName]; ok {
		// Already raised — should not happen (caller gates on !raised), but
		// keep idempotent: refresh pct, no duplicate syslog.
		m.active[poolName].pct = pct
		m.mu.Unlock()
		return
	}
	m.active[poolName] = &alarmState{pct: pct, raiseThr: raiseThr, firstSeen: m.nowFn()}
	m.mu.Unlock()

	m.emitLine(severityRaise, fmt.Sprintf(
		"RT_NAT - NAT_POOL_UTILIZATION_ALARM_RAISED pool-name=%q utilization=%d%% raise-threshold=%d%%",
		poolName, pct, raiseThr))
}

// clear removes an active alarm and emits one clear syslog line. It is a no-op
// (no emission) if the pool has no active alarm, so a single transition never
// double-clears.
func (m *Monitor) clear(poolName, reason string) {
	m.mu.Lock()
	st, ok := m.active[poolName]
	if !ok {
		m.mu.Unlock()
		return
	}
	pct := st.pct
	delete(m.active, poolName)
	m.mu.Unlock()

	m.emitLine(severityClear, fmt.Sprintf(
		"RT_NAT - NAT_POOL_UTILIZATION_ALARM_CLEARED pool-name=%q utilization=%d%% reason=%q",
		poolName, pct, reason))
}

// clearAll clears every active alarm (each via clear, so each emits a clear
// line). Used on the feature-disabled / nil-config early returns.
func (m *Monitor) clearAll(reason string) {
	for _, poolName := range m.activeKeys() {
		m.clear(poolName, reason)
	}
}

// updatePct refreshes the displayed pct for an already-raised pool that stays
// above the clear threshold. No transition → no syslog.
func (m *Monitor) updatePct(poolName string, pct uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if st, ok := m.active[poolName]; ok {
		st.pct = pct
	}
}

func (m *Monitor) emitLine(severity int, msg string) {
	if m.emit != nil {
		m.emit(severity, msg)
	}
}

// ActiveAlarms returns a sorted, thread-safe snapshot of the active NAT pool
// alarms for the `show security alarms` render sites.
func (m *Monitor) ActiveAlarms() []ActiveAlarm {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	out := make([]ActiveAlarm, 0, len(m.active))
	for name, st := range m.active {
		out = append(out, ActiveAlarm{
			PoolName:       name,
			CurrentPct:     st.pct,
			RaiseThreshold: st.raiseThr,
			FirstSeen:      st.firstSeen,
		})
	}
	m.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].PoolName < out[j].PoolName })
	return out
}
