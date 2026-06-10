// Package ipmon implements the `services ip-monitoring` engine
// (#1827 PR-1b, plan §4.3): probe-driven preferred-route injection
// with Junos semantics.
//
// State machine: a policy is FAIL while ANY test of its matched RPM
// probe is FAILED; it recovers when all tests pass (after the optional
// hold-down, an extension beyond Junos that damps recovery flaps —
// hold-down applies to recovery ONLY; a failure is acted on at the next
// debounce tick).
//
// The single decision point is the engine's effective-route overlay
// (ActiveOverlay): the set of currently-injected preferred routes after
// winner resolution — per (routing-instance, prefix) the lowest
// preferred-metric wins, tie-break lexicographic policy name. Both
// consumers (the FRR managed-section render and the userspace snapshot
// builder) read the same overlay, so kernel and dataplane agree by
// construction.
//
// Actuation is coalesced: a dirty bit with a bounded debounce (default
// 1 s) plus a minimum inter-actuation throttle (default 3 s), at most
// one actuation in flight (the single run-loop goroutine), and the
// actuator snapshots the overlay at run time (last-writer-wins) — a
// flap storm across N policies collapses to one actuation per throttle
// window. With hold-down 0 a sustained per-cycle flapper produces one
// actuation per throttle window indefinitely — bounded and observable
// via the per-policy transition counters.
//
// The overlay is runtime state, never config: it does not sync to the
// HA peer and re-derives from fresh probe results within seconds of a
// takeover.
package ipmon

import (
	"log/slog"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/rpm"
)

const (
	// DefaultDebounce is the bounded delay between the first pending
	// state change and the actuation that publishes it.
	DefaultDebounce = time.Second
	// DefaultThrottle is the minimum spacing between consecutive
	// actuations (frr-reload cooling window).
	DefaultThrottle = 3 * time.Second
)

// PolicyStatus is the per-policy view for show/metrics.
type PolicyStatus struct {
	Name              string
	Probe             string
	Failed            bool
	Since             time.Time // last state-change time (zero = never evaluated)
	FailingTests      []string
	HoldDownSecs      int
	PendingRecoveryAt time.Time // non-zero while a recovery hold-down is running
	Routes            []config.RouteOverlayEntry
	Transitions       uint64
}

type policyState struct {
	cfg               *config.IPMonitoringPolicy
	failed            bool
	since             time.Time
	pendingRecoveryAt time.Time
	transitions       uint64
}

// Engine evaluates ip-monitoring policies against RPM test state and
// triggers the route-overlay actuator through debounce + throttle.
type Engine struct {
	mu          sync.Mutex
	policies    map[string]*policyState
	failedTests map[string]map[string]bool // probe → test → failed

	// publishEnabled implements HA primary-only overlay publication
	// (§4.4): when false (standby), ActiveOverlay returns nil so the
	// actuator publishes the config baseline.
	publishEnabled bool

	dirtySince    time.Time // zero = clean
	lastActuation time.Time

	actuate  func() // daemon route-overlay actuator; called WITHOUT mu held
	now      func() time.Time
	debounce time.Duration
	throttle time.Duration

	kick chan struct{}
	stop chan struct{}
	done chan struct{}
}

// New creates an engine. actuate is the daemon's routes-only actuator;
// it is invoked from the engine's single run-loop goroutine (never
// concurrently) and must read ActiveOverlay() itself so it always
// publishes the freshest overlay.
func New(actuate func()) *Engine {
	return &Engine{
		policies:       make(map[string]*policyState),
		failedTests:    make(map[string]map[string]bool),
		publishEnabled: true,
		actuate:        actuate,
		now:            time.Now,
		debounce:       DefaultDebounce,
		throttle:       DefaultThrottle,
		kick:           make(chan struct{}, 1),
		stop:           make(chan struct{}),
		done:           make(chan struct{}),
	}
}

// Start launches the actuation loop.
func (e *Engine) Start() {
	go e.run()
}

// Stop terminates the actuation loop.
func (e *Engine) Stop() {
	select {
	case <-e.stop:
		return // already stopped
	default:
	}
	close(e.stop)
	<-e.done
}

// Apply installs a new policy set, preserving FAIL state for policies
// whose (name, probe) survives the commit, and seeds test state from
// the supplied results snapshot. Called under the daemon apply path on
// config change.
func (e *Engine) Apply(cfg *config.IPMonitoringConfig, results []*rpm.ProbeResult) {
	e.mu.Lock()
	next := make(map[string]*policyState)
	if cfg != nil {
		for name, pol := range cfg.Policies {
			if pol == nil {
				continue
			}
			st := &policyState{cfg: pol}
			if prev, ok := e.policies[name]; ok && prev.cfg.MatchRPMProbe == pol.MatchRPMProbe {
				st.failed = prev.failed
				st.since = prev.since
				st.pendingRecoveryAt = prev.pendingRecoveryAt
				st.transitions = prev.transitions
			}
			next[name] = st
		}
	}
	e.policies = next
	e.seedResultsLocked(results)
	e.evaluateLocked(e.now())
	// A config change always re-actuates: the overlay view may have
	// changed even without a policy state flip (routes edited).
	e.markDirtyLocked(true)
	e.mu.Unlock()
	e.kickLoop()
}

// HandleTransition is the rpm.TransitionCallback sensor input.
func (e *Engine) HandleTransition(t rpm.Transition) {
	e.mu.Lock()
	// The transition carries a full current-state snapshot — seed from
	// it (authoritative) and overlay the transition itself (the
	// snapshot already reflects it, but be explicit).
	e.seedResultsLocked(t.Results)
	if e.failedTests[t.ProbeName] == nil {
		e.failedTests[t.ProbeName] = make(map[string]bool)
	}
	e.failedTests[t.ProbeName][t.TestName] = t.Status == "fail"
	changed := e.evaluateLocked(e.now())
	e.markDirtyLocked(changed)
	e.mu.Unlock()
	if changed {
		e.kickLoop()
	}
}

// SetPublishEnabled gates overlay publication (HA primary-only, §4.4).
// Flipping the gate triggers an actuation: on standby the baseline is
// published; on takeover the baseline goes out first and the overlay
// follows fresh probe results.
func (e *Engine) SetPublishEnabled(enabled bool) {
	e.mu.Lock()
	if e.publishEnabled == enabled {
		e.mu.Unlock()
		return
	}
	e.publishEnabled = enabled
	e.markDirtyLocked(true)
	e.mu.Unlock()
	e.kickLoop()
	slog.Info("ip-monitoring overlay publication gate changed", "enabled", enabled)
}

// PublishEnabled reports the HA gate state.
func (e *Engine) PublishEnabled() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.publishEnabled
}

// ActiveOverlay returns the winner-resolved effective-route overlay:
// one entry per (routing-instance, family, prefix) across all policies
// currently in FAIL. Returns nil while publication is gated off
// (standby) — the config baseline.
func (e *Engine) ActiveOverlay() []config.RouteOverlayEntry {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.activeOverlayLocked()
}

func (e *Engine) activeOverlayLocked() []config.RouteOverlayEntry {
	if !e.publishEnabled {
		return nil
	}
	type candidate struct {
		metric int
		policy string
		entry  config.RouteOverlayEntry
	}
	best := make(map[string]candidate)
	for name, st := range e.policies {
		if !st.failed {
			continue
		}
		for _, pr := range st.cfg.PreferredRoutes {
			dest := canonicalCIDR(pr.Destination)
			if dest == "" {
				continue // commit validation prevents this
			}
			key := pr.RoutingInstance + "|" + dest
			cand := candidate{
				metric: pr.PreferredMetric,
				policy: name,
				entry: config.RouteOverlayEntry{
					RoutingInstance: pr.RoutingInstance,
					Destination:     dest,
					NextHop:         pr.NextHop,
					Metric:          pr.PreferredMetric,
					Policy:          name,
				},
			}
			ex, ok := best[key]
			if !ok || cand.metric < ex.metric ||
				(cand.metric == ex.metric && cand.policy < ex.policy) {
				best[key] = cand
			}
		}
	}
	if len(best) == 0 {
		return nil
	}
	out := make([]config.RouteOverlayEntry, 0, len(best))
	for _, c := range best {
		out = append(out, c.entry)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].RoutingInstance != out[j].RoutingInstance {
			return out[i].RoutingInstance < out[j].RoutingInstance
		}
		return out[i].Destination < out[j].Destination
	})
	return out
}

// Status returns the per-policy view, with each policy's currently
// winning routes attached.
func (e *Engine) Status() []PolicyStatus {
	e.mu.Lock()
	defer e.mu.Unlock()

	overlay := e.activeOverlayLocked()
	byPolicy := make(map[string][]config.RouteOverlayEntry)
	for _, entry := range overlay {
		byPolicy[entry.Policy] = append(byPolicy[entry.Policy], entry)
	}

	names := make([]string, 0, len(e.policies))
	for name := range e.policies {
		names = append(names, name)
	}
	sort.Strings(names)

	out := make([]PolicyStatus, 0, len(names))
	for _, name := range names {
		st := e.policies[name]
		ps := PolicyStatus{
			Name:              name,
			Probe:             st.cfg.MatchRPMProbe,
			Failed:            st.failed,
			Since:             st.since,
			HoldDownSecs:      st.cfg.HoldDownSecs,
			PendingRecoveryAt: st.pendingRecoveryAt,
			Routes:            byPolicy[name],
			Transitions:       st.transitions,
		}
		for test, failed := range e.failedTests[st.cfg.MatchRPMProbe] {
			if failed {
				ps.FailingTests = append(ps.FailingTests, test)
			}
		}
		sort.Strings(ps.FailingTests)
		out = append(out, ps)
	}
	return out
}

// RoutesApplied returns the number of overlay routes currently applied.
func (e *Engine) RoutesApplied() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.activeOverlayLocked())
}

// seedResultsLocked rebuilds per-test fail state from a results
// snapshot.
func (e *Engine) seedResultsLocked(results []*rpm.ProbeResult) {
	if results == nil {
		return
	}
	fresh := make(map[string]map[string]bool)
	for _, r := range results {
		if r == nil {
			continue
		}
		if fresh[r.ProbeName] == nil {
			fresh[r.ProbeName] = make(map[string]bool)
		}
		fresh[r.ProbeName][r.TestName] = r.LastStatus == "fail"
	}
	e.failedTests = fresh
}

// evaluateLocked runs the FAIL/recover state machine at time now.
// Returns true when any policy changed state.
func (e *Engine) evaluateLocked(now time.Time) bool {
	changed := false
	for name, st := range e.policies {
		anyFailed := false
		for _, failed := range e.failedTests[st.cfg.MatchRPMProbe] {
			if failed {
				anyFailed = true
				break
			}
		}
		switch {
		case anyFailed && !st.failed:
			st.failed = true
			st.since = now
			st.pendingRecoveryAt = time.Time{}
			st.transitions++
			changed = true
			slog.Info("ip-monitoring policy FAILED — injecting preferred routes",
				"policy", name, "probe", st.cfg.MatchRPMProbe)
		case anyFailed && st.failed:
			// Still failed: cancel any pending recovery.
			st.pendingRecoveryAt = time.Time{}
		case !anyFailed && st.failed:
			hold := time.Duration(st.cfg.HoldDownSecs) * time.Second
			if hold > 0 {
				if st.pendingRecoveryAt.IsZero() {
					st.pendingRecoveryAt = now.Add(hold)
					slog.Info("ip-monitoring policy recovery hold-down started",
						"policy", name, "hold_down", hold)
					continue
				}
				if now.Before(st.pendingRecoveryAt) {
					continue
				}
			}
			st.failed = false
			st.since = now
			st.pendingRecoveryAt = time.Time{}
			st.transitions++
			changed = true
			slog.Info("ip-monitoring policy recovered — withdrawing preferred routes",
				"policy", name, "probe", st.cfg.MatchRPMProbe)
		}
	}
	return changed
}

func (e *Engine) markDirtyLocked(changed bool) {
	if changed && e.dirtySince.IsZero() {
		e.dirtySince = e.now()
	}
}

func (e *Engine) kickLoop() {
	select {
	case e.kick <- struct{}{}:
	default:
	}
}

// run is the single actuation goroutine: it owns debounce, throttle,
// hold-down wakeups, and the at-most-one-actuation-in-flight invariant.
func (e *Engine) run() {
	defer close(e.done)
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	for {
		e.mu.Lock()
		// Re-evaluate for hold-down expiry before computing the wake.
		changed := e.evaluateLocked(e.now())
		e.markDirtyLocked(changed)

		now := e.now()
		fire := false
		if !e.dirtySince.IsZero() &&
			now.Sub(e.dirtySince) >= e.debounce &&
			now.Sub(e.lastActuation) >= e.throttle {
			fire = true
			e.dirtySince = time.Time{}
			e.lastActuation = now
		}
		wake := e.nextWakeLocked(now)
		e.mu.Unlock()

		if fire && e.actuate != nil {
			// Outside the lock; the actuator reads ActiveOverlay()
			// itself, so it publishes the freshest state
			// (last-writer-wins under flap storms).
			e.actuate()
		}

		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(wake)
		select {
		case <-e.kick:
		case <-timer.C:
		case <-e.stop:
			return
		}
	}
}

// nextWakeLocked computes how long the loop may sleep: the earliest of
// the debounce/throttle deadline for a pending dirty bit and any
// recovery hold-down expiry. Parks for an hour when idle.
func (e *Engine) nextWakeLocked(now time.Time) time.Duration {
	wake := time.Hour
	consider := func(t time.Time) {
		if t.IsZero() {
			return
		}
		d := t.Sub(now)
		if d < time.Millisecond {
			d = time.Millisecond
		}
		if d < wake {
			wake = d
		}
	}
	if !e.dirtySince.IsZero() {
		debounceAt := e.dirtySince.Add(e.debounce)
		throttleAt := e.lastActuation.Add(e.throttle)
		if throttleAt.After(debounceAt) {
			consider(throttleAt)
		} else {
			consider(debounceAt)
		}
	}
	for _, st := range e.policies {
		consider(st.pendingRecoveryAt)
	}
	return wake
}

// canonicalCIDR normalizes a prefix string (mask-aligned) so overlay
// matching against snapshot/FRR destinations is well-defined.
func canonicalCIDR(s string) string {
	_, n, err := net.ParseCIDR(s)
	if err != nil || n == nil {
		return ""
	}
	return n.String()
}

// FilterOverlayForConfig drops overlay entries that an INCOMING config
// no longer backs: entries whose owning policy was removed, or whose
// preferred-route spec (routing-instance, prefix, next-hop, metric)
// was edited (Codex review on PR #1843, HIGH-1). The full apply path
// caches the engine's overlay BEFORE reconcileIPMon installs the new
// policy set, so without this filter a commit that removes or edits a
// policy would republish the STALE overlay to both consumers (FRR +
// snapshot) until the delayed actuator caught up. Only still-valid
// entries ride the commit's own publish; the post-commit
// reconcile+actuation re-injects under the new spec if the probes
// still report FAILED.
func FilterOverlayForConfig(overlay []config.RouteOverlayEntry, ipmCfg *config.IPMonitoringConfig) []config.RouteOverlayEntry {
	if len(overlay) == 0 {
		return nil
	}
	if ipmCfg == nil || len(ipmCfg.Policies) == 0 {
		return nil
	}
	out := make([]config.RouteOverlayEntry, 0, len(overlay))
	for _, entry := range overlay {
		pol := ipmCfg.Policies[entry.Policy]
		if pol == nil {
			continue
		}
		backed := false
		for _, pr := range pol.PreferredRoutes {
			if pr == nil {
				continue
			}
			if pr.RoutingInstance == entry.RoutingInstance &&
				canonicalCIDR(pr.Destination) == entry.Destination &&
				pr.NextHop == entry.NextHop &&
				pr.PreferredMetric == entry.Metric {
				backed = true
				break
			}
		}
		if backed {
			out = append(out, entry)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
