package ipmon

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// #1844: interface-typed (DHCP-tracked) next-hop resolution.

// fakeResolver is a mutable NextHopResolver backing store.
type fakeResolver struct {
	mu  sync.Mutex
	gws map[string]string // lease key → gateway; absent = unresolvable
}

func (f *fakeResolver) set(key, gw string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.gws == nil {
		f.gws = make(map[string]string)
	}
	f.gws[key] = gw
}

func (f *fakeResolver) del(key string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.gws, key)
}

func (f *fakeResolver) resolve(key string) (string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	gw, ok := f.gws[key]
	return gw, ok
}

// dhcpPolicyConfig: two policies competing for 0.0.0.0/0 — the
// interface-typed one wins on metric when resolvable; the literal one
// is the losing static candidate.
func dhcpPolicyConfig() *config.IPMonitoringConfig {
	return &config.IPMonitoringConfig{Policies: map[string]*config.IPMonitoringPolicy{
		"dhcp-uplink": {
			Name:          "dhcp-uplink",
			MatchRPMProbe: "WAN",
			PreferredRoutes: []*config.PreferredRoute{
				{Destination: "0.0.0.0/0", NextHopInterface: "ge-0-0-3", PreferredMetric: 5},
			},
		},
		"static-backup": {
			Name:          "static-backup",
			MatchRPMProbe: "WAN",
			PreferredRoutes: []*config.PreferredRoute{
				{Destination: "0.0.0.0/0", NextHop: "172.16.50.1", PreferredMetric: 10},
			},
		},
	}}
}

func failWAN(e *Engine) {
	e.HandleTransition(transition("WAN", "wan-a", "fail", passResults()))
}

// TestUnresolvableWinnerYieldsToStaticCandidate is the load-bearing
// test of the plan (§4.2): resolution happens BEFORE winner selection,
// so an unresolvable interface-typed winner (better metric, no lease)
// lets the losing static candidate win — the prefix is never left
// uncovered while a usable candidate exists.
func TestUnresolvableWinnerYieldsToStaticCandidate(t *testing.T) {
	e, _ := newTestEngine(nil)
	r := &fakeResolver{}
	e.SetNextHopResolver(r.resolve)
	e.Apply(dhcpPolicyConfig(), passResults())
	failWAN(e)

	// No lease: the static candidate must win.
	overlay := e.ActiveOverlay()
	if len(overlay) != 1 || overlay[0].NextHop != "172.16.50.1" || overlay[0].Policy != "static-backup" {
		t.Fatalf("overlay = %+v, want the static candidate winning", overlay)
	}

	// Lease acquired: the better-metric interface-typed candidate
	// takes over with the resolved gateway.
	r.set("ge-0-0-3", "198.51.100.1")
	overlay = e.ActiveOverlay()
	if len(overlay) != 1 || overlay[0].NextHop != "198.51.100.1" || overlay[0].Policy != "dhcp-uplink" {
		t.Fatalf("overlay = %+v, want resolved DHCP candidate winning", overlay)
	}
	if overlay[0].NextHopInterface != "ge-0-0-3" {
		t.Fatalf("overlay entry lease key = %q, want ge-0-0-3", overlay[0].NextHopInterface)
	}
}

// TestResolverWithdrawal: the resolver flipping ok→!ok (lease record
// removed) makes the next overlay computation omit the route (§4.5).
func TestResolverWithdrawal(t *testing.T) {
	e, _ := newTestEngine(nil)
	r := &fakeResolver{}
	r.set("ge-0-0-3", "198.51.100.1")
	e.SetNextHopResolver(r.resolve)
	cfg := dhcpPolicyConfig()
	delete(cfg.Policies, "static-backup")
	e.Apply(cfg, passResults())
	failWAN(e)

	if overlay := e.ActiveOverlay(); len(overlay) != 1 {
		t.Fatalf("overlay = %+v, want resolved route", overlay)
	}
	r.del("ge-0-0-3")
	if overlay := e.ActiveOverlay(); overlay != nil {
		t.Fatalf("overlay = %+v after lease removal, want nil (withdrawn)", overlay)
	}
	// Re-acquisition with a NEW gateway re-injects re-pointed.
	r.set("ge-0-0-3", "198.51.100.254")
	overlay := e.ActiveOverlay()
	if len(overlay) != 1 || overlay[0].NextHop != "198.51.100.254" {
		t.Fatalf("overlay = %+v, want re-resolved gateway", overlay)
	}
}

// TestNilResolverSkips: defensive — without a wired resolver,
// interface-typed candidates always skip (and report unresolved).
func TestNilResolverSkips(t *testing.T) {
	e, _ := newTestEngine(nil)
	cfg := dhcpPolicyConfig()
	delete(cfg.Policies, "static-backup")
	e.Apply(cfg, passResults())
	failWAN(e)

	if overlay := e.ActiveOverlay(); overlay != nil {
		t.Fatalf("overlay = %+v with nil resolver, want nil", overlay)
	}
	st := e.Status()
	if len(st) != 1 || len(st[0].UnresolvedRoutes) != 1 || st[0].UnresolvedRoutes[0].Destination != "0.0.0.0/0" {
		t.Fatalf("status = %+v, want one unresolved route", st)
	}
}

// TestStatusUnresolvedRoutes: a FAILED policy's skipped candidates are
// reported; a healthy policy reports none even with no lease.
func TestStatusUnresolvedRoutes(t *testing.T) {
	e, _ := newTestEngine(nil)
	r := &fakeResolver{}
	e.SetNextHopResolver(r.resolve)
	e.Apply(dhcpPolicyConfig(), passResults())

	// Healthy: nothing unresolved (candidates aren't even considered).
	for _, ps := range e.Status() {
		if len(ps.UnresolvedRoutes) != 0 {
			t.Fatalf("healthy policy reports unresolved: %+v", ps)
		}
	}

	failWAN(e)
	sts := e.Status()
	var dhcpPS *PolicyStatus
	for i := range sts {
		if sts[i].Name == "dhcp-uplink" {
			dhcpPS = &sts[i]
		}
	}
	if dhcpPS == nil || len(dhcpPS.UnresolvedRoutes) != 1 {
		t.Fatalf("dhcp-uplink status = %+v, want one unresolved route", dhcpPS)
	}
	// Resolvable again: unresolved clears, route appears.
	r.set("ge-0-0-3", "198.51.100.1")
	for _, ps := range e.Status() {
		if ps.Name == "dhcp-uplink" {
			if len(ps.UnresolvedRoutes) != 0 || len(ps.Routes) != 1 {
				t.Fatalf("resolved status = %+v", ps)
			}
		}
	}
}

// TestNotifyNextHopChangeGate: the trigger marks dirty ONLY when a
// currently FAILED policy has an interface-typed route — lease churn
// with healthy policies (or with literal-only policies) never
// actuates.
func TestNotifyNextHopChangeGate(t *testing.T) {
	var actuations atomic.Int32
	e := New(func(context.Context) bool { actuations.Add(1); return true })
	e.debounce = 5 * time.Millisecond
	e.throttle = 5 * time.Millisecond
	r := &fakeResolver{}
	r.set("ge-0-0-3", "198.51.100.1")
	e.SetNextHopResolver(r.resolve)
	e.Apply(dhcpPolicyConfig(), passResults())
	e.Start()
	defer e.Stop()

	// #8664: this test mixes two waiting idioms, and only one of them is safe.
	//
	//   - "something MUST happen" is polled to a deadline. A fixed budget is
	//     wrong here: it fails when the actuation is merely LATE, which is a
	//     property of the machine, not of the engine.
	//   - "nothing MUST happen" genuinely needs a fixed wait — an absence
	//     cannot be polled for — but the wait is expressed as a multiple of the
	//     engine's OWN debounce and throttle rather than a bare literal, so it
	//     tracks those timings if they are ever retuned.
	//
	// Measured rather than assumed: with the budgets cut to 4ms this test fails
	// at "probe failure did not actuate" and nowhere else, while lengthening
	// them to 400ms is clean over 20 runs. So the squeezed-budget direction is
	// the failing one, and it is that single assertion that feels it.
	//
	// Enlarging the sleeps was explicitly rejected as the remedy: it converts a
	// fast flake into a slow one, makes the next occurrence rarer and more
	// confusing, and leaves the racing assertion racing. So the absence windows
	// are the SAME 40ms they were — 4 * (5ms + 5ms) — and the only behavioural
	// change is that the "must happen" assertion polls instead of racing.
	settle := 4 * (e.debounce + e.throttle)

	// Healthy policies: gateway churn must not actuate.
	for i := 0; i < 3; i++ {
		e.NotifyNextHopChange()
	}
	time.Sleep(settle)
	if got := actuations.Load(); got != 0 {
		t.Fatalf("actuations = %d on healthy policies, want 0", got)
	}

	// FAILED interface-typed policy: the trigger actuates. POLLED, not slept:
	// this is a "must happen" assertion and a fixed budget makes it a race
	// against the scheduler (#8664).
	failWAN(e)
	actuateDeadline := time.Now().Add(2 * time.Second)
	for actuations.Load() == 0 && time.Now().Before(actuateDeadline) {
		time.Sleep(time.Millisecond)
	}
	base := actuations.Load()
	if base == 0 {
		t.Fatal("probe failure did not actuate within 2s")
	}
	r.set("ge-0-0-3", "198.51.100.254")
	e.NotifyNextHopChange()
	deadline := time.Now().Add(2 * time.Second)
	for actuations.Load() == base && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if actuations.Load() == base {
		t.Fatal("gateway change on FAILED interface-typed policy did not actuate")
	}

	// Literal-only FAILED policy: gateway churn must not actuate.
	e2cnt := atomic.Int32{}
	e2 := New(func(context.Context) bool { e2cnt.Add(1); return true })
	e2.debounce = 5 * time.Millisecond
	e2.throttle = 5 * time.Millisecond
	e2.Apply(testPolicyConfig(), passResults())
	e2.Start()
	defer e2.Stop()
	e2.HandleTransition(transition("WAN", "wan-a", "fail", passResults()))
	settle2 := 4 * (e2.debounce + e2.throttle)
	// #8664: the BASELINE is a "must happen" step in disguise, and it had the
	// same fixed-budget defect as the assertion above. If the transition's own
	// actuation has not landed when `b2` is taken, it lands during the window
	// below and is attributed to `NotifyNextHopChange` — the test then reports
	// the literal-only policy actuating when it did no such thing. Found by
	// squeezing the budgets after fixing the first site: this one failed at
	// "literal-only policy actuated: 0 -> 1", which is a FALSE accusation
	// rather than a missed event, so it would have sent the next reader looking
	// for a spurious-actuation bug that does not exist.
	baseDeadline := time.Now().Add(2 * time.Second)
	for e2cnt.Load() == 0 && time.Now().Before(baseDeadline) {
		time.Sleep(time.Millisecond)
	}
	b2 := e2cnt.Load()
	e2.NotifyNextHopChange()
	// An absence cannot be polled for, so this one stays a fixed wait — but
	// derived from the engine's own timings (#8664).
	time.Sleep(settle2)
	if got := e2cnt.Load(); got != b2 {
		t.Fatalf("literal-only policy actuated on NotifyNextHopChange: %d -> %d", b2, got)
	}
}

// TestFilterOverlayForConfigInterfaceTyped extends the #1843 HIGH-1
// contract to interface-typed entries: an unrelated commit keeps the
// entry (matching on the lease key — the resolved gateway never equals
// the config spec); re-targeting the route to another interface, or
// flipping it to a literal next-hop, drops it.
func TestFilterOverlayForConfigInterfaceTyped(t *testing.T) {
	e, _ := newTestEngine(nil)
	r := &fakeResolver{}
	r.set("ge-0-0-3", "198.51.100.1")
	e.SetNextHopResolver(r.resolve)
	cfg := dhcpPolicyConfig()
	delete(cfg.Policies, "static-backup")
	e.Apply(cfg, passResults())
	failWAN(e)
	overlay := e.ActiveOverlay()
	if len(overlay) != 1 {
		t.Fatalf("setup overlay = %+v", overlay)
	}

	// Unrelated commit (same spec): kept.
	same := dhcpPolicyConfig()
	delete(same.Policies, "static-backup")
	if kept := FilterOverlayForConfig(overlay, same); len(kept) != 1 {
		t.Fatalf("same-spec commit dropped interface-typed entry: %+v", kept)
	}

	// Re-targeted to a different interface: dropped.
	moved := dhcpPolicyConfig()
	delete(moved.Policies, "static-backup")
	moved.Policies["dhcp-uplink"].PreferredRoutes[0].NextHopInterface = "ge-0-0-4"
	if kept := FilterOverlayForConfig(overlay, moved); kept != nil {
		t.Fatalf("re-targeted interface still riding the commit: %+v", kept)
	}

	// Flipped to a literal next-hop — even one equal to the resolved
	// gateway: dropped (spec changed).
	lit := dhcpPolicyConfig()
	delete(lit.Policies, "static-backup")
	lit.Policies["dhcp-uplink"].PreferredRoutes[0] = &config.PreferredRoute{
		Destination: "0.0.0.0/0", NextHop: "198.51.100.1", PreferredMetric: 5,
	}
	if kept := FilterOverlayForConfig(overlay, lit); kept != nil {
		t.Fatalf("interface→literal flip still riding the commit: %+v", kept)
	}
}

// TestGatewayChangeCoalescesWithProbeTransition: a gateway change
// racing a probe transition collapses into the shared debounce window
// — one actuation path, last-writer-wins.
func TestGatewayChangeCoalescesWithProbeTransition(t *testing.T) {
	var actuations atomic.Int32
	e := New(func(context.Context) bool { actuations.Add(1); return true })
	e.debounce = 20 * time.Millisecond
	e.throttle = 60 * time.Millisecond
	r := &fakeResolver{}
	r.set("ge-0-0-3", "198.51.100.1")
	e.SetNextHopResolver(r.resolve)
	e.Apply(dhcpPolicyConfig(), passResults())
	e.Start()
	defer e.Stop()

	failWAN(e)
	for i := 0; i < 5; i++ {
		r.set("ge-0-0-3", "198.51.100.1")
		e.NotifyNextHopChange()
	}

	// #7650: the two halves of this assertion have different natures and the
	// old `time.Sleep(40ms)` conflated them.
	//
	// The UPPER bound is the property: six notifications must collapse into at
	// most two actuations. The LOWER bound is an anti-vacuity floor — without
	// it the test passes having observed nothing.
	//
	// A fixed sleep only ever tested the property when the machine happened to
	// be fast enough. Under load the 40 ms expired before the actuator ran at
	// all, and the FLOOR fired with `actuations = 0` — which reads as an
	// over-coalescing failure but is the test failing to observe, not the
	// coalescer failing to coalesce. That is a reading of the machine, not of
	// the subject (docs/engineering-style.md #7563).
	//
	// So wait on the observable that IMPLIES the floor — the actuator having
	// run — and fail loudly naming what never arrived. Then let the engine's
	// OWN throttle window elapse from that observed point, so any further
	// actuation it was going to emit has had its chance before the upper bound
	// is checked. The settle is derived from e.throttle/e.debounce rather than
	// a literal, so retuning either cannot silently make this vacuous.
	waitForActuation(t, &actuations, 1, 5*time.Second)
	time.Sleep(e.throttle + e.debounce)
	if got := actuations.Load(); got > 2 {
		t.Fatalf("actuations = %d, want coalesced (at most 2) for transition + "+
			"gateway churn — the debounce/throttle did not collapse the six "+
			"notifications", got)
	}
}

// waitForActuation blocks until the counter reaches want, or fails the test
// naming what never arrived (#7650).
//
// This is the anti-vacuity floor expressed as a WAIT rather than as a sample
// taken at a fixed wall-clock point. The distinction is the whole fix: a
// sample can only report what the machine happened to have done by then, so on
// a loaded box it reports zero and the floor fires for a reason that has
// nothing to do with the property under test.
//
// The deadline is deliberately generous. It is not a timing assertion — it
// exists so a genuinely broken actuator fails in seconds with a clear message
// instead of hanging the suite.
func waitForActuation(t *testing.T, counter *atomic.Int32, want int32, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		if got := counter.Load(); got >= want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("actuator never reached %d actuations within %s (saw %d) — "+
				"the engine never actuated at all, so nothing below can be "+
				"interpreted as a coalescing result (#7650)",
				want, within, counter.Load())
		}
		time.Sleep(time.Millisecond)
	}
}
