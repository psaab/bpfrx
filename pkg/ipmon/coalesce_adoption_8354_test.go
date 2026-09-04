package ipmon

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/coalesce"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/rpm"
)

// #8354: the engine's coalescing loop is now pkg/coalesce.
//
// The debounce/throttle/dirty-generation discipline existed twice — once here
// and once in pkg/coalesce, which was written as the type this engine would
// adopt. A discipline whose entire purpose is to be obeyed identically,
// implemented twice, is a divergence with a delay fuse: whichever copy is
// edited first is right, and nothing tells the other.
//
// The 29 pre-existing ipmon tests are the real guard on the relocated
// behaviour and pass UNCHANGED. These cells cover the two things they cannot:
// that the adoption actually happened, and the interaction the extraction
// risked.

// TestTheEngineUsesTheSharedLoop8354 binds the adoption itself.
//
// Without it, a future "simplification" that reinstated a local dirty bit
// would pass all 29 relocated tests — they assert the BEHAVIOUR, which both
// implementations have. That is exactly how the two copies came to exist.
func TestTheEngineUsesTheSharedLoop8354(t *testing.T) {
	e := New(nil)
	if e.loop == nil {
		t.Fatal("the engine must construct its coalesce.Loop in New, not Start: " +
			"Apply and HandleTransition can mark it dirty before Start, and Go " +
			"compiles a nil-pointer method call happily — so a loop built later " +
			"is a runtime panic with no compile-time sign")
	}
	var _ *coalesce.Loop = e.loop
}

// TestTheHAGateHoldsOffActuation8354 is the interaction the extraction risked,
// and the reason #7437 declined to do it inside a feature PR.
//
// `publishEnabled` is the HA primary-only publication gate. On a standby it
// must hold actuation off entirely — a standby that actuates churns an
// frr-reload and a snapshot publish for an overlay it must not publish.
//
// The gate lives in the ENGINE (computeOverlayLocked returns the baseline when
// gated off), not in the loop, which is exactly the split the adoption had to
// preserve: the loop owns WHEN to actuate, the engine owns WHAT is published.
func TestTheHAGateHoldsOffActuation8354(t *testing.T) {
	var published atomic.Int64
	var lastLen atomic.Int64
	var e *Engine
	e = New(func(context.Context) bool {
		published.Add(1)
		lastLen.Store(int64(len(e8354Overlay(e))))
		return true
	})
	e.debounce = 5 * time.Millisecond
	e.throttle = 5 * time.Millisecond

	// Standby: gated off BEFORE anything is applied.
	e.SetPublishEnabled(false)
	e.Start()
	defer e.Stop()

	e.Apply(testPolicyConfig(), failedResults8354())
	waitFor8354(t, func() bool { return published.Load() > 0 }, time.Second,
		"the loop must still run while gated off")

	// The load-bearing assertion: it may actuate, but what it publishes is the
	// BASELINE — an empty overlay. A standby that published the failover
	// overlay would inject preferred routes on a node that must not.
	if got := lastLen.Load(); got != 0 {
		t.Fatalf("gated off, the published overlay must be the baseline (empty); "+
			"got %d entries. The HA gate is what the extraction risked and this "+
			"is the assertion that would catch it.", got)
	}

	// CONTROL: the same engine, same config, gate ON, must publish a non-empty
	// overlay. Without this the cell above passes against an engine that
	// publishes nothing under any condition — which is the failure mode of a
	// broken adoption, not of a working gate.
	before := published.Load()
	e.SetPublishEnabled(true)
	waitFor8354(t, func() bool { return published.Load() > before }, time.Second,
		"takeover must re-actuate")
	waitFor8354(t, func() bool { return lastLen.Load() > 0 }, time.Second,
		"on takeover the overlay must become non-empty — otherwise the gated-off "+
			"assertion above proves nothing")
}

// TestAConcurrentMarkKeepsTheStateDirty8354 pins the generation rule through
// the ENGINE rather than through pkg/coalesce's own cells.
//
// The rule is: the dirty bit clears only when the actuator converged AND no
// change landed while it ran. Marking DURING an actuation must therefore leave
// the engine dirty and produce a second actuation. This is the property most
// likely to be lost by an adoption that wires the actuator but not the
// generation, and it would be invisible under a slow flap.
func TestAConcurrentMarkKeepsTheStateDirty8354(t *testing.T) {
	var calls atomic.Int64
	var e *Engine
	e = New(func(context.Context) bool {
		// Mark DURING the actuation, exactly once, from inside the actuator.
		if calls.Add(1) == 1 {
			e8354MarkDirty(e)
		}
		return true
	})
	e.debounce = 5 * time.Millisecond
	e.throttle = 5 * time.Millisecond
	e.Start()
	defer e.Stop()

	e.Apply(testPolicyConfig(), failedResults8354())
	waitFor8354(t, func() bool { return calls.Load() >= 2 }, 2*time.Second,
		"a mark landing DURING an actuation must keep the state dirty and produce "+
			"a SECOND actuation — otherwise the change that arrived mid-flight is "+
			"swallowed by the actuation that never saw it (#3757 last-writer-wins)")
}

func e8354MarkDirty(e *Engine) {
	e.mu.Lock()
	e.markDirtyLocked(true)
	e.mu.Unlock()
	e.kickLoop()
}

func e8354Overlay(e *Engine) []config.RouteOverlayEntry { return e.ActiveOverlay() }

// failedResults8354 is testPolicyConfig()'s probe, FAILING — which is what
// makes the engine compute a non-empty overlay and therefore what makes the
// gated-off assertion meaningful.
func failedResults8354() []*rpm.ProbeResult {
	return []*rpm.ProbeResult{
		{ProbeName: "WAN", TestName: "wan-a", LastStatus: "fail"},
		{ProbeName: "WAN", TestName: "wan-b", LastStatus: "fail"},
	}
}

func waitFor8354(t *testing.T, cond func() bool, limit time.Duration, msg string) {
	t.Helper()
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out after %v: %s", limit, msg)
}
