package eventengine

import (
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/rpm"
)

// #7223. The `trigger on N` edge latch is keyed per (policy, event) and
// was decided INSIDE the single loop that walks the within clauses, which
// returned false from the middle of that walk. Multiple within clauses are
// ANDed, so with more than one `trigger on` clause the verdict depended on the
// ORDER the operator wrote them in: whichever clause was reached first decided
// whether the latch got checked or re-armed, and the other one was never seen.
//
// Concretely, with the LONG window written first and the policy already
// latched, the long clause was still at/above its threshold, hit the latch
// check and returned — so the SHORT clause, which had decayed below its own
// threshold and was the one that should have RE-ARMED the latch, never ran. The
// ANDed condition went false and then true again — a genuine crossing — and the
// policy stayed silent until the long window decayed too.
//
// The fix decides the re-arm across EVERY trigger-on clause before anything
// returns, so both orderings agree. This test drives the timeline against both
// orderings and asserts they produce the SAME sequence, which is the property;
// it also pins the absolute expectation, so a fix that made both orderings
// equally wrong cannot pass.
func TestWithinTriggerOnRearmIsIndependentOfClauseOrder(t *testing.T) {
	longFirst := []*config.EventWithin{
		{Seconds: 600, TriggerOn: 3},
		{Seconds: 60, TriggerOn: 3},
	}
	shortFirst := []*config.EventWithin{
		{Seconds: 60, TriggerOn: 3},
		{Seconds: 600, TriggerOn: 3},
	}

	// run drives the timeline and returns the offsets (seconds from base) at
	// which the policy fired.
	run := func(clauses []*config.EventWithin) []int {
		t.Helper()
		pol := &config.EventPolicy{Name: "p", Events: []string{"e"}, WithinClauses: clauses}
		e := newTestEngine(t, []*config.EventPolicy{pol})
		base := time.Unix(1_000_000, 0)
		var at int
		e.nowFn = func() time.Time { return base.Add(time.Duration(at) * time.Second) }

		var fired []int
		// Burst 1 at t=0,1,2 — the third event crosses BOTH thresholds.
		// Gap to t=100: the 60s window has decayed to empty while the 600s
		// window still holds all three, so the ANDed condition is false and the
		// latch must re-arm.
		// Burst 2 at t=100,101,102 — the third event is a NEW crossing.
		for _, at = range []int{0, 1, 2, 100, 101, 102} {
			if n := len(e.evaluateEvent(rpm.Event{Name: "e"})); n > 0 {
				fired = append(fired, at)
			}
		}
		return fired
	}

	gotLong := run(longFirst)
	gotShort := run(shortFirst)

	want := []int{2, 102}
	eq := func(a, b []int) bool {
		if len(a) != len(b) {
			return false
		}
		for i := range a {
			if a[i] != b[i] {
				return false
			}
		}
		return true
	}

	if !eq(gotLong, gotShort) {
		t.Fatalf("clause ORDER changed the outcome: long-window-first fired at %v, "+
			"short-window-first fired at %v — the re-arm is being decided inside "+
			"the walk again", gotLong, gotShort)
	}
	if !eq(gotLong, want) {
		t.Fatalf("fired at %v, want %v: the third event of each burst is a threshold "+
			"CROSSING and must fire exactly once per burst", gotLong, want)
	}
}

// Single-clause edge semantics are unchanged: one fire per crossing, suppressed
// while the level stays at or above N, re-armed once it drops below.
func TestWithinSingleTriggerOnKeepsEdgeSemantics(t *testing.T) {
	pol := &config.EventPolicy{
		Name:          "p",
		Events:        []string{"e"},
		WithinClauses: []*config.EventWithin{{Seconds: 60, TriggerOn: 3}},
	}
	e := newTestEngine(t, []*config.EventPolicy{pol})
	base := time.Unix(2_000_000, 0)
	var at int
	e.nowFn = func() time.Time { return base.Add(time.Duration(at) * time.Second) }

	var fired []int
	// 0,1,2 -> crossing at 2. 3,4 -> level sustained, suppressed. Gap to 200
	// drains the 60s window; 200,201,202 -> a second crossing at 202.
	for _, at = range []int{0, 1, 2, 3, 4, 200, 201, 202} {
		if n := len(e.evaluateEvent(rpm.Event{Name: "e"})); n > 0 {
			fired = append(fired, at)
		}
	}
	if len(fired) != 2 || fired[0] != 2 || fired[1] != 202 {
		t.Fatalf("fired at %v, want [2 202] — one fire per crossing", fired)
	}
}

// A structurally invalid clause still fails CLOSED regardless of position
// (#3751), and mixing it with a valid one does not make the policy fire.
func TestWithinInvalidClauseStillFailsClosedInEitherPosition(t *testing.T) {
	for name, clauses := range map[string][]*config.EventWithin{
		"invalid first": {{Seconds: 0, TriggerOn: 1}, {Seconds: 60, TriggerOn: 1}},
		"invalid last":  {{Seconds: 60, TriggerOn: 1}, {Seconds: 0, TriggerOn: 1}},
		"no threshold":  {{Seconds: 60}},
	} {
		t.Run(name, func(t *testing.T) {
			pol := &config.EventPolicy{Name: "p", Events: []string{"e"}, WithinClauses: clauses}
			e := newTestEngine(t, []*config.EventPolicy{pol})
			base := time.Unix(3_000_000, 0)
			var at int
			e.nowFn = func() time.Time { return base.Add(time.Duration(at) * time.Second) }
			for _, at = range []int{0, 1, 2, 3} {
				if n := len(e.evaluateEvent(rpm.Event{Name: "e"})); n != 0 {
					t.Fatalf("a policy with an unusable within clause must never fire, fired %d at t=%d", n, at)
				}
			}
		})
	}
}
