package eventengine

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// Regression tests for #3756 M2: `within { trigger until N }` fires through the
// INCLUSIVE N-th matching event, then stops. The event is appended to the
// window BEFORE withinMatches runs, so the N-th event makes count==N. The old
// boundary (`count >= N`) treated count==N as "stop", so:
//   - `until 1` never fired at all (the first event already makes count==1) — a
//     genuine dead-config bug.
//   - `until N` fired only on events 1..N-1 instead of 1..N.
// The fix (`count > N`) fires on 1..N and stops at N+1.
//
// These reuse feedEvents/firstFireIndex from engine_within_failclosed_3751_test.go.

// countTriggersAcross drives count events and returns the number that fired.
func countTriggersAcross(t *testing.T, pol *config.EventPolicy, count int) int {
	t.Helper()
	return feedEvents(t, pol, count)
}

// `trigger until 1` must fire on the FIRST event (exactly once), then stop.
//
// RED-on-revert: with the old `count >= 1` boundary the first event makes
// count==1 -> 1>=1 -> return false -> NEVER fires; firstFireIndex returns -1.
func TestInclusiveUntil_One_FiresOnce_3756(t *testing.T) {
	pol := &config.EventPolicy{
		Name:          "until1",
		Events:        []string{"ping_probe_failed"},
		WithinClauses: []*config.EventWithin{{Seconds: 300, TriggerUntil: 1}},
	}
	if got := firstFireIndex(t, pol, 5); got != 0 {
		t.Fatalf("`trigger until 1` first fired at event index %d; want 0 — the "+
			"first event is the inclusive N=1th and MUST fire (#3756 M2 dead-config bug)", got)
	}
	// It fires exactly once (event 1); event 2 makes count==2 > 1 -> stops.
	if got := countTriggersAcross(t, pol, 5); got != 1 {
		t.Fatalf("`trigger until 1` fired %d times across 5 events; want exactly 1 "+
			"(the inclusive N-th, then stop)", got)
	}
}

// `trigger until 2` fires on events 1 and 2 (inclusive of the 2nd), then stops.
//
// RED-on-revert: the old `count >= 2` boundary fired only on event 1 (count==1)
// and stopped at event 2 (count==2 >= 2), so the total was 1, not 2.
func TestInclusiveUntil_Two_FiresThroughSecond_3756(t *testing.T) {
	pol := &config.EventPolicy{
		Name:          "until2",
		Events:        []string{"ping_probe_failed"},
		WithinClauses: []*config.EventWithin{{Seconds: 300, TriggerUntil: 2}},
	}
	if got := countTriggersAcross(t, pol, 6); got != 2 {
		t.Fatalf("`trigger until 2` fired %d times across 6 events; want exactly 2 "+
			"(events 1 and 2, inclusive of the 2nd; the 3rd makes count==3 > 2 and stops) (#3756 M2)", got)
	}
}

// The 2216A never-reaches-threshold guard for trigger-until is preserved: an
// until clause whose window never accumulates N events keeps firing (it never
// reaches the stop boundary). Here `until 100` within a 30s window at 1 event/s
// caps the count near 30, well below 100, so EVERY event fires. This confirms
// the boundary shift did not accidentally suppress the below-threshold case.
func TestInclusiveUntil_BelowThresholdKeepsFiring_3756(t *testing.T) {
	pol := &config.EventPolicy{
		Name:          "until100",
		Events:        []string{"ping_probe_failed"},
		WithinClauses: []*config.EventWithin{{Seconds: 30, TriggerUntil: 100}},
	}
	// At 1 event/s within a 30s window the count never exceeds ~31 < 100, so
	// every one of the 20 events is below the stop boundary and fires.
	if got := countTriggersAcross(t, pol, 20); got != 20 {
		t.Fatalf("`trigger until 100` fired %d/20 events; a window that never "+
			"reaches N must keep firing on every event (#3756 M2)", got)
	}
}
