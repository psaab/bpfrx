package daemon

import (
	"testing"
	"time"
)

// #7181: the daemon-side transitions.
//
// These bind the LATCH, not the renderer. A renderer test passes against a
// latch that never moves, so the two halves need separate cells — the #7181
// defect was precisely that the state machine existed and nothing carried it
// out, and a test that only exercises the mapping would not have noticed.
func TestHostInboundAppliedTransitions7181(t *testing.T) {
	d := &Daemon{}

	// Cold boot: nothing established. The zero value must claim NOTHING.
	if got := d.HostInboundApplied(); got.Established || got.Current() || got.Generation != 0 {
		t.Fatalf("cold boot claimed something: %+v", got)
	}

	// A successful real install: generation advances, state becomes current.
	d.hostInboundEnforced.Store(true)
	d.noteHostInboundApplySucceeded()
	got := d.HostInboundApplied()
	if !got.Current() || got.Generation != 1 {
		t.Fatalf("after a successful install: %+v, want current with generation 1", got)
	}

	// A later FAILED render. Established stays true (the retained generation may
	// still be protecting — that is why the latch is sticky), but the state must
	// no longer read as current.
	failedAt := time.Now()
	d.noteHostInboundApplyFailed(failedAt)
	got = d.HostInboundApplied()
	if !got.Established {
		t.Error("a failed render cleared Established. It must NOT: the retained " +
			"generation is untouched and may still be protecting, which is the whole " +
			"reason the latch is sticky")
	}
	if got.Current() {
		t.Error("a failed render still reports Current. This is the #7181 defect: the " +
			"operator sees enforcement in force while the latest render failed and any " +
			"address that appeared since may have no rule at all")
	}
	if got.LastFailureAt.IsZero() {
		t.Error("no failure timestamp recorded — an operator cannot tell a failure from " +
			"a minute ago from one standing since boot")
	}
	if got.Generation != 1 {
		t.Errorf("Generation = %d, want 1: a FAILED apply must not advance the generation, "+
			"or the counter stops meaning 'installs that succeeded'", got.Generation)
	}

	// Recovery: a successful install clears the staleness and advances again.
	d.noteHostInboundApplySucceeded()
	got = d.HostInboundApplied()
	if !got.Current() || got.Generation != 2 || !got.LastFailureAt.IsZero() {
		t.Fatalf("after recovery: %+v, want current, generation 2, no failure time", got)
	}
}

// The gap fence is part of the applied truth: a box enforcing through the
// additive fence is in a different state from one whose main table covers
// everything, and only the gap flag distinguishes them.
func TestHostInboundGapFenceClearedByASuccessfulInstall7181(t *testing.T) {
	d := &Daemon{}
	d.hostInboundEnforced.Store(true)
	d.hostInboundGapFenceActive.Store(true)
	d.noteHostInboundApplyFailed(time.Now())
	if !d.HostInboundApplied().GapFenceActive {
		t.Fatal("gap fence not reported while standing")
	}
	d.noteHostInboundApplySucceeded()
	if d.HostInboundApplied().GapFenceActive {
		t.Error("the gap fence still reads ACTIVE after a successful real install. " +
			"The real table now covers the desired set and the gap is torn down, so " +
			"leaving the flag set sends an operator looking for a second table that " +
			"is no longer there")
	}
}

// A nil daemon must claim nothing rather than panicking or reporting health.
// The projections reach this from paths that run without a daemon in tests.
func TestHostInboundAppliedNilDaemonClaimsNothing7181(t *testing.T) {
	var d *Daemon
	got := d.HostInboundApplied()
	if got.Established || got.Current() {
		t.Errorf("a nil daemon claimed enforcement: %+v", got)
	}
}
