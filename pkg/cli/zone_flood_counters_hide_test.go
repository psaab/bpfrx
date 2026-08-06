package cli

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// notPopulatedCLIDP is a loaded DP whose per-zone traffic + flood reads report
// dataplane.ErrCounterNotPopulated -- the #3643 HIDE state (the userspace
// dataplane does not source per-zone/flood counters).
type notPopulatedCLIDP struct {
	dataplane.DataPlane
	apply *dataplane.ApplyResult
}

func (d *notPopulatedCLIDP) IsLoaded() bool                          { return true }
func (d *notPopulatedCLIDP) LastApplyResult() *dataplane.ApplyResult { return d.apply }
func (d *notPopulatedCLIDP) ReadZoneCounters(uint16, int) (dataplane.CounterValue, error) {
	return dataplane.CounterValue{}, dataplane.ErrCounterNotPopulated
}
func (d *notPopulatedCLIDP) ReadFloodCounters(uint16) (dataplane.FloodState, error) {
	return dataplane.FloodState{}, dataplane.ErrCounterNotPopulated
}

// TestShowZonesDisplayZoneCountersNotAvailable is the #3643 CLI HIDE pin for
// `show security zones`: an unpopulated per-zone read renders an explicit "not
// available" line, NOT a "0 packets, 0 bytes" block and NOT a read-error
// warning.
//
// FAIL-ON-REVERT: dropping the ErrCounterNotPopulated branch makes the display
// print "Traffic statistics:" with a 0/0 block (the sentinel falls into the
// value path) or a counter-read warning, so the "not available" assertion goes
// RED.
func TestShowZonesDisplayZoneCountersNotAvailable(t *testing.T) {
	store := newPolicyHitCountCLIStore(t, true) // trust + untrust zones
	c := &CLI{store: store, dp: &notPopulatedCLIDP{
		apply: &dataplane.ApplyResult{ZoneIDs: map[string]uint16{"trust": 40000, "untrust": 41000}},
	}}

	out := captureStdout(t, func() {
		if err := c.showZonesDisplay(store.ActiveConfig(), false, ""); err != nil {
			t.Fatalf("showZonesDisplay() error = %v", err)
		}
	})
	if !strings.Contains(out, "Traffic statistics: not available") {
		t.Fatalf("show security zones lacks the per-zone 'not available' marker; got:\n%s", out)
	}

	// #6843 M3: bind the CAUSE clause, not just the invariant prefix. Reverting
	// the parenthetical to the pre-#6843 "(per-zone accounting not implemented
	// in the userspace dataplane)" left both packages green, because the only
	// assertion matched "Traffic statistics: not available". That wording is now
	// actively wrong -- #3651 shipped per-zone accounting -- and with 64+ zones
	// one command prints real byte counts for slotted zones and "not
	// implemented" for overflowed ones, sending the operator after a feature gap
	// that does not exist. Assert the reason, and assert the retracted claim is
	// absent.
	if !strings.Contains(out, "no per-zone volume published for this zone") {
		t.Errorf("the unavailable line must name the CAUSE (nothing published "+
			"for this zone), not just report unavailability:\n%s", out)
	}
	if strings.Contains(out, "not implemented") {
		t.Errorf("the unavailable line still claims per-zone accounting is not "+
			"implemented; #3651 shipped it, so this names the wrong cause:\n%s", out)
	}
	if strings.Contains(out, "0 packets, 0 bytes") {
		t.Fatalf("show security zones printed a misleading 0/0 per-zone block; got:\n%s", out)
	}
	if strings.Contains(out, "warning") {
		t.Fatalf("show security zones raised a false counter-read warning for an unpopulated counter; got:\n%s", out)
	}
}

// TestShowScreenStatisticsAllFloodNotAvailable is the #3643 CLI HIDE pin for
// `show security screen ids-option statistics`: an unpopulated per-zone flood
// read renders "not available", NOT "SYN flood events 0" and NOT the #3408
// aggregate read-error warning.
func TestShowScreenStatisticsAllFloodNotAvailable(t *testing.T) {
	store := newPolicyHitCountCLIStore(t, true)
	c := &CLI{store: store, dp: &notPopulatedCLIDP{
		apply: &dataplane.ApplyResult{ZoneIDs: map[string]uint16{"trust": 40000, "untrust": 41000}},
	}}

	out := captureStdout(t, func() {
		if err := c.showScreenStatisticsAll(); err != nil {
			t.Fatalf("showScreenStatisticsAll() error = %v", err)
		}
	})
	if !strings.Contains(out, "Per-zone flood counters: not available") {
		t.Fatalf("screen statistics lacks the per-zone flood 'not available' marker; got:\n%s", out)
	}
	if strings.Contains(out, "SYN flood events") {
		t.Fatalf("screen statistics printed a misleading flood-event 0 block; got:\n%s", out)
	}
	if strings.Contains(out, "warning") {
		t.Fatalf("screen statistics raised a false flood counter-read warning; got:\n%s", out)
	}
}
