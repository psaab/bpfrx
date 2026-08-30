package api

import (
	"errors"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/psaab/xpf/pkg/diagcmd"
)

// countingWalkDP records whether the full-table walk was actually entered.
// Counting the CALL rather than asserting the error is what distinguishes
// "admission refused before walking" from "walked, then failed" — those look
// identical from the return value and only one of them bounds the work.
type countingWalkDP struct {
	apiRuntimeDataPlane
	walks int
}

func (d *countingWalkDP) IterateSessions(fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	d.walks++
	return nil
}

func (d *countingWalkDP) IterateSessionsV6(fn func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	d.walks++
	return nil
}

// #8001: the metrics walk must take a sessionWalkLimiter slot like the six
// other full-table walks in this package.
//
// FIRING INPUT, named before the assertion: the limiter saturated by other
// holders. Under that condition the walk must refuse admission and must NOT
// iterate. Without the fix it iterates regardless, because it never consulted
// the limiter at all.
func TestMetricsSessionWalkTakesALimiterSlot8001(t *testing.T) {
	// Saturate the shared limiter, releasing at the end.
	var held []func()
	for {
		release, err := sessionWalkLimiter.Acquire()
		if err != nil {
			break
		}
		held = append(held, release)
		if len(held) > 64 {
			t.Fatal("limiter never reported busy after 64 acquisitions — the cap is " +
				"far larger than expected, or Acquire is not the admission gate")
		}
	}
	if len(held) == 0 {
		t.Fatal("could not acquire even one slot; the limiter is already saturated " +
			"by something else and this cell cannot measure anything")
	}
	defer func() {
		for _, r := range held {
			r()
		}
	}()

	dp := &countingWalkDP{}
	_, err := walkSessionGauges(dp)
	if !errors.Is(err, diagcmd.ErrBusy) {
		t.Errorf("walkSessionGauges returned %v, want ErrBusy. A Prometheus scrape "+
			"drives this on a fixed interval, so an ungated walk is the call site "+
			"least likely to be noticed under load and most likely to overlap with "+
			"an operator's session scan", err)
	}
	if dp.walks != 0 {
		t.Errorf("the walk ran %d times despite the limiter being saturated. Returning "+
			"an error after walking bounds nothing — the point of the slot is that the "+
			"iteration does not start", dp.walks)
	}
}

// The negative control. Without it, an implementation that always returns
// ErrBusy passes the cell above while emitting no session gauges ever.
func TestMetricsSessionWalkProceedsWhenNotSaturated8001(t *testing.T) {
	dp := &countingWalkDP{}
	if _, err := walkSessionGauges(dp); err != nil {
		t.Fatalf("walkSessionGauges failed on an idle limiter: %v", err)
	}
	if dp.walks == 0 {
		t.Error("the walk did not run on an idle limiter, so the gauges would be " +
			"permanently absent rather than merely bounded")
	}
}
