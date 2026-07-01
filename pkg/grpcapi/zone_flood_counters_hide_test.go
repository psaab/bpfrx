// #3643: the gRPC TEXT surfaces (show security zones detail, show security
// screen statistics all-zones) must render an explicit "not available" for the
// HIDE'd per-zone traffic / flood counters -- distinct from a "0" block and
// distinct from a genuine read-error warning.
//
// FAIL-ON-REVERT: dropping the dataplane.ErrCounterNotPopulated branch makes
// the sentinel fall into the value path (0-count block) or the genuine-error
// warning path, so the "not available" assertions go RED.
package grpcapi

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// notPopulatedGRPCDP is a loaded DP whose per-zone traffic + flood reads report
// dataplane.ErrCounterNotPopulated (the #3643 HIDE state).
type notPopulatedGRPCDP struct {
	*dataplane.Manager
	apply *dataplane.ApplyResult
}

func (d *notPopulatedGRPCDP) IsLoaded() bool                          { return true }
func (d *notPopulatedGRPCDP) LastApplyResult() *dataplane.ApplyResult { return d.apply }
func (d *notPopulatedGRPCDP) ReadZoneCounters(uint16, int) (dataplane.CounterValue, error) {
	return dataplane.CounterValue{}, dataplane.ErrCounterNotPopulated
}
func (d *notPopulatedGRPCDP) ReadFloodCounters(uint16) (dataplane.FloodState, error) {
	return dataplane.FloodState{}, dataplane.ErrCounterNotPopulated
}

func TestShowZonesDetailTextZoneCountersNotAvailable(t *testing.T) {
	store := newSchedulerCounterGRPCStore(t)
	s := &Server{
		store: store,
		dp: &notPopulatedGRPCDP{
			Manager: dataplane.New(),
			apply:   &dataplane.ApplyResult{ZoneIDs: map[string]uint16{"trust": 40000, "untrust": 41000, "dmz": 42000}},
		},
	}
	var buf strings.Builder
	s.showZonesDetail(store.ActiveConfig(), &buf)
	out := buf.String()
	if !strings.Contains(out, "Traffic statistics: not available") {
		t.Fatalf("zone text lacks the per-zone 'not available' marker; got:\n%s", out)
	}
	if strings.Contains(out, "warning") {
		t.Fatalf("zone text raised a false counter-read warning for an unpopulated counter; got:\n%s", out)
	}
}

func TestShowScreenStatisticsAllTextFloodNotAvailable(t *testing.T) {
	store := newSchedulerCounterGRPCStore(t)
	s := &Server{
		store: store,
		dp: &notPopulatedGRPCDP{
			Manager: dataplane.New(),
			apply:   &dataplane.ApplyResult{ZoneIDs: map[string]uint16{"trust": 40000, "untrust": 41000, "dmz": 42000}},
		},
	}
	var buf strings.Builder
	if _, err := s.showScreenStatisticsAll(store.ActiveConfig(), &buf); err != nil {
		t.Fatalf("showScreenStatisticsAll() error = %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "Per-zone flood counters: not available") {
		t.Fatalf("screen text lacks the per-zone flood 'not available' marker; got:\n%s", out)
	}
	if strings.Contains(out, "warning") {
		t.Fatalf("screen text raised a false flood counter-read warning; got:\n%s", out)
	}
}
