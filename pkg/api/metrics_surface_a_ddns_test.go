package api

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/psaab/xpf/pkg/ddns"
)

// TestSurfaceADDNSSkippedNoBackendMetric pins #2726 (a): the Surface A
// (router/interface-address) DDNS skip counter must surface the
// no-backend reason as a third series on
// xpf_ddns_surface_a_skipped_total{reason="no-backend"}, mirroring the
// lease-path xpf_dhcp_ddns_skipped_total{reason="no-backend"}. P3 added
// SurfaceAStats.SkippedNoBackend + its increment but the operator
// surfaces only showed unchanged/backoff.
//
// The emitter is driven directly (collectSurfaceADDNSMetrics runs behind
// the full dataplane-loaded gate in Collect(); this isolates the one
// emitter under test without standing up a loaded DP + config store).
//
// FAIL-ON-REVERT: without the no-backend emitter line the
// {reason="no-backend"} series is never produced and the lookup misses
// → the test fails.
func TestSurfaceADDNSSkippedNoBackendMetric(t *testing.T) {
	s := &Server{
		surfaceAStatsFn: func() *ddns.SurfaceAStats {
			return &ddns.SurfaceAStats{
				Scopes:           2,
				UpsertOK:         7,
				DeleteOK:         1,
				Skipped:          4,
				BackedOff:        2,
				SkippedNoBackend: 5,
			}
		},
	}
	c := newCollector(s)

	ch := make(chan prometheus.Metric, 64)
	c.collectSurfaceADDNSMetrics(ch)
	close(ch)

	var metrics []prometheus.Metric
	for m := range ch {
		metrics = append(metrics, m)
	}

	reasonValue := func(name, reason string) (float64, bool) {
		for _, m := range metrics {
			if descName(m.Desc()) != name {
				continue
			}
			var dm dto.Metric
			if err := m.Write(&dm); err != nil {
				t.Fatalf("metric Write: %v", err)
			}
			for _, lp := range dm.GetLabel() {
				if lp.GetName() == "reason" && lp.GetValue() == reason {
					if ctr := dm.GetCounter(); ctr != nil {
						return ctr.GetValue(), true
					}
				}
			}
		}
		return 0, false
	}

	if v, ok := reasonValue("xpf_ddns_surface_a_skipped_total", "no-backend"); !ok || v != 5 {
		t.Errorf("surface_a skipped no-backend = %v (ok=%v), want 5", v, ok)
	}
	// The pre-existing reasons must still be emitted alongside it.
	if v, ok := reasonValue("xpf_ddns_surface_a_skipped_total", "unchanged"); !ok || v != 4 {
		t.Errorf("surface_a skipped unchanged = %v (ok=%v), want 4", v, ok)
	}
	if v, ok := reasonValue("xpf_ddns_surface_a_skipped_total", "backoff"); !ok || v != 2 {
		t.Errorf("surface_a skipped backoff = %v (ok=%v), want 2", v, ok)
	}
}
