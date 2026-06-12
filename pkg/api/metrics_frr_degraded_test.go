package api

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

// TestFRRReloadDegradedGauge pins #1880 (Codex code-r1 M2): the
// xpf_frr_reload_degraded gauge must be emitted even when the
// dataplane is NOT loaded — the daemon applies FRR config in
// config-only mode too, so the signal must not disappear exactly when
// the fallback path is active — and it must track the wired fn.
func TestFRRReloadDegradedGauge(t *testing.T) {
	for _, tc := range []struct {
		name     string
		degraded bool
		want     float64
	}{
		{"degraded", true, 1},
		{"healthy", false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &Server{ // dp intentionally nil — gauge must still emit
				frrReloadDegradedFn: func() bool { return tc.degraded },
			}
			reg := prometheus.NewPedanticRegistry()
			reg.MustRegister(newCollector(s))
			mfs, err := reg.Gather()
			if err != nil {
				t.Fatalf("Gather: %v", err)
			}
			found := false
			for _, mf := range mfs {
				if mf.GetName() != "xpf_frr_reload_degraded" {
					continue
				}
				found = true
				if len(mf.GetMetric()) != 1 {
					t.Fatalf("metric count = %d, want 1", len(mf.GetMetric()))
				}
				if got := mf.GetMetric()[0].GetGauge().GetValue(); got != tc.want {
					t.Errorf("gauge = %v, want %v", got, tc.want)
				}
			}
			if !found {
				t.Error("xpf_frr_reload_degraded not emitted with dataplane unloaded")
			}
		})
	}
}
