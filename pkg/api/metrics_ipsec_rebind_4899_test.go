package api

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

// TestIPsecRebindPendingGauge pins #4899: the xpf_ipsec_rebind_pending gauge
// must be emitted even when the dataplane is NOT loaded — the daemon
// re-renders swanctl on a DHCP lease change in config-only mode too, so a
// stale-local_addrs tunnel that cannot re-establish must stay visible exactly
// when the rebind is failing — and it must track the wired fn.
func TestIPsecRebindPendingGauge(t *testing.T) {
	for _, tc := range []struct {
		name    string
		pending bool
		want    float64
	}{
		{"pending", true, 1},
		{"healthy", false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &Server{ // dp intentionally nil — gauge must still emit
				ipsecRebindPendingFn: func() bool { return tc.pending },
			}
			reg := prometheus.NewPedanticRegistry()
			reg.MustRegister(newCollector(s))
			mfs, err := reg.Gather()
			if err != nil {
				t.Fatalf("Gather: %v", err)
			}
			found := false
			for _, mf := range mfs {
				if mf.GetName() != "xpf_ipsec_rebind_pending" {
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
				t.Error("xpf_ipsec_rebind_pending not emitted with dataplane unloaded")
			}
		})
	}
}
