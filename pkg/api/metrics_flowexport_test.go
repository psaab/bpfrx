package api

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/psaab/xpf/pkg/flowexport"
)

// TestFlowExportCollectorMetrics pins #2464: per-collector NetFlow v9 /
// IPFIX write-health must be emitted as the xpf_flow_export_collector_*
// family, labeled by protocol + collector address, even when the
// dataplane is NOT loaded (the exporters are control-plane and run
// independent of dataplane load). A collector going silently unreachable
// was previously invisible; these metrics make write_failures and the
// healthy flag observable to an operator's dashboard.
//
// FAIL-ON-REVERT: without the FlowCollectorHealthFn wiring and the
// collectFlowExportMetrics emitter, none of these metric families are
// produced and every lookup below misses → the test fails.
func TestFlowExportCollectorMetrics(t *testing.T) {
	lastSuccess := time.Unix(1_700_000_000, 0)
	lastFailure := time.Unix(1_700_000_100, 0)
	s := &Server{ // dp intentionally nil — flow-export is control-plane
		flowCollectorHealthFn: func() []flowexport.ExporterCollectorHealth {
			return []flowexport.ExporterCollectorHealth{
				{
					Protocol: "netflow-v9",
					Instance: "inst1",
					Template: "",
					CollectorHealth: flowexport.CollectorHealth{
						Address:         "10.0.0.1:2055",
						WriteAttempts:   100,
						WriteFailures:   0,
						Healthy:         true,
						LastSuccessTime: lastSuccess,
					},
				},
				{
					Protocol: "ipfix",
					Instance: "inst2",
					CollectorHealth: flowexport.CollectorHealth{
						Address:         "10.0.0.2:4739",
						WriteAttempts:   50,
						WriteFailures:   50,
						Healthy:         false,
						LastError:       "connection refused",
						LastFailureTime: lastFailure,
					},
				},
			}
		},
	}
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(newCollector(s))
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}

	// metricValue looks up one labeled sample value by metric name +
	// (protocol, collector) label pair.
	metricValue := func(name, proto, collector string) (float64, bool) {
		for _, mf := range mfs {
			if mf.GetName() != name {
				continue
			}
			for _, m := range mf.GetMetric() {
				var p, c string
				for _, lp := range m.GetLabel() {
					switch lp.GetName() {
					case "protocol":
						p = lp.GetValue()
					case "collector":
						c = lp.GetValue()
					}
				}
				if p == proto && c == collector {
					if g := m.GetGauge(); g != nil {
						return g.GetValue(), true
					}
					if ctr := m.GetCounter(); ctr != nil {
						return ctr.GetValue(), true
					}
				}
			}
		}
		return 0, false
	}

	// Healthy netflow-v9 collector.
	if v, ok := metricValue("xpf_flow_export_collector_write_attempts_total", "netflow-v9", "10.0.0.1:2055"); !ok || v != 100 {
		t.Errorf("netflow-v9 write_attempts = %v (ok=%v), want 100", v, ok)
	}
	if v, ok := metricValue("xpf_flow_export_collector_write_failures_total", "netflow-v9", "10.0.0.1:2055"); !ok || v != 0 {
		t.Errorf("netflow-v9 write_failures = %v (ok=%v), want 0", v, ok)
	}
	if v, ok := metricValue("xpf_flow_export_collector_healthy", "netflow-v9", "10.0.0.1:2055"); !ok || v != 1 {
		t.Errorf("netflow-v9 healthy = %v (ok=%v), want 1", v, ok)
	}
	if v, ok := metricValue("xpf_flow_export_collector_last_success_timestamp_seconds", "netflow-v9", "10.0.0.1:2055"); !ok || v != float64(lastSuccess.Unix()) {
		t.Errorf("netflow-v9 last_success = %v (ok=%v), want %d", v, ok, lastSuccess.Unix())
	}

	// Unhealthy ipfix collector.
	if v, ok := metricValue("xpf_flow_export_collector_write_failures_total", "ipfix", "10.0.0.2:4739"); !ok || v != 50 {
		t.Errorf("ipfix write_failures = %v (ok=%v), want 50", v, ok)
	}
	if v, ok := metricValue("xpf_flow_export_collector_healthy", "ipfix", "10.0.0.2:4739"); !ok || v != 0 {
		t.Errorf("ipfix healthy = %v (ok=%v), want 0", v, ok)
	}
	if v, ok := metricValue("xpf_flow_export_collector_last_failure_timestamp_seconds", "ipfix", "10.0.0.2:4739"); !ok || v != float64(lastFailure.Unix()) {
		t.Errorf("ipfix last_failure = %v (ok=%v), want %d", v, ok, lastFailure.Unix())
	}
}

// TestFlowExportCollectorMetricsOmittedWhenUnwired proves the family is
// omitted entirely (no spurious zero series) when no FlowCollectorHealthFn
// is wired — matching the DDNS / feeds families.
func TestFlowExportCollectorMetricsOmittedWhenUnwired(t *testing.T) {
	s := &Server{} // no flowCollectorHealthFn
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(newCollector(s))
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	for _, mf := range mfs {
		switch mf.GetName() {
		case "xpf_flow_export_collector_write_attempts_total",
			"xpf_flow_export_collector_write_failures_total",
			"xpf_flow_export_collector_healthy":
			t.Errorf("%s emitted with no health fn wired", mf.GetName())
		}
	}
}
