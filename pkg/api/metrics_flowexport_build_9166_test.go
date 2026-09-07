package api

import (
	"strconv"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/psaab/xpf/pkg/flowexport"
)

// #9166: a failed flow-exporter build was INDISTINGUISHABLE from "flow export
// is not configured" on every surface. `FlowExportError()` had zero production
// readers; the xpf_flow_export_collector_* family is omitted when the health
// slice is empty, which is exactly what a failed build produces; and `show`
// renders the configuration as present because the config IS present.
//
// The acceptance the issue asked for is three cells producing three
// DISTINGUISHABLE observations. Two of the three were identical before this,
// and a test that checks only "healthy exports metrics" passes on the defect —
// which is why the not-configured row is the load-bearing one.

func flowBuildGauges9166(t *testing.T, states []flowexport.BuildState) map[string]float64 {
	t.Helper()
	c := newCollector(&Server{
		flowExportBuildStateFn: func() []flowexport.BuildState { return states },
	})
	reg := prometheus.NewPedanticRegistry()
	if err := reg.Register(c); err != nil {
		t.Fatalf("register: %v", err)
	}
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	out := map[string]float64{}
	for _, mf := range mfs {
		name := mf.GetName()
		if name != "xpf_flowexport_configured_groups" && name != "xpf_flowexport_build_failed" {
			continue
		}
		for _, m := range mf.GetMetric() {
			fam := ""
			for _, l := range m.GetLabel() {
				if l.GetName() == "family" {
					fam = l.GetValue()
				}
			}
			out[name+"{"+fam+"}"] = gaugeOrCounter9166(m)
		}
	}
	return out
}

func gaugeOrCounter9166(m *dto.Metric) float64 {
	if m.Gauge != nil {
		return m.Gauge.GetValue()
	}
	return m.Counter.GetValue()
}

// THE THREE STATES. Asserted as a table rather than three separate cells so the
// distinguishability is checked directly: any two rows producing the same
// observation fails here, which a per-row assertion cannot see.
func TestTheThreeFlowExportStatesAreDistinguishable9166(t *testing.T) {
	rows := []struct {
		name   string
		states []flowexport.BuildState
	}{
		{"not configured", []flowexport.BuildState{
			{Family: "netflow-v9", ConfiguredGroups: 0, BuildFailed: false},
		}},
		{"configured and healthy", []flowexport.BuildState{
			{Family: "netflow-v9", ConfiguredGroups: 2, BuildFailed: false},
		}},
		{"configured and build failed", []flowexport.BuildState{
			{Family: "netflow-v9", ConfiguredGroups: 2, BuildFailed: true},
		}},
	}

	seen := map[string]string{}
	for _, r := range rows {
		got := flowBuildGauges9166(t, r.states)
		key := ""
		for _, k := range []string{
			"xpf_flowexport_configured_groups{netflow-v9}",
			"xpf_flowexport_build_failed{netflow-v9}",
		} {
			v, ok := got[k]
			if !ok {
				t.Fatalf("%s: %s absent — an absent series is also what a scrape "+
					"that never reached this code looks like, which is the "+
					"ambiguity #9166 is about", r.name, k)
			}
			key += k + "=" + formatFloat9166(v) + ";"
		}
		if prev, dup := seen[key]; dup {
			t.Errorf("%q and %q produce the IDENTICAL observation %s — the states "+
				"are still not distinguishable (#9166)", prev, r.name, key)
		}
		seen[key] = r.name
	}
}

func formatFloat9166(v float64) string {
	return strconv.FormatFloat(v, 'g', -1, 64)
}

// The two families are independent: NetFlow v9 can fail while IPFIX is healthy,
// and a single unlabelled gauge would report one of them wrongly.
func TestFamiliesAreReportedIndependently9166(t *testing.T) {
	got := flowBuildGauges9166(t, []flowexport.BuildState{
		{Family: "netflow-v9", ConfiguredGroups: 1, BuildFailed: true},
		{Family: "ipfix", ConfiguredGroups: 3, BuildFailed: false},
	})
	if got["xpf_flowexport_build_failed{netflow-v9}"] != 1 {
		t.Errorf("netflow-v9 failure not reported: %v", got)
	}
	if got["xpf_flowexport_build_failed{ipfix}"] != 0 {
		t.Errorf("ipfix reported as failed while healthy: %v", got)
	}
	if got["xpf_flowexport_configured_groups{ipfix}"] != 3 {
		t.Errorf("ipfix configured count wrong: %v", got)
	}
}

// CONTROL — an unwired hook emits nothing rather than a phantom "configured=0,
// failed=0", which would read as a confidently-measured "not configured" on a
// box where nothing was measured at all.
func TestNoBuildStateHookEmitsNothing9166(t *testing.T) {
	if got := flowBuildGauges9166(t, nil); len(got) != 0 {
		// nil states is distinct from a nil hook; check the nil hook too.
		t.Logf("nil states produced: %v", got)
	}
	c := newCollector(&Server{})
	reg := prometheus.NewPedanticRegistry()
	if err := reg.Register(c); err != nil {
		t.Fatalf("register: %v", err)
	}
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() == "xpf_flowexport_build_failed" {
			t.Error("an unwired hook emitted the build-failed gauge")
		}
	}
}

// BIND THE WIRING: every cell above builds a Server literal and sets the field
// directly, so all of them stay green if NewServer stops copying
// Config.FlowExportBuildStateFn onto it — the only path production uses.
func TestNewServerCopiesTheFlowBuildStateHook9166(t *testing.T) {
	srv := NewServer(Config{
		FlowExportBuildStateFn: func() []flowexport.BuildState {
			return []flowexport.BuildState{{Family: "ipfix", ConfiguredGroups: 4, BuildFailed: true}}
		},
	})
	if srv.flowExportBuildStateFn == nil {
		t.Fatal("NewServer dropped Config.FlowExportBuildStateFn, so the daemon's " +
			"hook never reaches the collector and the family is permanently absent")
	}
}
