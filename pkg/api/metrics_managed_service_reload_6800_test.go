package api

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

// metrics_managed_service_reload_6800_test.go — #6800.
//
// The managed-service appliers converge a configuration file on disk and then
// gate the RUNTIME reload on "did the on-disk set change". A reload that FAILED
// after the file converged was erased by that gate: the next apply saw no
// change, skipped the reload, and the node kept serving the previous ruleset.
// The daemon side of the fix adds the retained debt and the retry owner; this
// file binds the operator-visible half, which is the part that stays silently
// missing when an accessor is exported but never reaches a Desc (#6852).
//
// Both series must emit with the dataplane NOT loaded (`dp` nil): rsyslog
// forwarding and chrony time sync are reconciled in config-only mode too, so a
// node whose dataplane never came up is exactly the node whose stale logging
// pipeline most needs to be visible.
//
// A pedantic registry is the instrument on purpose: it is the only registry
// that enforces Describe() ⊇ Collect(), so deleting either `ch <-` line from
// Describe reds these instead of silently degrading a production scrape.

// TestManagedServiceReloadPendingGauge6800 is PAIRED, per label. The owed leg
// alone is satisfied by a gauge hardwired to 1, which pages an operator on
// every healthy node forever; the healthy leg alone is satisfied by one
// hardwired to 0, which is the pre-#6800 blindness with extra steps.
//
// It is also per-SERVICE on purpose. A single collapsed gauge would tell an
// operator that "something" is unreloaded without saying which reload never
// landed, and the two chrony legs drive different commands and fail
// independently — so a fixture where only one leg is owed is the one that can
// tell a correctly-labelled series from a broadcast.
func TestManagedServiceReloadPendingGauge6800(t *testing.T) {
	owed := map[string]bool{
		"rsyslog":          true,
		"chrony-sources":   false,
		"chrony-threshold": true,
	}
	s := &Server{ // dp intentionally nil — the gauge must still emit
		managedServiceReloadOwedFn: func() map[string]bool { return owed },
	}
	got := gatherLabelled6800(t, s, "xpf_managed_service_reload_pending")
	if len(got) == 0 {
		t.Fatal("xpf_managed_service_reload_pending was not emitted; a managed " +
			"service whose configuration converged on disk but whose reload " +
			"never landed is invisible to an operator, which is half of #6800")
	}
	for svc, want := range map[string]float64{
		"rsyslog": 1, "chrony-sources": 0, "chrony-threshold": 1,
	} {
		v, ok := got[svc]
		if !ok {
			t.Errorf("no sample for service=%q; the series must carry one per "+
				"managed service or an operator cannot tell WHICH reload is owed", svc)
			continue
		}
		if v != want {
			t.Errorf("service=%q gauge = %v, want %v — the gauge does not track "+
				"the wired fn per service, so it reports the same value whether "+
				"or not that service is still running the previous ruleset", svc, v, want)
		}
	}
}

// TestManagedServiceReloadFailuresCounter6800 pins the counter to the wired
// fn's VALUE, not merely to its existence. A counter stuck at 0 is
// indistinguishable from a healthy node; the distinguishing case is a node that
// has failed repeatedly, so the non-zero legs carry the weight and the zero leg
// exists to reject a counter hardwired to a non-zero constant.
//
// The signal it adds over the gauge: a count that CLIMBS while the gauge stays
// 1 means the retry owner is running but not converging (a masked or failed
// unit), which is operationally very different from one transient failure paid
// on the next tick. The gauge alone cannot separate them.
func TestManagedServiceReloadFailuresCounter6800(t *testing.T) {
	failures := map[string]uint64{
		"rsyslog":          7,
		"chrony-sources":   0,
		"chrony-threshold": 1,
	}
	s := &Server{ // dp intentionally nil
		managedServiceReloadFailuresFn: func() map[string]uint64 { return failures },
	}
	got := gatherLabelled6800(t, s, "xpf_managed_service_reload_failures_total")
	if len(got) == 0 {
		t.Fatal("xpf_managed_service_reload_failures_total was not emitted; an " +
			"operator cannot tell a retry owner that is running-but-not-converging " +
			"from one that never ran (#6800)")
	}
	for svc, want := range map[string]float64{
		"rsyslog": 7, "chrony-sources": 0, "chrony-threshold": 1,
	} {
		if v, ok := got[svc]; !ok {
			t.Errorf("no sample for service=%q", svc)
		} else if v != want {
			t.Errorf("service=%q counter = %v, want %v", svc, v, want)
		}
	}
}

// TestManagedServiceReloadSeriesAreOptional6800 pins the nil-fn contract the
// sibling control-plane signals all carry: a Server with the fns unset must not
// emit the series at all, rather than publishing an authoritative 0. That is
// the #6828 absent-vs-zero distinction — a hardcoded 0 from a node that never
// wired the accessor reads exactly like a converged node.
func TestManagedServiceReloadSeriesAreOptional6800(t *testing.T) {
	s := &Server{} // both fns nil
	for _, name := range []string{
		"xpf_managed_service_reload_pending",
		"xpf_managed_service_reload_failures_total",
	} {
		if got := gatherLabelled6800(t, s, name); len(got) != 0 {
			t.Errorf("%s was emitted with no fn wired (%v); an unwired node "+
				"publishes an authoritative value indistinguishable from a "+
				"converged one", name, got)
		}
	}
}

// gatherLabelled6800 scrapes s through a PEDANTIC registry and returns the
// named family's samples keyed by their `service` label. The pedantic registry
// is what makes a missing Describe() entry a hard error rather than a silent
// production degradation.
func gatherLabelled6800(t *testing.T, s *Server, name string) map[string]float64 {
	t.Helper()
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(newCollector(s))
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	out := map[string]float64{}
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
		for _, m := range mf.GetMetric() {
			svc := ""
			for _, lp := range m.GetLabel() {
				if lp.GetName() == "service" {
					svc = lp.GetValue()
				}
			}
			if svc == "" {
				t.Fatalf("%s: a sample carries no `service` label; the label is "+
					"the only thing that says WHICH reload is owed", name)
			}
			switch {
			case m.GetGauge() != nil:
				out[svc] = m.GetGauge().GetValue()
			case m.GetCounter() != nil:
				out[svc] = m.GetCounter().GetValue()
			default:
				t.Fatalf("%s: sample is neither a gauge nor a counter", name)
			}
		}
	}
	return out
}
