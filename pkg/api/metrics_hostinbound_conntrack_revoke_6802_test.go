package api

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

// metrics_hostinbound_conntrack_revoke_6802_test.go — #6802.
//
// A failed host-inbound kernel-conntrack revocation had no return value, no
// dirty flag, no counter, NO METRIC and no retry owner. The daemon side of the
// fix adds the debt and the retry loop; this file binds the operator-visible
// half, which is the part that stays silently missing if the accessor is
// exported but never reaches a Desc.
//
// Both series must emit with the dataplane NOT loaded (`dp` nil): the daemon
// rebuilds the kernel host-inbound table and reconciles conntrack in
// config-only mode too, so a now-denied host service that is still reachable
// over an established kernel connection has to stay visible exactly when the
// dataplane is absent.
//
// A pedantic registry is the instrument on purpose: it is the only registry
// that enforces Describe() ⊇ Collect(), so deleting either `ch <-` line from
// Describe reds these instead of silently degrading a production scrape.

// TestHostInboundConntrackRevocationPendingGauge6802 is PAIRED. The owed leg
// alone is satisfied by a gauge hardwired to 1, which would page an operator on
// every healthy node forever; the healthy leg alone is satisfied by one
// hardwired to 0, which is the pre-#6802 blindness with extra steps.
func TestHostInboundConntrackRevocationPendingGauge6802(t *testing.T) {
	for _, tc := range []struct {
		name string
		owed bool
		want float64
	}{
		{"revocation-owed", true, 1},
		{"converged", false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &Server{ // dp intentionally nil — gauge must still emit
				hostInboundConntrackRevocationOwedFn: func() bool { return tc.owed },
			}
			got, ok := gatherSingleSample6802(t, s,
				"xpf_host_inbound_conntrack_revocation_pending")
			if !ok {
				t.Fatalf("xpf_host_inbound_conntrack_revocation_pending was not " +
					"emitted; a failed host-inbound conntrack revocation is " +
					"invisible to an operator, which is half of #6802")
			}
			if got != tc.want {
				t.Errorf("gauge = %v, want %v — the gauge does not track the wired "+
					"fn, so it reports the same value whether or not a now-denied "+
					"host service is still authorized", got, tc.want)
			}
		})
	}
}

// TestHostInboundConntrackRevocationFailuresCounter6802 pins the counter to the
// wired fn's VALUE, not merely to its existence. A counter stuck at 0 is
// indistinguishable from a healthy node; the distinguishing case is a node that
// has failed repeatedly, so the non-zero leg carries the weight and the zero leg
// exists to reject a counter hardwired to the non-zero constant.
func TestHostInboundConntrackRevocationFailuresCounter6802(t *testing.T) {
	for _, tc := range []struct {
		name     string
		failures uint64
		want     float64
	}{
		{"none", 0, 0},
		{"repeated", 7, 7},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &Server{ // dp intentionally nil
				hostInboundConntrackFlushFailuresFn: func() uint64 { return tc.failures },
			}
			got, ok := gatherSingleSample6802(t, s,
				"xpf_host_inbound_conntrack_revocation_failures_total")
			if !ok {
				t.Fatalf("xpf_host_inbound_conntrack_revocation_failures_total was " +
					"not emitted; an operator cannot tell a retry owner that is " +
					"running-but-not-converging from one that never ran (#6802)")
			}
			if got != tc.want {
				t.Errorf("counter = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestHostInboundConntrackSeriesAreOptional6802 pins the nil-fn contract the
// sibling control-plane signals all carry: a Server with the fns unset must not
// emit the series at all, rather than publishing an authoritative 0. That is the
// #6828 absent-vs-zero distinction — a hardcoded 0 from a node that never wired
// the accessor reads exactly like a converged node.
func TestHostInboundConntrackSeriesAreOptional6802(t *testing.T) {
	s := &Server{} // both fns nil
	for _, name := range []string{
		"xpf_host_inbound_conntrack_revocation_pending",
		"xpf_host_inbound_conntrack_revocation_failures_total",
	} {
		if _, ok := gatherSingleSample6802(t, s, name); ok {
			t.Errorf("%s was emitted with no fn wired; an unwired node publishes "+
				"an authoritative value indistinguishable from a converged one", name)
		}
	}
}

// gatherSingleSample6802 scrapes s through a PEDANTIC registry and returns the
// single sample of the named family. The pedantic registry is what makes a
// missing Describe() entry a hard error rather than a silent production
// degradation.
func gatherSingleSample6802(t *testing.T, s *Server, name string) (float64, bool) {
	t.Helper()
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(newCollector(s))
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
		ms := mf.GetMetric()
		if len(ms) != 1 {
			t.Fatalf("%s: metric count = %d, want 1", name, len(ms))
		}
		if g := ms[0].GetGauge(); g != nil {
			return g.GetValue(), true
		}
		if c := ms[0].GetCounter(); c != nil {
			return c.GetValue(), true
		}
		t.Fatalf("%s: sample is neither a gauge nor a counter", name)
	}
	return 0, false
}
