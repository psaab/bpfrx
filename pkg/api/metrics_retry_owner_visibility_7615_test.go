package api

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

// metrics_retry_owner_visibility_7615_test.go — #7615.
//
// Six always-on retry owners re-drive a failure that had no other owner. Two
// already published (#6800, #6802); these are the remaining debt-driven three.
// The point is not the metric — it is that a node carrying an unpaid debt stops
// being indistinguishable from a healthy one.
//
// A pedantic registry is the instrument on purpose: it is the only registry
// that enforces Describe() ⊇ Collect(), so deleting a `ch <-` line from
// Describe reds here rather than silently degrading a production scrape.
//
// All three must emit with the dataplane NOT loaded (`dp` nil). Every one of
// these repairs runs in config-only mode too, and a node whose dataplane never
// came up is exactly the node whose unpaid debt most needs to be visible.

// TestRetryOwnerGaugesTrackTheirFn7615 is PAIRED per gauge. The owed leg alone
// is satisfied by a gauge hardwired to 1, which pages on every healthy node
// forever; the healthy leg alone is satisfied by one hardwired to 0, which is
// the pre-#7615 blindness with extra steps.
func TestRetryOwnerGaugesTrackTheirFn7615(t *testing.T) {
	for _, tc := range []struct {
		name   string
		series string
		wire   func(*Server, bool)
	}{
		{
			"RA dead sender", "xpf_ra_dead_sender_pending",
			func(s *Server, v bool) { s.raDeadSenderPendingFn = func() bool { return v } },
		},
		{
			"fabric overlay", "xpf_fabric_overlay_missing",
			func(s *Server, v bool) { s.fabricOverlayMissingFn = func() bool { return v } },
		},
		{
			"management listener", "xpf_management_listener_down",
			func(s *Server, v bool) { s.managementListenerDownFn = func() bool { return v } },
		},
		{
			// #7685: the sixth owner. Its debt is NOT "the kernel drifted" —
			// that is expected after a link flap and self-corrects on the next
			// tick — but a CONFIGURED proxy-arp interface whose netdev does not
			// resolve, which persists until the interface exists.
			"proxy-arp unresolved", "xpf_proxy_arp_unresolved_pending",
			func(s *Server, v bool) { s.proxyARPUnresolvedFn = func() bool { return v } },
		},
	} {
		for _, leg := range []struct {
			owed bool
			want float64
		}{{true, 1}, {false, 0}} {
			s := &Server{} // dp intentionally nil
			tc.wire(s, leg.owed)
			got, ok := gatherSingleSample7615(t, s, tc.series)
			if !ok {
				t.Fatalf("%s: %s was not emitted; the retry owner is re-driving a "+
					"failed repair with nothing an operator can see (#7615)",
					tc.name, tc.series)
			}
			if got != leg.want {
				t.Errorf("%s: gauge = %v with owed=%v, want %v — the gauge does not "+
					"track the wired fn, so it reports the same value whether or not "+
					"the repair is outstanding", tc.name, got, leg.owed, leg.want)
			}
		}
	}
}

// TestRetryOwnerGaugesAreOptional7615 pins the nil-fn contract the sibling
// control-plane signals carry: unset fns must emit NOTHING rather than an
// authoritative 0. That is the #6828 absent-vs-zero distinction — a hardcoded 0
// from a node that never wired the accessor reads exactly like a healthy one.
func TestRetryOwnerGaugesAreOptional7615(t *testing.T) {
	s := &Server{} // all three fns nil
	for _, name := range []string{
		"xpf_ra_dead_sender_pending",
		"xpf_fabric_overlay_missing",
		"xpf_management_listener_down",
		"xpf_proxy_arp_unresolved_pending",
	} {
		if _, ok := gatherSingleSample7615(t, s, name); ok {
			t.Errorf("%s was emitted with no fn wired; an unwired node publishes a "+
				"value indistinguishable from a converged one", name)
		}
	}
}

func gatherSingleSample7615(t *testing.T, s *Server, name string) (float64, bool) {
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
		t.Fatalf("%s: sample is not a gauge", name)
	}
	return 0, false
}
