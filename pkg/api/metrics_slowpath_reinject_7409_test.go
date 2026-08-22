package api

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #7409 — the slow-path reinject counters must be exported, and must be
// exported UNCONDITIONALLY.
//
// All four have been on the BindingStatus wire since the helper gained them
// and are already delta-tracked in pkg/monitoriface, but nothing exported them
// to Prometheus. That is what made the bypass unobservable in production: the
// affected traffic is forwarded by the kernel with no zone policy, session,
// NAT or screen, and the only counter that moved was one nobody could alert on.

func slowPathTestCollector() *xpfCollector {
	c := &xpfCollector{}
	c.initBindingDescriptors()
	return c
}

func collectSlowPathSeries(t *testing.T, c *xpfCollector, status dpuserspace.ProcessStatus) map[string]float64 {
	t.Helper()
	ch := make(chan prometheus.Metric)
	go func() {
		c.emitBindingSlowPathReinjectCounters(ch, status)
		close(ch)
	}()
	out := map[string]float64{}
	for m := range ch {
		var pb dto.Metric
		if err := m.Write(&pb); err != nil {
			t.Fatalf("write metric: %v", err)
		}
		name := m.Desc().String()
		for _, want := range []string{
			"slow_path_no_route_packets_total",
			"slow_path_next_table_packets_total",
			"slow_path_local_delivery_packets_total",
			"slow_path_missing_neighbor_packets_total",
		} {
			// Desc.String() embeds the HELP text as well as the fqName, and
			// several of these help strings cross-reference the other
			// reasons — so a bare Contains would misattribute a series.
			// Anchor on the quoted fqName the Desc renders.
			if strings.Contains(name, `fqName: "xpf_userspace_binding_`+want+`"`) {
				out[want] = pb.GetCounter().GetValue()
			}
		}
	}
	return out
}

// A ZERO MUST BE A REAL DATAPOINT. An absent series cannot be alerted on, and
// alerting on this is the entire point of exporting it — a reinject rate that
// rises from nothing is exactly the signal an operator needs, and it is
// invisible if the series only appears once it is already non-zero.
//
// RED on revert: guard the emission behind `if b.SlowPath...Packets > 0`.
func TestSlowPathReinjectCountersAreEmittedEvenWhenZero(t *testing.T) {
	c := slowPathTestCollector()
	status := dpuserspace.ProcessStatus{
		Bindings: []dpuserspace.BindingStatus{{
			Slot: 2, QueueID: 5, WorkerID: 7, Interface: "ge-0-0-1",
			// every counter deliberately left at its zero value
		}},
	}

	got := collectSlowPathSeries(t, c, status)
	if len(got) != 4 {
		t.Fatalf("want all 4 reinject series present at zero, got %d: %v", len(got), got)
	}
	for name, v := range got {
		if v != 0 {
			t.Errorf("%s = %v, want 0", name, v)
		}
	}
}

// The values must reach the right series. A transposition here would point an
// operator at the wrong disposition — and only `no_route` is the policy-bypass
// signal, so confusing it with `local_delivery` (which IS gated, by the
// host-inbound plane) would invert the conclusion.
func TestSlowPathReinjectCountersMapToTheCorrectSeries(t *testing.T) {
	c := slowPathTestCollector()
	status := dpuserspace.ProcessStatus{
		Bindings: []dpuserspace.BindingStatus{{
			Slot: 1, QueueID: 0, WorkerID: 0, Interface: "ge-0-0-2",
			SlowPathNoRoutePackets:         11,
			SlowPathNextTablePackets:       22,
			SlowPathLocalDeliveryPackets:   33,
			SlowPathMissingNeighborPackets: 44,
		}},
	}

	got := collectSlowPathSeries(t, c, status)
	for name, want := range map[string]float64{
		"slow_path_no_route_packets_total":         11,
		"slow_path_next_table_packets_total":       22,
		"slow_path_local_delivery_packets_total":   33,
		"slow_path_missing_neighbor_packets_total": 44,
	} {
		if got[name] != want {
			t.Errorf("%s = %v, want %v", name, got[name], want)
		}
	}
}

// Every binding reports independently: a single hot worker reinjecting must
// not be averaged away by quiet siblings.
func TestSlowPathReinjectCountersAreEmittedPerBinding(t *testing.T) {
	c := slowPathTestCollector()
	status := dpuserspace.ProcessStatus{
		Bindings: []dpuserspace.BindingStatus{
			{Slot: 0, QueueID: 0, WorkerID: 0, Interface: "ge-0-0-1", SlowPathNoRoutePackets: 5},
			{Slot: 1, QueueID: 1, WorkerID: 1, Interface: "ge-0-0-2", SlowPathNoRoutePackets: 7},
		},
	}

	ch := make(chan prometheus.Metric)
	go func() {
		c.emitBindingSlowPathReinjectCounters(ch, status)
		close(ch)
	}()
	n := 0
	for range ch {
		n++
	}
	if n != 8 {
		t.Fatalf("want 4 series x 2 bindings = 8 metrics, got %d", n)
	}
}
