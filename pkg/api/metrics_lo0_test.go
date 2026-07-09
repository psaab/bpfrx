package api

import (
	"errors"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	xnft "github.com/psaab/xpf/pkg/nftables"
)

// TestLo0CounterHitsEmittedWhenDataplaneUnloaded is the #4422 fail-on-revert
// proof: the kernel nftables lo0 loopback input-filter chain (`inet xpf_lo0`) is
// installed and counts host-inbound loopback traffic INDEPENDENT of dataplane
// load state, so xpf_lo0_counter_hits_total must be emitted even with the
// dataplane unloaded (config-only / degraded boot). Collect must call
// collectLo0Counters BEFORE the `dp == nil || !dp.IsLoaded()` early-return;
// moving it back below the gate makes this RED (with dp nil, Collect returns
// before reaching it and the series vanishes). The lo0 counts are DISTINCT from
// the userspace fast-path xpf_filter_hits_total.
func TestLo0CounterHitsEmittedWhenDataplaneUnloaded(t *testing.T) {
	orig := readLo0Counters
	defer func() { readLo0Counters = orig }()
	readLo0Counters = func() ([]xnft.Lo0Count, error) {
		return []xnft.Lo0Count{
			{Counter: "ssh-hits", Packets: 12, Bytes: 1200},
			{Counter: "bgp-in", Packets: 4, Bytes: 400},
		}, nil
	}

	s := &Server{} // dp intentionally nil — degraded / config-only boot.
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(newCollector(s))
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}

	got := map[string]float64{}
	for _, mf := range mfs {
		if mf.GetName() != "xpf_lo0_counter_hits_total" {
			continue
		}
		for _, m := range mf.GetMetric() {
			var counter string
			for _, l := range m.GetLabel() {
				if l.GetName() == "counter" {
					counter = l.GetValue()
				}
			}
			got[counter] = m.GetCounter().GetValue()
		}
	}

	if len(got) == 0 {
		t.Fatal("xpf_lo0_counter_hits_total not emitted with dataplane unloaded " +
			"(collectLo0Counters must run BEFORE the dataplane gate)")
	}
	if got["ssh-hits"] != 12 {
		t.Errorf("ssh-hits = %v, want 12", got["ssh-hits"])
	}
	if got["bgp-in"] != 4 {
		t.Errorf("bgp-in = %v, want 4", got["bgp-in"])
	}
}

// TestLo0CounterReadErrorOmitsSeries verifies the #3345 contract on this path: a
// netlink read failure SKIPS the series (no misleading 0) and bumps the
// scrape-error counter rather than fabricating a zero.
func TestLo0CounterReadErrorOmitsSeries(t *testing.T) {
	orig := readLo0Counters
	defer func() { readLo0Counters = orig }()
	readLo0Counters = func() ([]xnft.Lo0Count, error) {
		return nil, errors.New("netlink dial: permission denied")
	}

	s := &Server{}
	c := newCollector(s)
	ch := make(chan prometheus.Metric, 8)
	c.collectLo0Counters(ch)
	close(ch)

	for m := range ch {
		t.Errorf("expected no lo0-counter series on read error, got %v", m.Desc())
	}
	if c.counterReadErrors.Load() == 0 {
		t.Error("read error must bump counterReadErrors (#3345 contract)")
	}
}
