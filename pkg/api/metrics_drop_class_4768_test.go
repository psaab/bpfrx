package api

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #4768: emitDropClassCounters must SUM the per-binding #4743 drop-class
// counters (MartianDropped, IPv6ExtHeaderDropped) across all bindings and
// emit one aggregate CounterValue series each, unconditionally (0 is a real
// signal). RED-on-revert: dropping a binding from the sum, mislabeling the
// series, or gating on nonzero would fail this.
func TestEmitDropClassCounters_4768(t *testing.T) {
	c := &xpfCollector{
		userspaceMartianDropped: prometheus.NewDesc(
			"xpf_userspace_martian_dropped_total", "test", nil, nil),
		userspaceIPv6ExtHeaderDropped: prometheus.NewDesc(
			"xpf_userspace_ipv6_ext_header_dropped_total", "test", nil, nil),
	}

	status := dpuserspace.ProcessStatus{
		Bindings: []dpuserspace.BindingStatus{
			{MartianDropped: 3, IPv6ExtHeaderDropped: 0},
			{MartianDropped: 4, IPv6ExtHeaderDropped: 10},
			{MartianDropped: 0, IPv6ExtHeaderDropped: 5},
		},
	}
	// Expected aggregates: martian 3+4+0=7, ext-header 0+10+5=15.

	ch := make(chan prometheus.Metric)
	go func() {
		c.emitDropClassCounters(ch, status)
		close(ch)
	}()
	byName := map[string]float64{}
	count := 0
	for m := range ch {
		count++
		var pb dto.Metric
		if err := m.Write(&pb); err != nil {
			t.Fatalf("write metric: %v", err)
		}
		if pb.Counter == nil {
			t.Fatalf("metric %s is not a Counter", m.Desc().String())
		}
		byName[m.Desc().String()] = pb.Counter.GetValue()
	}

	if count != 2 {
		t.Fatalf("want exactly 2 aggregate metrics, got %d", count)
	}

	var martian, extHdr float64
	for desc, v := range byName {
		switch {
		case strings.Contains(desc, "martian_dropped_total"):
			martian = v
		case strings.Contains(desc, "ipv6_ext_header_dropped_total"):
			extHdr = v
		default:
			t.Errorf("unexpected metric desc: %s", desc)
		}
	}
	if martian != 7 {
		t.Errorf("martian_dropped: want summed 7 (3+4+0), got %v", martian)
	}
	if extHdr != 15 {
		t.Errorf("ipv6_ext_header_dropped: want summed 15 (0+10+5), got %v", extHdr)
	}

	// Empty bindings still emit both series at 0 (unconditional).
	ch2 := make(chan prometheus.Metric)
	go func() {
		c.emitDropClassCounters(ch2, dpuserspace.ProcessStatus{})
		close(ch2)
	}()
	zeros := 0
	for m := range ch2 {
		var pb dto.Metric
		if err := m.Write(&pb); err != nil {
			t.Fatalf("write metric: %v", err)
		}
		if pb.Counter.GetValue() != 0 {
			t.Errorf("empty bindings: want 0, got %v", pb.Counter.GetValue())
		}
		zeros++
	}
	if zeros != 2 {
		t.Errorf("empty bindings: want 2 series emitted at 0, got %d", zeros)
	}
}
