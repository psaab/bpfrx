package api

import (
	"errors"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	xnft "github.com/psaab/xpf/pkg/nftables"
)

// TestHostInboundAcceptCountersEmittedWhenDataplaneUnloaded is the #4759
// fail-on-revert proof: the kernel nftables host-inbound chain
// (`inet xpf_hostinbound`) counts the GLOBAL ICMP-error / ND accepts INDEPENDENT
// of dataplane load state, so xpf_host_inbound_icmp_nd_accept_total must be
// emitted even with the dataplane unloaded (config-only / degraded boot).
// Collect must call collectHostInboundICMPNDAccepts BEFORE the
// `dp == nil || !dp.IsLoaded()` early-return; moving it below the gate makes this
// RED. The per-type-class series is labeled by `type`.
func TestHostInboundAcceptCountersEmittedWhenDataplaneUnloaded(t *testing.T) {
	orig := readHostInboundAcceptCounters
	defer func() { readHostInboundAcceptCounters = orig }()
	readHostInboundAcceptCounters = func() ([]xnft.HostInboundAcceptCount, error) {
		return []xnft.HostInboundAcceptCount{
			{Type: xnft.HostInboundAcceptICMP6ND, Packets: 9, Bytes: 900},
			{Type: xnft.HostInboundAcceptICMP6Error, Packets: 4, Bytes: 400},
			{Type: xnft.HostInboundAcceptICMP4Error, Packets: 2, Bytes: 200},
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
		if mf.GetName() != "xpf_host_inbound_icmp_nd_accept_total" {
			continue
		}
		for _, m := range mf.GetMetric() {
			var typ string
			for _, l := range m.GetLabel() {
				if l.GetName() == "type" {
					typ = l.GetValue()
				}
			}
			got[typ] = m.GetCounter().GetValue()
		}
	}

	if len(got) == 0 {
		t.Fatal("xpf_host_inbound_icmp_nd_accept_total not emitted with dataplane " +
			"unloaded (collectHostInboundICMPNDAccepts must run BEFORE the dataplane gate)")
	}
	if got[xnft.HostInboundAcceptICMP6ND] != 9 {
		t.Errorf("icmp6_nd = %v, want 9", got[xnft.HostInboundAcceptICMP6ND])
	}
	if got[xnft.HostInboundAcceptICMP6Error] != 4 {
		t.Errorf("icmp6_error = %v, want 4", got[xnft.HostInboundAcceptICMP6Error])
	}
	if got[xnft.HostInboundAcceptICMP4Error] != 2 {
		t.Errorf("icmp4_error = %v, want 2", got[xnft.HostInboundAcceptICMP4Error])
	}
}

// TestHostInboundAcceptCounterReadErrorOmitsSeries verifies the #3345 contract:
// a netlink read failure SKIPS the series (no misleading 0) and bumps the
// scrape-error counter rather than fabricating a zero.
func TestHostInboundAcceptCounterReadErrorOmitsSeries(t *testing.T) {
	orig := readHostInboundAcceptCounters
	defer func() { readHostInboundAcceptCounters = orig }()
	readHostInboundAcceptCounters = func() ([]xnft.HostInboundAcceptCount, error) {
		return nil, errors.New("netlink dial: permission denied")
	}

	s := &Server{}
	c := newCollector(s)
	ch := make(chan prometheus.Metric, 8)
	c.collectHostInboundICMPNDAccepts(ch)
	close(ch)

	for m := range ch {
		t.Errorf("expected no accept-counter series on read error, got %v", m.Desc())
	}
	if c.counterReadErrors.Load() == 0 {
		t.Error("read error must bump counterReadErrors (#3345 contract)")
	}
}
