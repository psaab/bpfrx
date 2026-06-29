package api

import (
	"errors"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	xnft "github.com/psaab/xpf/pkg/nftables"
)

// TestHostInboundKernelDeniesEmittedWhenDataplaneUnloaded is the #3361 SMR
// fail-on-revert proof: the kernel nftables host-inbound chain is installed and
// actively DROPS control-plane traffic INDEPENDENT of dataplane load state, so
// xpf_host_inbound_kernel_denies_total must be emitted even with the dataplane
// unloaded (config-only / degraded boot) — the exact blind spot this metric
// closes. Collect must call collectHostInboundKernelDenies BEFORE the
// `dp == nil || !dp.IsLoaded()` early-return; moving it back below the gate makes
// this RED (with dp nil, Collect returns before reaching it and the series
// vanishes).
func TestHostInboundKernelDeniesEmittedWhenDataplaneUnloaded(t *testing.T) {
	orig := readHostInboundDenyCounters
	defer func() { readHostInboundDenyCounters = orig }()
	readHostInboundDenyCounters = func() ([]xnft.HostInboundDenyCount, error) {
		return []xnft.HostInboundDenyCount{
			{Zone: "wan", Family: "ip", Packets: 7, Bytes: 700},
			{Zone: "wan", Family: "ip6", Packets: 3, Bytes: 300},
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
		if mf.GetName() != "xpf_host_inbound_kernel_denies_total" {
			continue
		}
		for _, m := range mf.GetMetric() {
			var zone, family string
			for _, l := range m.GetLabel() {
				switch l.GetName() {
				case "zone":
					zone = l.GetValue()
				case "family":
					family = l.GetValue()
				}
			}
			got[zone+"/"+family] = m.GetCounter().GetValue()
		}
	}

	if len(got) == 0 {
		t.Fatal("xpf_host_inbound_kernel_denies_total not emitted with dataplane unloaded " +
			"(collectHostInboundKernelDenies must run BEFORE the dataplane gate)")
	}
	if got["wan/ip"] != 7 {
		t.Errorf("wan/ip = %v, want 7", got["wan/ip"])
	}
	if got["wan/ip6"] != 3 {
		t.Errorf("wan/ip6 = %v, want 3", got["wan/ip6"])
	}
}

// TestHostInboundKernelDeniesReadErrorOmitsSeries verifies the #3345 contract on
// this path: a netlink read failure SKIPS the series (no misleading 0) and bumps
// the scrape-error counter rather than fabricating a zero.
func TestHostInboundKernelDeniesReadErrorOmitsSeries(t *testing.T) {
	orig := readHostInboundDenyCounters
	defer func() { readHostInboundDenyCounters = orig }()
	readHostInboundDenyCounters = func() ([]xnft.HostInboundDenyCount, error) {
		return nil, errors.New("netlink dial: permission denied")
	}

	s := &Server{}
	c := newCollector(s)
	ch := make(chan prometheus.Metric, 8)
	c.collectHostInboundKernelDenies(ch)
	close(ch)

	for m := range ch {
		t.Errorf("expected no kernel-deny series on read error, got %v", m.Desc())
	}
	if c.counterReadErrors.Load() == 0 {
		t.Error("read error must bump counterReadErrors (#3345 contract)")
	}
}
