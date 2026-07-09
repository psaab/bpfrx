package api

import (
	"errors"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	xnft "github.com/psaab/xpf/pkg/nftables"
)

// TestHostInboundJunosHostDeniesEmittedWhenDataplaneUnloaded is the #4146
// fail-on-revert proof: the kernel `to-zone junos-host` DENY rules drop direct
// host-bound traffic INDEPENDENT of dataplane load state, so
// xpf_host_inbound_junos_host_denies_total must be emitted even with the
// dataplane unloaded (config-only / degraded boot). collectHostInboundJunosHost
// Denies must run BEFORE the dataplane gate.
func TestHostInboundJunosHostDeniesEmittedWhenDataplaneUnloaded(t *testing.T) {
	orig := readHostInboundJunosHostDenyCounters
	defer func() { readHostInboundJunosHostDenyCounters = orig }()
	readHostInboundJunosHostDenyCounters = func() ([]xnft.HostInboundJunosHostDenyCount, error) {
		return []xnft.HostInboundJunosHostDenyCount{
			{Scope: "untrust", Family: "ip", Packets: 11, Bytes: 1100},
			{Scope: "untrust", Family: "ip6", Packets: 4, Bytes: 400},
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
		if mf.GetName() != "xpf_host_inbound_junos_host_denies_total" {
			continue
		}
		for _, m := range mf.GetMetric() {
			var scope, family string
			for _, l := range m.GetLabel() {
				switch l.GetName() {
				case "scope":
					scope = l.GetValue()
				case "family":
					family = l.GetValue()
				}
			}
			got[scope+"/"+family] = m.GetCounter().GetValue()
		}
	}

	if len(got) == 0 {
		t.Fatal("xpf_host_inbound_junos_host_denies_total not emitted with dataplane unloaded " +
			"(collectHostInboundJunosHostDenies must run BEFORE the dataplane gate)")
	}
	if got["untrust/ip"] != 11 {
		t.Errorf("untrust/ip = %v, want 11", got["untrust/ip"])
	}
	if got["untrust/ip6"] != 4 {
		t.Errorf("untrust/ip6 = %v, want 4", got["untrust/ip6"])
	}
}

// TestHostInboundJunosHostDeniesReadErrorOmitsSeries verifies the #3345 contract:
// a netlink read failure SKIPS the series and bumps the scrape-error counter.
func TestHostInboundJunosHostDeniesReadErrorOmitsSeries(t *testing.T) {
	orig := readHostInboundJunosHostDenyCounters
	defer func() { readHostInboundJunosHostDenyCounters = orig }()
	readHostInboundJunosHostDenyCounters = func() ([]xnft.HostInboundJunosHostDenyCount, error) {
		return nil, errors.New("netlink dial: permission denied")
	}

	s := &Server{}
	c := newCollector(s)
	ch := make(chan prometheus.Metric, 8)
	c.collectHostInboundJunosHostDenies(ch)
	close(ch)

	for m := range ch {
		t.Errorf("expected no junos-host-deny series on read error, got %v", m.Desc())
	}
	if c.counterReadErrors.Load() == 0 {
		t.Error("read error must bump counterReadErrors (#3345 contract)")
	}
}
