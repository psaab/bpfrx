package api

import (
	"path/filepath"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/psaab/xpf/pkg/configstore"
)

// addresslessZoneStore builds a config with two enforcing zones: trust, whose
// interface carries a static address (scoped by the host-inbound deny), and wan,
// whose interface is DHCP with no static address and no live kernel lease in the
// test (an empty address set → the transient fail-open admit window, #3698).
func addresslessZoneStore(t *testing.T) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if err := store.LoadOverride(`
interfaces {
    ge-0/0/0 { unit 0 { family inet { address 10.0.1.10/24; } } }
    ge-0/0/1 { unit 0 { family inet { dhcp; } } }
}
security {
    zones {
        security-zone trust { interfaces { ge-0/0/0.0; } }
        security-zone wan { interfaces { ge-0/0/1.0; } }
    }
}
`); err != nil {
		t.Fatalf("LoadOverride() error = %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	return store
}

// TestHostInboundAddresslessZonesEmittedWhenDataplaneUnloaded is the #3698
// fail-on-revert proof. The transient fail-open admit window is a config-derived
// control-plane signal that can be open in a config-only / degraded boot, so
// xpf_host_inbound_addressless_zones must be emitted even with the dataplane
// unloaded. Collect must call collectHostInboundAddresslessZones BEFORE the
// `dp == nil || !dp.IsLoaded()` gate; moving it below the gate makes this RED
// (dp is nil here, so Collect returns before reaching it and the series vanishes).
// Only the addressless zone (wan) is emitted — the scoped zone (trust) must NOT
// appear, guarding the low-noise contract.
func TestHostInboundAddresslessZonesEmittedWhenDataplaneUnloaded(t *testing.T) {
	s := &Server{store: addresslessZoneStore(t)} // dp intentionally nil.
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(newCollector(s))
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}

	got := map[string]float64{}
	for _, mf := range mfs {
		if mf.GetName() != "xpf_host_inbound_addressless_zones" {
			continue
		}
		for _, m := range mf.GetMetric() {
			var zone string
			for _, l := range m.GetLabel() {
				if l.GetName() == "zone" {
					zone = l.GetValue()
				}
			}
			got[zone] = m.GetGauge().GetValue()
		}
	}

	if len(got) != 1 {
		t.Fatalf("xpf_host_inbound_addressless_zones series = %v, want exactly {wan:1} "+
			"(config-only boot; collector must run BEFORE the dataplane gate)", got)
	}
	if got["wan"] != 1 {
		t.Errorf("wan gauge = %v, want 1", got["wan"])
	}
	if _, ok := got["trust"]; ok {
		t.Error("trust is statically addressed (scoped) — it must not appear in the addressless series")
	}
}

// TestHostInboundAddresslessZonesNilStoreNoPanic guards the degraded path: a
// Server with no store (early boot) must not panic when the collector runs
// before the dataplane gate.
func TestHostInboundAddresslessZonesNilStoreNoPanic(t *testing.T) {
	c := newCollector(&Server{}) // store nil
	ch := make(chan prometheus.Metric, 4)
	c.collectHostInboundAddresslessZones(ch)
	close(ch)
	if n := len(ch); n != 0 {
		t.Fatalf("emitted %d series with nil store, want 0", n)
	}
}
