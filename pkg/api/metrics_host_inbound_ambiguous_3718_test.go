package api

import (
	"path/filepath"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
)

// ambiguousHostInboundStore builds a store whose ACTIVE config a tolerant load
// accepts but the strict commit gate would reject (#3718 Option B): the same
// IPv4 (192.0.2.1) on two interfaces in two zones with DIFFERING host-inbound
// sets (aaa default-deny, zzz ssh). The kernel host-inbound verdict for
// 192.0.2.1 is then order-dependent. Commit() runs the STRICT path and would
// reject this, so the store is seeded via a persisted DB + tolerant Load() —
// modeling a peer-synced / older-binary config that slipped one through, exactly
// the case the runtime metric exists to surface (the ambiguity is NOT
// self-healing).
func ambiguousHostInboundStore(t *testing.T) *configstore.Store {
	t.Helper()
	dir := t.TempDir()
	// Built via flat-set commands (the parser merges hierarchical newlines, so
	// set-command construction is the reliable form for a multi-stanza fixture).
	lines := []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 192.0.2.1/24",
		"set interfaces ge-0/0/1 unit 0 family inet address 192.0.2.1/24",
		"set security zones security-zone aaa interfaces ge-0/0/0.0",
		"set security zones security-zone zzz interfaces ge-0/0/1.0",
		"set security zones security-zone zzz host-inbound-traffic system-services ssh",
	}
	tree := &config.ConfigTree{}
	for _, l := range lines {
		p, err := config.ParseSetCommand(l)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", l, err)
		}
		if err := tree.SetPath(p); err != nil {
			t.Fatalf("SetPath(%q): %v", l, err)
		}
	}
	// Sanity: it must be strict-REJECTED (proving the gate is live) yet
	// lenient-ACCEPTED (so a tolerant Load promotes it to the active config).
	if _, err := config.CompileConfig(tree); err == nil {
		t.Fatal("precondition: ambiguous config compiled cleanly on the STRICT path; the #3718 gate must reject it")
	}
	if _, err := config.CompileConfigLenient(tree); err != nil {
		t.Fatalf("precondition: ambiguous config must compile on the tolerant path (warning, not error): %v", err)
	}

	db, err := configstore.NewDB(filepath.Join(dir, ".configdb"))
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	db.SetWriterVersion("test-1.0")
	if err := db.WriteActive(tree); err != nil {
		t.Fatalf("WriteActive: %v", err)
	}

	store := newConfigStore(t, filepath.Join(dir, "xpf.conf"))
	if err := store.Load(); err != nil {
		t.Fatalf("tolerant Load() of the seeded DB must succeed: %v", err)
	}
	if store.ActiveConfig() == nil {
		t.Fatal("ActiveConfig() nil after tolerant Load of a lenient-compilable config")
	}
	return store
}

// TestHostInboundAmbiguousAddressesEmittedWhenDataplaneUnloaded is the #3718
// fail-on-revert proof: the ambiguity is a config-derived control-plane signal
// that can be open in a config-only / degraded boot AND is NOT self-healing, so
// xpf_host_inbound_ambiguous_addresses must be emitted even with the dataplane
// unloaded. Collect must call collectHostInboundAmbiguousAddresses BEFORE the
// `dp == nil || !dp.IsLoaded()` gate; moving it below makes this RED (dp is nil
// here, so Collect returns before reaching it and the series vanishes).
func TestHostInboundAmbiguousAddressesEmittedWhenDataplaneUnloaded(t *testing.T) {
	s := &Server{store: ambiguousHostInboundStore(t)} // dp intentionally nil.
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(newCollector(s))
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}

	type key struct{ addr, family string }
	got := map[key]float64{}
	for _, mf := range mfs {
		if mf.GetName() != "xpf_host_inbound_ambiguous_addresses" {
			continue
		}
		for _, m := range mf.GetMetric() {
			var k key
			for _, l := range m.GetLabel() {
				switch l.GetName() {
				case "address":
					k.addr = l.GetValue()
				case "family":
					k.family = l.GetValue()
				}
			}
			got[k] = m.GetGauge().GetValue()
		}
	}

	if len(got) != 1 {
		t.Fatalf("xpf_host_inbound_ambiguous_addresses series = %v, want exactly {192.0.2.1/inet:1} "+
			"(config-only boot; collector must run BEFORE the dataplane gate)", got)
	}
	if v := got[key{addr: "192.0.2.1", family: "inet"}]; v != 1 {
		t.Errorf("192.0.2.1/inet gauge = %v, want 1", v)
	}
}

// TestHostInboundAmbiguousAddressesNilStoreNoPanic guards the degraded path: a
// Server with no store must not panic when the collector runs before the
// dataplane gate.
func TestHostInboundAmbiguousAddressesNilStoreNoPanic(t *testing.T) {
	c := newCollector(&Server{}) // store nil
	ch := make(chan prometheus.Metric, 4)
	c.collectHostInboundAmbiguousAddresses(ch)
	close(ch)
	if n := len(ch); n != 0 {
		t.Fatalf("emitted %d series with nil store, want 0", n)
	}
}
