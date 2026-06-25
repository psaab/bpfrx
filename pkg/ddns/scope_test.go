package ddns

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// #2691 P1b scope tests: ScopeKey ownership-key independence, per-family
// independent policy (#2663), and the per-RG HA writer gate (#2664). All drive
// the engine through ReconcileScoped with a fakeUpdater (no network/DNS).

// scopeManager builds a manager wired to a per-family fake lease source + a
// fakeUpdater for BOTH families (the same updater records all ops). The updater
// factory returns the recording updater whenever a family is enabled, so the
// per-family backend resolution is exercised end to end.
func scopeManager(t *testing.T, up DNSUpdater, v4, v6 []Lease) *Manager {
	t.Helper()
	dir := t.TempDir()
	src := &fakeLeaseSource{v4: v4, v6: v6}
	m := newManagerForTesting(
		src.parser(),
		up,
		filepath.Join(dir, "state.json"),
		filepath.Join(dir, "leases4.csv"),
		filepath.Join(dir, "leases6.csv"),
		"node0",
		func() time.Time { return time.Unix(1_700_000_000, 0) },
	)
	// Resolve to the recording updater whenever the family is enabled.
	m.newUpdater = func(pol ddnsPolicy, c *config.DHCPDynamicDNSConfig) (DNSUpdater, error) {
		if !pol.enabled || c == nil {
			return nopUpdater{}, nil
		}
		return up, nil
	}
	return m
}

// scopeRecOf counts how many owned records carry the given RGOwner.
func ownedByRG(m *Manager, rg int) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, r := range m.state.records {
		if r.scopeOf().RGOwner == rg {
			n++
		}
	}
	return n
}

// TestScopeKeyDistinctForDifferentScopes proves the ScopeKey primitive: two
// owned records with the SAME identity+address but DIFFERENT scopes (different
// RG owner, or different family) are DISTINCT entries that never collide
// (#2663/#2664 — the unifying requirement). Against a flat identity|address key
// (the pre-P1b shape) the second put would OVERWRITE the first.
func TestScopeKeyDistinctForDifferentScopes(t *testing.T) {
	s := &ddnsState{path: "", records: map[string]ownedRecord{}}

	base := ownedRecord{Identity: "mac:aa", Address: "10.0.1.5", FQDN: "h.example.com",
		ForwardType: "A", Family: 4, TTL: 300}

	// Same identity+address under two different RG scopes.
	rg1 := base.withScope(ScopeKey{Family: FamilyV4, RGOwner: 1})
	rg2 := base.withScope(ScopeKey{Family: FamilyV4, RGOwner: 2})
	s.put(rg1)
	s.put(rg2)
	if len(s.records) != 2 {
		t.Fatalf("two different-RG scopes must be distinct owned entries, got %d", len(s.records))
	}
	if _, ok := s.get(ScopeKey{Family: FamilyV4, RGOwner: 1}, "mac:aa", "10.0.1.5"); !ok {
		t.Fatal("RG1-scoped record not retrievable by its scope")
	}
	if _, ok := s.get(ScopeKey{Family: FamilyV4, RGOwner: 2}, "mac:aa", "10.0.1.5"); !ok {
		t.Fatal("RG2-scoped record not retrievable by its scope")
	}

	// The ZERO scope yields the pre-P1b "identity|address" key, distinct from
	// the RG-scoped keys.
	if got := ownedRecordKey(ScopeKey{}, "mac:aa", "10.0.1.5"); got != "mac:aa|10.0.1.5" {
		t.Fatalf("zero-scope key must be the pre-P1b form, got %q", got)
	}
	if ownedRecordKey(ScopeKey{RGOwner: 1}, "mac:aa", "10.0.1.5") == ownedRecordKey(ScopeKey{}, "mac:aa", "10.0.1.5") {
		t.Fatal("a non-zero scope must not collide with the zero/global key")
	}
}

// TestScopeKeyZeroRoundTripsPreP1bStore proves a pre-P1b ownership record (no
// "scope" JSON key) loads as the zero/global scope and is keyed exactly as
// before — no migration, no churn (plan §11 Q7).
func TestScopeKeyZeroRoundTripsPreP1bStore(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	// A pre-P1b store: records with NO "scope" field.
	writeCSV(t, path, `{"version":1,"records":[
	  {"family":4,"identity":"mac:aa","subnet_id":"1","address":"10.0.1.5",
	   "fqdn":"h.example.com","forward_type":"A","ptr_name":"5.1.0.10.in-addr.arpa","ttl":300,"owner_id":"x"}
	]}`)
	st, err := loadDDNSState(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if _, ok := st.records["mac:aa|10.0.1.5"]; !ok {
		t.Fatalf("pre-P1b record not keyed by the global identity|address form: %v", keysOf(st))
	}
	r := st.records["mac:aa|10.0.1.5"]
	if r.Scope != nil {
		t.Fatalf("pre-P1b record must decode to a nil (zero) scope, got %+v", r.Scope)
	}
}

func keysOf(s *ddnsState) []string {
	out := make([]string, 0, len(s.records))
	for k := range s.records {
		out = append(out, k)
	}
	return out
}

// TestIndependentV4V6Policy proves #2663: the v4 and v6 families reconcile with
// INDEPENDENT policies + backends. A v4-scoped publish and a v6-scoped publish
// for the same host are independent; a disabled/failed v4 family does not block
// v6 publishing. Here both families are enabled with different domains, and both
// publish their own records.
func TestIndependentV4V6Policy(t *testing.T) {
	up := newFakeUpdater()
	v4 := []Lease{{Family: 4, Address: "10.0.1.5", Identity: "mac:aa", HostName: "host", SubnetID: "1"}}
	v6 := []Lease{{Family: 6, Address: "2001:db8::5", Identity: "duid:00:01", HostName: "host", SubnetID: "1"}}
	m := scopeManager(t, up, v4, v6)

	cfg := &config.DHCPServerConfig{
		DynamicDNS:   &config.DHCPDynamicDNSConfig{Enabled: true, Domain: "v4.example.com", TTLSeconds: 300},
		DynamicDNSv6: &config.DHCPDynamicDNSConfig{Enabled: true, Domain: "v6.example.com", TTLSeconds: 300},
	}
	if err := m.Reconcile(context.Background(), cfg); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	names := up.upsertNames()
	var sawV4, sawV6 bool
	for _, n := range names {
		switch n {
		case "host.v4.example.com=10.0.1.5":
			sawV4 = true
		case "host.v6.example.com=2001:db8::5":
			sawV6 = true
		}
	}
	if !sawV4 {
		t.Errorf("v4 lease must publish under its OWN domain v4.example.com; upserts=%v", names)
	}
	if !sawV6 {
		t.Errorf("v6 lease must publish under its OWN domain v6.example.com; upserts=%v", names)
	}
}

// TestV4DisableLeavesV6Untouched proves #2663 independence on the disable path:
// turning v4 OFF withdraws v4 records but must NOT touch v6 records.
func TestV4DisableLeavesV6Untouched(t *testing.T) {
	up := newFakeUpdater()
	v4 := []Lease{{Family: 4, Address: "10.0.1.5", Identity: "mac:aa", HostName: "h4", SubnetID: "1"}}
	v6 := []Lease{{Family: 6, Address: "2001:db8::5", Identity: "duid:00:01", HostName: "h6", SubnetID: "1"}}
	m := scopeManager(t, up, v4, v6)

	both := &config.DHCPServerConfig{
		DynamicDNS:   &config.DHCPDynamicDNSConfig{Enabled: true, Domain: "example.com", TTLSeconds: 300},
		DynamicDNSv6: &config.DHCPDynamicDNSConfig{Enabled: true, Domain: "example.com", TTLSeconds: 300},
	}
	if err := m.Reconcile(context.Background(), both); err != nil {
		t.Fatalf("reconcile both: %v", err)
	}
	if len(m.state.records) != 2 {
		t.Fatalf("both families should own a record, got %d", len(m.state.records))
	}

	// Disable v4 only (v6 stays enabled).
	up.deletes = nil
	v4Off := &config.DHCPServerConfig{
		DynamicDNS:   &config.DHCPDynamicDNSConfig{Enabled: false, Domain: "example.com", TTLSeconds: 300},
		DynamicDNSv6: &config.DHCPDynamicDNSConfig{Enabled: true, Domain: "example.com", TTLSeconds: 300},
	}
	if err := m.Reconcile(context.Background(), v4Off); err != nil {
		t.Fatalf("reconcile v4-off: %v", err)
	}
	// v4 record withdrawn, v6 retained.
	for _, d := range up.deletes {
		if d.Addr.Is6() {
			t.Fatalf("v6 record deleted when only v4 was disabled: %s", d.FQDN)
		}
	}
	if _, ok := m.state.get(ScopeKey{}, "duid:00:01", "2001:db8::5"); !ok {
		t.Fatal("v6 owned record lost when only v4 was disabled (independence broken)")
	}
	if _, ok := m.state.get(ScopeKey{}, "mac:aa", "10.0.1.5"); ok {
		t.Fatal("v4 owned record must be withdrawn when v4 is disabled")
	}
}

// TestPerRGGatePublishesOwnedRGOnly proves the #2664 per-RG HA writer gate: a
// node that is MASTER for RG1 but NOT RG2 publishes RG1's leases, does NOT
// publish RG2's leases, and does NOT withdraw RG2's previously-owned records
// (stop-writing, never withdraw). This is the partial-demotion invariant.
//
// Fail-on-revert: with the pre-#2664 node-level gate (publish-everything-when-
// master-for-any-RG), RG2's lease WOULD be published from this node — the
// `sawRG2Upsert` assertion below catches that regression.
func TestPerRGGatePublishesOwnedRGOnly(t *testing.T) {
	up := newFakeUpdater()
	// Two leases in two different RG-owned subnets.
	rg1Lease := Lease{Family: 4, Address: "10.0.1.5", Identity: "mac:11", HostName: "rg1host", SubnetID: "1"}
	rg2Lease := Lease{Family: 4, Address: "10.0.2.5", Identity: "mac:22", HostName: "rg2host", SubnetID: "2"}
	m := scopeManager(t, up, []Lease{rg1Lease, rg2Lease}, nil)

	cfg := &config.DHCPServerConfig{
		DynamicDNS: &config.DHCPDynamicDNSConfig{Enabled: true, Domain: "example.com", TTLSeconds: 300},
	}

	// Resolver: 10.0.1.0/24 → RG1, 10.0.2.0/24 → RG2.
	resolver := func(l Lease) (ScopeKey, bool) {
		switch l.Address {
		case "10.0.1.5":
			return ScopeKey{Family: FamilyV4, RGOwner: 1}, true
		case "10.0.2.5":
			return ScopeKey{Family: FamilyV4, RGOwner: 2}, true
		}
		return ScopeKey{}, false
	}
	// Phase 1: node is MASTER for BOTH RGs → both publish + owned.
	gateBoth := func(s ScopeKey) bool { return true }
	if err := m.ReconcileScoped(context.Background(), cfg,
		ReconcileOptions{Gate: gateBoth, Resolver: resolver}); err != nil {
		t.Fatalf("reconcile (master for both): %v", err)
	}
	if ownedByRG(m, 1) != 1 || ownedByRG(m, 2) != 1 {
		t.Fatalf("both RGs should be owned: rg1=%d rg2=%d", ownedByRG(m, 1), ownedByRG(m, 2))
	}

	// Phase 2: PARTIAL DEMOTION — node loses RG2, keeps RG1. The gate now
	// CLOSES for RG2. RG2's lease is still in the (stale) memfile.
	up.upserts = nil
	up.deletes = nil
	gateRG1Only := func(s ScopeKey) bool { return s.RGOwner == 1 }
	if err := m.ReconcileScoped(context.Background(), cfg,
		ReconcileOptions{Gate: gateRG1Only, Resolver: resolver}); err != nil {
		t.Fatalf("reconcile (master for RG1 only): %v", err)
	}

	// RG2 must NOT be published from this node (the #2664 double-write fix).
	for _, u := range up.upserts {
		if u.FQDN == "rg2host.example.com" {
			t.Fatalf("RG2 lease published from a node that is NOT MASTER for RG2 (double-writer): %s", u.FQDN)
		}
	}
	// RG2 must NOT be withdrawn (stop-writing, never withdraw — the peer that
	// became MASTER for RG2 refreshes it; a withdraw would blackhole).
	for _, d := range up.deletes {
		if d.FQDN == "rg2host.example.com" {
			t.Fatalf("RG2 record WITHDRAWN on partial demotion (blackhole risk): %s", d.FQDN)
		}
	}
	// RG2's owned record is PRESERVED in the store (still owned, just not
	// touched from here).
	if ownedByRG(m, 2) != 1 {
		t.Fatalf("RG2 owned record must be preserved on partial demotion, got %d", ownedByRG(m, 2))
	}
	// RG1 is still owned + serviced.
	if ownedByRG(m, 1) != 1 {
		t.Fatalf("RG1 owned record must remain, got %d", ownedByRG(m, 1))
	}
}

// TestPerRGGateFailClosedUnattributable proves the fail-closed contract
// (#2664): a lease the gate rejects (admit=false) is NOT published and NOT
// stored. The resolver returns ok=false → the engine drops it.
func TestPerRGGateFailClosedUnattributable(t *testing.T) {
	up := newFakeUpdater()
	lease := Lease{Family: 4, Address: "10.9.9.9", Identity: "mac:99", HostName: "ghost", SubnetID: "9"}
	m := scopeManager(t, up, []Lease{lease}, nil)
	cfg := &config.DHCPServerConfig{
		DynamicDNS: &config.DHCPDynamicDNSConfig{Enabled: true, Domain: "example.com", TTLSeconds: 300},
	}
	resolver := func(l Lease) (ScopeKey, bool) { return ScopeKey{}, false } // never attributable
	gate := func(s ScopeKey) bool { return true }
	if err := m.ReconcileScoped(context.Background(), cfg,
		ReconcileOptions{Gate: gate, Resolver: resolver}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if len(up.upserts) != 0 {
		t.Fatalf("an unattributable (fail-closed) lease must not be published, got %v", up.upsertNames())
	}
	if len(m.state.records) != 0 {
		t.Fatalf("an unattributable lease must not be recorded as owned, got %d", len(m.state.records))
	}
}
