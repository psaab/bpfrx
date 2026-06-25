package dhcpserver

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/psaab/xpf/pkg/config"
)

// #1387 inc-2 manager-level integration tests: the DDNSManager driving the
// LIVE rfc2136 backend (resolved per-Reconcile) against the in-process
// miekg/dns server, plus the reconcile-pass / skip counters and the
// enabled→disabled withdraw-once behaviour.

// prodManagerTo builds a production-shaped manager (resolve-per-Reconcile)
// whose factory points the live backend at the fake server.
func prodManagerTo(t *testing.T, srv *fakeDNSServer) *DDNSManager {
	t.Helper()
	dir := t.TempDir()
	m := newDDNSManagerForTesting(
		nopUpdater{},
		filepath.Join(dir, "state.json"),
		filepath.Join(dir, "leases4.csv"),
		filepath.Join(dir, "leases6.csv"),
		"node0",
		func() time.Time { return time.Unix(1_700_000_000, 0) },
	)
	m.newUpdater = func(pol ddnsPolicy, c *config.DHCPDynamicDNSConfig) (DNSUpdater, error) {
		if pol.backend != "rfc2136" || c == nil || c.UpdateServer == "" {
			return nopUpdater{}, nil
		}
		c.UpdateServer = srv.addrUDP
		return newRFC2136Updater(pol, c, nil,
			func() { m.skippedPTRNotAuth.Add(1) },
			func() { m.skippedConflict.Add(1) })
	}
	return m
}

func ddnsCfg(server string) *config.DHCPServerConfig {
	return &config.DHCPServerConfig{
		DynamicDNS: &config.DHCPDynamicDNSConfig{
			Enabled:      true,
			Domain:       "example.com",
			TTLSeconds:   300,
			Backend:      "rfc2136",
			UpdateServer: server,
		},
	}
}

func TestManagerReconcileLiveBackendPublishesAndExpires(t *testing.T) {
	srv := newFakeDNSServer(t, nil)
	m := prodManagerTo(t, srv)
	cfg := ddnsCfg(srv.addrUDP)

	// Cycle 1: one active v4 lease → forward + reverse published; owned.
	writeCSV(t, m.leasePath4, `address,hwaddr,client_id,valid_lifetime,expire,subnet_id,hostname,state
10.0.1.5,aa,,3600,1900000000,1,laptop,0
`)
	writeCSV(t, m.leasePath6, "address,duid,valid_lifetime,expire,subnet_id,iaid,hostname,state\n")
	if err := m.Reconcile(context.Background(), cfg); err != nil {
		t.Fatalf("reconcile 1: %v", err)
	}
	st := m.Stats()
	if st.UpsertOK == 0 {
		t.Errorf("UpsertOK = 0, want >0 (live backend should publish)")
	}
	if st.OwnedRecords != 1 {
		t.Errorf("OwnedRecords = %d, want 1", st.OwnedRecords)
	}
	if st.ReconcileOK != 1 {
		t.Errorf("ReconcileOK = %d, want 1", st.ReconcileOK)
	}
	// The server saw a forward A add + a reverse PTR add.
	var sawA, sawPTR bool
	for _, up := range srv.recorded() {
		for _, rr := range up.adds {
			switch rr.(type) {
			case *dns.A:
				sawA = true
			case *dns.PTR:
				sawPTR = true
			}
		}
	}
	if !sawA || !sawPTR {
		t.Errorf("server did not see both A and PTR adds (A=%v PTR=%v)", sawA, sawPTR)
	}

	// Cycle 2: lease gone (empty CSV) → the owned record is deleted.
	writeCSV(t, m.leasePath4, "address,hwaddr,client_id,valid_lifetime,expire,subnet_id,hostname,state\n")
	if err := m.Reconcile(context.Background(), cfg); err != nil {
		t.Fatalf("reconcile 2: %v", err)
	}
	st = m.Stats()
	if st.DeleteOK == 0 {
		t.Errorf("DeleteOK = 0, want >0 (expired lease should delete)")
	}
	if st.OwnedRecords != 0 {
		t.Errorf("OwnedRecords = %d, want 0 after expiry", st.OwnedRecords)
	}
}

func TestManagerReconcileSteadyStateNoChurn(t *testing.T) {
	srv := newFakeDNSServer(t, nil)
	m := prodManagerTo(t, srv)
	cfg := ddnsCfg(srv.addrUDP)
	writeCSV(t, m.leasePath4, `address,hwaddr,client_id,valid_lifetime,expire,subnet_id,hostname,state
10.0.1.5,aa,,3600,1900000000,1,laptop,0
`)
	writeCSV(t, m.leasePath6, "address,duid,valid_lifetime,expire,subnet_id,iaid,hostname,state\n")
	if err := m.Reconcile(context.Background(), cfg); err != nil {
		t.Fatalf("reconcile 1: %v", err)
	}
	after1 := m.Stats().UpsertOK
	// Two more cycles with the SAME lease: recordsEqual short-circuit means
	// the stable lease is NOT re-upserted (plan risk R5).
	for i := 0; i < 2; i++ {
		if err := m.Reconcile(context.Background(), cfg); err != nil {
			t.Fatalf("reconcile %d: %v", i+2, err)
		}
	}
	if got := m.Stats().UpsertOK; got != after1 {
		t.Errorf("UpsertOK churned across steady-state cycles: %d -> %d (want flat)", after1, got)
	}
}

func TestManagerEnabledThenDisabledWithdrawsOnce(t *testing.T) {
	srv := newFakeDNSServer(t, nil)
	m := prodManagerTo(t, srv)
	enabled := ddnsCfg(srv.addrUDP)
	writeCSV(t, m.leasePath4, `address,hwaddr,client_id,valid_lifetime,expire,subnet_id,hostname,state
10.0.1.5,aa,,3600,1900000000,1,laptop,0
`)
	writeCSV(t, m.leasePath6, "address,duid,valid_lifetime,expire,subnet_id,iaid,hostname,state\n")
	if err := m.Reconcile(context.Background(), enabled); err != nil {
		t.Fatalf("enable reconcile: %v", err)
	}
	if m.Stats().OwnedRecords != 1 {
		t.Fatalf("expected 1 owned record after enable")
	}

	// Disable via DynamicDNS != nil with Enabled=false (NOT a nil stanza):
	// the backend config (Backend + UpdateServer) is retained, so the
	// resolve-per-Reconcile factory still builds the LIVE backend (a disabled
	// policy that keeps backend "rfc2136" + an update-server resolves the
	// rfc2136 updater, not the nop). withdrawAllLocked then deletes the owned
	// record THROUGH that live backend before the !pol.enabled branch returns.
	// (Whole-stanza removal — DynamicDNS=nil — resolves the nop and is covered
	// by the stanza-removal withdraw test.)
	disabled := &config.DHCPServerConfig{DynamicDNS: &config.DHCPDynamicDNSConfig{
		Enabled:      false,
		Domain:       "example.com",
		Backend:      "rfc2136",
		UpdateServer: srv.addrUDP,
	}}
	if err := m.Reconcile(context.Background(), disabled); err != nil {
		t.Fatalf("disable reconcile: %v", err)
	}
	if m.Stats().OwnedRecords != 0 {
		t.Errorf("OwnedRecords = %d after disable, want 0 (withdraw)", m.Stats().OwnedRecords)
	}
	delsAfterDisable := m.Stats().DeleteOK
	// A second disabled reconcile is a no-op (store empty) — withdraw once.
	if err := m.Reconcile(context.Background(), disabled); err != nil {
		t.Fatalf("second disable reconcile: %v", err)
	}
	if got := m.Stats().DeleteOK; got != delsAfterDisable {
		t.Errorf("second disabled reconcile re-deleted: %d -> %d (want once)", delsAfterDisable, got)
	}
}

// TestManagerStanzaRemovalWithdrawsThroughLiveBackend covers the
// whole-stanza removal path (DynamicDNS == nil), distinct from the
// Enabled=false path above. When the operator deletes the entire DynamicDNS
// stanza, policyFromConfig(nil) yields backend "" so the resolve-per-Reconcile
// factory resolves a nopUpdater (no update-server/TSIG left to build the live
// backend). The manager must NOT swap the live updater (which published the
// records) for the nop before withdrawing — otherwise withdrawAllLocked runs
// through the nop, dropping ownership entries while sending NO real DNS delete,
// orphaning the published records. This test wires a recording fakeUpdater as
// the live backend, publishes a record, then removes the stanza and asserts
// the fake RECEIVES the delete (record actually withdrawn) and ownership is
// cleared. It FAILS pre-fix (the nop swallows the delete: 0 deletes recorded).
func TestManagerStanzaRemovalWithdrawsThroughLiveBackend(t *testing.T) {
	dir := t.TempDir()
	fake := newFakeUpdater()
	m := newDDNSManagerForTesting(
		fake,
		filepath.Join(dir, "state.json"),
		filepath.Join(dir, "leases4.csv"),
		filepath.Join(dir, "leases6.csv"),
		"node0",
		func() time.Time { return time.Unix(1_700_000_000, 0) },
	)
	// Factory mirrors NewProductionDDNSManager: a usable rfc2136 policy yields
	// the (recording) live backend; anything else (incl. stanza removal where
	// backend resolves to "") yields the nopUpdater.
	m.newUpdater = func(pol ddnsPolicy, c *config.DHCPDynamicDNSConfig) (DNSUpdater, error) {
		if pol.backend != "rfc2136" || c == nil || c.UpdateServer == "" {
			return nopUpdater{}, nil
		}
		return fake, nil
	}

	writeCSV(t, m.leasePath4, `address,hwaddr,client_id,valid_lifetime,expire,subnet_id,hostname,state
10.0.1.5,aa,,3600,1900000000,1,laptop,0
`)
	writeCSV(t, m.leasePath6, "address,duid,valid_lifetime,expire,subnet_id,iaid,hostname,state\n")

	// Enable + publish via the live (fake) backend.
	enabled := &config.DHCPServerConfig{DynamicDNS: &config.DHCPDynamicDNSConfig{
		Enabled: true, Domain: "example.com", TTLSeconds: 300,
		Backend: "rfc2136", UpdateServer: "192.0.2.53",
	}}
	if err := m.Reconcile(context.Background(), enabled); err != nil {
		t.Fatalf("enable reconcile: %v", err)
	}
	if m.Stats().OwnedRecords != 1 {
		t.Fatalf("expected 1 owned record after enable, got %d", m.Stats().OwnedRecords)
	}
	if len(fake.upserts) == 0 {
		t.Fatalf("live backend recorded no upsert on enable")
	}

	// Remove the ENTIRE stanza (DynamicDNS == nil). The factory now resolves
	// the nop, but the live updater must still withdraw the owned record.
	removed := &config.DHCPServerConfig{DynamicDNS: nil}
	if err := m.Reconcile(context.Background(), removed); err != nil {
		t.Fatalf("stanza-removal reconcile: %v", err)
	}
	if got := m.Stats().OwnedRecords; got != 0 {
		t.Errorf("OwnedRecords = %d after stanza removal, want 0 (withdrawn)", got)
	}
	if len(fake.deletes) == 0 {
		t.Fatal("stanza removal did not send a real DNS delete through the live backend " +
			"(records orphaned) — the nop swallowed the withdraw")
	}
}

func TestManagerReconcileFailCountsAndDoesNotWedge(t *testing.T) {
	srv := newFakeDNSServer(t, nil)
	// Make the FORWARD zone always SERVFAIL so the upsert errors.
	srv.setRcode("example.com.", dns.RcodeServerFailure)
	m := prodManagerTo(t, srv)
	cfg := ddnsCfg(srv.addrUDP)
	writeCSV(t, m.leasePath4, `address,hwaddr,client_id,valid_lifetime,expire,subnet_id,hostname,state
10.0.1.5,aa,,3600,1900000000,1,laptop,0
`)
	writeCSV(t, m.leasePath6, "address,duid,valid_lifetime,expire,subnet_id,iaid,hostname,state\n")
	err := m.Reconcile(context.Background(), cfg)
	if err == nil {
		t.Fatal("a forward-zone SERVFAIL must surface a reconcile error")
	}
	st := m.Stats()
	if st.UpsertFail == 0 {
		t.Errorf("UpsertFail = 0, want >0")
	}
	if st.ReconcileFail != 1 {
		t.Errorf("ReconcileFail = %d, want 1", st.ReconcileFail)
	}
	// Nothing was recorded as owned (upsert failed before recording).
	if st.OwnedRecords != 0 {
		t.Errorf("OwnedRecords = %d, want 0 (failed upsert records no ownership)", st.OwnedRecords)
	}
	// The loop is not wedged: a subsequent successful cycle publishes.
	srv.clearRcode("example.com.")
	if err := m.Reconcile(context.Background(), cfg); err != nil {
		t.Fatalf("recovery reconcile: %v", err)
	}
	if m.Stats().OwnedRecords != 1 {
		t.Errorf("recovery did not publish: OwnedRecords = %d", m.Stats().OwnedRecords)
	}
}

func TestManagerPTRNotAuthCountedNotFailed(t *testing.T) {
	srv := newFakeDNSServer(t, nil)
	srv.setRcode("1.0.10.in-addr.arpa.", dns.RcodeNotAuth)
	m := prodManagerTo(t, srv)
	cfg := ddnsCfg(srv.addrUDP)
	writeCSV(t, m.leasePath4, `address,hwaddr,client_id,valid_lifetime,expire,subnet_id,hostname,state
10.0.1.5,aa,,3600,1900000000,1,laptop,0
`)
	writeCSV(t, m.leasePath6, "address,duid,valid_lifetime,expire,subnet_id,iaid,hostname,state\n")
	if err := m.Reconcile(context.Background(), cfg); err != nil {
		t.Fatalf("reconcile: a reverse NOTAUTH must not fail the pass: %v", err)
	}
	st := m.Stats()
	if st.SkippedPTRNotAuth != 1 {
		t.Errorf("SkippedPTRNotAuth = %d, want 1", st.SkippedPTRNotAuth)
	}
	// Forward A still owned + reconcile OK.
	if st.OwnedRecords != 1 {
		t.Errorf("OwnedRecords = %d, want 1 (forward published)", st.OwnedRecords)
	}
	if st.ReconcileOK != 1 {
		t.Errorf("ReconcileOK = %d, want 1", st.ReconcileOK)
	}
}

// ownedFQDNs returns the FQDNs the manager currently records as owned.
func ownedFQDNs(m *DDNSManager) []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []string{}
	for _, r := range m.state.records {
		out = append(out, r.FQDN)
	}
	return out
}

// TestManagerReplaceOwnedRefusedAddRecordsNoOwnership_NoIdentity is the #2648
// MAJOR-1 regression at the MANAGER level (the layer the original tests never
// exercised). A third party owns the forward name; the lease has NO client
// identity (empty client_id AND hwaddr), so the delete path has no DHCID-match
// guard. Cycle 1 must REFUSE the add and record NO ownership; cycle 2 (lease
// gone) must issue NO delete and leave the third party's A intact.
//
// fail-on-revert: restoring upsertLocked's unconditional state.put on the
// refusal path re-records phantom ownership, and cycle 2 then deletes the
// third party's A → this test goes red (BOUNDARY BREACH).
func TestManagerReplaceOwnedRefusedAddRecordsNoOwnership_NoIdentity(t *testing.T) {
	srv := newFakeDNSServer(t, nil)
	srv.setStateful(true)
	// Third party already published laptop.example.com A 10.0.1.5 (no DHCID).
	thirdParty := &dns.A{
		Hdr: dns.RR_Header{Name: "laptop.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   net.ParseIP("10.0.1.5"),
	}
	srv.seedRR(thirdParty)

	m := prodManagerTo(t, srv)
	cfg := ddnsCfg(srv.addrUDP)

	// Cycle 1: an active v4 lease for the SAME name+address, NO identity
	// (empty client_id AND hwaddr).
	writeCSV(t, m.leasePath4, `address,hwaddr,client_id,valid_lifetime,expire,subnet_id,hostname,state
10.0.1.5,,,3600,1900000000,1,laptop,0
`)
	writeCSV(t, m.leasePath6, "address,duid,valid_lifetime,expire,subnet_id,iaid,hostname,state\n")
	if err := m.Reconcile(context.Background(), cfg); err != nil {
		t.Fatalf("reconcile 1: %v", err)
	}
	if got := m.Stats().OwnedRecords; got != 0 {
		t.Fatalf("#2648: refused add recorded phantom ownership; OwnedRecords=%d want 0 (owned=%v)",
			got, ownedFQDNs(m))
	}
	if !srv.zoneHas(thirdParty) {
		t.Fatalf("third-party A vanished after a refused add")
	}

	// Cycle 2: lease gone — no owned state, so NO delete must be issued and the
	// third party's A must survive.
	writeCSV(t, m.leasePath4, "address,hwaddr,client_id,valid_lifetime,expire,subnet_id,hostname,state\n")
	if err := m.Reconcile(context.Background(), cfg); err != nil {
		t.Fatalf("reconcile 2: %v", err)
	}
	if !srv.zoneHas(thirdParty) {
		t.Fatalf("#2648 BOUNDARY BREACH (end-to-end, no-identity): manager deleted a third-party A it did not create")
	}
	if m.Stats().DeleteOK != 0 {
		t.Errorf("a delete was issued for a name xpf never owned; DeleteOK=%d want 0", m.Stats().DeleteOK)
	}
}

// TestManagerReplaceOwnedRefusedAddRecordsNoOwnership_Identity is the
// identity-bearing arm of the #2648 MAJOR-1 regression: a third party owns the
// name (no DHCID / a foreign DHCID), and the lease HAS a client identity. The
// add must still be refused with NO ownership recorded (phantom-state
// pollution), and the third party's record must survive both cycles.
func TestManagerReplaceOwnedRefusedAddRecordsNoOwnership_Identity(t *testing.T) {
	srv := newFakeDNSServer(t, nil)
	srv.setStateful(true)
	thirdParty := &dns.A{
		Hdr: dns.RR_Header{Name: "laptop.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   net.ParseIP("10.0.1.5"),
	}
	srv.seedRR(thirdParty)

	m := prodManagerTo(t, srv)
	cfg := ddnsCfg(srv.addrUDP)

	// Active v4 lease WITH an identity (client_id set).
	writeCSV(t, m.leasePath4, `address,hwaddr,client_id,valid_lifetime,expire,subnet_id,hostname,state
10.0.1.5,aa:bb,01:02:03,3600,1900000000,1,laptop,0
`)
	writeCSV(t, m.leasePath6, "address,duid,valid_lifetime,expire,subnet_id,iaid,hostname,state\n")
	if err := m.Reconcile(context.Background(), cfg); err != nil {
		t.Fatalf("reconcile 1: %v", err)
	}
	if got := m.Stats().OwnedRecords; got != 0 {
		t.Fatalf("#2648: refused identity add recorded phantom ownership; OwnedRecords=%d want 0 (owned=%v)",
			got, ownedFQDNs(m))
	}
	if !srv.zoneHas(thirdParty) {
		t.Fatalf("third-party A vanished after a refused identity add")
	}

	// Cycle 2: lease gone — third party survives, no delete issued.
	writeCSV(t, m.leasePath4, "address,hwaddr,client_id,valid_lifetime,expire,subnet_id,hostname,state\n")
	if err := m.Reconcile(context.Background(), cfg); err != nil {
		t.Fatalf("reconcile 2: %v", err)
	}
	if !srv.zoneHas(thirdParty) {
		t.Fatalf("#2648 BOUNDARY BREACH (end-to-end, identity): manager deleted a third-party A it did not create")
	}
}

// TestManagerReplaceOwnedFreshNameFullLifecycle proves the manager path still
// works for the happy case: a fresh name is claimed (ownership recorded), and
// the lease's expiry deletes exactly that owned record via the DHCID-guarded
// delete.
func TestManagerReplaceOwnedFreshNameFullLifecycle(t *testing.T) {
	srv := newFakeDNSServer(t, nil)
	srv.setStateful(true)
	m := prodManagerTo(t, srv)
	cfg := ddnsCfg(srv.addrUDP)

	writeCSV(t, m.leasePath4, `address,hwaddr,client_id,valid_lifetime,expire,subnet_id,hostname,state
10.0.1.9,aa:bb,07:08:09,3600,1900000000,1,fresh,0
`)
	writeCSV(t, m.leasePath6, "address,duid,valid_lifetime,expire,subnet_id,iaid,hostname,state\n")
	if err := m.Reconcile(context.Background(), cfg); err != nil {
		t.Fatalf("reconcile 1: %v", err)
	}
	if m.Stats().OwnedRecords != 1 {
		t.Fatalf("fresh name not owned; OwnedRecords=%d want 1", m.Stats().OwnedRecords)
	}
	a := &dns.A{Hdr: dns.RR_Header{Name: "fresh.example.com.", Rrtype: dns.TypeA}, A: net.ParseIP("10.0.1.9")}
	if !srv.zoneHas(a) {
		t.Fatalf("fresh A not published")
	}

	writeCSV(t, m.leasePath4, "address,hwaddr,client_id,valid_lifetime,expire,subnet_id,hostname,state\n")
	if err := m.Reconcile(context.Background(), cfg); err != nil {
		t.Fatalf("reconcile 2: %v", err)
	}
	if m.Stats().OwnedRecords != 0 {
		t.Errorf("owned record not cleared after expiry; OwnedRecords=%d", m.Stats().OwnedRecords)
	}
	if srv.zoneHas(a) {
		t.Errorf("owned A not deleted after expiry")
	}
}

// ddnsCfgSkipExisting is ddnsCfg with the skip-existing conflict policy.
func ddnsCfgSkipExisting(server string) *config.DHCPServerConfig {
	cfg := ddnsCfg(server)
	cfg.DynamicDNS.ConflictPolicy = "skip-existing"
	return cfg
}

// TestManagerSkipExistingConflictRecordsNoOwnership is the #2660 boundary
// regression at the MANAGER level (the #2648/#2659 lesson: test through
// reconcileOnceLocked, the layer that surfaces the breach, not the updater in
// isolation). Under skip-existing, a third party already owns the forward name.
// Cycle 1 must REFUSE the add and record NO ownership; cycle 2 (lease gone)
// must issue NO delete and leave the third party's A intact. skip-existing
// never writes a DHCID, so a phantom-owned record's later release would take
// sendRemoveForward's plain exact-RR delete branch and wipe the third party's
// RR — the exact breach #2660 closes.
//
// fail-on-revert: changing the skip-existing YX path back to `return nil`
// re-records phantom ownership (cycle 1 OwnedRecords=1), and cycle 2 then
// deletes the third party's A → this test goes red.
func TestManagerSkipExistingConflictRecordsNoOwnership(t *testing.T) {
	srv := newFakeDNSServer(t, nil)
	srv.setStateful(true)
	// Third party already published laptop.example.com A 10.0.1.5 (no DHCID).
	thirdParty := &dns.A{
		Hdr: dns.RR_Header{Name: "laptop.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   net.ParseIP("10.0.1.5"),
	}
	srv.seedRR(thirdParty)

	m := prodManagerTo(t, srv)
	cfg := ddnsCfgSkipExisting(srv.addrUDP)

	// Cycle 1: an active v4 lease for the SAME name+address.
	writeCSV(t, m.leasePath4, `address,hwaddr,client_id,valid_lifetime,expire,subnet_id,hostname,state
10.0.1.5,aa:bb,01:02:03,3600,1900000000,1,laptop,0
`)
	writeCSV(t, m.leasePath6, "address,duid,valid_lifetime,expire,subnet_id,iaid,hostname,state\n")
	if err := m.Reconcile(context.Background(), cfg); err != nil {
		t.Fatalf("reconcile 1: %v", err)
	}
	if got := m.Stats().OwnedRecords; got != 0 {
		t.Fatalf("#2660: skip-existing refused add recorded phantom ownership; OwnedRecords=%d want 0 (owned=%v)",
			got, ownedFQDNs(m))
	}
	if !srv.zoneHas(thirdParty) {
		t.Fatalf("third-party A vanished after a refused skip-existing add")
	}
	if got := m.Stats().SkippedConflict; got != 1 {
		t.Errorf("SkippedConflict = %d, want 1", got)
	}

	// Cycle 2: lease gone — no owned state, so NO delete must be issued and the
	// third party's A must survive.
	writeCSV(t, m.leasePath4, "address,hwaddr,client_id,valid_lifetime,expire,subnet_id,hostname,state\n")
	if err := m.Reconcile(context.Background(), cfg); err != nil {
		t.Fatalf("reconcile 2: %v", err)
	}
	if !srv.zoneHas(thirdParty) {
		t.Fatalf("#2660 BOUNDARY BREACH (end-to-end): manager deleted a third-party A it did not create under skip-existing")
	}
	if got := m.Stats().DeleteOK; got != 0 {
		t.Errorf("a delete was issued for a name xpf never owned; DeleteOK=%d want 0", got)
	}
}

// TestManagerSkipExistingFreshNameFullLifecycle proves the manager path still
// works for the happy case under skip-existing: a fresh (unused) name is
// claimed (ownership recorded → the RRsetNotUsed prereq passes), and the
// lease's expiry deletes exactly that owned record.
func TestManagerSkipExistingFreshNameFullLifecycle(t *testing.T) {
	srv := newFakeDNSServer(t, nil)
	srv.setStateful(true)
	m := prodManagerTo(t, srv)
	cfg := ddnsCfgSkipExisting(srv.addrUDP)

	writeCSV(t, m.leasePath4, `address,hwaddr,client_id,valid_lifetime,expire,subnet_id,hostname,state
10.0.1.9,aa:bb,07:08:09,3600,1900000000,1,fresh,0
`)
	writeCSV(t, m.leasePath6, "address,duid,valid_lifetime,expire,subnet_id,iaid,hostname,state\n")
	if err := m.Reconcile(context.Background(), cfg); err != nil {
		t.Fatalf("reconcile 1: %v", err)
	}
	if m.Stats().OwnedRecords != 1 {
		t.Fatalf("fresh skip-existing name not owned; OwnedRecords=%d want 1", m.Stats().OwnedRecords)
	}
	a := &dns.A{Hdr: dns.RR_Header{Name: "fresh.example.com.", Rrtype: dns.TypeA}, A: net.ParseIP("10.0.1.9")}
	if !srv.zoneHas(a) {
		t.Fatalf("fresh A not published")
	}

	writeCSV(t, m.leasePath4, "address,hwaddr,client_id,valid_lifetime,expire,subnet_id,hostname,state\n")
	if err := m.Reconcile(context.Background(), cfg); err != nil {
		t.Fatalf("reconcile 2: %v", err)
	}
	if m.Stats().OwnedRecords != 0 {
		t.Errorf("owned record not cleared after expiry; OwnedRecords=%d", m.Stats().OwnedRecords)
	}
	if srv.zoneHas(a) {
		t.Errorf("owned A not deleted after expiry")
	}
}

func TestOwnedRecordViews(t *testing.T) {
	srv := newFakeDNSServer(t, nil)
	m := prodManagerTo(t, srv)
	cfg := ddnsCfg(srv.addrUDP)
	writeCSV(t, m.leasePath4, `address,hwaddr,client_id,valid_lifetime,expire,subnet_id,hostname,state
10.0.1.5,aa,,3600,1900000000,1,laptop,0
`)
	writeCSV(t, m.leasePath6, "address,duid,valid_lifetime,expire,subnet_id,iaid,hostname,state\n")
	if err := m.Reconcile(context.Background(), cfg); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	views := m.OwnedRecordViews()
	if len(views) != 1 {
		t.Fatalf("OwnedRecordViews len = %d, want 1", len(views))
	}
	v := views[0]
	if v.FQDN != "laptop.example.com" || v.ForwardType != "A" || v.Address != "10.0.1.5" {
		t.Errorf("unexpected view: %+v", v)
	}
	if v.PTRName == "" {
		t.Errorf("view missing PTR name")
	}
}
