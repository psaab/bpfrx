package dhcpserver

import (
	"context"
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

	// Disable: a nil DynamicDNS block → withdrawAllLocked deletes the owned
	// record THROUGH the live backend (the factory still resolves it because
	// resolve-per-Reconcile runs before the enabled check). The factory keys
	// off the policy; a disabled policy has backend "" → resolves nop. So a
	// turn-off via Enabled=false (keeping the backend config) must still
	// withdraw through the live backend.
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

func TestManagerReconcileFailCountsAndDoesNotWedge(t *testing.T) {
	srv := newFakeDNSServer(t, nil)
	// Make the FORWARD zone always SERVFAIL so the upsert errors.
	srv.rcodeForZone["example.com."] = dns.RcodeServerFailure
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
	srv.mu.Lock()
	delete(srv.rcodeForZone, "example.com.")
	srv.mu.Unlock()
	if err := m.Reconcile(context.Background(), cfg); err != nil {
		t.Fatalf("recovery reconcile: %v", err)
	}
	if m.Stats().OwnedRecords != 1 {
		t.Errorf("recovery did not publish: OwnedRecords = %d", m.Stats().OwnedRecords)
	}
}

func TestManagerPTRNotAuthCountedNotFailed(t *testing.T) {
	srv := newFakeDNSServer(t, nil)
	srv.rcodeForZone["1.0.10.in-addr.arpa."] = dns.RcodeNotAuth
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
