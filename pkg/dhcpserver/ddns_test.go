package dhcpserver

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// #1387 DHCP DDNS reconciler unit tests (increment 1). Everything is
// driven through fakeUpdater — no network, no DNS, no lab. These prove
// the never-delete-non-owned boundary, the move/reassign/expire
// transitions, the state-aware lease parser, hostname normalization,
// PTR byte-order, retry-no-wedge, and withdraw-on-disable.

// fakeUpdater records every upsert/delete and can be made to fail.
type fakeUpdater struct {
	mu        sync.Mutex
	upserts   []LeaseDNSRecord
	deletes   []LeaseDNSRecord
	failUpd   map[string]bool // FQDN -> fail upsert
	failDel   map[string]bool // FQDN -> fail delete
	failEvery bool            // fail all ops (retry-no-wedge probe)
}

func newFakeUpdater() *fakeUpdater {
	return &fakeUpdater{failUpd: map[string]bool{}, failDel: map[string]bool{}}
}

func (f *fakeUpdater) UpsertLease(_ context.Context, rec LeaseDNSRecord) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failEvery || f.failUpd[rec.FQDN] {
		return fmt.Errorf("fake: upsert %s failed", rec.FQDN)
	}
	f.upserts = append(f.upserts, rec)
	return nil
}

func (f *fakeUpdater) DeleteLease(_ context.Context, rec LeaseDNSRecord) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failEvery || f.failDel[rec.FQDN] {
		return fmt.Errorf("fake: delete %s failed", rec.FQDN)
	}
	f.deletes = append(f.deletes, rec)
	return nil
}

func (f *fakeUpdater) upsertNames() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, r := range f.upserts {
		out = append(out, r.FQDN+"="+r.Addr.String())
	}
	sort.Strings(out)
	return out
}

func (f *fakeUpdater) deleteNames() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, r := range f.deletes {
		out = append(out, r.FQDN+"="+r.Addr.String())
	}
	sort.Strings(out)
	return out
}

func testDDNS(t *testing.T, up DNSUpdater) *DDNSManager {
	t.Helper()
	dir := t.TempDir()
	return newDDNSManagerForTesting(
		up,
		filepath.Join(dir, "state.json"),
		filepath.Join(dir, "leases4.csv"),
		filepath.Join(dir, "leases6.csv"),
		"node0",
		func() time.Time { return time.Unix(1_700_000_000, 0) },
	)
}

func enabledPolicy() ddnsPolicy {
	return policyFromConfig(&config.DHCPDynamicDNSConfig{
		Enabled:    true,
		Domain:     "example.com",
		TTLSeconds: 300,
	})
}

func leaseV4(addr, ident, host string) ddnsLease {
	return ddnsLease{Family: 4, Address: addr, Identity: ident, HostName: host, SubnetID: "1"}
}

func runReconcile(t *testing.T, m *DDNSManager, pol ddnsPolicy, leases []ddnsLease) error {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.reconcileOnceLocked(context.Background(), pol, leases, nil)
}

// ---- hostname normalization ----

func TestDeriveFQDN(t *testing.T) {
	cases := []struct {
		name                         string
		host, clientFQDN, id, domain string
		source                       string
		want                         string
		wantErr                      bool
	}{
		{"plain host + domain", "laptop", "", "mac:aa", "example.com", "client-hostname", "laptop.example.com", false},
		{"uppercase sanitized", "LapTop", "", "mac:aa", "example.com", "client-hostname", "laptop.example.com", false},
		{"already fqdn passes through", "host.sub.example.com", "", "mac:aa", "example.com", "client-hostname", "host.sub.example.com", false},
		{"illegal chars stripped", "my_host!*", "", "mac:aa", "example.com", "client-hostname", "myhost.example.com", false},
		{"no name no domain errors", "", "", "mac:aa", "example.com", "client-hostname", "", true},
		{"fqdn source prefers client fqdn (relabeled into zone)", "ignored", "real.example.org", "mac:aa", "example.com", "fqdn", "real.example.com", false},
		{"fqdn within zone kept", "ignored", "real.dept.example.com", "mac:aa", "example.com", "fqdn", "real.dept.example.com", false},
		{"mac-fallback synthesizes", "", "", "mac:aabbccddeeff", "example.com", "mac-fallback", "dhcp-macaabbccddeeff.example.com", false},
		{"bare label no domain", "host", "", "mac:aa", "", "client-hostname", "host", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := deriveFQDN(tc.host, tc.clientFQDN, tc.id, tc.domain, tc.source)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("want error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("deriveFQDN = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestDeriveFQDNEnforcesZoneContainment proves a client can never publish a
// name OUTSIDE the configured domain (the #1387 MAJOR-1 escape boundary).
// Every escape vector — a dotted name in a foreign TLD, a trailing dot, a
// double-dot, a deeper foreign subtree — must yield a name contained in the
// configured zone. Non-tautological: against the pre-fix finalizeFQDN (which
// returned sanitizeFQDN(name) for any dotted name) every one of these cases
// publishes outside example.com and the containment assertion fails.
func TestDeriveFQDNEnforcesZoneContainment(t *testing.T) {
	const domain = "corp.example.com"
	// Each input is a client-controlled name that tries to escape the zone.
	escapeInputs := []struct {
		name   string
		offer  string // the client-controlled name fed to the active source
		want   string // expected published FQDN (must be within domain)
		source string
	}{
		{"foreign tld", "host.attacker.tld", "host.corp.example.com", "client-hostname"},
		{"sibling public domain", "evil.example.net", "evil.corp.example.com", "client-hostname"},
		{"trailing dot foreign", "evil.example.net.", "evil.corp.example.com", "client-hostname"},
		{"double dot", "a..evil.net", "a.corp.example.com", "client-hostname"},
		{"deep foreign subtree", "a.b.c.attacker.tld", "a.corp.example.com", "client-hostname"},
		{"fqdn source foreign", "evil.attacker.tld", "evil.corp.example.com", "fqdn"},
	}
	for _, tc := range escapeInputs {
		t.Run(tc.name, func(t *testing.T) {
			// Route the client-controlled name through whichever source is
			// active: the client-FQDN option for source=fqdn, the host-name
			// option otherwise.
			host, clientFQDN := tc.offer, ""
			if tc.source == "fqdn" {
				host, clientFQDN = "ignored", tc.offer
			}
			got, err := deriveFQDN(host, clientFQDN, "mac:aa", domain, tc.source)
			if err != nil {
				t.Fatalf("deriveFQDN error: %v", err)
			}
			// The cardinal assertion: the result is contained in the zone.
			if got != domain && !strings.HasSuffix(got, "."+domain) {
				t.Fatalf("name %q ESCAPED zone %q (derived from %q)", got, domain, tc.offer)
			}
			if tc.want != "" && got != tc.want {
				t.Fatalf("deriveFQDN = %q, want %q", got, tc.want)
			}
		})
	}

	// A within-zone dotted name is preserved verbatim (no needless relabel).
	got, err := deriveFQDN("host.dept.corp.example.com", "", "mac:aa", domain, "client-hostname")
	if err != nil {
		t.Fatal(err)
	}
	if got != "host.dept.corp.example.com" {
		t.Fatalf("within-zone name relabeled: %q", got)
	}
}

func TestSanitizeLabelTrimsAndCaps(t *testing.T) {
	if got := sanitizeLabel("-foo-"); got != "foo" {
		t.Fatalf("trim dashes: got %q", got)
	}
	long := ""
	for i := 0; i < 80; i++ {
		long += "a"
	}
	if got := sanitizeLabel(long); len(got) != maxDNSLabel {
		t.Fatalf("cap: got len %d want %d", len(got), maxDNSLabel)
	}
	if got := sanitizeLabel("___"); got != "" {
		t.Fatalf("all-illegal: got %q", got)
	}
}

// ---- PTR byte-order ----

func TestReversePTRName(t *testing.T) {
	v4 := reversePTRName(netip.MustParseAddr("192.0.2.5"))
	if v4 != "5.2.0.192.in-addr.arpa" {
		t.Fatalf("v4 PTR = %q", v4)
	}
	// 2001:db8::1 -> 32 reversed nibbles + ip6.arpa
	v6 := reversePTRName(netip.MustParseAddr("2001:db8::1"))
	want := "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
	if v6 != want {
		t.Fatalf("v6 PTR =\n %q\nwant\n %q", v6, want)
	}
}

func TestBuildLeaseRecordFamilyAndTTLDefault(t *testing.T) {
	rec, err := buildLeaseRecord("h.example.com", "10.0.0.5", 0)
	if err != nil {
		t.Fatal(err)
	}
	if rec.ForwardType != "A" || rec.TTL != defaultDDNSTTL {
		t.Fatalf("v4 record wrong: %+v", rec)
	}
	rec6, err := buildLeaseRecord("h.example.com", "2001:db8::5", 120)
	if err != nil {
		t.Fatal(err)
	}
	if rec6.ForwardType != "AAAA" || rec6.TTL != 120 {
		t.Fatalf("v6 record wrong: %+v", rec6)
	}
	if _, err := buildLeaseRecord("h", "not-an-ip", 60); err == nil {
		t.Fatal("expected error for invalid address")
	}
}

// ---- reconciler transitions ----

func TestReconcileAddsActiveLeases(t *testing.T) {
	up := newFakeUpdater()
	m := testDDNS(t, up)
	pol := enabledPolicy()
	if err := runReconcile(t, m, pol, []ddnsLease{
		leaseV4("10.0.0.10", "mac:aa", "host-a"),
		leaseV4("10.0.0.11", "mac:bb", "host-b"),
	}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	got := up.upsertNames()
	want := []string{"host-a.example.com=10.0.0.10", "host-b.example.com=10.0.0.11"}
	if !equalStr(got, want) {
		t.Fatalf("upserts = %v want %v", got, want)
	}
	// Idempotent: a second reconcile with the same leases adds nothing.
	up.upserts = nil
	if err := runReconcile(t, m, pol, []ddnsLease{
		leaseV4("10.0.0.10", "mac:aa", "host-a"),
		leaseV4("10.0.0.11", "mac:bb", "host-b"),
	}); err != nil {
		t.Fatalf("reconcile 2: %v", err)
	}
	if n := len(up.upserts); n != 0 {
		t.Fatalf("idempotent reconcile re-upserted %d records", n)
	}
}

func TestReconcileExpireDeletesOwnedRecord(t *testing.T) {
	up := newFakeUpdater()
	m := testDDNS(t, up)
	pol := enabledPolicy()
	if err := runReconcile(t, m, pol, []ddnsLease{leaseV4("10.0.0.10", "mac:aa", "host-a")}); err != nil {
		t.Fatal(err)
	}
	// Lease gone -> record deleted.
	if err := runReconcile(t, m, pol, nil); err != nil {
		t.Fatal(err)
	}
	if got := up.deleteNames(); !equalStr(got, []string{"host-a.example.com=10.0.0.10"}) {
		t.Fatalf("deletes = %v", got)
	}
	if n := len(m.state.records); n != 0 {
		t.Fatalf("owned state not cleared after delete: %d", n)
	}
}

func TestReconcileClientMovesAddress(t *testing.T) {
	up := newFakeUpdater()
	m := testDDNS(t, up)
	pol := enabledPolicy()
	if err := runReconcile(t, m, pol, []ddnsLease{leaseV4("10.0.0.10", "mac:aa", "host-a")}); err != nil {
		t.Fatal(err)
	}
	// Same client (mac:aa), new address.
	if err := runReconcile(t, m, pol, []ddnsLease{leaseV4("10.0.0.20", "mac:aa", "host-a")}); err != nil {
		t.Fatal(err)
	}
	if got := up.deleteNames(); !equalStr(got, []string{"host-a.example.com=10.0.0.10"}) {
		t.Fatalf("old address not deleted on move: deletes=%v", got)
	}
	// New address added.
	found := false
	for _, r := range up.upserts {
		if r.Addr.String() == "10.0.0.20" {
			found = true
		}
	}
	if !found {
		t.Fatalf("new address not added on move: upserts=%v", up.upsertNames())
	}
}

func TestReconcileAddressReassignedToNewClient(t *testing.T) {
	up := newFakeUpdater()
	m := testDDNS(t, up)
	pol := enabledPolicy()
	// Client A holds 10.0.0.10.
	if err := runReconcile(t, m, pol, []ddnsLease{leaseV4("10.0.0.10", "mac:aa", "host-a")}); err != nil {
		t.Fatal(err)
	}
	// Same address now leased to client B with a different name. Old
	// owner must be cleaned before the new owner is added.
	if err := runReconcile(t, m, pol, []ddnsLease{leaseV4("10.0.0.10", "mac:bb", "host-b")}); err != nil {
		t.Fatal(err)
	}
	if got := up.deleteNames(); !equalStr(got, []string{"host-a.example.com=10.0.0.10"}) {
		t.Fatalf("old owner not cleaned on reassign: deletes=%v", got)
	}
	gotUp := false
	for _, r := range up.upserts {
		if r.FQDN == "host-b.example.com" && r.Addr.String() == "10.0.0.10" {
			gotUp = true
		}
	}
	if !gotUp {
		t.Fatalf("new owner not added on reassign: upserts=%v", up.upsertNames())
	}
}

func TestReconcileDeleteFailureBlocksReplacementUpsert(t *testing.T) {
	up := newFakeUpdater()
	m := testDDNS(t, up)
	pol := enabledPolicy()
	if err := runReconcile(t, m, pol, []ddnsLease{leaseV4("10.0.0.10", "mac:aa", "host-a")}); err != nil {
		t.Fatal(err)
	}

	up.upserts = nil
	up.deletes = nil
	up.failDel["host-a.example.com"] = true
	err := runReconcile(t, m, pol, []ddnsLease{leaseV4("10.0.0.10", "mac:bb", "host-b")})
	if err == nil {
		t.Fatal("expected delete failure")
	}
	if n := len(up.upserts); n != 0 {
		t.Fatalf("replacement upserted despite failed cleanup: %v", up.upsertNames())
	}
	if n := len(up.deletes); n != 0 {
		t.Fatalf("unexpected successful delete despite injected failure: %v", up.deleteNames())
	}
	if m.deleteFail.Load() != 1 {
		t.Fatalf("deleteFail = %d, want 1", m.deleteFail.Load())
	}
	if _, ok := m.state.get("mac:aa", "10.0.0.10"); !ok {
		t.Fatal("old ownership entry dropped after failed delete")
	}

	delete(up.failDel, "host-a.example.com")
	if err := runReconcile(t, m, pol, []ddnsLease{leaseV4("10.0.0.10", "mac:bb", "host-b")}); err != nil {
		t.Fatalf("retry reconcile: %v", err)
	}
	if got := up.deleteNames(); !equalStr(got, []string{"host-a.example.com=10.0.0.10"}) {
		t.Fatalf("retry cleanup delete calls = %v", got)
	}
	if m.deleteOK.Load() != 1 {
		t.Fatalf("deleteOK = %d, want 1", m.deleteOK.Load())
	}
	if got := up.upsertNames(); !equalStr(got, []string{"host-b.example.com=10.0.0.10"}) {
		t.Fatalf("replacement upserts = %v", got)
	}
	if _, ok := m.state.get("mac:aa", "10.0.0.10"); ok {
		t.Fatal("old ownership entry still present after successful retry")
	}
}

// TestReconcileNeverDeletesNonOwned proves the cardinal-sin boundary: a
// record that was never recorded as owned is never deleted, even when a
// lease for that address/name disappears between reconciles. We seed the
// store via reconcile, then DELETE the store entry out from under the
// manager (simulating a record the firewall does not own) and confirm a
// subsequent expire issues NO delete for it.
func TestReconcileNeverDeletesNonOwned(t *testing.T) {
	up := newFakeUpdater()
	m := testDDNS(t, up)
	pol := enabledPolicy()
	if err := runReconcile(t, m, pol, []ddnsLease{leaseV4("10.0.0.10", "mac:aa", "host-a")}); err != nil {
		t.Fatal(err)
	}
	// Forget ownership (as if this record belongs to someone else).
	m.mu.Lock()
	m.state.records = map[string]ownedRecord{}
	m.mu.Unlock()
	up.deletes = nil
	// Lease disappears: with no owned entry, nothing must be deleted.
	if err := runReconcile(t, m, pol, nil); err != nil {
		t.Fatal(err)
	}
	if n := len(up.deletes); n != 0 {
		t.Fatalf("deleted %d non-owned records (cardinal sin)", n)
	}
}

// TestReconcileRetryDoesNotWedge proves a permanently-failing updater does
// not wedge the loop: reconcile returns the error but completes, and a
// later reconcile after the updater recovers makes progress.
func TestReconcileRetryDoesNotWedge(t *testing.T) {
	up := newFakeUpdater()
	up.failEvery = true
	m := testDDNS(t, up)
	pol := enabledPolicy()
	lease := []ddnsLease{leaseV4("10.0.0.10", "mac:aa", "host-a")}

	for i := 0; i < 3; i++ {
		err := runReconcile(t, m, pol, lease)
		if err == nil {
			t.Fatalf("iter %d: expected error from failing updater", i)
		}
	}
	if m.upsertFail.Load() < 3 {
		t.Fatalf("upsertFail = %d, want >= 3", m.upsertFail.Load())
	}
	// Nothing got recorded as owned (no successful upsert).
	if n := len(m.state.records); n != 0 {
		t.Fatalf("owned state populated despite all upserts failing: %d", n)
	}
	// Updater recovers: now the record is published.
	up.failEvery = false
	if err := runReconcile(t, m, pol, lease); err != nil {
		t.Fatalf("recovery reconcile: %v", err)
	}
	if n := len(m.state.records); n != 1 {
		t.Fatalf("owned state not populated after recovery: %d", n)
	}
}

// TestReconcileSkipsUnnamedLease: a lease with no host-name and the
// default source is skipped (counted), not published with junk.
func TestReconcileSkipsUnnamedLease(t *testing.T) {
	up := newFakeUpdater()
	m := testDDNS(t, up)
	pol := enabledPolicy()
	if err := runReconcile(t, m, pol, []ddnsLease{leaseV4("10.0.0.10", "mac:aa", "")}); err != nil {
		t.Fatal(err)
	}
	if n := len(up.upserts); n != 0 {
		t.Fatalf("published %d records for an unnamed lease", n)
	}
	if m.skippedNoName.Load() != 1 {
		t.Fatalf("skippedNoName = %d, want 1", m.skippedNoName.Load())
	}
}

// TestWithdrawOnDisable: when the feature is turned off, owned records are
// withdrawn from DNS.
func TestWithdrawOnDisable(t *testing.T) {
	up := newFakeUpdater()
	m := testDDNS(t, up)
	pol := enabledPolicy()
	if err := runReconcile(t, m, pol, []ddnsLease{leaseV4("10.0.0.10", "mac:aa", "host-a")}); err != nil {
		t.Fatal(err)
	}
	up.deletes = nil
	// Disabled policy -> withdraw all.
	m.mu.Lock()
	err := m.withdrawAllLocked(context.Background())
	m.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if got := up.deleteNames(); !equalStr(got, []string{"host-a.example.com=10.0.0.10"}) {
		t.Fatalf("withdraw deletes = %v", got)
	}
	if n := len(m.state.records); n != 0 {
		t.Fatalf("owned state not cleared on withdraw: %d", n)
	}
}

// TestNilUpdaterIsNopNotPanic proves the #1387 MAJOR-2 boundary: increment 1
// defers the live backend, so a manager built with a nil DNSUpdater must run
// as a logged no-op, NOT panic on the first publish or on a withdraw. Against
// the pre-fix code (m.updater.UpsertLease called unguarded on a nil
// interface) the enabled reconcile panics with a nil-pointer dereference, so
// this test is non-tautological.
func TestNilUpdaterIsNopNotPanic(t *testing.T) {
	// Construction with nil must not panic and must substitute a no-op
	// backend (the production constructor path).
	prod := NewDDNSManager(nil, "node0")
	if prod.updater == nil {
		t.Fatal("NewDDNSManager(nil, ...) left a nil updater")
	}
	if !isNopUpdater(prod.updater) {
		t.Fatalf("NewDDNSManager(nil, ...) did not install a nopUpdater: %T", prod.updater)
	}

	// Enabled reconcile + withdraw on a manager with no live backend: both
	// must complete without panicking. Use the testing constructor so the
	// state/lease paths are temp dirs.
	m := testDDNS(t, nil) // nil -> nopUpdater
	if !isNopUpdater(m.updater) {
		t.Fatalf("nil updater not converted to nopUpdater: %T", m.updater)
	}
	pol := enabledPolicy()

	// Publish path: an active lease must be processed (logged-skipped), with
	// NO ownership recorded for a record that never reached a real backend.
	if err := runReconcile(t, m, pol, []ddnsLease{leaseV4("10.0.0.10", "mac:aa", "host-a")}); err != nil {
		t.Fatalf("reconcile with no backend errored: %v", err)
	}
	if n := len(m.state.records); n != 0 {
		t.Fatalf("no-backend reconcile recorded %d phantom ownership entries", n)
	}
	if m.skippedNoBackend.Load() == 0 {
		t.Fatal("no-backend upsert was not counted as skipped")
	}
	if m.upsertOK.Load() != 0 {
		t.Fatalf("no-backend upsert counted as upsertOK = %d", m.upsertOK.Load())
	}

	// Withdraw path: disabling DDNS while owned state exists must also be a
	// safe no-op. Seed a stale owned record (as if a prior backend wrote it),
	// then run the disabled (withdraw-all) reconcile.
	m.mu.Lock()
	m.state.put(ownedRecord{
		Family: 4, Identity: "mac:bb", Address: "10.0.0.20",
		FQDN: "host-b.example.com", ForwardType: "A",
		PTRName: "20.0.0.10.in-addr.arpa", TTL: 300,
	})
	err := m.withdrawAllLocked(context.Background())
	m.mu.Unlock()
	if err != nil {
		t.Fatalf("withdraw with no backend errored: %v", err)
	}
	if _, ok := m.state.get("mac:bb", "10.0.0.20"); ok {
		t.Fatal("withdraw did not drop the owned entry under no-backend mode")
	}
}

// TestReconcileParseErrorSuppressesFamilyDeletes proves the #1387 MAJOR-4
// fail-safe: when a family's lease CSV cannot be parsed, that family's lease
// set is unreliable, so the reconciler must NOT delete its owned records (a
// transient malformed CSV would otherwise mass-delete every valid record of
// that family). The v6 family, whose CSV is fine, is unaffected. Against the
// pre-fix Reconcile (which logged the parse error then reconciled with the
// nil/partial set) the owned v4 record looks expired and is deleted, so this
// test fails pre-fix.
func TestReconcileParseErrorSuppressesFamilyDeletes(t *testing.T) {
	up := newFakeUpdater()
	m := testDDNS(t, up)

	cfg := &config.DHCPServerConfig{
		DynamicDNS: &config.DHCPDynamicDNSConfig{
			Enabled:    true,
			Domain:     "example.com",
			TTLSeconds: 300,
		},
	}

	// Cycle 1: a valid v4 lease and a valid v6 lease -> both published+owned.
	writeCSV(t, m.leasePath4, `address,hwaddr,client_id,valid_lifetime,expire,subnet_id,hostname,state
10.0.0.10,aa,,3600,1900000000,1,host-a,0
`)
	writeCSV(t, m.leasePath6, `address,duid,valid_lifetime,expire,subnet_id,iaid,hostname,state
2001:db8::5,00:01,3600,1900000000,1,7,host-6,0
`)
	if err := m.Reconcile(context.Background(), cfg); err != nil {
		t.Fatalf("cycle 1 reconcile: %v", err)
	}
	if n := len(m.state.records); n != 2 {
		t.Fatalf("cycle 1 owned records = %d, want 2", n)
	}

	// Cycle 2: corrupt the v4 CSV (bare quote => csv parse error); leave the
	// v6 CSV valid. The v4 owned record must be PRESERVED (no delete); the
	// reconcile must surface the parse error.
	up.deletes = nil
	writeCSV(t, m.leasePath4, `address,hwaddr,client_id,valid_lifetime,expire,subnet_id,hostname,state
10.0.0.10,aa,,3600,1900000000,1,bad"name,0
`)
	err := m.Reconcile(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected the v4 parse error to be surfaced")
	}
	// No v4 deletes at all this cycle.
	for _, d := range up.deletes {
		if d.Addr.Is4() {
			t.Fatalf("v4 record deleted despite unreadable lease CSV: %s", d.FQDN)
		}
	}
	// The v4 owned record is still in the store.
	if _, ok := m.state.get("mac:aa", "10.0.0.10"); !ok {
		t.Fatal("v4 owned record dropped after a v4 parse error (mass-delete bug)")
	}
	// The healthy v6 owned record is also still present (active in its CSV).
	if _, ok := m.state.get("duid:00:01/7", "2001:db8::5"); !ok {
		t.Fatal("healthy v6 owned record lost while v4 was untrusted")
	}
}

// ---- state-aware lease parser ----

func writeCSV(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestParseActiveLeases4FiltersStateAndExpiry(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "leases4.csv")
	// expire epoch far in the future for active rows; a past epoch for the
	// stale row. now = 1_700_000_000.
	writeCSV(t, path, `address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state
10.0.0.10,aa:bb:cc:dd:ee:01,,3600,1900000000,1,0,1,host-a,0
10.0.0.11,aa:bb:cc:dd:ee:02,,3600,1900000000,1,0,1,host-b,1
10.0.0.12,aa:bb:cc:dd:ee:03,,3600,1900000000,1,0,1,host-c,2
10.0.0.13,aa:bb:cc:dd:ee:04,,3600,1600000000,1,0,1,host-d,0
`)
	now := time.Unix(1_700_000_000, 0)
	leases, err := parseActiveLeases4(path, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(leases) != 1 {
		t.Fatalf("want 1 active lease, got %d: %+v", len(leases), leases)
	}
	if leases[0].Address != "10.0.0.10" || leases[0].HostName != "host-a" {
		t.Fatalf("wrong active lease: %+v", leases[0])
	}
	if leases[0].Identity != "mac:aa:bb:cc:dd:ee:01" {
		t.Fatalf("identity = %q", leases[0].Identity)
	}
}

func TestParseActiveLeases4ClientIDPreferred(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "leases4.csv")
	writeCSV(t, path, `address,hwaddr,client_id,valid_lifetime,expire,subnet_id,hostname,state
10.0.0.10,aa:bb:cc:dd:ee:01,01aabbcc,3600,1900000000,1,host-a,0
`)
	leases, err := parseActiveLeases4(path, time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(leases) != 1 || leases[0].Identity != "cid:01aabbcc" {
		t.Fatalf("client-id not preferred: %+v", leases)
	}
}

func TestParseActiveLeases4FQDNForwardFlagSplitsNameSource(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "leases4.csv")
	writeCSV(t, path, `address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,hostname,state
10.0.0.10,aa:bb:cc:dd:ee:01,,3600,1900000000,1,0,host-a,0
10.0.0.11,aa:bb:cc:dd:ee:02,,3600,1900000000,1,1,client.example.com,0
`)
	leases, err := parseActiveLeases4(path, time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(leases) != 2 {
		t.Fatalf("want 2 active leases, got %d: %+v", len(leases), leases)
	}
	if leases[0].HostName != "host-a" || leases[0].ClientFQDN != "" {
		t.Fatalf("hostname row parsed wrong: %+v", leases[0])
	}
	if leases[1].HostName != "" || leases[1].ClientFQDN != "client.example.com" {
		t.Fatalf("fqdn row parsed wrong: %+v", leases[1])
	}
}

func TestParseActiveLeases6DUIDIAID(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "leases6.csv")
	writeCSV(t, path, `address,duid,valid_lifetime,expire,subnet_id,pref_lifetime,lease_type,iaid,prefix_len,fqdn_fwd,fqdn_rev,hostname,hwaddr,state
2001:db8::5,00:01:00:01:de:ad,3600,1900000000,1,1800,0,7,128,1,1,host-6,aa:bb,0
2001:db8::6,00:01:00:01:be:ef,3600,1900000000,1,1800,0,8,128,1,1,host-7,aa:cc,2
`)
	leases, err := parseActiveLeases6(path, time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(leases) != 1 {
		t.Fatalf("want 1 active v6 lease, got %d: %+v", len(leases), leases)
	}
	if leases[0].Identity != "duid:00:01:00:01:de:ad/7" {
		t.Fatalf("v6 identity = %q", leases[0].Identity)
	}
	if leases[0].Family != 6 {
		t.Fatalf("family = %d", leases[0].Family)
	}
}

func TestParseActiveLeasesLastRowWins(t *testing.T) {
	// A renewal appends a new row; the later row supersedes. An address
	// whose final row is declined/expired must drop out entirely.
	dir := t.TempDir()
	path := filepath.Join(dir, "leases4.csv")
	writeCSV(t, path, `address,hwaddr,client_id,valid_lifetime,expire,subnet_id,hostname,state
10.0.0.10,aa,,3600,1900000000,1,old-name,0
10.0.0.10,aa,,3600,1900000000,1,new-name,0
10.0.0.20,bb,,3600,1900000000,1,host-x,0
10.0.0.20,bb,,3600,1900000000,1,host-x,1
`)
	leases, err := parseActiveLeases4(path, time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(leases) != 1 {
		t.Fatalf("want 1 lease (10.0.0.10 with new-name), got %d: %+v", len(leases), leases)
	}
	if leases[0].Address != "10.0.0.10" || leases[0].HostName != "new-name" {
		t.Fatalf("last-row-wins failed: %+v", leases[0])
	}
}

// TestParseActiveLeasesInactiveThenActiveReclaim proves the #1387 MAJOR-3
// boundary: an inactive (declined/expired-reclaimed) row that PRECEDES a
// later active row for the SAME address must NOT suppress that active row.
// Last-row-wins means the final active allocation reclaims the address and
// it appears in the output. Against the pre-fix parser (which tombstoned the
// address out of the output order and never re-added it when a later active
// row arrived) the reclaimed address is silently OMITTED, so this test fails
// pre-fix.
func TestParseActiveLeasesInactiveThenActiveReclaim(t *testing.T) {
	dir := t.TempDir()
	now := time.Unix(1_700_000_000, 0)

	t.Run("inactive then active", func(t *testing.T) {
		path := filepath.Join(dir, "leases-ia.csv")
		// 10.0.0.10: declined (state=1) THEN a fresh active allocation.
		writeCSV(t, path, `address,hwaddr,client_id,valid_lifetime,expire,subnet_id,hostname,state
10.0.0.10,aa,,3600,1900000000,1,old-decl,1
10.0.0.10,bb,,3600,1900000000,1,new-active,0
`)
		leases, err := parseActiveLeases4(path, now)
		if err != nil {
			t.Fatal(err)
		}
		if len(leases) != 1 {
			t.Fatalf("reclaimed active lease omitted: got %d leases %+v", len(leases), leases)
		}
		if leases[0].Address != "10.0.0.10" || leases[0].HostName != "new-active" {
			t.Fatalf("wrong reclaimed lease: %+v", leases[0])
		}
	})

	t.Run("active inactive active", func(t *testing.T) {
		path := filepath.Join(dir, "leases-aia.csv")
		// 10.0.0.20: active, then expired-reclaimed (state=2), then active
		// again — the FINAL active row must win.
		writeCSV(t, path, `address,hwaddr,client_id,valid_lifetime,expire,subnet_id,hostname,state
10.0.0.20,aa,,3600,1900000000,1,first,0
10.0.0.20,aa,,3600,1900000000,1,gone,2
10.0.0.20,cc,,3600,1900000000,1,final,0
`)
		leases, err := parseActiveLeases4(path, now)
		if err != nil {
			t.Fatal(err)
		}
		if len(leases) != 1 {
			t.Fatalf("final active row omitted: got %d leases %+v", len(leases), leases)
		}
		if leases[0].HostName != "final" {
			t.Fatalf("active->inactive->active did not keep final: %+v", leases[0])
		}
	})

	t.Run("inactive last row still drops", func(t *testing.T) {
		path := filepath.Join(dir, "leases-final-inactive.csv")
		// 10.0.0.30: active then declined — final row inactive => dropped.
		writeCSV(t, path, `address,hwaddr,client_id,valid_lifetime,expire,subnet_id,hostname,state
10.0.0.30,aa,,3600,1900000000,1,was-active,0
10.0.0.30,aa,,3600,1900000000,1,now-declined,1
`)
		leases, err := parseActiveLeases4(path, now)
		if err != nil {
			t.Fatal(err)
		}
		if len(leases) != 0 {
			t.Fatalf("address with final inactive row should drop: %+v", leases)
		}
	})
}

// TestParseActiveLeasesMangledHeaderErrors proves the AGY MINOR-1 / MAJOR-4
// re-open fix: a Kea memfile whose header is MANGLED (a required column
// missing or renamed) must return a parse ERROR — not a silent empty lease
// set — so the reconciler marks the family untrusted and SKIPS the
// destructive delete pass. Otherwise every owned record of that family
// looks expired and is mass-deleted, the exact failure MAJOR-4 prevents,
// reached through the header-validation gap. The two sub-cases exercise the
// header-mangle path end to end through Reconcile (owned records preserved)
// and the direct-parser path (error returned). Against the pre-fix code the
// parser returns 0 leases with no error, so the owned record is deleted and
// these assertions fail.
func TestParseActiveLeasesMangledHeaderErrors(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)

	t.Run("missing address column errors", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "leases-noaddr.csv")
		// Header lacks "address"; the body row still carries a value where
		// address would be. Pre-fix: every addr reads "" -> all rows skipped
		// -> 0 leases, no error.
		writeCSV(t, path, `hwaddr,client_id,valid_lifetime,expire,subnet_id,hostname,state
aa:bb:cc:dd:ee:01,,3600,1900000000,1,host-a,0
`)
		if _, err := parseActiveLeases4(path, now); err == nil {
			t.Fatal("missing 'address' column must produce a parse error")
		}
	})

	t.Run("missing state column errors", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "leases-nostate.csv")
		writeCSV(t, path, `address,hwaddr,client_id,valid_lifetime,expire,subnet_id,hostname
10.0.0.10,aa:bb:cc:dd:ee:01,,3600,1900000000,1,host-a
`)
		if _, err := parseActiveLeases4(path, now); err == nil {
			t.Fatal("missing 'state' column must produce a parse error")
		}
	})

	t.Run("mangled header does not mass-delete via Reconcile", func(t *testing.T) {
		up := newFakeUpdater()
		m := testDDNS(t, up)
		cfg := &config.DHCPServerConfig{
			DynamicDNS: &config.DHCPDynamicDNSConfig{
				Enabled:    true,
				Domain:     "example.com",
				TTLSeconds: 300,
			},
		}
		// Cycle 1: a valid header -> the v4 lease is published and owned.
		writeCSV(t, m.leasePath4, `address,hwaddr,client_id,valid_lifetime,expire,subnet_id,hostname,state
10.0.0.10,aa,,3600,1900000000,1,host-a,0
`)
		if err := m.Reconcile(context.Background(), cfg); err != nil {
			t.Fatalf("cycle 1 reconcile: %v", err)
		}
		if _, ok := m.state.get("mac:aa", "10.0.0.10"); !ok {
			t.Fatal("cycle 1 did not record the owned v4 record")
		}
		// Cycle 2: the v4 header is now mangled (no "state" column). The
		// reconcile must surface an error and NOT delete the owned record.
		up.deletes = nil
		writeCSV(t, m.leasePath4, `address,hwaddr,client_id,valid_lifetime,expire,subnet_id,hostname
10.0.0.10,aa,,3600,1900000000,1,host-a
`)
		err := m.Reconcile(context.Background(), cfg)
		if err == nil {
			t.Fatal("mangled header must surface a parse error from Reconcile")
		}
		for _, d := range up.deletes {
			if d.Addr.Is4() {
				t.Fatalf("v4 record deleted on a mangled header: %s", d.FQDN)
			}
		}
		if _, ok := m.state.get("mac:aa", "10.0.0.10"); !ok {
			t.Fatal("v4 owned record mass-deleted on a mangled header (MAJOR-4 re-opened)")
		}
	})
}

// TestParseActiveLeasesCaseInsensitiveHeader proves AGY MINOR-2: header
// column names are matched case-insensitively, so a memfile written with
// mixed-case headers ("Address","State", ...) still resolves its columns
// and parses leases correctly. Against the pre-fix case-sensitive cols map
// the columns are not found, every row is skipped, and the parser returns 0
// leases — so this test fails pre-fix.
func TestParseActiveLeasesCaseInsensitiveHeader(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "leases-mixedcase.csv")
	writeCSV(t, path, `Address,HwAddr,Client_ID,Valid_Lifetime,Expire,Subnet_ID,Hostname,State
10.0.0.10,aa:bb:cc:dd:ee:01,,3600,1900000000,1,host-a,0
10.0.0.11,aa:bb:cc:dd:ee:02,,3600,1900000000,1,host-b,1
`)
	leases, err := parseActiveLeases4(path, time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatalf("mixed-case header should parse, got error: %v", err)
	}
	if len(leases) != 1 {
		t.Fatalf("want 1 active lease from mixed-case header, got %d: %+v", len(leases), leases)
	}
	if leases[0].Address != "10.0.0.10" || leases[0].HostName != "host-a" {
		t.Fatalf("mixed-case columns resolved wrong: %+v", leases[0])
	}
	if leases[0].Identity != "mac:aa:bb:cc:dd:ee:01" {
		t.Fatalf("identity from mixed-case header = %q", leases[0].Identity)
	}
}

// reconcileWithLeaseHeaders is a helper: seed an owned record from a healthy
// lease file, then re-run Reconcile with a (possibly mangled) header and
// assert the owned record is preserved + the reconcile surfaces an error.
// Used by the Codex-r3 MAJOR-A (naming) and MAJOR-B (identity) tests.
func assertReconcilePreservesOwned(t *testing.T, family int, healthyHeader, healthyRow, mangledHeader, mangledRow, ownIdentity, ownAddr string) {
	t.Helper()
	up := newFakeUpdater()
	m := testDDNS(t, up)
	cfg := &config.DHCPServerConfig{
		DynamicDNS: &config.DHCPDynamicDNSConfig{
			Enabled:    true,
			Domain:     "example.com",
			TTLSeconds: 300,
		},
	}
	leasePath := m.leasePath4
	if family == 6 {
		leasePath = m.leasePath6
	}
	// Cycle 1: healthy header -> the lease is published and owned.
	writeCSV(t, leasePath, healthyHeader+"\n"+healthyRow+"\n")
	if err := m.Reconcile(context.Background(), cfg); err != nil {
		t.Fatalf("cycle 1 reconcile: %v", err)
	}
	if _, ok := m.state.get(ownIdentity, ownAddr); !ok {
		t.Fatalf("cycle 1 did not record owned record %s|%s; state=%+v", ownIdentity, ownAddr, m.state.records)
	}
	// Cycle 2: mangled header -> must error, must not delete the owned record.
	up.deletes = nil
	writeCSV(t, leasePath, mangledHeader+"\n"+mangledRow+"\n")
	if err := m.Reconcile(context.Background(), cfg); err == nil {
		t.Fatal("mangled header must surface a parse error from Reconcile")
	}
	if len(up.deletes) != 0 {
		t.Fatalf("records deleted on a mangled header (record loss): %v", up.deleteNames())
	}
	if _, ok := m.state.get(ownIdentity, ownAddr); !ok {
		t.Fatalf("owned record %s|%s lost on a mangled header", ownIdentity, ownAddr)
	}
}

// TestParseActiveLeasesNamingColumnRequired proves Codex-r3 MAJOR-A: if the
// naming column ("hostname") is missing while address+state remain, the
// pre-fix parser SUCCEEDS with empty names, Reconcile skips every lease as
// unnamed (empty desired set), and the destructive pass mass-deletes all
// owned records. The naming column is now REQUIRED, so a header without it
// errors and Reconcile marks the family untrusted. Against pre-fix code the
// parser returns named=0 with no error -> the owned record is mass-deleted ->
// this fails.
func TestParseActiveLeasesNamingColumnRequired(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	// Direct parser: missing hostname errors (v4 and v6).
	t.Run("v4 missing hostname errors", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "l4.csv")
		writeCSV(t, path, `address,hwaddr,client_id,valid_lifetime,expire,subnet_id,state
10.0.0.10,aa,,3600,1900000000,1,0
`)
		if _, err := parseActiveLeases4(path, now); err == nil {
			t.Fatal("v4 header missing 'hostname' must error")
		}
	})
	t.Run("v6 missing hostname errors", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "l6.csv")
		writeCSV(t, path, `address,duid,valid_lifetime,expire,subnet_id,iaid,state
2001:db8::5,00:01,3600,1900000000,1,7,0
`)
		if _, err := parseActiveLeases6(path, now); err == nil {
			t.Fatal("v6 header missing 'hostname' must error")
		}
	})
	// End-to-end: a missing hostname must not mass-delete owned records.
	t.Run("v4 missing hostname does not mass-delete", func(t *testing.T) {
		assertReconcilePreservesOwned(t, 4,
			"address,hwaddr,client_id,valid_lifetime,expire,subnet_id,hostname,state",
			"10.0.0.10,aa,,3600,1900000000,1,host-a,0",
			"address,hwaddr,client_id,valid_lifetime,expire,subnet_id,state",
			"10.0.0.10,aa,,3600,1900000000,1,0",
			"mac:aa", "10.0.0.10")
	})
}

// TestParseActiveLeasesIdentityColumnRequired proves Codex-r3 MAJOR-B: if the
// per-family identity columns disappear (v4: client_id+hwaddr; v6: duid+iaid)
// while address/state/hostname remain, the pre-fix parser SUCCEEDS but the
// identity collapses to the address fallback, so the owned record keyed by the
// PRIOR real identity no longer matches desired -> delete + re-add churn (and
// record loss if the re-add upsert fails). The identity columns are now
// REQUIRED per family, so a header without them errors and Reconcile marks the
// family untrusted. Against pre-fix code the parser succeeds and the owned
// record is deleted+rekeyed -> this fails.
func TestParseActiveLeasesIdentityColumnRequired(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	t.Run("v4 missing client_id+hwaddr errors", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "l4.csv")
		writeCSV(t, path, `address,valid_lifetime,expire,subnet_id,hostname,state
10.0.0.10,3600,1900000000,1,host-a,0
`)
		if _, err := parseActiveLeases4(path, now); err == nil {
			t.Fatal("v4 header missing identity columns must error")
		}
	})
	t.Run("v6 missing duid+iaid errors", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "l6.csv")
		writeCSV(t, path, `address,valid_lifetime,expire,subnet_id,hostname,state
2001:db8::5,3600,1900000000,1,host-6,0
`)
		if _, err := parseActiveLeases6(path, now); err == nil {
			t.Fatal("v6 header missing identity columns must error")
		}
	})
	// End-to-end: a v4 header losing its identity columns must not delete the
	// record keyed by the prior real identity.
	t.Run("v4 missing identity does not churn owned record", func(t *testing.T) {
		assertReconcilePreservesOwned(t, 4,
			"address,hwaddr,client_id,valid_lifetime,expire,subnet_id,hostname,state",
			"10.0.0.10,aa,,3600,1900000000,1,host-a,0",
			"address,valid_lifetime,expire,subnet_id,hostname,state",
			"10.0.0.10,3600,1900000000,1,host-a,0",
			"mac:aa", "10.0.0.10")
	})
	// End-to-end: a v6 header losing its identity columns must not churn.
	t.Run("v6 missing identity does not churn owned record", func(t *testing.T) {
		assertReconcilePreservesOwned(t, 6,
			"address,duid,valid_lifetime,expire,subnet_id,iaid,hostname,state",
			"2001:db8::5,00:01,3600,1900000000,1,7,host-6,0",
			"address,valid_lifetime,expire,subnet_id,hostname,state",
			"2001:db8::5,3600,1900000000,1,host-6,0",
			"duid:00:01/7", "2001:db8::5")
	})
}

// TestParseActiveLeasesOptionalColumnsDegradeSafely proves the columns kept
// OPTIONAL (fqdn_fwd, expire, subnet_id) do not error and degrade safely: a
// healthy header without them still parses the lease (named, active). This
// documents the deliberate boundary — only columns whose absence is
// destructive are required.
func TestParseActiveLeasesOptionalColumnsDegradeSafely(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "l4.csv")
	// No fqdn_fwd, no expire, no subnet_id — all the required columns present.
	writeCSV(t, path, `address,hwaddr,client_id,hostname,state
10.0.0.10,aa,,host-a,0
`)
	leases, err := parseActiveLeases4(path, time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatalf("optional columns absent should still parse, got error: %v", err)
	}
	if len(leases) != 1 || leases[0].HostName != "host-a" || leases[0].Identity != "mac:aa" {
		t.Fatalf("optional-absent lease parsed wrong: %+v", leases)
	}
}

// TestLeaseColumnValueLowerCasesLookupName proves the Codex-r3 MINOR: the
// column lookup lower-cases its NAME argument so the case-insensitivity
// invariant holds at the call site, not merely because every caller passes a
// lower-case literal. The cols map (built lower-cased) is queried with a
// MIXED-case lookup name; it must still resolve. Against the pre-fix lookup
// (cols[name], no lower-casing of name) a mixed-case lookup name misses and
// returns "" — so this test fails pre-fix. This is the direct guard the
// documented invariant requires.
func TestLeaseColumnValueLowerCasesLookupName(t *testing.T) {
	// cols keys are lower-case (as built from the header). Look them up with
	// mixed/upper-case names — they must resolve.
	cols := map[string]int{"address": 0, "client_id": 1, "hostname": 2}
	fields := []string{"10.0.0.10", "01deadbeef", "host-a"}
	cases := []struct{ name, want string }{
		{"Address", "10.0.0.10"},
		{"ADDRESS", "10.0.0.10"},
		{"Client_ID", "01deadbeef"},
		{"HostName", "host-a"},
		{"absent", ""},
	}
	for _, tc := range cases {
		if got := leaseColumnValue(cols, fields, tc.name); got != tc.want {
			t.Fatalf("leaseColumnValue(%q) = %q, want %q (lookup name not lower-cased)", tc.name, got, tc.want)
		}
	}
}

// ---- state store persistence ----

func TestStateStorePersistsAndReloads(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.json")
	s, err := loadDDNSState(statePath)
	if err != nil {
		t.Fatal(err)
	}
	s.put(ownedRecord{Family: 4, Identity: "mac:aa", Address: "10.0.0.10", FQDN: "h.example.com", ForwardType: "A", PTRName: "10.0.0.10.in-addr.arpa", TTL: 300})
	if err := s.save(); err != nil {
		t.Fatal(err)
	}
	s2, err := loadDDNSState(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if r, ok := s2.get("mac:aa", "10.0.0.10"); !ok || r.FQDN != "h.example.com" {
		t.Fatalf("reload lost record: %+v ok=%v", r, ok)
	}
}

func TestStateStoreCorruptResetsEmptyFailOpen(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.json")
	writeCSV(t, statePath, "{ this is not json")
	s, err := loadDDNSState(statePath)
	if err == nil {
		t.Fatal("expected an error for corrupt state")
	}
	if s == nil || len(s.records) != 0 {
		t.Fatalf("corrupt store must reset to empty, got %+v", s)
	}
}

func equalStr(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
