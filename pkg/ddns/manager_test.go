package ddns

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

func testDDNS(t *testing.T, up DNSUpdater) *Manager {
	t.Helper()
	dir := t.TempDir()
	return newManagerForTesting(
		nil, // spine tests drive reconcileOnceLocked with synthetic Leases
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

func leaseV4(addr, ident, host string) Lease {
	return Lease{Family: 4, Address: addr, Identity: ident, HostName: host, SubnetID: "1"}
}

func runReconcile(t *testing.T, m *Manager, pol ddnsPolicy, leases []Lease) error {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.reconcileOnceLocked(context.Background(), pol, leases, nil)
}

// writeCSV writes a file (used by the state-store tests to seed an on-disk
// state JSON). Moved from ddns_test.go; the Kea-CSV-specific uses stayed with
// the parser tests in pkg/dhcpserver.
func writeCSV(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
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
	if err := runReconcile(t, m, pol, []Lease{
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
	if err := runReconcile(t, m, pol, []Lease{
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
	if err := runReconcile(t, m, pol, []Lease{leaseV4("10.0.0.10", "mac:aa", "host-a")}); err != nil {
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
	if err := runReconcile(t, m, pol, []Lease{leaseV4("10.0.0.10", "mac:aa", "host-a")}); err != nil {
		t.Fatal(err)
	}
	// Same client (mac:aa), new address.
	if err := runReconcile(t, m, pol, []Lease{leaseV4("10.0.0.20", "mac:aa", "host-a")}); err != nil {
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
	if err := runReconcile(t, m, pol, []Lease{leaseV4("10.0.0.10", "mac:aa", "host-a")}); err != nil {
		t.Fatal(err)
	}
	// Same address now leased to client B with a different name. Old
	// owner must be cleaned before the new owner is added.
	if err := runReconcile(t, m, pol, []Lease{leaseV4("10.0.0.10", "mac:bb", "host-b")}); err != nil {
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
	if err := runReconcile(t, m, pol, []Lease{leaseV4("10.0.0.10", "mac:aa", "host-a")}); err != nil {
		t.Fatal(err)
	}

	up.upserts = nil
	up.deletes = nil
	up.failDel["host-a.example.com"] = true
	err := runReconcile(t, m, pol, []Lease{leaseV4("10.0.0.10", "mac:bb", "host-b")})
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
	if err := runReconcile(t, m, pol, []Lease{leaseV4("10.0.0.10", "mac:bb", "host-b")}); err != nil {
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
	if err := runReconcile(t, m, pol, []Lease{leaseV4("10.0.0.10", "mac:aa", "host-a")}); err != nil {
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
	lease := []Lease{leaseV4("10.0.0.10", "mac:aa", "host-a")}

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
	if err := runReconcile(t, m, pol, []Lease{leaseV4("10.0.0.10", "mac:aa", "")}); err != nil {
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
	if err := runReconcile(t, m, pol, []Lease{leaseV4("10.0.0.10", "mac:aa", "host-a")}); err != nil {
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
	prod := NewManager(nil, nil, "node0")
	if prod.updater == nil {
		t.Fatal("NewManager(nil, nil, ...) left a nil updater")
	}
	if !isNopUpdater(prod.updater) {
		t.Fatalf("NewManager(nil, nil, ...) did not install a nopUpdater: %T", prod.updater)
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
	if err := runReconcile(t, m, pol, []Lease{leaseV4("10.0.0.10", "mac:aa", "host-a")}); err != nil {
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
// TestReconcileParseErrorSuppressesFamilyDeletes exercises the engine's
// untrusted-family fail-safe: when a family's LeaseParser returns an error,
// that family's destructive diff is suppressed (no deletes) and the error is
// surfaced, while a healthy family reconciles normally. #2691 P1a moved the
// engine to pkg/ddns and replaced the internal Kea-memfile parse with the
// LeaseParser seam, so this test injects a parser that errors for family 4 and
// succeeds for family 6 — the SAME engine behavior the dhcpserver-resident
// version asserted via the real Kea parser (whose CSV-specific parse-error
// detection stays covered verbatim by the parser tests in pkg/dhcpserver).
func TestReconcileParseErrorSuppressesFamilyDeletes(t *testing.T) {
	up := newFakeUpdater()
	dir := t.TempDir()

	v4OK := []Lease{{Family: 4, Address: "10.0.0.10", Identity: "mac:aa", HostName: "host-a", SubnetID: "1"}}
	v6OK := []Lease{{Family: 6, Address: "2001:db8::5", Identity: "duid:00:01/7", HostName: "host-6", SubnetID: "1"}}

	// v4Broken flips on for cycle 2: the v4 parser then returns an error
	// (unreadable source) so the engine must mark family 4 untrusted.
	v4Broken := false
	parser := func(_ string, family int, _ time.Time) ([]Lease, error) {
		switch family {
		case 4:
			if v4Broken {
				return nil, fmt.Errorf("fake: v4 lease source unreadable")
			}
			return v4OK, nil
		default:
			return v6OK, nil
		}
	}

	m := newManagerForTesting(
		parser,
		up,
		filepath.Join(dir, "state.json"),
		filepath.Join(dir, "leases4.csv"),
		filepath.Join(dir, "leases6.csv"),
		"node0",
		func() time.Time { return time.Unix(1_700_000_000, 0) },
	)

	cfg := &config.DHCPServerConfig{
		DynamicDNS: &config.DHCPDynamicDNSConfig{
			Enabled:    true,
			Domain:     "example.com",
			TTLSeconds: 300,
		},
	}

	// Cycle 1: a valid v4 lease and a valid v6 lease -> both published+owned.
	if err := m.Reconcile(context.Background(), cfg); err != nil {
		t.Fatalf("cycle 1 reconcile: %v", err)
	}
	if n := len(m.state.records); n != 2 {
		t.Fatalf("cycle 1 owned records = %d, want 2", n)
	}

	// Cycle 2: the v4 parser errors (unreadable source); the v6 parser is
	// still healthy. The v4 owned record must be PRESERVED (no delete); the
	// reconcile must surface the parse error.
	up.deletes = nil
	v4Broken = true
	err := m.Reconcile(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected the v4 parse error to be surfaced")
	}
	// No v4 deletes at all this cycle.
	for _, d := range up.deletes {
		if d.Addr.Is4() {
			t.Fatalf("v4 record deleted despite unreadable lease source: %s", d.FQDN)
		}
	}
	// The v4 owned record is still in the store.
	if _, ok := m.state.get("mac:aa", "10.0.0.10"); !ok {
		t.Fatal("v4 owned record dropped after a v4 parse error (mass-delete bug)")
	}
	// The healthy v6 owned record is also still present (active this cycle).
	if _, ok := m.state.get("duid:00:01/7", "2001:db8::5"); !ok {
		t.Fatal("healthy v6 owned record lost while v4 was untrusted")
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

// TestStateStoreUnsupportedVersionFailsOpen proves the Copilot robustness
// fix: a state file with an unknown (future) non-zero Version is treated
// like a corrupt store — fail-open to an EMPTY store + surface an error (so
// the caller warns), rather than silently decoding records that may carry a
// different tuple shape into wrong-tuple deletes. No panic. Against the
// pre-fix loader (which never checked Version) the records load and would be
// trusted, so this test fails pre-fix.
func TestStateStoreUnsupportedVersionFailsOpen(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.json")
	// A syntactically-valid state file from a FUTURE format version, with a
	// record. The current loader must NOT trust it.
	writeCSV(t, statePath, `{"version":99,"records":[{"family":4,"identity":"mac:aa","address":"10.0.0.10","fqdn":"h.example.com","forward_type":"A","ptr_name":"10.0.0.10.in-addr.arpa","ttl":300}]}`)
	s, err := loadDDNSState(statePath)
	if err == nil {
		t.Fatal("expected an error for an unsupported state version")
	}
	if s == nil {
		t.Fatal("loadDDNSState returned nil store on unsupported version (must be empty store)")
	}
	if len(s.records) != 0 {
		t.Fatalf("unsupported version must reset to empty (no wrong-tuple records), got %d records", len(s.records))
	}

	// A version-0 (pre-versioning / zero-value) file is tolerated and its
	// records load — the field was absent or defaulted, not a future format.
	v0path := filepath.Join(dir, "state-v0.json")
	writeCSV(t, v0path, `{"records":[{"family":4,"identity":"mac:bb","address":"10.0.0.20","fqdn":"h2.example.com","forward_type":"A","ptr_name":"20.0.0.10.in-addr.arpa","ttl":300}]}`)
	s0, err := loadDDNSState(v0path)
	if err != nil {
		t.Fatalf("version-0 store must load, got error: %v", err)
	}
	if _, ok := s0.get("mac:bb", "10.0.0.20"); !ok {
		t.Fatal("version-0 store should load its records")
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
