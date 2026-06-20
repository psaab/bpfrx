package dhcpserver

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
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
	return m.reconcileOnceLocked(context.Background(), pol, leases)
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
		{"fqdn source prefers client fqdn", "ignored", "real.example.org", "mac:aa", "example.com", "fqdn", "real.example.org", false},
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
	writeCSV(t, path, `address,hwaddr,client_id,valid_lifetime,expire,subnet_id,state
10.0.0.10,aa:bb:cc:dd:ee:01,01aabbcc,3600,1900000000,1,0
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
