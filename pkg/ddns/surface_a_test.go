package ddns

import (
	"context"
	"net/netip"
	"path/filepath"
	"testing"
	"time"
)

// #2691 P2 Surface A engine tests. Everything is driven through a fakeUpdater
// (the spine's test seam) + a synthetic AddressObserver — no network, no DNS,
// no netlink. These are the fail-on-revert proofs for the engine discipline the
// plan requires: change-detection, forced-refresh, error backoff, replace (not
// withdraw-then-add) on address change, withdraw on config removal / address
// loss, and the per-RG HA gate (publish/never-withdraw).

func newSurfaceATestManager(t *testing.T, up DNSUpdater, now func() time.Time) *SurfaceAManager {
	t.Helper()
	dir := t.TempDir()
	return newSurfaceAManagerForTesting(filepath.Join(dir, "iface-ddns.json"), up, now)
}

func surfaceAScope(fqdn string, family Family, rg int) SurfaceAScope {
	return SurfaceAScope{
		Key: ScopeKey{
			Family:    family,
			Interface: "ge-0-0-2",
			Unit:      50,
			RGOwner:   rg,
			PolicyID:  "corp-2136",
			// The published name is part of the Surface A scope identity (#2903):
			// Key.FQDN must equal SurfaceAScope.FQDN so a hostname change is a new
			// scope (old withdrawn, new published), not an orphaning in-place rename.
			FQDN: fqdn,
		},
		FQDN:   fqdn,
		TTL:    300,
		Source: AddressSourceDHCP,
	}
}

// fixedObserver returns a single address for every scope.
func fixedObserver(addr string) AddressObserver {
	a := netip.MustParseAddr(addr)
	return func(SurfaceAScope) (AddressObservation, bool) {
		return AddressObservation{Addr: a, Source: AddressSourceDHCP}, true
	}
}

func TestSurfaceAPublishesObservedAddress(t *testing.T) {
	fu := newFakeUpdater()
	now := time.Unix(1_700_000_000, 0)
	m := newSurfaceATestManager(t, fu, func() time.Time { return now })

	sc := surfaceAScope("wan.example.net", FamilyV4, 0)
	if err := m.Reconcile(context.Background(), []SurfaceAScope{sc}, fixedObserver("203.0.113.5"), nil, nil); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	ups := fu.upsertNames()
	if len(ups) != 1 || ups[0] != "wan.example.net=203.0.113.5" {
		t.Fatalf("expected one publish of wan.example.net=203.0.113.5, got %v", ups)
	}
	if st := m.Stats(); st.UpsertOK != 1 || st.Scopes != 1 {
		t.Fatalf("stats: %+v", st)
	}
}

func TestSurfaceASkipsUnchangedWithinForcedRefresh(t *testing.T) {
	fu := newFakeUpdater()
	now := time.Unix(1_700_000_000, 0)
	m := newSurfaceATestManager(t, fu, func() time.Time { return now })
	sc := surfaceAScope("wan.example.net", FamilyV4, 0)
	obs := fixedObserver("203.0.113.5")

	if err := m.Reconcile(context.Background(), []SurfaceAScope{sc}, obs, nil, nil); err != nil {
		t.Fatalf("Reconcile1: %v", err)
	}
	// Second pass, same address, still inside the forced-refresh floor: NO wire
	// update.
	now = now.Add(time.Minute)
	if err := m.Reconcile(context.Background(), []SurfaceAScope{sc}, obs, nil, nil); err != nil {
		t.Fatalf("Reconcile2: %v", err)
	}
	if got := len(fu.upserts); got != 1 {
		t.Fatalf("unchanged address inside forced-refresh must not republish; got %d upserts", got)
	}
	if st := m.Stats(); st.Skipped != 1 {
		t.Fatalf("expected 1 unchanged skip, got %+v", st)
	}
}

func TestSurfaceARepublishesAfterForcedRefresh(t *testing.T) {
	fu := newFakeUpdater()
	now := time.Unix(1_700_000_000, 0)
	m := newSurfaceATestManager(t, fu, func() time.Time { return now })
	sc := surfaceAScope("wan.example.net", FamilyV4, 0)
	sc.ForcedRefresh = time.Hour
	obs := fixedObserver("203.0.113.5")

	if err := m.Reconcile(context.Background(), []SurfaceAScope{sc}, obs, nil, nil); err != nil {
		t.Fatalf("Reconcile1: %v", err)
	}
	// Past the forced-refresh floor: a wire re-assert fires even with no change.
	now = now.Add(2 * time.Hour)
	if err := m.Reconcile(context.Background(), []SurfaceAScope{sc}, obs, nil, nil); err != nil {
		t.Fatalf("Reconcile2: %v", err)
	}
	if got := len(fu.upserts); got != 2 {
		t.Fatalf("forced-refresh elapsed must re-assert; got %d upserts", got)
	}
}

// NOTE (#2691 P2 review): the replace-on-address-change, withdraw-on-config-
// removal, withdraw-on-address-loss, and per-RG-gate-withdraw proofs moved to
// surface_a_rfc2136_test.go — they MUST run through the REAL rfc2136 backend
// against the stateful fake DNS server, because the two production-path bugs the
// review found (the no-DHCID replace refusal + the no-op withdraw) are invisible
// to fakeUpdater (it appends on any UpsertLease and the old withdraw helper
// returned the injected static backend regardless of the production newBackend
// wiring). The fakeUpdater tests below stay only for backend-AGNOSTIC engine
// cadence (publish-once, skip-unchanged, forced-refresh fires, transient does
// not withdraw, backoff, status).

func TestSurfaceATransientObservationDoesNotWithdraw(t *testing.T) {
	fu := newFakeUpdater()
	now := time.Unix(1_700_000_000, 0)
	m := newSurfaceATestManager(t, fu, func() time.Time { return now })
	sc := surfaceAScope("wan.example.net", FamilyV4, 0)

	if err := m.Reconcile(context.Background(), []SurfaceAScope{sc}, fixedObserver("203.0.113.5"), nil, nil); err != nil {
		t.Fatalf("Reconcile1: %v", err)
	}
	// Transient observation failure (ok=false): NEVER withdraw (the
	// never-blackhole rule).
	transient := func(SurfaceAScope) (AddressObservation, bool) {
		return AddressObservation{}, false
	}
	if err := m.Reconcile(context.Background(), []SurfaceAScope{sc}, transient, nil, nil); err != nil {
		t.Fatalf("Reconcile2: %v", err)
	}
	if got := len(fu.deletes); got != 0 {
		t.Fatalf("transient observation failure must NOT withdraw; got %d deletes", got)
	}
	if st := m.Stats(); st.Scopes != 1 {
		t.Fatalf("the record must stay owned across a transient; got %d scopes", st.Scopes)
	}
}

// TestSurfaceAPerRGGate moved to surface_a_rfc2136_test.go
// (TestSurfaceARealBackendPerRGGate) — it asserts the actual zone state through
// the real backend, not fakeUpdater call counts.

func TestSurfaceABackoffOnRepeatedFailure(t *testing.T) {
	fu := newFakeUpdater()
	fu.failEvery = true // every publish fails
	now := time.Unix(1_700_000_000, 0)
	m := newSurfaceATestManager(t, fu, func() time.Time { return now })
	sc := surfaceAScope("wan.example.net", FamilyV4, 0)
	obs := fixedObserver("203.0.113.5")

	// First pass: attempts a publish, fails, arms backoff.
	if err := m.Reconcile(context.Background(), []SurfaceAScope{sc}, obs, nil, nil); err == nil {
		t.Fatal("expected a publish error on first pass")
	}
	attemptsAfterFirst := len(fu.upserts) // the fakeUpdater records nothing on failure
	_ = attemptsAfterFirst
	failCalls1 := fu.failedCalls
	// Second pass immediately after (still inside the backoff window): the
	// scope is SKIPPED, so the backend is NOT hit again (ban-avoidance).
	now = now.Add(time.Second)
	_ = m.Reconcile(context.Background(), []SurfaceAScope{sc}, obs, nil, nil)
	if fu.failedCalls != failCalls1 {
		t.Fatalf("scope in backoff window must not hit the backend again; calls %d -> %d",
			failCalls1, fu.failedCalls)
	}
	if st := m.Stats(); st.BackedOff < 1 {
		t.Fatalf("expected a backed-off skip, got %+v", st)
	}
	// Well past the backoff window: the scope is eligible again and retries.
	now = now.Add(time.Hour)
	_ = m.Reconcile(context.Background(), []SurfaceAScope{sc}, obs, nil, nil)
	if fu.failedCalls <= failCalls1 {
		t.Fatalf("after backoff window the scope must retry; calls stayed at %d", fu.failedCalls)
	}
}

func TestSurfaceAStatusViews(t *testing.T) {
	fu := newFakeUpdater()
	now := time.Unix(1_700_000_000, 0)
	m := newSurfaceATestManager(t, fu, func() time.Time { return now })
	sc := surfaceAScope("wan.example.net", FamilyV4, 0)
	if err := m.Reconcile(context.Background(), []SurfaceAScope{sc}, fixedObserver("203.0.113.5"), nil, nil); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	views := m.StatusViews([]SurfaceAScope{sc})
	if len(views) != 1 {
		t.Fatalf("expected one status view, got %d", len(views))
	}
	v := views[0]
	if v.FQDN != "wan.example.net" || v.Published != "203.0.113.5" ||
		v.Interface != "ge-0-0-2" || v.Family != 4 || v.Provider != "corp-2136" {
		t.Fatalf("status view mismatch: %+v", v)
	}
	if v.State != SurfaceAStatePublished {
		t.Fatalf("published scope must have state %q, got %q", SurfaceAStatePublished, v.State)
	}
	if v.LastPublished.IsZero() {
		t.Fatal("status view must carry a last-published time")
	}
}

// TestSurfaceAFQDNChangeDetectedAndPublished is the #2903 fail-on-revert proof
// for the change-detection half: changing ONLY the configured hostname for a
// scope (same interface/unit/family/RG/provider, SAME address) must be detected
// as a change and the NEW name published. Before #2903 the ScopeKey had no FQDN
// axis, so a FQDN-only edit kept the same scope key; change detection compared
// only the IP, so `owned && !changed && !refreshDue` skipped the pass and the
// new name was never published (RED: only the first publish would appear). The
// fix folds the published FQDN into the scope identity so the renamed scope is a
// new, not-yet-owned scope whose publish is not skipped.
func TestSurfaceAFQDNChangeDetectedAndPublished(t *testing.T) {
	fu := newFakeUpdater()
	now := time.Unix(1_700_000_000, 0)
	m := newSurfaceATestManager(t, fu, func() time.Time { return now })

	old := surfaceAScope("old.example.net", FamilyV4, 0)
	obs := fixedObserver("203.0.113.5")
	if err := m.Reconcile(context.Background(), []SurfaceAScope{old}, obs, nil, nil); err != nil {
		t.Fatalf("Reconcile(old): %v", err)
	}

	// Operator renames the published hostname; the address is UNCHANGED and we
	// are well inside the forced-refresh floor (only a minute later).
	now = now.Add(time.Minute)
	renamed := surfaceAScope("new.example.net", FamilyV4, 0)
	if err := m.Reconcile(context.Background(), []SurfaceAScope{renamed}, obs, nil, nil); err != nil {
		t.Fatalf("Reconcile(renamed): %v", err)
	}

	ups := fu.upsertNames()
	if !contains(ups, "new.example.net=203.0.113.5") {
		t.Fatalf("FQDN-only change (same IP) must publish the NEW name; upserts=%v", ups)
	}
}

// TestSurfaceAFQDNChangeWithdrawsOldName is the #2903 fail-on-revert proof for
// the orphan half: when the configured hostname changes, the OLD name's RR must
// be withdrawn at the provider (a real DeleteLease), not left orphaned. Before
// #2903 the in-place ownership overwrite stored the new FQDN under the SAME
// scope key and never DeleteLease'd the old name (RED: zero deletes, the old
// record resolves forever). The fix makes the old FQDN its own scope key; once
// the binding is reconciled under the new name, the old scope is gone-from-
// config and Reconcile Pass 2 withdraws it through the same backend.
func TestSurfaceAFQDNChangeWithdrawsOldName(t *testing.T) {
	fu := newFakeUpdater()
	now := time.Unix(1_700_000_000, 0)
	m := newSurfaceATestManager(t, fu, func() time.Time { return now })

	old := surfaceAScope("old.example.net", FamilyV4, 0)
	obs := fixedObserver("203.0.113.5")
	if err := m.Reconcile(context.Background(), []SurfaceAScope{old}, obs, nil, nil); err != nil {
		t.Fatalf("Reconcile(old): %v", err)
	}

	now = now.Add(time.Minute)
	renamed := surfaceAScope("new.example.net", FamilyV4, 0)
	if err := m.Reconcile(context.Background(), []SurfaceAScope{renamed}, obs, nil, nil); err != nil {
		t.Fatalf("Reconcile(renamed): %v", err)
	}

	dels := fu.deleteNames()
	if !contains(dels, "old.example.net=203.0.113.5") {
		t.Fatalf("a FQDN rename must withdraw the OLD name (no orphaned RR); deletes=%v", dels)
	}
	// And only ONE record is owned afterward (the new name); the old scope's
	// ownership entry must be dropped after the successful withdraw.
	if st := m.Stats(); st.Scopes != 1 {
		t.Fatalf("after a rename exactly one scope must remain owned (the new name); got %d", st.Scopes)
	}
	// Status must show the renamed scope as published, no stale withdraw-pending.
	views := m.StatusViews([]SurfaceAScope{renamed})
	if len(views) != 1 || views[0].FQDN != "new.example.net" || views[0].State != SurfaceAStatePublished {
		t.Fatalf("after a rename the only status row must be the published new name; got %+v", views)
	}
}

// TestSurfaceAFQDNMigrationAdoptsExistingRecord proves the #2903 on-disk
// upgrade path does NOT blackhole: a pre-#2903 ownership record was keyed under
// an FQDN-LESS scope prefix; after upgrade the configured scope keys under the
// FQDN-bearing prefix with the SAME name+address. Pass 1 (re)publishes under the
// new prefix; Pass 2 must adopt the stale old-prefix entry (drop it WITHOUT an
// exact-RR delete that would remove the just-published live RR). Net: the name
// stays published and no stale ownership lingers.
func TestSurfaceAFQDNMigrationAdoptsExistingRecord(t *testing.T) {
	fu := newFakeUpdater()
	now := time.Unix(1_700_000_000, 0)
	dir := t.TempDir()
	statePath := filepath.Join(dir, "iface-ddns.json")

	sc := surfaceAScope("wan.example.net", FamilyV4, 0)

	// Seed a PRE-#2903 ownership record: same scope, but FQDN NOT in the key
	// (the old on-disk shape). We build the manager, then inject the legacy entry
	// directly into the store under the FQDN-less scope key.
	m := newSurfaceAManagerForTesting(statePath, fu, func() time.Time { return now })
	legacyKey := sc.Key // NOTE: no FQDN folded in — the pre-#2903 prefix.
	m.state.put(ownedRecord{
		Family:      4,
		Identity:    surfaceAIdentity,
		Address:     "",
		FQDN:        "wan.example.net",
		ForwardType: "A",
		TTL:         300,
		AddrText:    "203.0.113.5",
	}.withScope(legacyKey))
	if err := m.state.save(); err != nil {
		t.Fatalf("seed save: %v", err)
	}

	// First post-upgrade reconcile, same address.
	if err := m.Reconcile(context.Background(), []SurfaceAScope{sc}, fixedObserver("203.0.113.5"), nil, nil); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	// The name must NOT have been withdrawn (no blackhole on upgrade).
	if dels := fu.deleteNames(); contains(dels, "wan.example.net=203.0.113.5") {
		t.Fatalf("upgrade migration must NOT delete the live RR; deletes=%v", dels)
	}
	// Exactly one scope owned (the new FQDN-bearing prefix); the stale legacy
	// entry must have been adopted/dropped.
	if st := m.Stats(); st.Scopes != 1 {
		t.Fatalf("after migration exactly one scope must remain owned; got %d", st.Scopes)
	}
	views := m.StatusViews([]SurfaceAScope{sc})
	if len(views) != 1 || views[0].State != SurfaceAStatePublished {
		t.Fatalf("migrated scope must be the single published row; got %+v", views)
	}
}

// contains reports whether s is present in xs.
func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
