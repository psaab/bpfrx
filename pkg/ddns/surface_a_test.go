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
