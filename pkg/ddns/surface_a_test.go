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
	if err := m.Reconcile(context.Background(), []SurfaceAScope{sc}, fixedObserver("203.0.113.5"), nil); err != nil {
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

	if err := m.Reconcile(context.Background(), []SurfaceAScope{sc}, obs, nil); err != nil {
		t.Fatalf("Reconcile1: %v", err)
	}
	// Second pass, same address, still inside the forced-refresh floor: NO wire
	// update.
	now = now.Add(time.Minute)
	if err := m.Reconcile(context.Background(), []SurfaceAScope{sc}, obs, nil); err != nil {
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

	if err := m.Reconcile(context.Background(), []SurfaceAScope{sc}, obs, nil); err != nil {
		t.Fatalf("Reconcile1: %v", err)
	}
	// Past the forced-refresh floor: a wire re-assert fires even with no change.
	now = now.Add(2 * time.Hour)
	if err := m.Reconcile(context.Background(), []SurfaceAScope{sc}, obs, nil); err != nil {
		t.Fatalf("Reconcile2: %v", err)
	}
	if got := len(fu.upserts); got != 2 {
		t.Fatalf("forced-refresh elapsed must re-assert; got %d upserts", got)
	}
}

func TestSurfaceAReplacesOnAddressChange(t *testing.T) {
	fu := newFakeUpdater()
	now := time.Unix(1_700_000_000, 0)
	m := newSurfaceATestManager(t, fu, func() time.Time { return now })
	sc := surfaceAScope("wan.example.net", FamilyV4, 0)

	if err := m.Reconcile(context.Background(), []SurfaceAScope{sc}, fixedObserver("203.0.113.5"), nil); err != nil {
		t.Fatalf("Reconcile1: %v", err)
	}
	now = now.Add(time.Minute)
	if err := m.Reconcile(context.Background(), []SurfaceAScope{sc}, fixedObserver("203.0.113.9"), nil); err != nil {
		t.Fatalf("Reconcile2: %v", err)
	}
	// The address change is a REPLACE (idempotent replace-owned add of the new
	// rdata), NOT a withdraw-then-add: there must be NO delete (never a
	// blackhole gap), and the second upsert carries the new address.
	if got := len(fu.deletes); got != 0 {
		t.Fatalf("address change must REPLACE, not withdraw-then-add; got %d deletes", got)
	}
	if got := len(fu.upserts); got != 2 {
		t.Fatalf("expected 2 upserts (publish + replace), got %d", got)
	}
	if last := fu.upserts[len(fu.upserts)-1]; last.Addr.String() != "203.0.113.9" {
		t.Fatalf("replace must carry the new address, got %s", last.Addr)
	}
	// The scope still owns exactly one record.
	if st := m.Stats(); st.Scopes != 1 {
		t.Fatalf("a scope owns exactly one record; got %d", st.Scopes)
	}
}

func TestSurfaceAWithdrawsOnConfigRemoval(t *testing.T) {
	fu := newFakeUpdater()
	now := time.Unix(1_700_000_000, 0)
	m := newSurfaceATestManager(t, fu, func() time.Time { return now })
	sc := surfaceAScope("wan.example.net", FamilyV4, 0)

	if err := m.Reconcile(context.Background(), []SurfaceAScope{sc}, fixedObserver("203.0.113.5"), nil); err != nil {
		t.Fatalf("Reconcile1: %v", err)
	}
	// Binding removed: empty scope list → withdraw the owned record.
	if err := m.Reconcile(context.Background(), nil, fixedObserver("203.0.113.5"), nil); err != nil {
		t.Fatalf("Reconcile2: %v", err)
	}
	if got := fu.deleteNames(); len(got) != 1 || got[0] != "wan.example.net=203.0.113.5" {
		t.Fatalf("config removal must withdraw the owned record, got %v", got)
	}
	if st := m.Stats(); st.Scopes != 0 {
		t.Fatalf("withdraw must drop ownership; got %d scopes", st.Scopes)
	}
}

func TestSurfaceAWithdrawsOnAddressLoss(t *testing.T) {
	fu := newFakeUpdater()
	now := time.Unix(1_700_000_000, 0)
	m := newSurfaceATestManager(t, fu, func() time.Time { return now })
	sc := surfaceAScope("wan.example.net", FamilyV4, 0)

	if err := m.Reconcile(context.Background(), []SurfaceAScope{sc}, fixedObserver("203.0.113.5"), nil); err != nil {
		t.Fatalf("Reconcile1: %v", err)
	}
	// Address definitively lost (Invalid Addr, ok=true): withdraw.
	lost := func(SurfaceAScope) (AddressObservation, bool) {
		return AddressObservation{Source: AddressSourceDHCP}, true
	}
	if err := m.Reconcile(context.Background(), []SurfaceAScope{sc}, lost, nil); err != nil {
		t.Fatalf("Reconcile2: %v", err)
	}
	if got := len(fu.deletes); got != 1 {
		t.Fatalf("address loss must withdraw, got %d deletes", got)
	}
}

func TestSurfaceATransientObservationDoesNotWithdraw(t *testing.T) {
	fu := newFakeUpdater()
	now := time.Unix(1_700_000_000, 0)
	m := newSurfaceATestManager(t, fu, func() time.Time { return now })
	sc := surfaceAScope("wan.example.net", FamilyV4, 0)

	if err := m.Reconcile(context.Background(), []SurfaceAScope{sc}, fixedObserver("203.0.113.5"), nil); err != nil {
		t.Fatalf("Reconcile1: %v", err)
	}
	// Transient observation failure (ok=false): NEVER withdraw (the
	// never-blackhole rule).
	transient := func(SurfaceAScope) (AddressObservation, bool) {
		return AddressObservation{}, false
	}
	if err := m.Reconcile(context.Background(), []SurfaceAScope{sc}, transient, nil); err != nil {
		t.Fatalf("Reconcile2: %v", err)
	}
	if got := len(fu.deletes); got != 0 {
		t.Fatalf("transient observation failure must NOT withdraw; got %d deletes", got)
	}
	if st := m.Stats(); st.Scopes != 1 {
		t.Fatalf("the record must stay owned across a transient; got %d scopes", st.Scopes)
	}
}

func TestSurfaceAPerRGGate(t *testing.T) {
	// A scope on RG1: the RG1 MASTER publishes; a node that is NOT master for
	// RG1 neither publishes NOR withdraws (stop-writing, never-withdraw).
	scRG1 := surfaceAScope("vip.example.net", FamilyV4, 1)
	obs := fixedObserver("198.51.100.7")

	// MASTER node: gate admits RG1 → publishes.
	fuM := newFakeUpdater()
	now := time.Unix(1_700_000_000, 0)
	mMaster := newSurfaceATestManager(t, fuM, func() time.Time { return now })
	gateMaster := func(s ScopeKey) bool { return s.RGOwner == 1 }
	if err := mMaster.Reconcile(context.Background(), []SurfaceAScope{scRG1}, obs, gateMaster); err != nil {
		t.Fatalf("master Reconcile: %v", err)
	}
	if got := len(fuM.upserts); got != 1 {
		t.Fatalf("RG1 master must publish; got %d upserts", got)
	}

	// NON-master node that ALREADY owns the record (e.g. it just lost RG1):
	// it must NOT withdraw (the peer master refreshes; a withdraw blackholes).
	fuB := newFakeUpdater()
	mBackup := newSurfaceATestManager(t, fuB, func() time.Time { return now })
	// Seed ownership as if it had published before demotion.
	gateAdmitAll := func(ScopeKey) bool { return true }
	if err := mBackup.Reconcile(context.Background(), []SurfaceAScope{scRG1}, obs, gateAdmitAll); err != nil {
		t.Fatalf("backup seed Reconcile: %v", err)
	}
	fuB.deletes = nil
	fuB.upserts = nil
	// Now it is NOT master for RG1: stop-writing, never-withdraw.
	gateBackup := func(ScopeKey) bool { return false }
	if err := mBackup.Reconcile(context.Background(), []SurfaceAScope{scRG1}, obs, gateBackup); err != nil {
		t.Fatalf("backup Reconcile: %v", err)
	}
	if got := len(fuB.deletes); got != 0 {
		t.Fatalf("non-master must NOT withdraw a gated-out scope; got %d deletes", got)
	}
	if got := len(fuB.upserts); got != 0 {
		t.Fatalf("non-master must NOT publish a gated-out scope; got %d upserts", got)
	}
	if st := mBackup.Stats(); st.Scopes != 1 {
		t.Fatalf("the gated-out record must stay owned (peer refreshes); got %d scopes", st.Scopes)
	}
}

func TestSurfaceABackoffOnRepeatedFailure(t *testing.T) {
	fu := newFakeUpdater()
	fu.failEvery = true // every publish fails
	now := time.Unix(1_700_000_000, 0)
	m := newSurfaceATestManager(t, fu, func() time.Time { return now })
	sc := surfaceAScope("wan.example.net", FamilyV4, 0)
	obs := fixedObserver("203.0.113.5")

	// First pass: attempts a publish, fails, arms backoff.
	if err := m.Reconcile(context.Background(), []SurfaceAScope{sc}, obs, nil); err == nil {
		t.Fatal("expected a publish error on first pass")
	}
	attemptsAfterFirst := len(fu.upserts) // the fakeUpdater records nothing on failure
	_ = attemptsAfterFirst
	failCalls1 := fu.failedCalls
	// Second pass immediately after (still inside the backoff window): the
	// scope is SKIPPED, so the backend is NOT hit again (ban-avoidance).
	now = now.Add(time.Second)
	_ = m.Reconcile(context.Background(), []SurfaceAScope{sc}, obs, nil)
	if fu.failedCalls != failCalls1 {
		t.Fatalf("scope in backoff window must not hit the backend again; calls %d -> %d",
			failCalls1, fu.failedCalls)
	}
	if st := m.Stats(); st.BackedOff < 1 {
		t.Fatalf("expected a backed-off skip, got %+v", st)
	}
	// Well past the backoff window: the scope is eligible again and retries.
	now = now.Add(time.Hour)
	_ = m.Reconcile(context.Background(), []SurfaceAScope{sc}, obs, nil)
	if fu.failedCalls <= failCalls1 {
		t.Fatalf("after backoff window the scope must retry; calls stayed at %d", fu.failedCalls)
	}
}

func TestSurfaceAStatusViews(t *testing.T) {
	fu := newFakeUpdater()
	now := time.Unix(1_700_000_000, 0)
	m := newSurfaceATestManager(t, fu, func() time.Time { return now })
	sc := surfaceAScope("wan.example.net", FamilyV4, 0)
	if err := m.Reconcile(context.Background(), []SurfaceAScope{sc}, fixedObserver("203.0.113.5"), nil); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	views := m.StatusViews()
	if len(views) != 1 {
		t.Fatalf("expected one status view, got %d", len(views))
	}
	v := views[0]
	if v.FQDN != "wan.example.net" || v.Published != "203.0.113.5" ||
		v.Interface != "ge-0-0-2" || v.Family != 4 || v.Provider != "corp-2136" {
		t.Fatalf("status view mismatch: %+v", v)
	}
	if v.LastPublished.IsZero() {
		t.Fatal("status view must carry a last-published time")
	}
}
