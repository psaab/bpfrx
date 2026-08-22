package ddns

import (
	"context"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// #5748 cross-surface wire-RR clobber guard tests.
//
// #5709 added the wireRRSharedWithOther co-ownership guard so a DHCP-lease
// (Surface B) teardown does not delete a wire RR another lease scope still
// co-owns. That guard scanned ONLY the lease store (m.state.records). Router /
// interface DDNS records live in a SEPARATE ownership surface (Surface A,
// SurfaceAManager, rdata in AddrText not Address). A Surface A record and a
// Surface B lease can resolve the SAME host to the SAME address and thus co-own
// ONE wire RR — but the #5709 guard could not see the other surface, so a
// teardown on either surface could still CLOBBER the identical RR the other
// surface owns and refreshes. #5748 extends the guard across BOTH surfaces via a
// LOCK-FREE claim-snapshot accessor the daemon injects in each direction.
//
// These are the fail-on-revert proofs. They assert on the WIRE DELETE
// disposition (the fakeUpdater's recorded deletes), not merely an internal flag.
// The Surface-B-to-Surface-B #5709 guard itself stays covered by
// TestCoOwnedWireRRSurvivesOtherScopeTeardown (scope_test.go), which runs with a
// nil cross-surface accessor and therefore also guards that the pre-#5748
// Surface-B path is unchanged (regression (ii)).

// TestLeaseTeardownSuppressedBySurfaceACoowner_5748 is the primary fail-on-revert
// test for the lease→Surface-A direction: a DHCP lease publishes
// host-a.example.com A 10.0.0.10, and a Surface A router record co-owns the
// IDENTICAL wire RR. When the lease expires, its teardown must NOT issue the wire
// DELETE — that would clobber the Surface-A-owned RR.
//
// Fail-on-revert: neutralize the cross-surface arm of wireRRSharedWithOther (drop
// the m.surfaceACoowners scan) and the lease teardown reconstructs
// host-a.example.com A 10.0.0.10 from its expiring owned record and issues a wire
// DELETE — the "no delete" assertion below then goes RED.
func TestLeaseTeardownSuppressedBySurfaceACoowner_5748(t *testing.T) {
	up := newFakeUpdater()
	m := testDDNS(t, up)
	pol := enabledPolicy()

	// A Surface A router record co-owns the SAME wire RR. On the Surface A side its
	// rdata lives in AddrText; the injected accessor presents the already-normalized
	// WireRRClaim the lease guard consults (exactly what SurfaceAManager.WireRRClaims
	// returns in production).
	m.surfaceACoowners = func() []WireRRClaim {
		return []WireRRClaim{wireRRClaim("host-a.example.com", "A", "10.0.0.10", "")}
	}

	// Phase 1: publish + own the lease record.
	if err := runReconcile(t, m, pol, []Lease{leaseV4("10.0.0.10", "mac:aa", "host-a")}); err != nil {
		t.Fatalf("phase 1 reconcile: %v", err)
	}
	if n := len(m.state.records); n != 1 {
		t.Fatalf("phase 1: lease record must be owned, got %d", n)
	}
	up.upserts = nil
	up.deletes = nil

	// Phase 2: the lease disappears (expiry) → teardown. The wire RR is still
	// co-owned by the Surface A record, so NO wire delete may be issued.
	if err := runReconcile(t, m, pol, nil); err != nil {
		t.Fatalf("phase 2 reconcile: %v", err)
	}

	// THE ASSERTION (RED pre-fix): no wire delete for the Surface-A-co-owned RR.
	if names := up.deleteNames(); len(names) != 0 {
		t.Fatalf("lease teardown issued a wire DELETE for a Surface-A-co-owned RR "+
			"(cross-surface clobber #5748): %v", names)
	}
	// The suppression is observable and reuses the #5709 counter.
	if got := m.deleteCoowned.Load(); got != 1 {
		t.Fatalf("expected exactly one cross-surface co-owned suppression, got %d", got)
	}
	// The lease's own ownership claim is released; the RR is left live for Surface A.
	if n := len(m.state.records); n != 0 {
		t.Fatalf("lease ownership claim must be released after suppression, got %d", n)
	}
}

// TestLeaseTeardownNoCoownerStillDeletes_5748 is regression guard (i): a lease
// teardown with NO co-owner on EITHER surface still issues the wire DELETE (no
// over-suppression → no stale RR left on the wire). The accessor is wired but
// returns a NON-matching claim, so the cross-surface arm must not fire.
func TestLeaseTeardownNoCoownerStillDeletes_5748(t *testing.T) {
	up := newFakeUpdater()
	m := testDDNS(t, up)
	pol := enabledPolicy()
	// A Surface A record exists, but for a DIFFERENT name/address — not a co-owner.
	m.surfaceACoowners = func() []WireRRClaim {
		return []WireRRClaim{wireRRClaim("other.example.com", "A", "10.9.9.9", "")}
	}

	if err := runReconcile(t, m, pol, []Lease{leaseV4("10.0.0.10", "mac:aa", "host-a")}); err != nil {
		t.Fatalf("phase 1 reconcile: %v", err)
	}
	up.deletes = nil
	if err := runReconcile(t, m, pol, nil); err != nil {
		t.Fatalf("phase 2 reconcile: %v", err)
	}

	if got := up.deleteNames(); !equalStr(got, []string{"host-a.example.com=10.0.0.10"}) {
		t.Fatalf("a lease teardown with NO co-owner must issue the wire delete; got %v", got)
	}
	if got := m.deleteCoowned.Load(); got != 0 {
		t.Fatalf("no suppression expected without a co-owner, got %d", got)
	}
	if n := len(m.state.records); n != 0 {
		t.Fatalf("ownership must be cleared after a real withdraw, got %d", n)
	}
}

// TestLeaseTeardownNilSurfaceAAccessorDeletes_5748 is regression guard (iii): a
// nil Surface A accessor (not wired — standalone / test / pre-wire boot) behaves
// EXACTLY as pre-#5748: the lease teardown issues the wire DELETE and never
// panics.
func TestLeaseTeardownNilSurfaceAAccessorDeletes_5748(t *testing.T) {
	up := newFakeUpdater()
	m := testDDNS(t, up) // m.surfaceACoowners is nil (never wired)
	pol := enabledPolicy()

	if err := runReconcile(t, m, pol, []Lease{leaseV4("10.0.0.10", "mac:aa", "host-a")}); err != nil {
		t.Fatalf("phase 1 reconcile: %v", err)
	}
	up.deletes = nil
	if err := runReconcile(t, m, pol, nil); err != nil {
		t.Fatalf("phase 2 reconcile: %v", err)
	}

	if got := up.deleteNames(); !equalStr(got, []string{"host-a.example.com=10.0.0.10"}) {
		t.Fatalf("nil Surface A accessor must behave as pre-#5748 (delete issued); got %v", got)
	}
	if got := m.deleteCoowned.Load(); got != 0 {
		t.Fatalf("nil accessor must never suppress, got %d", got)
	}
}

// TestSurfaceATeardownDefersToLeaseCoowner_5748_6015 is the fail-on-revert test for
// the SYMMETRIC direction (Surface A → lease) under the #6015 deterministic
// tie-break: a Surface A router record publishes wan.example.net A 203.0.113.5, and
// a DHCP lease co-owns the IDENTICAL wire RR. When the Surface A binding is removed,
// its withdraw must NOT issue the wire DELETE — that would clobber the lease-owned
// RR (the #6012 protection). Under #6015 Surface A is the NON-AUTHORITY, so rather
// than suppress-and-RELEASE (like the lease side) it DEFERS: it RE-ASSERTS (re-UPSERTs)
// the RR and KEEPS its ownership claim until the lease authority releases.
//
// Fail-on-revert (the #6012 caution): make the leaseWireRRCoowner branch DELETE
// instead of defer (the naive "A always deletes") and the Surface A teardown issues a
// wire DELETE of wan.example.net A 203.0.113.5 — the "no delete" assertion goes RED,
// i.e. A clobbers the lease-owned RR.
func TestSurfaceATeardownDefersToLeaseCoowner_5748_6015(t *testing.T) {
	fu := newFakeUpdater()
	now := time.Unix(1_700_000_000, 0)
	m := newSurfaceATestManager(t, fu, func() time.Time { return now })

	// A DHCP lease scope co-owns the SAME wire RR (rdata in Address on the lease
	// side); the injected accessor presents the normalized WireRRClaim (exactly what
	// Manager.WireRRClaims returns in production).
	m.SetLeaseCoownerSource(func() []WireRRClaim {
		return []WireRRClaim{wireRRClaim("wan.example.net", "A", "203.0.113.5", "")}
	})

	sc := surfaceAScope("wan.example.net", FamilyV4, 0)
	obs := fixedObserver("203.0.113.5")

	// Phase 1: publish the Surface A record.
	if err := m.Reconcile(context.Background(), []SurfaceAScope{sc}, obs, nil, nil); err != nil {
		t.Fatalf("phase 1 publish: %v", err)
	}
	if st := m.Stats(); st.Scopes != 1 || st.UpsertOK != 1 {
		t.Fatalf("phase 1 stats: %+v", st)
	}
	fu.upserts = nil

	// Phase 2: the binding is REMOVED → withdraw. The RR is still co-owned by the
	// DHCP lease, so NO wire delete may be issued.
	now = now.Add(time.Minute)
	fu.deletes = nil
	if err := m.Reconcile(context.Background(), []SurfaceAScope{}, obs, nil, nil); err != nil {
		t.Fatalf("phase 2 withdraw: %v", err)
	}

	// THE #6012 CAUTION ASSERTION (RED on the naive "A always deletes"): no wire
	// delete for the lease-co-owned RR — Surface A never clobbers a lease-owned RR.
	if names := fu.deleteNames(); len(names) != 0 {
		t.Fatalf("surface A teardown issued a wire DELETE for a lease-co-owned RR "+
			"(cross-surface clobber #5748/#6015 caution): %v", names)
	}
	st := m.Stats()
	if st.DeleteCoowned != 1 {
		t.Fatalf("expected exactly one cross-surface deferral, got %+v", st)
	}
	// No real withdraw happened, so DeleteOK must not be inflated.
	if st.DeleteOK != 0 {
		t.Fatalf("no wire delete was issued; DeleteOK must stay 0, got %d", st.DeleteOK)
	}
	// #6015: the non-authority DEFERS — it KEEPS its ownership claim (does NOT
	// release) so the RR can never be orphaned by a simultaneous lease teardown.
	if st.Scopes != 1 {
		t.Fatalf("surface A (non-authority) must KEEP its claim (deferred), got Scopes=%d", st.Scopes)
	}
	// #6015: the non-authority RE-ASSERTS (re-UPSERTs) the RR so a leaked RR
	// self-heals.
	if got := fu.upsertNames(); !equalStr(got, []string{"wan.example.net=203.0.113.5"}) {
		t.Fatalf("surface A must re-assert the co-owned RR (self-heal); got upserts %v", got)
	}
}

// TestCrossSurfaceMutualTeardownNotOrphaned_6015 is the primary fail-on-revert
// proof for window (b): BOTH surfaces tear down the SAME co-owned wire RR in
// overlapping passes, each reading the OTHER's pre-rebuild snapshot (still listing
// the RR owned). Without a deterministic tie-break both suppress-and-release → the
// RR is left on the wire UNOWNED (orphaned). With the #6015 tie-break exactly one
// deterministic outcome holds: the lease Manager (Surface B, AUTHORITY) releases and
// the SurfaceAManager (Surface A, NON-AUTHORITY) DEFERS — it keeps its claim and
// re-asserts — so the RR remains owned by exactly one surface and is never orphaned.
//
// Fail-on-revert: make Surface A's leaseWireRRCoowner branch suppress-and-RELEASE
// (drop the claim, the pre-#6015 behavior) and after both tear down NEITHER surface
// owns the RR → orphaned → the "still owned by Surface A" assertion goes RED.
func TestCrossSurfaceMutualTeardownNotOrphaned_6015(t *testing.T) {
	// The single co-owned wire RR both surfaces publish.
	const fqdn = "shared.example.net"
	const rdata = "203.0.113.9"

	// ---- Surface B: the lease Manager ----
	up := newFakeUpdater()
	b := testDDNS(t, up)
	// Surface A's PRE-REBUILD snapshot still lists the co-owned RR (frozen to model
	// the overlapping-pass race: B reads A's snapshot before A rebuilds it).
	b.surfaceACoowners = func() []WireRRClaim {
		return []WireRRClaim{wireRRClaim(fqdn, "A", rdata, "")}
	}

	// ---- Surface A: the SurfaceAManager ----
	fu := newFakeUpdater()
	now := time.Unix(1_700_000_000, 0)
	a := newSurfaceATestManager(t, fu, func() time.Time { return now })
	// Surface B's PRE-REBUILD snapshot still lists the co-owned RR (the symmetric
	// frozen snapshot: A reads B's snapshot before B rebuilds it).
	a.SetLeaseCoownerSource(func() []WireRRClaim {
		return []WireRRClaim{wireRRClaim(fqdn, "A", rdata, "")}
	})

	// Phase 1 — both surfaces publish + own the SAME RR. The lease host is the
	// leftmost label and the policy Domain is the zone, so host "shared" + Domain
	// "example.net" resolves to shared.example.net — the SAME name Surface A owns.
	polLease := policyFromConfig(&config.DHCPDynamicDNSConfig{
		Enabled: true, Domain: "example.net", TTLSeconds: 300,
	})
	if err := runReconcile(t, b, polLease, []Lease{leaseV4(rdata, "mac:bb", "shared")}); err != nil {
		t.Fatalf("surface B publish: %v", err)
	}
	if n := len(b.state.records); n != 1 {
		t.Fatalf("surface B must own the lease RR, got %d", n)
	}
	scA := surfaceAScope(fqdn, FamilyV4, 0)
	obs := fixedObserver(rdata)
	if err := a.Reconcile(context.Background(), []SurfaceAScope{scA}, obs, nil, nil); err != nil {
		t.Fatalf("surface A publish: %v", err)
	}
	if st := a.Stats(); st.Scopes != 1 {
		t.Fatalf("surface A must own the RR, got Scopes=%d", st.Scopes)
	}

	// Phase 2 — BOTH tear down the SAME RR in overlapping passes, each seeing the
	// peer's frozen (pre-rebuild) snapshot.
	up.deletes = nil
	fu.deletes = nil
	fu.upserts = nil
	now = now.Add(time.Minute)
	// Surface B tears down: its lease is gone. It is the AUTHORITY → suppress + RELEASE.
	if err := runReconcile(t, b, polLease, nil); err != nil {
		t.Fatalf("surface B teardown: %v", err)
	}
	// Surface A tears down: its binding is gone. It is the NON-AUTHORITY → DEFER
	// (keep claim + re-assert), NEVER release-and-forget.
	if err := a.Reconcile(context.Background(), []SurfaceAScope{}, obs, nil, nil); err != nil {
		t.Fatalf("surface A teardown: %v", err)
	}

	// Surface B (authority) released its claim (unchanged #6012).
	if n := len(b.state.records); n != 0 {
		t.Fatalf("surface B (authority) must release its claim, got %d owned", n)
	}
	// THE WINDOW-(b) ASSERTION (RED pre-fix): after both tore down the RR must NOT
	// be orphaned. Surface A (non-authority) still owns it (deferred) → not orphaned.
	// Revert the tie-break (A releases too) → Scopes==0 → this fails RED.
	if st := a.Stats(); st.Scopes != 1 {
		t.Fatalf("window (b): co-owned RR left ORPHANED — the non-authority must KEEP "+
			"its claim after a simultaneous teardown, got Scopes=%d", st.Scopes)
	}
	// Neither surface issued a wire DELETE (the RR is still valid on the wire).
	if names := up.deleteNames(); len(names) != 0 {
		t.Fatalf("surface B must not delete a co-owned RR, got %v", names)
	}
	if names := fu.deleteNames(); len(names) != 0 {
		t.Fatalf("surface A must not delete a co-owned RR, got %v", names)
	}
	// Surface A re-asserted the RR (self-heal).
	if got := fu.upsertNames(); !equalStr(got, []string{fqdn + "=" + rdata}) {
		t.Fatalf("surface A must re-assert the co-owned RR during the deferred teardown; got %v", got)
	}

	// Phase 3 — the lease authority has now RELEASED. Its rebuilt snapshot no longer
	// lists the RR, so Surface A's next teardown pass finds no co-owner and issues
	// the deterministic real delete + releases its claim. This closes the loop: the
	// RR is correctly REMOVED (not orphaned) once neither surface owns it.
	a.SetLeaseCoownerSource(func() []WireRRClaim { return nil })
	fu.deletes = nil
	now = now.Add(time.Minute)
	if err := a.Reconcile(context.Background(), []SurfaceAScope{}, obs, nil, nil); err != nil {
		t.Fatalf("surface A final teardown: %v", err)
	}
	if got := fu.deleteNames(); !contains(got, fqdn+"="+rdata) {
		t.Fatalf("once the lease authority released, surface A must issue the real delete; got %v", got)
	}
	if st := a.Stats(); st.Scopes != 0 {
		t.Fatalf("surface A must release after the lease authority is gone, got Scopes=%d", st.Scopes)
	}
}

// TestSurfaceATeardownNoLeaseCoownerStillDeletes_5748 is the symmetric regression
// guard: a Surface A teardown with NO lease co-owner still issues the wire DELETE
// (and a nil lease accessor never panics — the accessor here returns a
// non-matching claim, and the nil-accessor path is covered by every pre-existing
// surface_a withdraw test which never wires a lease source).
func TestSurfaceATeardownNoLeaseCoownerStillDeletes_5748(t *testing.T) {
	fu := newFakeUpdater()
	now := time.Unix(1_700_000_000, 0)
	m := newSurfaceATestManager(t, fu, func() time.Time { return now })
	m.SetLeaseCoownerSource(func() []WireRRClaim {
		return []WireRRClaim{wireRRClaim("other.example.net", "A", "198.51.100.7", "")}
	})

	sc := surfaceAScope("wan.example.net", FamilyV4, 0)
	obs := fixedObserver("203.0.113.5")
	if err := m.Reconcile(context.Background(), []SurfaceAScope{sc}, obs, nil, nil); err != nil {
		t.Fatalf("phase 1 publish: %v", err)
	}
	now = now.Add(time.Minute)
	fu.deletes = nil
	if err := m.Reconcile(context.Background(), []SurfaceAScope{}, obs, nil, nil); err != nil {
		t.Fatalf("phase 2 withdraw: %v", err)
	}

	if got := fu.deleteNames(); !contains(got, "wan.example.net=203.0.113.5") {
		t.Fatalf("a surface A teardown with NO lease co-owner must issue the wire delete; got %v", got)
	}
	if st := m.Stats(); st.DeleteCoowned != 0 {
		t.Fatalf("no suppression expected without a lease co-owner, got %+v", st)
	}
}
