package ddns

import (
	"context"
	"testing"
	"time"
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
		return []WireRRClaim{wireRRClaim("host-a.example.com", "A", "10.0.0.10")}
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
		return []WireRRClaim{wireRRClaim("other.example.com", "A", "10.9.9.9")}
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

// TestSurfaceATeardownSuppressedByLeaseCoowner_5748 is the fail-on-revert test for
// the SYMMETRIC direction (Surface A → lease): a Surface A router record publishes
// wan.example.net A 203.0.113.5, and a DHCP lease co-owns the IDENTICAL wire RR.
// When the Surface A binding is removed, its withdraw must NOT issue the wire
// DELETE — that would clobber the lease-owned RR.
//
// Fail-on-revert: neutralize the per-target leaseWireRRCoowner skip in
// withdrawOwnedLocked and the Surface A teardown issues a wire DELETE of
// wan.example.net A 203.0.113.5 — the "no delete" assertion goes RED.
func TestSurfaceATeardownSuppressedByLeaseCoowner_5748(t *testing.T) {
	fu := newFakeUpdater()
	now := time.Unix(1_700_000_000, 0)
	m := newSurfaceATestManager(t, fu, func() time.Time { return now })

	// A DHCP lease scope co-owns the SAME wire RR (rdata in Address on the lease
	// side); the injected accessor presents the normalized WireRRClaim (exactly what
	// Manager.WireRRClaims returns in production).
	m.SetLeaseCoownerSource(func() []WireRRClaim {
		return []WireRRClaim{wireRRClaim("wan.example.net", "A", "203.0.113.5")}
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

	// Phase 2: the binding is REMOVED → withdraw. The RR is still co-owned by the
	// DHCP lease, so NO wire delete may be issued.
	now = now.Add(time.Minute)
	fu.deletes = nil
	if err := m.Reconcile(context.Background(), []SurfaceAScope{}, obs, nil, nil); err != nil {
		t.Fatalf("phase 2 withdraw: %v", err)
	}

	// THE ASSERTION (RED pre-fix): no wire delete for the lease-co-owned RR.
	if names := fu.deleteNames(); len(names) != 0 {
		t.Fatalf("surface A teardown issued a wire DELETE for a lease-co-owned RR "+
			"(cross-surface clobber #5748): %v", names)
	}
	st := m.Stats()
	if st.DeleteCoowned != 1 {
		t.Fatalf("expected exactly one cross-surface suppression, got %+v", st)
	}
	// No real withdraw happened, so DeleteOK must not be inflated.
	if st.DeleteOK != 0 {
		t.Fatalf("no wire delete was issued; DeleteOK must stay 0, got %d", st.DeleteOK)
	}
	// The Surface A ownership claim is released; the RR is left live for the lease.
	if st.Scopes != 0 {
		t.Fatalf("surface A ownership must be released after suppression, got Scopes=%d", st.Scopes)
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
		return []WireRRClaim{wireRRClaim("other.example.net", "A", "198.51.100.7")}
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
