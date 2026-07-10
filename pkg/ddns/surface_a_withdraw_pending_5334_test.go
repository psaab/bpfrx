package ddns

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

// surface_a_withdraw_pending_5334_test.go: #5334 fail-on-revert proofs for the
// Surface A withdraw-target selection on a crash-left PENDING record.
//
// ROOT CAUSE (#5334, follow-up to #5285/#5332): reconcileScopeLocked Pass 2's
// withdrawOwnedLocked deleted owned.AddrText unconditionally. But if the record
// is PublishPending at that moment — a crash left {AddrText=B (desired, NEVER
// reached the wire), PublishPending=true, PriorAddrText=A (live)} — the withdraw
// deleted B (which never reached public DNS) and left the LIVE prior value A
// ORPHANED in public DNS while xpf reported the scope withdrawn.
//
// FIX: when owned.PublishPending is set, withdrawOwnedLocked prefers
// PriorAddrText (the real live value A) as the delete target instead of AddrText
// (the desired-but-unpublished B), mirroring publishLocked. An empty prior (a
// first publish that never reached the wire) has nothing live to delete — the
// wire delete is skipped and only the on-disk state is cleaned up.

// crashState5334 drives a manager to a PENDING on-disk ownership row by publishing
// through the crash backend (panics mid-wire, after the durable write-ahead save),
// exactly the #5285 save->wire crash. It returns the persisted record so the
// caller can assert the pending shape before exercising the withdraw.
func crashState5334(t *testing.T, statePath string, sc SurfaceAScope, addr string, clock func() time.Time) {
	t.Helper()
	crash := &crashUpsertUpdater{}
	m := newSurfaceAManagerForTesting(statePath, crash, clock)
	func() {
		defer func() {
			if r := recover(); r == nil {
				t.Fatal("expected the crash backend to panic during the wire add")
			}
		}()
		_ = m.Reconcile(context.Background(), []SurfaceAScope{sc}, fixedObserver(addr), nil, nil)
	}()
	if !crash.called {
		t.Fatal("the crash backend's UpsertLease was never reached (write-ahead did not precede the wire)")
	}
}

// TestSurfaceAWithdrawPendingDeletesLivePrior is the #5334 fail-on-revert proof.
// A renumber A->B is killed mid-wire (pending {B, prior=A}, wire still at A); the
// binding is then REMOVED and a restart's Pass-2 withdraw MUST delete the LIVE
// value A (never the never-published desired B) so nothing is orphaned in public
// DNS, and the on-disk ownership record is cleared.
//
// RED-on-revert: restore the unconditional `netip.ParseAddr(owned.AddrText)`
// delete target and the withdraw deletes B (198.51.100.9) — A stays live and
// orphaned. The "wire delete targets A" assertion then fails.
func TestSurfaceAWithdrawPendingDeletesLivePrior(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "iface-ddns.json")
	now := time.Unix(1_700_000_000, 0)
	clock := func() time.Time { return now }

	const fqdn = "wan.example.net"
	const addrA = "203.0.113.5"
	const addrB = "198.51.100.9"
	sc := surfaceAScope(fqdn, FamilyV4, 0)

	// Boot 1: publish A -> CONFIRMED ownership {A}.
	fu1 := newFakeUpdater()
	m1 := newSurfaceAManagerForTesting(statePath, fu1, clock)
	if err := m1.Reconcile(context.Background(), []SurfaceAScope{sc}, fixedObserver(addrA), nil, nil); err != nil {
		t.Fatalf("boot1 publish A: %v", err)
	}

	// Boot 2: renumber A->B, CRASH mid-wire -> on-disk {B, pending, prior=A}; the
	// wire is still at A (the crash backend never applied B).
	now = now.Add(time.Hour)
	crashState5334(t, statePath, sc, addrB, clock)

	rec := onlyOwned5285(t, statePath)
	if !rec.PublishPending || rec.AddrText != addrB || rec.PriorAddrText != addrA {
		t.Fatalf("crash setup: want pending {AddrText=B, prior=A}, got %+v", rec)
	}

	// Boot 3: the binding is REMOVED (empty scopes) -> Pass-2 gone-from-config
	// withdraw. It MUST delete the LIVE prior A, never the never-published B.
	now = now.Add(time.Hour)
	fu3 := newFakeUpdater()
	m3 := newSurfaceAManagerForTesting(statePath, fu3, clock)
	if err := m3.Reconcile(context.Background(), nil, fixedObserver(addrA), nil, nil); err != nil {
		t.Fatalf("boot3 withdraw reconcile: %v", err)
	}

	dels := fu3.deleteNames()
	if len(dels) != 1 || dels[0] != fqdn+"="+addrA {
		t.Fatalf("pending withdraw must delete the LIVE prior A (%s=%s), got %v — "+
			"deleting AddrText=B orphans the live A in public DNS", fqdn, addrA, dels)
	}
	if st := m3.Stats(); st.DeleteOK != 1 || st.DeleteFail != 0 {
		t.Fatalf("withdraw stats: want DeleteOK=1 DeleteFail=0, got %+v", st)
	}
	// On-disk ownership cleared: the scope is genuinely withdrawn.
	if recs := readDurableOwnership(t, statePath); len(recs) != 0 {
		t.Fatalf("withdraw must clear the on-disk ownership record, got %d: %v", len(recs), recs)
	}
}

// TestSurfaceAWithdrawNonPendingUnchanged proves the ordinary (settled, non-
// pending) withdraw is unchanged: a confirmed {X} whose binding is removed is
// withdrawn by deleting X.
func TestSurfaceAWithdrawNonPendingUnchanged(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "iface-ddns.json")
	now := time.Unix(1_700_000_000, 0)
	clock := func() time.Time { return now }

	const fqdn = "wan.example.net"
	const addrX = "203.0.113.5"
	sc := surfaceAScope(fqdn, FamilyV4, 0)

	fu := newFakeUpdater()
	m := newSurfaceAManagerForTesting(statePath, fu, clock)
	if err := m.Reconcile(context.Background(), []SurfaceAScope{sc}, fixedObserver(addrX), nil, nil); err != nil {
		t.Fatalf("publish X: %v", err)
	}
	if rec := onlyOwned5285(t, statePath); rec.PublishPending || rec.AddrText != addrX {
		t.Fatalf("after X: want settled {X}, got %+v", rec)
	}

	// Remove the binding -> Pass-2 withdraw deletes X (existing behavior).
	now = now.Add(time.Hour)
	if err := m.Reconcile(context.Background(), nil, fixedObserver(addrX), nil, nil); err != nil {
		t.Fatalf("withdraw reconcile: %v", err)
	}
	dels := fu.deleteNames()
	if len(dels) != 1 || dels[0] != fqdn+"="+addrX {
		t.Fatalf("non-pending withdraw must delete X (%s=%s), got %v", fqdn, addrX, dels)
	}
	if recs := readDurableOwnership(t, statePath); len(recs) != 0 {
		t.Fatalf("withdraw must clear the on-disk ownership record, got %d: %v", len(recs), recs)
	}
}

// TestSurfaceAWithdrawPendingFirstPublishNoWireDelete proves the empty-prior
// case: a PENDING FIRST publish (AddrText=B, PublishPending=true, prior="") whose
// binding is removed has NOTHING live on the wire — B never reached the provider.
// The withdraw must issue NO wire delete of B (which would target a record that
// never existed), clear the on-disk state cleanly, and NOT error.
//
// RED-on-revert: restore the unconditional AddrText delete target and the
// withdraw issues a spurious DELETE of the never-published B — the "no wire
// delete" assertion then fails.
func TestSurfaceAWithdrawPendingFirstPublishNoWireDelete(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "iface-ddns.json")
	now := time.Unix(1_700_000_000, 0)
	clock := func() time.Time { return now }

	const fqdn = "wan.example.net"
	const addrB = "198.51.100.9"
	sc := surfaceAScope(fqdn, FamilyV4, 0)

	// Boot 1: FIRST publish of B, crash mid-wire -> on-disk {B, pending, prior=""}.
	// No prior confirmed value existed, so nothing is live at the provider.
	crashState5334(t, statePath, sc, addrB, clock)
	rec := onlyOwned5285(t, statePath)
	if !rec.PublishPending || rec.AddrText != addrB || rec.PriorAddrText != "" {
		t.Fatalf("crash setup: want pending first-publish {AddrText=B, prior=\"\"}, got %+v", rec)
	}

	// Boot 2: the binding is removed -> Pass-2 withdraw. Nothing is live, so no
	// wire delete is issued; the on-disk state is cleared and no error surfaces.
	now = now.Add(time.Hour)
	fu2 := newFakeUpdater()
	m2 := newSurfaceAManagerForTesting(statePath, fu2, clock)
	if err := m2.Reconcile(context.Background(), nil, fixedObserver(addrB), nil, nil); err != nil {
		t.Fatalf("withdraw reconcile must not error on an empty-prior pending record: %v", err)
	}
	if dels := fu2.deleteNames(); len(dels) != 0 {
		t.Fatalf("empty-prior pending withdraw must issue NO wire delete (nothing was published), got %v", dels)
	}
	if st := m2.Stats(); st.DeleteFail != 0 {
		t.Fatalf("empty-prior pending withdraw must not count a delete failure, got %+v", st)
	}
	if recs := readDurableOwnership(t, statePath); len(recs) != 0 {
		t.Fatalf("withdraw must clear the on-disk ownership record, got %d: %v", len(recs), recs)
	}
}
