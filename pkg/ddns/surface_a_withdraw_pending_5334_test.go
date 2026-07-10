package ddns

import (
	"context"
	"net/netip"
	"path/filepath"
	"testing"
	"time"
)

// surface_a_withdraw_pending_5334_test.go: #5334 fail-on-revert proofs for the
// Surface A withdraw-target selection on a crash-left PENDING record.
//
// ROOT CAUSE (#5334, follow-up to #5285/#5332): reconcileScopeLocked Pass 2's
// withdrawOwnedLocked deleted owned.AddrText unconditionally. But a crash-left
// PENDING record {AddrText=B, PublishPending=true, PriorAddrText=A} is AMBIGUOUS
// about which value is live — publishLocked has TWO crash windows that produce
// the byte-identical on-disk shape:
//   - Window 1: crash BETWEEN the durable write-ahead save and the wire add — B
//     never reached the provider, so the CONFIRMED prior A is still live.
//   - Window 2: crash AFTER a SUCCESSFUL wire add but BEFORE the confirm-save
//     clears the pending bit — sendAddSelfOwned atomically removed A and inserted
//     B, so B is live and A is gone.
// Withdrawing EITHER single value orphans the other window's live RR.
//
// FIX: a pending withdraw issues an exact-RR delete of BOTH candidate rdata
// (AddrText AND PriorAddrText). A value-specific exact-RR delete of a non-live
// value is BENIGN (rfc2136 maps NXRrset/NameError to success), so the both-delete
// removes whichever value the crash left live and no-ops the other — the "delete
// the actually-live value" invariant holds regardless of the window. The
// non-pending path is unchanged (delete AddrText only).

// crashPending5334 drives a manager (crash backend) through one Reconcile that is
// expected to panic in the wire add — AFTER publishLocked's durable write-ahead
// save and BEFORE the wire add takes effect — leaving a PENDING record on disk,
// exactly as a hard kill in that window would.
func crashPending5334(t *testing.T, statePath string, scopes []SurfaceAScope, obs AddressObserver, clock func() time.Time) {
	t.Helper()
	crash := &crashUpsertUpdater{}
	m := newSurfaceAManagerForTesting(statePath, crash, clock)
	func() {
		defer func() {
			if r := recover(); r == nil {
				t.Fatal("expected the crash backend to panic during the wire add")
			}
		}()
		_ = m.Reconcile(context.Background(), scopes, obs, nil, nil)
	}()
	if !crash.called {
		t.Fatal("the crash backend's UpsertLease was never reached (write-ahead did not precede the wire)")
	}
}

// familyObserver returns a family-specific address so a v4 and a v6 scope can be
// driven in the same pass (fixedObserver returns one address for every scope).
func familyObserver(v4, v6 string) AddressObserver {
	a4 := netip.MustParseAddr(v4)
	a6 := netip.MustParseAddr(v6)
	return func(_ context.Context, sc SurfaceAScope) (AddressObservation, bool) {
		if sc.Key.Family == FamilyV6 {
			return AddressObservation{Addr: a6, Source: AddressSourceDHCP}, true
		}
		return AddressObservation{Addr: a4, Source: AddressSourceDHCP}, true
	}
}

// TestSurfaceAWithdrawPendingDeletesBothCandidates is the #5334 fail-on-revert
// proof for the crash-window ambiguity. A renumber A->B killed mid-wire leaves
// {AddrText=B, PublishPending=true, PriorAddrText=A}; the binding is then removed
// and a restart's Pass-2 withdraw MUST delete BOTH A and B so the actually-live
// value (A in window 1, B in window 2) is removed regardless of which window the
// crash fell in — nothing orphaned. The on-disk record is cleared.
//
// RED-on-revert: restore the single-target delete of owned.AddrText (original
// master) and only B is deleted -> the window-1 live A is orphaned; restore the
// prefer-PriorAddrText interim and only A is deleted -> the window-2 live B is
// orphaned. Either way the "delete BOTH" assertion below fails.
func TestSurfaceAWithdrawPendingDeletesBothCandidates(t *testing.T) {
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

	// Boot 2: renumber A->B, CRASH mid-wire -> on-disk {B, pending, prior=A}.
	now = now.Add(time.Hour)
	crashPending5334(t, statePath, []SurfaceAScope{sc}, fixedObserver(addrB), clock)
	rec := onlyOwned5285(t, statePath)
	if !rec.PublishPending || rec.AddrText != addrB || rec.PriorAddrText != addrA {
		t.Fatalf("crash setup: want pending {AddrText=B, prior=A}, got %+v", rec)
	}

	// Boot 3: the binding is REMOVED (nil scopes) -> Pass-2 withdraw deletes BOTH
	// candidates. The actually-live value is removed regardless of the crash window.
	now = now.Add(time.Hour)
	fu3 := newFakeUpdater()
	m3 := newSurfaceAManagerForTesting(statePath, fu3, clock)
	if err := m3.Reconcile(context.Background(), nil, fixedObserver(addrA), nil, nil); err != nil {
		t.Fatalf("boot3 withdraw reconcile: %v", err)
	}

	dels := fu3.deleteNames()
	if len(dels) != 2 || !contains(dels, fqdn+"="+addrA) || !contains(dels, fqdn+"="+addrB) {
		t.Fatalf("pending withdraw must delete BOTH crash-window candidates A(%s) and B(%s), got %v — "+
			"a single-value delete orphans the other window's live RR", addrA, addrB, dels)
	}
	if st := m3.Stats(); st.DeleteOK != 1 || st.DeleteFail != 0 {
		t.Fatalf("withdraw stats: want DeleteOK=1 DeleteFail=0, got %+v", st)
	}
	if recs := readDurableOwnership(t, statePath); len(recs) != 0 {
		t.Fatalf("withdraw must clear the on-disk ownership record, got %d: %v", len(recs), recs)
	}
}

// TestSurfaceAWithdrawPendingEmptyPriorDeletesLive is the strict-regression guard
// for the empty-prior case. A PENDING FIRST publish {AddrText=B, prior=""} that
// crashed AFTER the wire add (window 2) has B LIVE at the provider. The withdraw
// MUST delete B — never skip it. (Pre-#5334 deleted B correctly; the rejected
// prefer-prior interim SKIPPED it, orphaning the live B — a strict regression.)
//
// RED-on-revert: the prefer-prior interim skips the delete (no wire delete) and
// the "B deleted" assertion fails; the live B is orphaned.
func TestSurfaceAWithdrawPendingEmptyPriorDeletesLive(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "iface-ddns.json")
	now := time.Unix(1_700_000_000, 0)
	clock := func() time.Time { return now }

	const fqdn = "wan.example.net"
	const addrB = "198.51.100.9"
	sc := surfaceAScope(fqdn, FamilyV4, 0)

	// Boot 1: FIRST publish of B, crash mid-wire -> on-disk {B, pending, prior=""}.
	crashPending5334(t, statePath, []SurfaceAScope{sc}, fixedObserver(addrB), clock)
	rec := onlyOwned5285(t, statePath)
	if !rec.PublishPending || rec.AddrText != addrB || rec.PriorAddrText != "" {
		t.Fatalf("crash setup: want pending first-publish {AddrText=B, prior=\"\"}, got %+v", rec)
	}

	// Boot 2: the binding is removed -> Pass-2 withdraw deletes B (the only
	// candidate). If the crash was in window 2, B is live and this un-orphans it;
	// if it was in window 1, deleting B is a benign no-op.
	now = now.Add(time.Hour)
	fu2 := newFakeUpdater()
	m2 := newSurfaceAManagerForTesting(statePath, fu2, clock)
	if err := m2.Reconcile(context.Background(), nil, fixedObserver(addrB), nil, nil); err != nil {
		t.Fatalf("withdraw reconcile: %v", err)
	}
	dels := fu2.deleteNames()
	if len(dels) != 1 || dels[0] != fqdn+"="+addrB {
		t.Fatalf("empty-prior pending withdraw must delete the live B (%s=%s), got %v — "+
			"skipping it orphans the window-2 live B", fqdn, addrB, dels)
	}
	if st := m2.Stats(); st.DeleteOK != 1 || st.DeleteFail != 0 {
		t.Fatalf("withdraw stats: want DeleteOK=1 DeleteFail=0, got %+v", st)
	}
	if recs := readDurableOwnership(t, statePath); len(recs) != 0 {
		t.Fatalf("withdraw must clear the on-disk ownership record, got %d: %v", len(recs), recs)
	}
}

// TestSurfaceAWithdrawNonPendingUnchanged proves the settled (non-pending)
// withdraw is unchanged: a confirmed {X} whose binding is removed is withdrawn by
// deleting X and nothing else.
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

	now = now.Add(time.Hour)
	if err := m.Reconcile(context.Background(), nil, fixedObserver(addrX), nil, nil); err != nil {
		t.Fatalf("withdraw reconcile: %v", err)
	}
	dels := fu.deleteNames()
	if len(dels) != 1 || dels[0] != fqdn+"="+addrX {
		t.Fatalf("non-pending withdraw must delete exactly X (%s=%s), got %v", fqdn, addrX, dels)
	}
	if recs := readDurableOwnership(t, statePath); len(recs) != 0 {
		t.Fatalf("withdraw must clear the on-disk ownership record, got %d: %v", len(recs), recs)
	}
}

// TestSurfaceAWithdrawPendingV6DeletesBoth proves the both-delete on a v6 scope:
// a crash-left pending AAAA {B6, prior=A6} withdrawn deletes BOTH v6 candidates.
func TestSurfaceAWithdrawPendingV6DeletesBoth(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "iface-ddns.json")
	now := time.Unix(1_700_000_000, 0)
	clock := func() time.Time { return now }

	const fqdn = "wan6.example.net"
	const addrA = "2001:db8::5"
	const addrB = "2001:db8::9"
	sc := surfaceAScope(fqdn, FamilyV6, 0)

	fu1 := newFakeUpdater()
	m1 := newSurfaceAManagerForTesting(statePath, fu1, clock)
	if err := m1.Reconcile(context.Background(), []SurfaceAScope{sc}, fixedObserver(addrA), nil, nil); err != nil {
		t.Fatalf("boot1 publish A6: %v", err)
	}
	now = now.Add(time.Hour)
	crashPending5334(t, statePath, []SurfaceAScope{sc}, fixedObserver(addrB), clock)
	if rec := onlyOwned5285(t, statePath); !rec.PublishPending || rec.AddrText != addrB || rec.PriorAddrText != addrA {
		t.Fatalf("crash setup: want pending v6 {AddrText=B6, prior=A6}, got %+v", rec)
	}

	now = now.Add(time.Hour)
	fu3 := newFakeUpdater()
	m3 := newSurfaceAManagerForTesting(statePath, fu3, clock)
	if err := m3.Reconcile(context.Background(), nil, fixedObserver(addrA), nil, nil); err != nil {
		t.Fatalf("boot3 v6 withdraw: %v", err)
	}
	dels := fu3.deleteNames()
	if len(dels) != 2 || !contains(dels, fqdn+"="+addrA) || !contains(dels, fqdn+"="+addrB) {
		t.Fatalf("pending v6 withdraw must delete BOTH candidates A6(%s) and B6(%s), got %v", addrA, addrB, dels)
	}
	if recs := readDurableOwnership(t, statePath); len(recs) != 0 {
		t.Fatalf("withdraw must clear the on-disk ownership record, got %d: %v", len(recs), recs)
	}
}

// TestSurfaceAWithdrawPendingPreservesSibling proves the both-delete of a pending
// v4 scope still carries SiblingFamilyOwned=true when a live v6 sibling shares the
// name+provider — so a host-granular backend (DuckDNS/dyndns2) suppresses its
// whole-host destructive verb and the live sibling is preserved (#3738) — and the
// v6 ownership record is NOT touched by the v4 withdraw.
func TestSurfaceAWithdrawPendingPreservesSibling(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "iface-ddns.json")
	now := time.Unix(1_700_000_000, 0)
	clock := func() time.Time { return now }

	const fqdn = "dual.example.net"
	const a4 = "203.0.113.5"
	const b4 = "198.51.100.9"
	const a6 = "2001:db8::5"
	scV4 := surfaceAScope(fqdn, FamilyV4, 0)
	scV6 := surfaceAScope(fqdn, FamilyV6, 0)

	// Boot 1: publish BOTH families -> settled {A4}, {A6}.
	fu1 := newFakeUpdater()
	m1 := newSurfaceAManagerForTesting(statePath, fu1, clock)
	if err := m1.Reconcile(context.Background(), []SurfaceAScope{scV4, scV6}, familyObserver(a4, a6), nil, nil); err != nil {
		t.Fatalf("boot1 publish v4+v6: %v", err)
	}

	// Boot 2: renumber v4 A4->B4 with the v6 unchanged; crash mid-wire on v4 ->
	// on-disk {v4 pending B4 prior=A4, v6 settled A6}.
	now = now.Add(time.Hour)
	crashPending5334(t, statePath, []SurfaceAScope{scV4, scV6}, familyObserver(b4, a6), clock)

	// Boot 3: the v4 binding is removed, v6 stays configured -> Pass-2 withdraw of
	// the pending v4 deletes BOTH v4 candidates, each flagged SiblingFamilyOwned
	// (the live v6 sibling), and leaves the v6 ownership record intact.
	now = now.Add(time.Hour)
	fu3 := newFakeUpdater()
	m3 := newSurfaceAManagerForTesting(statePath, fu3, clock)
	if err := m3.Reconcile(context.Background(), []SurfaceAScope{scV6}, familyObserver(b4, a6), nil, nil); err != nil {
		t.Fatalf("boot3 v4 withdraw (v6 kept): %v", err)
	}

	dels := fu3.deleteNames()
	if len(dels) != 2 || !contains(dels, fqdn+"="+a4) || !contains(dels, fqdn+"="+b4) {
		t.Fatalf("pending v4 withdraw must delete BOTH v4 candidates A4(%s) and B4(%s), got %v", a4, b4, dels)
	}
	for _, d := range fu3.deletes {
		if !d.SiblingFamilyOwned {
			t.Fatalf("every v4 withdraw delete must carry SiblingFamilyOwned=true (live v6 sibling), got %+v", d)
		}
	}
	// The v6 record survives; only the v4 record is gone.
	recs := readDurableOwnership(t, statePath)
	if len(recs) != 1 {
		t.Fatalf("v4 withdraw must leave exactly the v6 record, got %d: %v", len(recs), recs)
	}
	for _, r := range recs {
		if r.Family != 6 {
			t.Fatalf("surviving record must be the v6 sibling, got %+v", r)
		}
	}
}
