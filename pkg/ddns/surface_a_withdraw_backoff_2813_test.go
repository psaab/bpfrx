package ddns

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// #2813: a persistently-failing Surface A WITHDRAW must participate in the SAME
// per-scope error-backoff machinery the publish path uses, instead of
// re-attempting (and warning) on every 30s reconcile sweep. These are the
// fail-on-revert proofs: removing the withdraw-path backoff arming makes
// TestSurfaceAWithdrawBacksOff* go RED (the backend is re-hit every sweep).

// genericDeleteUnsupportedUpdater upserts successfully but FAILS every delete
// with errGenericDeleteUnsupported — modelling the generic HTTP backend that
// has no portable withdraw verb (#2772/#2811). Used to prove the terminal
// (attempt-once) classification.
type genericDeleteUnsupportedUpdater struct {
	upserts int
	deletes int
}

func (u *genericDeleteUnsupportedUpdater) UpsertLease(_ context.Context, _ LeaseDNSRecord) error {
	u.upserts++
	return nil
}

func (u *genericDeleteUnsupportedUpdater) DeleteLease(_ context.Context, rec LeaseDNSRecord) error {
	u.deletes++
	return fmt.Errorf("generic: cannot withdraw %s: %w", rec.FQDN, errGenericDeleteUnsupported)
}

// publishOneScope publishes a scope so the manager owns a record for it, then
// returns the scope. Upserts succeed (failDel is set by the caller afterwards).
func publishOneScope(t *testing.T, m *SurfaceAManager) SurfaceAScope {
	t.Helper()
	sc := surfaceAScope("wan.example.net", FamilyV4, 0)
	if err := m.Reconcile(context.Background(), []SurfaceAScope{sc}, fixedObserver("203.0.113.5"), nil, nil); err != nil {
		t.Fatalf("initial publish Reconcile: %v", err)
	}
	if st := m.Stats(); st.Scopes != 1 || st.UpsertOK != 1 {
		t.Fatalf("expected one owned scope after publish, got %+v", st)
	}
	return sc
}

// TestSurfaceAWithdrawBacksOffGoneFromConfig drives the Pass-2 (binding removed
// from config) withdraw path. A delete that always fails must arm the per-scope
// backoff so the backend is NOT re-hit on every sweep — the attempt count over N
// sweeps is bounded by the doubling backoff schedule, not N.
func TestSurfaceAWithdrawBacksOffGoneFromConfig(t *testing.T) {
	fu := newFakeUpdater()
	now := time.Unix(1_700_000_000, 0)
	m := newSurfaceATestManager(t, fu, func() time.Time { return now })

	publishOneScope(t, m)
	// Now every delete fails (a persistently-failing provider withdraw).
	fu.failDel["wan.example.net"] = true

	const sweeps = 12
	for i := 0; i < sweeps; i++ {
		now = now.Add(surfaceABaseBackoff) // one 30s sweep
		// Empty config: the owned record is gone-from-config → Pass 2 withdraw.
		_ = m.Reconcile(context.Background(), nil, fixedObserver("203.0.113.5"), nil, nil)
	}

	// Without backoff the backend is hit on EVERY sweep (sweeps failed deletes).
	// With backoff (30s base, doubling) only a handful land inside the window.
	st := m.Stats()
	if fu.failedCalls >= sweeps {
		t.Fatalf("withdraw must back off, not re-attempt every sweep; got %d delete attempts over %d sweeps",
			fu.failedCalls, sweeps)
	}
	if fu.failedCalls == 0 {
		t.Fatalf("expected at least one withdraw attempt; got 0")
	}
	if st.BackedOff == 0 {
		t.Fatalf("expected backed-off skips to be counted; stats %+v", st)
	}
	// Ownership is KEPT for retry (a failing withdraw must not orphan the record).
	if st.Scopes != 1 {
		t.Fatalf("a failing withdraw must keep ownership; got %d scopes", st.Scopes)
	}
}

// TestSurfaceAWithdrawBacksOffAddressLoss drives the Pass-1 (address lost)
// withdraw path: the scope stays configured but its address is gone, so the
// engine withdraws. A failing delete must arm the same per-scope backoff.
func TestSurfaceAWithdrawBacksOffAddressLoss(t *testing.T) {
	fu := newFakeUpdater()
	now := time.Unix(1_700_000_000, 0)
	m := newSurfaceATestManager(t, fu, func() time.Time { return now })

	sc := publishOneScope(t, m)
	fu.failDel["wan.example.net"] = true

	// Observer now reports a definitive "no address" (ok=true, invalid Addr) →
	// the engine withdraws the previously-published record.
	lost := func(SurfaceAScope) (AddressObservation, bool) {
		return AddressObservation{Source: AddressSourceDHCP}, true
	}

	const sweeps = 12
	for i := 0; i < sweeps; i++ {
		now = now.Add(surfaceABaseBackoff)
		_ = m.Reconcile(context.Background(), []SurfaceAScope{sc}, lost, nil, nil)
	}

	st := m.Stats()
	if fu.failedCalls >= sweeps {
		t.Fatalf("address-loss withdraw must back off; got %d attempts over %d sweeps",
			fu.failedCalls, sweeps)
	}
	if fu.failedCalls == 0 {
		t.Fatalf("expected at least one withdraw attempt; got 0")
	}
	if st.BackedOff == 0 {
		t.Fatalf("expected backed-off skips to be counted; stats %+v", st)
	}
	if st.Scopes != 1 {
		t.Fatalf("a failing withdraw must keep ownership; got %d scopes", st.Scopes)
	}
}

// TestSurfaceAWithdrawRetriesAfterBackoffThenSucceeds proves the backoff does
// NOT over-suppress: a withdraw that fails transiently is retried after the
// backoff window and, once the backend recovers, succeeds and CLEARS the
// per-scope backoff state (the record is actually withdrawn — no leaked
// ownership).
func TestSurfaceAWithdrawRetriesAfterBackoffThenSucceeds(t *testing.T) {
	fu := newFakeUpdater()
	now := time.Unix(1_700_000_000, 0)
	m := newSurfaceATestManager(t, fu, func() time.Time { return now })

	publishOneScope(t, m)
	fu.failDel["wan.example.net"] = true

	// First gone-from-config sweep: attempt the withdraw, it fails, backoff armed.
	now = now.Add(surfaceABaseBackoff)
	_ = m.Reconcile(context.Background(), nil, fixedObserver("203.0.113.5"), nil, nil)
	if fu.failedCalls != 1 {
		t.Fatalf("expected one failed withdraw attempt, got %d", fu.failedCalls)
	}
	if got := len(fu.deletes); got != 0 {
		t.Fatalf("a failed withdraw records no successful delete; got %d", got)
	}

	// Immediately again (still inside the backoff window): the backend is NOT hit.
	now = now.Add(time.Second)
	_ = m.Reconcile(context.Background(), nil, fixedObserver("203.0.113.5"), nil, nil)
	if fu.failedCalls != 1 {
		t.Fatalf("scope in backoff window must not re-hit the backend; attempts %d", fu.failedCalls)
	}

	// The backend recovers; advance well past the backoff window.
	delete(fu.failDel, "wan.example.net")
	now = now.Add(time.Hour)
	if err := m.Reconcile(context.Background(), nil, fixedObserver("203.0.113.5"), nil, nil); err != nil {
		t.Fatalf("recovered withdraw Reconcile returned error: %v", err)
	}
	if got := len(fu.deletes); got != 1 {
		t.Fatalf("after backoff the withdraw must retry and succeed; got %d successful deletes", got)
	}
	// Success cleared ownership — the record is gone, not leaked.
	if st := m.Stats(); st.Scopes != 0 || st.DeleteOK != 1 {
		t.Fatalf("a successful withdraw must drop ownership; stats %+v", st)
	}
}

// TestSurfaceAWithdrawUnsupportedIsTerminal proves errGenericDeleteUnsupported is
// treated as terminal: the wire delete is attempted at MOST once and never
// retried (no per-sweep churn), while ownership is kept so the abandoned record
// stays operator-visible.
func TestSurfaceAWithdrawUnsupportedIsTerminal(t *testing.T) {
	up := &genericDeleteUnsupportedUpdater{}
	now := time.Unix(1_700_000_000, 0)
	m := newSurfaceATestManager(t, up, func() time.Time { return now })

	publishOneScope(t, m)

	const sweeps = 8
	for i := 0; i < sweeps; i++ {
		now = now.Add(surfaceABaseBackoff)
		_ = m.Reconcile(context.Background(), nil, fixedObserver("203.0.113.5"), nil, nil)
	}

	if up.deletes != 1 {
		t.Fatalf("an unsupported withdraw verb must be attempted at most once; got %d delete attempts", up.deletes)
	}
	// Ownership is kept (the abandoned RR stays operator-visible).
	if st := m.Stats(); st.Scopes != 1 {
		t.Fatalf("an unsupported withdraw must keep ownership; got %d scopes", st.Scopes)
	}
}
