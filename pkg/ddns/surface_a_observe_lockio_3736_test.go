package ddns

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

// surface_a_observe_lockio_3736_test.go: #3736 — the per-scope ADDRESS
// OBSERVATION (the checkip source performs a blocking external HTTP GET) must
// run with the manager mutex RELEASED and with the reconcile context threaded,
// the observation residual #2778 left behind. These are the fail-on-revert
// proofs: revert the observeIO lock-release and the "concurrent StatusViews/
// Stats proceed while observe is in flight" waits HANG; revert the ctx
// threading in reconcileScopeLocked and the ctx-cancel wait HANGS.

// blockingObserver signals entry on `entered` then blocks the observe call until
// `release` is closed (or the reconcile ctx is cancelled). Deterministic:
// channels, no sleeps. It mirrors blockingUpdater, but for the observe seam.
type blockingObserver struct {
	entered chan struct{}
	release chan struct{}
	addr    netip.Addr
}

func (b *blockingObserver) observe(ctx context.Context, _ SurfaceAScope) (AddressObservation, bool) {
	b.entered <- struct{}{}
	select {
	case <-b.release:
		return AddressObservation{Addr: b.addr, Source: AddressSourceDHCP}, true
	case <-ctx.Done():
		return AddressObservation{}, false
	}
}

// TestSurfaceALockNotHeldDuringObserve proves m.mu is released while the address
// observation is in flight (#3736). A blocking observer holds the observe call
// open (as a slow/black-holed checkip HTTP GET would); concurrently a
// StatusViews() and a Stats() call (both take m.mu) MUST complete. If the lock
// were held across the observation — the pre-#3736 behaviour — these reads block
// until release and the bounded waits fire t.Fatal (fail-on-revert).
func TestSurfaceALockNotHeldDuringObserve(t *testing.T) {
	fu := newFakeUpdater()
	now := time.Unix(1_700_000_000, 0)
	m := newSurfaceATestManager(t, fu, func() time.Time { return now })
	sc := surfaceAScope("wan.example.net", FamilyV4, 0)

	bo := &blockingObserver{
		entered: make(chan struct{}, 1),
		release: make(chan struct{}),
		addr:    netip.MustParseAddr("203.0.113.5"),
	}

	reconcileDone := make(chan struct{})
	go func() {
		_ = m.Reconcile(context.Background(), []SurfaceAScope{sc}, bo.observe, nil, nil)
		close(reconcileDone)
	}()

	// Wait until the observation is actually in flight (the lock, if held across
	// observe, would be held now).
	select {
	case <-bo.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("observer never started")
	}

	// While the observation is blocked, a StatusViews() (which takes m.mu) MUST
	// proceed. If the lock were held across the observation this read would block
	// and the bounded wait fires — the fail-on-revert assertion.
	statusDone := make(chan []SurfaceAStatusView, 1)
	go func() { statusDone <- m.StatusViews([]SurfaceAScope{sc}) }()
	select {
	case <-statusDone:
	case <-time.After(2 * time.Second):
		t.Fatal("StatusViews blocked while the address observation was in flight — lock held across observe (#3736 regression)")
	}

	// Same for Stats().
	statsDone := make(chan SurfaceAStats, 1)
	go func() { statsDone <- m.Stats() }()
	select {
	case <-statsDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Stats blocked while the address observation was in flight — lock held across observe (#3736 regression)")
	}

	// Release the observation and let the pass complete.
	close(bo.release)
	select {
	case <-reconcileDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Reconcile did not finish after the observer released")
	}

	// Happy path preserved: the observed address is still applied under the lock.
	ups := fu.upsertNames()
	if len(ups) != 1 || ups[0] != "wan.example.net=203.0.113.5" {
		t.Fatalf("expected the observed address to be published, got %v", ups)
	}
	if st := m.Stats(); st.UpsertOK != 1 || st.Scopes != 1 {
		t.Fatalf("stats after release: %+v", st)
	}
}

// TestSurfaceAObserveHonorsReconcileContextCancel proves the engine threads the
// reconcile/pass context into the observer (#3736) so a shutdown/pass-deadline
// cancel aborts an in-flight observation promptly instead of hanging. The
// observer returns ok=false (a transient miss) ONLY when it sees ctx.Done(); if
// reconcileScopeLocked passed context.Background() (or dropped the ctx) instead
// of the reconcile ctx, the cancel below would never reach the observer and
// Reconcile would hang — fail-on-revert.
func TestSurfaceAObserveHonorsReconcileContextCancel(t *testing.T) {
	fu := newFakeUpdater()
	now := time.Unix(1_700_000_000, 0)
	m := newSurfaceATestManager(t, fu, func() time.Time { return now })
	sc := surfaceAScope("wan.example.net", FamilyV4, 0)

	entered := make(chan struct{}, 1)
	observe := func(ctx context.Context, _ SurfaceAScope) (AddressObservation, bool) {
		entered <- struct{}{}
		<-ctx.Done()
		return AddressObservation{}, false
	}

	ctx, cancel := context.WithCancel(context.Background())
	reconcileDone := make(chan error, 1)
	go func() {
		reconcileDone <- m.Reconcile(ctx, []SurfaceAScope{sc}, observe, nil, nil)
	}()

	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("observer never started")
	}
	cancel()
	select {
	case err := <-reconcileDone:
		if err != nil {
			t.Fatalf("Reconcile after ctx cancel: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Reconcile did not observe the ctx cancel — engine did not thread the reconcile context into the observer (#3736 regression)")
	}

	// A ctx-cancelled transient observation (ok=false) must never touch the wire.
	if got := len(fu.upserts); got != 0 {
		t.Fatalf("a ctx-cancelled transient observation must not publish; got %d upserts", got)
	}
}
