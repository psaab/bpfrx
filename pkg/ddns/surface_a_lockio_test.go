package ddns

import (
	"context"
	"sync"
	"testing"
	"time"
)

// surface_a_lockio_test.go: #2778 — Surface A must NOT hold its manager mutex
// across provider network I/O (UpsertLease/DeleteLease run with a 15s client
// timeout). A slow/hung provider must not block StatusViews/Stats/other-scope
// reconcile work. These are the fail-on-revert proofs: if the lock-release is
// reverted (I/O performed under the lock again), the "concurrent op proceeds
// while I/O is blocked" assertions HANG and the bounded waits fire t.Fatal.

// blockingUpdater blocks every UpsertLease/DeleteLease until released, signaling
// entry on `entered` so the test knows the wire op is in flight (and thus the
// lock, if held, would be held now). Deterministic: channels, no sleeps.
type blockingUpdater struct {
	entered chan struct{} // closed-style signal: one send per call entry
	release chan struct{} // the call returns once this is closed
	mu      sync.Mutex
	upserts int
	deletes int
}

func newBlockingUpdater() *blockingUpdater {
	return &blockingUpdater{
		entered: make(chan struct{}, 8),
		release: make(chan struct{}),
	}
}

func (b *blockingUpdater) UpsertLease(ctx context.Context, _ LeaseDNSRecord) error {
	b.mu.Lock()
	b.upserts++
	b.mu.Unlock()
	b.entered <- struct{}{}
	select {
	case <-b.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (b *blockingUpdater) DeleteLease(ctx context.Context, _ LeaseDNSRecord) error {
	b.mu.Lock()
	b.deletes++
	b.mu.Unlock()
	b.entered <- struct{}{}
	select {
	case <-b.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// TestSurfaceALockNotHeldDuringUpsert proves m.mu is released while the provider
// UpsertLease is in flight (#2778). A blocking provider holds the wire op open;
// concurrently a StatusViews() call must complete (it takes m.mu). If the lock
// were held across the I/O, StatusViews would block until release and the
// bounded wait below would fire — fail-on-revert.
func TestSurfaceALockNotHeldDuringUpsert(t *testing.T) {
	bu := newBlockingUpdater()
	now := time.Unix(1_700_000_000, 0)
	m := newSurfaceATestManager(t, bu, func() time.Time { return now })
	sc := surfaceAScope("wan.example.net", FamilyV4, 0)

	reconcileDone := make(chan struct{})
	go func() {
		_ = m.Reconcile(context.Background(), []SurfaceAScope{sc}, fixedObserver("203.0.113.5"), nil, nil)
		close(reconcileDone)
	}()

	// Wait until the provider Upsert is actually in flight (wire op open).
	select {
	case <-bu.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("provider UpsertLease never started")
	}

	// While the wire op is blocked, a StatusViews() (which takes m.mu) MUST
	// proceed. If the lock were held across the I/O this read would block and the
	// bounded wait fires — the fail-on-revert assertion.
	statusDone := make(chan []SurfaceAStatusView, 1)
	go func() { statusDone <- m.StatusViews() }()
	select {
	case <-statusDone:
		// good: the lock was free during provider I/O.
	case <-time.After(2 * time.Second):
		t.Fatal("StatusViews blocked while provider UpsertLease was in flight — lock held across I/O (#2778 regression)")
	}

	// Same for Stats().
	statsDone := make(chan SurfaceAStats, 1)
	go func() { statsDone <- m.Stats() }()
	select {
	case <-statsDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Stats blocked while provider UpsertLease was in flight — lock held across I/O (#2778 regression)")
	}

	close(bu.release)
	select {
	case <-reconcileDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Reconcile did not finish after provider released")
	}
	if bu.upserts != 1 {
		t.Fatalf("expected exactly one upsert, got %d", bu.upserts)
	}
	if st := m.Stats(); st.UpsertOK != 1 {
		t.Fatalf("expected UpsertOK=1 after release, got %+v", st)
	}
}

// TestSurfaceALockNotHeldDuringDelete proves m.mu is released while a withdraw's
// provider DeleteLease is in flight (#2778). First publish a record, then drive
// a withdraw (binding removed from config → Pass 2 delete) while the provider
// delete blocks; a concurrent StatusViews must proceed.
func TestSurfaceALockNotHeldDuringDelete(t *testing.T) {
	bu := newBlockingUpdater()
	now := time.Unix(1_700_000_000, 0)
	m := newSurfaceATestManager(t, bu, func() time.Time { return now })
	sc := surfaceAScope("wan.example.net", FamilyV4, 0)

	// Publish once (let it through immediately).
	pubDone := make(chan struct{})
	go func() {
		_ = m.Reconcile(context.Background(), []SurfaceAScope{sc}, fixedObserver("203.0.113.5"), nil, nil)
		close(pubDone)
	}()
	<-bu.entered
	close(bu.release)
	<-pubDone

	// Re-arm the release gate for the delete pass.
	bu.release = make(chan struct{})

	// Now reconcile with NO scopes → the owned record is withdrawn (Pass 2).
	withdrawDone := make(chan struct{})
	go func() {
		_ = m.Reconcile(context.Background(), nil, fixedObserver("203.0.113.5"), nil, nil)
		close(withdrawDone)
	}()
	select {
	case <-bu.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("provider DeleteLease never started")
	}

	statusDone := make(chan []SurfaceAStatusView, 1)
	go func() { statusDone <- m.StatusViews() }()
	select {
	case <-statusDone:
	case <-time.After(2 * time.Second):
		t.Fatal("StatusViews blocked while provider DeleteLease was in flight — lock held across I/O (#2778 regression)")
	}

	close(bu.release)
	select {
	case <-withdrawDone:
	case <-time.After(2 * time.Second):
		t.Fatal("withdraw Reconcile did not finish after provider released")
	}
	if bu.deletes != 1 {
		t.Fatalf("expected exactly one delete, got %d", bu.deletes)
	}
	if st := m.Stats(); st.DeleteOK != 1 || st.Scopes != 0 {
		t.Fatalf("expected DeleteOK=1 and no owned scopes after withdraw, got %+v", st)
	}
}

// raceUpsertUpdater blocks the FIRST UpsertLease until released (so the test can
// mutate state while the lock is free during the I/O), and lets every later call
// through. It records every published address in order.
type raceUpsertUpdater struct {
	mu        sync.Mutex
	entered   chan struct{}
	release   chan struct{}
	calls     int
	published []string
}

func newRaceUpsertUpdater() *raceUpsertUpdater {
	return &raceUpsertUpdater{
		entered: make(chan struct{}, 8),
		release: make(chan struct{}),
	}
}

func (r *raceUpsertUpdater) UpsertLease(ctx context.Context, rec LeaseDNSRecord) error {
	r.mu.Lock()
	r.calls++
	first := r.calls == 1
	r.published = append(r.published, rec.Addr.String())
	r.mu.Unlock()
	if first {
		r.entered <- struct{}{}
		select {
		case <-r.release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

func (r *raceUpsertUpdater) DeleteLease(_ context.Context, _ LeaseDNSRecord) error { return nil }

func (r *raceUpsertUpdater) addrs() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.published))
	copy(out, r.published)
	return out
}

// TestSurfaceAPublishRaceDoesNotClobberNewerState proves the racing-reconcile
// guard (#2778): when the lock is released during the wire UpsertLease and a
// concurrent op changes the scope's owned record, the stale wire result must NOT
// clobber the newer desired state.
//
// Sequence:
//  1. Reconcile #1 publishes addr A; its wire UpsertLease BLOCKS (lock free).
//  2. While blocked, a second goroutine runs Reconcile #2 observing addr B; it
//     acquires the lock, write-aheads B, and publishes B on the wire (the
//     blocking updater only blocks the FIRST call, so #2 completes).
//  3. Reconcile #1's wire op is released and returns success — but its
//     write-ahead (A) is no longer the live owned record (B is). The guard must
//     leave B as the owned/published address (not roll back to or re-assert A).
func TestSurfaceAPublishRaceDoesNotClobberNewerState(t *testing.T) {
	ru := newRaceUpsertUpdater()
	now := time.Unix(1_700_000_000, 0)
	m := newSurfaceATestManager(t, ru, func() time.Time { return now })
	sc := surfaceAScope("wan.example.net", FamilyV4, 0)

	// Reconcile #1 — observes A, blocks in the wire op with the lock RELEASED.
	r1Done := make(chan struct{})
	go func() {
		_ = m.Reconcile(context.Background(), []SurfaceAScope{sc}, fixedObserver("203.0.113.5"), nil, nil)
		close(r1Done)
	}()
	select {
	case <-ru.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("first publish never reached the wire")
	}

	// Reconcile #2 — observes B; runs fully (its wire call is the 2nd, unblocked).
	// It can only acquire m.mu if #1 released it during I/O (#2778). The bounded
	// wait is the fail-on-revert: if the lock were held, this Reconcile hangs.
	r2Done := make(chan error, 1)
	go func() {
		r2Done <- m.Reconcile(context.Background(), []SurfaceAScope{sc}, fixedObserver("203.0.113.10"), nil, nil)
	}()
	select {
	case err := <-r2Done:
		if err != nil {
			t.Fatalf("Reconcile #2 (addr B) failed: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Reconcile #2 blocked — lock held across the first publish I/O (#2778 regression)")
	}

	// Now release #1's stale wire op. Its committed write-ahead was A, but the
	// live owned record is now B. The guard must NOT roll back / re-assert A.
	close(ru.release)
	select {
	case <-r1Done:
	case <-time.After(2 * time.Second):
		t.Fatal("Reconcile #1 did not finish after release")
	}

	// The owned/published address must be B (the newer desired state), never
	// reverted to A by the stale result.
	views := m.StatusViews()
	if len(views) != 1 {
		t.Fatalf("expected one owned scope, got %d: %+v", len(views), views)
	}
	if views[0].Published != "203.0.113.10" {
		t.Fatalf("stale publish clobbered newer state: published=%q want 203.0.113.10", views[0].Published)
	}

	// Both addresses were sent to the wire (A by #1, B by #2); the guard governs
	// the OWNERSHIP commit, not the wire op that already happened.
	got := ru.addrs()
	if len(got) != 2 {
		t.Fatalf("expected two wire publishes (A then B), got %v", got)
	}
}
