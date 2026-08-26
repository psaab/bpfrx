// #1922 Item 1a: serialization + atomicity contract for the
// commit-confirmed timeout rollback executor.
//
// executeConfirmedRollback must hold d.applySem across BOTH the store
// promotion (PromoteRollback) and the dataplane re-apply, so a
// concurrent commitAndApply can never interleave between them. Before
// this change the rollback callback promoted the store state and
// persisted it OUTSIDE the apply lock and re-applied the dataplane in a
// separate critical section, opening a store-vs-kernel split-brain
// window. These tests would fail if a future refactor:
//
//   - dropped Acquire from executeConfirmedRollback (the body-overlap
//     test would see >1 concurrent applyConfigLocked invocation), or
//   - re-applied the dataplane to a config different from the one the
//     store ended on (the consistency test would catch the torn state).
package daemon

import (
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
)

// newRollbackTestStore builds a store with a CONFIRMED initial config
// "A" and an armed (pending) confirmed commit promoting it to "B".
// PromoteRollback(gen) will therefore revert active to "A". Returns the
// store and the confirm generation that armed the timer.
func newRollbackTestStore(t *testing.T) (*configstore.Store, uint64) {
	t.Helper()
	s, err := configstore.New(filepath.Join(t.TempDir(), "config"))
	if err != nil {
		t.Fatalf("configstore.New: %v", err)
	}

	// Confirmed baseline config A.
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := s.SetFromInput("system host-name A"); err != nil {
		t.Fatalf("set host-name A: %v", err)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("commit A: %v", err)
	}

	// Unconfirmed commit-confirmed promoting to B; rollback target = A.
	if err := s.SetFromInput("system host-name B"); err != nil {
		t.Fatalf("set host-name B: %v", err)
	}
	if _, err := s.CommitConfirmed(1); err != nil {
		t.Fatalf("CommitConfirmed: %v", err)
	}
	if got := s.ActiveConfig().System.HostName; got != "B" {
		t.Fatalf("after CommitConfirmed active host-name = %q, want B", got)
	}
	return s, s.ConfirmGenForTesting()
}

// executeConfirmedRollback and commitAndApply must NOT run their
// applyConfigLocked bodies concurrently — both serialize through
// d.applySem.
func TestExecuteConfirmedRollbackSerializesWithCommit(t *testing.T) {
	s, gen := newRollbackTestStore(t)
	d := &Daemon{applySem: semaphore.NewWeighted(1), store: s}

	var (
		inFlight int32
		maxSeen  int32
		total    int32
	)
	d.applyBodyForTest = func(_ *config.Config) {
		atomic.AddInt32(&total, 1)
		n := atomic.AddInt32(&inFlight, 1)
		for {
			cur := atomic.LoadInt32(&maxSeen)
			if n <= cur || atomic.CompareAndSwapInt32(&maxSeen, cur, n) {
				break
			}
		}
		// Hold long enough that a missing serialization would show as
		// inFlight > 1.
		time.Sleep(10 * time.Millisecond)
		atomic.AddInt32(&inFlight, -1)
	}

	// Stage a candidate "C" so the concurrent commitAndApply has
	// something to promote+apply. CommitConfirmed leaves the store in
	// configure mode (candidate recloned from active), so set directly.
	if err := s.SetFromInput("system host-name C"); err != nil {
		t.Fatalf("set host-name C: %v", err)
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		d.executeConfirmedRollback(gen)
	}()
	go func() {
		defer wg.Done()
		_, _ = d.commitAndApply(t.Context(), configstore.InternalCommitter(), "", peerSyncNever)
	}()
	wg.Wait()

	if got := atomic.LoadInt32(&maxSeen); got != 1 {
		t.Fatalf("rollback and commit must serialize via applySem; saw %d concurrent body invocations", got)
	}
	// #3861: a plain commit during a pending commit-confirmed window now
	// CONFIRMS it (Junos: any subsequent explicit commit confirms a pending
	// `commit confirmed`). The two operations still fully serialize on
	// applySem, but whether the rollback body runs depends on who wins the
	// semaphore:
	//   - commit-first: Commit() confirms the window (cancels the timer and
	//     bumps confirmGen); the later executeConfirmedRollback(gen) sees a
	//     stale generation and no-ops. The committed config is NOT silently
	//     reverted — the #3861 fix — so only the commit body runs (total==1).
	//   - rollback-first: PromoteRollback reverts to A and re-seeds the
	//     candidate from A, then the commit re-commits A (total==2).
	// Either way the body count is bounded by [1,2]: fully serialized, never
	// overlapping, never a spurious third apply. The deterministic
	// anti-TryAcquire-skip guarantee (a rollback must BLOCK on a contended
	// applySem, never be silently dropped) is covered by
	// TestExecuteConfirmedRollbackBlocksOnApplySem below; store/dataplane
	// atomicity by TestExecuteConfirmedRollbackStoreApplyConsistency.
	if got := atomic.LoadInt32(&total); got < 1 || got > 2 {
		t.Fatalf("apply body ran %d times, want 1 (commit-first confirms per #3861) or 2 (rollback-first)", got)
	}
}

// #1922 Item 1a anti-skip guarantee, revalidated under #3861: the rollback
// executor must BLOCK on d.applySem when it is contended, never skip the
// rollback (a TryAcquire refactor would satisfy the no-overlap check by
// silently dropping the rollback body). The concurrent-race sibling above can
// no longer assert this via total==2 because a commit that wins the race now
// legitimately confirms the window and supersedes the rollback (#3861), so
// prove the blocking behavior DETERMINISTICALLY: hold applySem, fire the
// executor, and confirm it waits (store still B, body not run) then completes
// once the semaphore is released (store reverts to A, body ran exactly once).
// A TryAcquire-skip refactor would return immediately without ever rolling
// back, leaving the store on B — which the post-release assertions catch.
func TestExecuteConfirmedRollbackBlocksOnApplySem(t *testing.T) {
	s, gen := newRollbackTestStore(t) // active=B pending, rollback target=A
	d := &Daemon{applySem: semaphore.NewWeighted(1), store: s}

	var bodyRan int32
	d.applyBodyForTest = func(_ *config.Config) { atomic.AddInt32(&bodyRan, 1) }

	// Hold the apply semaphore so the executor must wait for it.
	if err := d.applySem.Acquire(t.Context(), 1); err != nil {
		t.Fatalf("Acquire: %v", err)
	}

	done := make(chan struct{})
	go func() {
		d.executeConfirmedRollback(gen)
		close(done)
	}()

	// While the semaphore is held the executor must be blocked: no rollback.
	time.Sleep(30 * time.Millisecond)
	if got := atomic.LoadInt32(&bodyRan); got != 0 {
		t.Fatalf("rollback body ran (%d) while applySem was held — executor did not block on the semaphore", got)
	}
	if got := s.ActiveConfig().System.HostName; got != "B" {
		t.Fatalf("store promoted while applySem held: host-name = %q, want B", got)
	}

	// Release the semaphore: a BLOCKING executor now proceeds. A TryAcquire-
	// skip refactor would already have returned without rolling back.
	d.applySem.Release(1)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("executor did not complete after applySem release (did it block forever?)")
	}
	if got := atomic.LoadInt32(&bodyRan); got != 1 {
		t.Fatalf("rollback body ran %d times after release, want 1 (blocked-then-ran, not skipped)", got)
	}
	if got := s.ActiveConfig().System.HostName; got != "A" {
		t.Fatalf("after rollback active host-name = %q, want A", got)
	}
}

// Through the real CommitConfirmed timer the registered executor must
// fire EXACTLY ONCE on timeout — proving the store->daemon executor wiring
// (SetRollbackExecutor + the timer's executor branch) actually drives the
// daemon transaction, not the in-store performAutoRollback fallback. Uses
// a sub-minute timer by arming via CommitConfirmed then overriding the
// confirm timer with a short one is not exposed; instead drive the timer
// branch directly by invoking the store's confirm-timer closure semantics:
// register the executor and assert it is the path taken.
func TestRollbackExecutorFiresOnceViaTimer(t *testing.T) {
	s, _ := newRollbackTestStore(t) // active=B pending, target=A
	d := &Daemon{applySem: semaphore.NewWeighted(1), store: s}

	var execCalls int32
	d.applyBodyForTest = func(_ *config.Config) {}

	// Wrap the daemon executor in a counter and register it as the store's
	// rollback executor (this is exactly what daemon init does).
	s.SetRollbackExecutor(func(gen uint64) {
		atomic.AddInt32(&execCalls, 1)
		d.executeConfirmedRollback(gen)
	})

	// Fire the confirm timer's executor branch the way the timer does:
	// read the current generation and invoke the registered executor.
	// (The production timer closure does the same read-under-lock then
	// off-lock invoke; ConfirmGenForTesting returns that generation.)
	gen := s.ConfirmGenForTesting()
	s.InvokeRollbackTimerForTesting(gen)

	if got := atomic.LoadInt32(&execCalls); got != 1 {
		t.Fatalf("executor must fire exactly once on timer expiry; got %d", got)
	}
	if host := s.ActiveConfig().System.HostName; host != "A" {
		t.Fatalf("after timer rollback active host-name = %q, want A", host)
	}

	// A second timer fire with the same (now superseded) generation must be
	// a no-op — the executor still runs but PromoteRollback rejects it.
	s.InvokeRollbackTimerForTesting(gen)
	if got := atomic.LoadInt32(&execCalls); got != 2 {
		t.Fatalf("second timer fire should still invoke the executor (it self-guards), got %d calls", got)
	}
	if host := s.ActiveConfig().System.HostName; host != "A" {
		t.Fatalf("stale second timer fire must not mutate; active host-name = %q, want A", host)
	}
}

// After a rollback races a commit, the dataplane config last applied
// must equal the store's final active config — no torn state where the
// store says one config and the kernel was left on another.
func TestExecuteConfirmedRollbackStoreApplyConsistency(t *testing.T) {
	// Run several times; the race outcome (rollback-then-commit vs
	// commit-then-rollback) is nondeterministic but BOTH orders must end
	// store-consistent with the last applied config.
	for iter := 0; iter < 50; iter++ {
		s, gen := newRollbackTestStore(t)
		d := &Daemon{applySem: semaphore.NewWeighted(1), store: s}

		var (
			mu          sync.Mutex
			lastApplied string
		)
		d.applyBodyForTest = func(cfg *config.Config) {
			mu.Lock()
			lastApplied = cfg.System.HostName
			mu.Unlock()
		}

		if err := s.SetFromInput("system host-name C"); err != nil {
			t.Fatalf("iter %d set host-name C: %v", iter, err)
		}

		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			d.executeConfirmedRollback(gen)
		}()
		go func() {
			defer wg.Done()
			_, _ = d.commitAndApply(t.Context(), configstore.InternalCommitter(), "", peerSyncNever)
		}()
		wg.Wait()

		storeHost := s.ActiveConfig().System.HostName
		mu.Lock()
		applied := lastApplied
		mu.Unlock()

		// The committer always wins the final store state when it runs
		// last; when the rollback runs last it reverts to A. Either way,
		// the LAST applyConfigLocked body must have seen the same config
		// the store ended on — that is the atomicity guarantee. (If the
		// commit ran entirely before the rollback's PromoteRollback, the
		// rollback still re-applies A; if the commit ran after, it
		// re-applies C. The rollback can never leave the store on A while
		// the dataplane was last told C, or vice-versa.)
		if applied != storeHost {
			t.Fatalf("iter %d torn state: store host-name=%q but dataplane last applied=%q",
				iter, storeHost, applied)
		}
	}
}
