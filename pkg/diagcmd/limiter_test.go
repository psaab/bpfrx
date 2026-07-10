package diagcmd

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestLimiterAdmitsUpToCapThenRejects locks the core semaphore
// invariant: exactly Cap concurrent holders are admitted and the next
// Acquire fails fast with ErrBusy rather than blocking. RED-on-revert:
// widen or remove the fail-fast branch in Acquire and the (N+1)th
// Acquire either blocks (test times out) or succeeds (assertion fires).
func TestLimiterAdmitsUpToCapThenRejects(t *testing.T) {
	const n = 3
	l := NewLimiter(n)
	if l.Cap() != n {
		t.Fatalf("Cap() = %d, want %d", l.Cap(), n)
	}

	releases := make([]func(), 0, n)
	for i := 0; i < n; i++ {
		rel, err := l.Acquire()
		if err != nil {
			t.Fatalf("Acquire %d/%d failed unexpectedly: %v", i+1, n, err)
		}
		releases = append(releases, rel)
	}
	if got := l.InFlight(); got != n {
		t.Fatalf("InFlight after %d acquires = %d, want %d", n, got, n)
	}

	// Cap reached: the next acquire must be rejected immediately.
	rel, err := l.Acquire()
	if !errors.Is(err, ErrBusy) {
		t.Fatalf("Acquire past cap: err = %v, want ErrBusy", err)
	}
	if rel != nil {
		t.Fatalf("Acquire past cap returned a non-nil release")
	}

	// Release one slot: a subsequent acquire must now succeed, proving
	// the slot was returned (no leak).
	releases[0]()
	rel2, err := l.Acquire()
	if err != nil {
		t.Fatalf("Acquire after release failed: %v", err)
	}
	rel2()

	// Release the rest and confirm the limiter drains fully.
	for _, r := range releases[1:] {
		r()
	}
	if got := l.InFlight(); got != 0 {
		t.Fatalf("InFlight after all releases = %d, want 0", got)
	}
}

// TestLimiterReleaseIdempotent proves a double-release cannot
// over-release and free another caller's slot — the sync.Once guard.
func TestLimiterReleaseIdempotent(t *testing.T) {
	l := NewLimiter(1)
	rel, err := l.Acquire()
	if err != nil {
		t.Fatalf("Acquire failed: %v", err)
	}
	rel()
	rel() // second call must be a no-op

	// Hold the single slot; a stray extra release earlier would have
	// left phantom capacity, letting a second acquire succeed.
	if _, err := l.Acquire(); err != nil {
		t.Fatalf("first post-release Acquire failed: %v", err)
	}
	if _, err := l.Acquire(); !errors.Is(err, ErrBusy) {
		t.Fatalf("second Acquire: err = %v, want ErrBusy (double-release leaked a slot)", err)
	}
}

// TestLimiterBoundsConcurrentFakeDiagnostics is the concurrency
// fail-on-revert test at the limiter level: it fires N+K goroutines that
// each Acquire, run a fake slow "diagnostic", then Release. It asserts
// (1) at most Cap run at once, (2) the K excess are rejected with
// ErrBusy (not hung, not admitted), and (3) after the admitted work
// finishes the limiter is fully released so a fresh Acquire succeeds.
//
// The `release` gate is held until EVERY goroutine has attempted Acquire
// (the allAttempted barrier), so no admitted goroutine frees its slot
// before the excess goroutines have run — otherwise a freed slot could
// be won by an excess goroutine and the rejection count would be racy.
func TestLimiterBoundsConcurrentFakeDiagnostics(t *testing.T) {
	const (
		cap   = 2
		k     = 4 // excess beyond cap
		total = cap + k
	)
	l := NewLimiter(cap)

	var (
		inFlight    int32
		maxObserved int32
		admitted    int32
		rejected    int32
		attempts    int32
	)
	release := make(chan struct{})      // gate: hold admitted work until closed
	allAttempted := make(chan struct{}) // closed once every goroutine has run Acquire
	noteAttempt := func() {
		if atomic.AddInt32(&attempts, 1) == total {
			close(allAttempted)
		}
	}

	var wg sync.WaitGroup
	for i := 0; i < total; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rel, err := l.Acquire()
			if errors.Is(err, ErrBusy) {
				atomic.AddInt32(&rejected, 1)
				noteAttempt()
				return
			}
			if err != nil {
				t.Errorf("unexpected Acquire error: %v", err)
				noteAttempt()
				return
			}
			defer rel()
			// Fake slow diagnostic: hold the slot until released.
			cur := atomic.AddInt32(&inFlight, 1)
			for {
				m := atomic.LoadInt32(&maxObserved)
				if cur <= m || atomic.CompareAndSwapInt32(&maxObserved, m, cur) {
					break
				}
			}
			atomic.AddInt32(&admitted, 1)
			noteAttempt()
			<-release
			atomic.AddInt32(&inFlight, -1)
		}()
	}

	// Wait until all goroutines have attempted, then unblock everyone.
	select {
	case <-allAttempted:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for %d attempts; admitted=%d rejected=%d",
			total, atomic.LoadInt32(&admitted), atomic.LoadInt32(&rejected))
	}
	if got := atomic.LoadInt32(&rejected); got != k {
		t.Fatalf("rejected = %d, want %d (excess must fail fast, not queue)", got, k)
	}
	if got := atomic.LoadInt32(&admitted); got != cap {
		t.Fatalf("admitted = %d, want %d", got, cap)
	}
	close(release)
	wg.Wait()

	if got := atomic.LoadInt32(&maxObserved); got > cap {
		t.Fatalf("max concurrent diagnostics = %d, want <= %d", got, cap)
	}

	// Fully released: the limiter must accept a fresh acquire.
	if l.InFlight() != 0 {
		t.Fatalf("InFlight after drain = %d, want 0", l.InFlight())
	}
	rel, err := l.Acquire()
	if err != nil {
		t.Fatalf("post-drain Acquire failed: %v (limiter not fully released)", err)
	}
	rel()
}
