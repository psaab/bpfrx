package diagcmd

import (
	"context"
	"sync"
	"testing"
)

// #8312: the refusal counter, and the fail-fast question the weighted-cost
// model has to answer before it can be built.

// TestRefusalsCountsOnlyRefusals8312 pins what the counter means.
//
// A FIXTURE WITH ONE ACQUIRE CANNOT SEE THIS. The counter is wrong in three
// different ways that a single call would miss — counting successes, counting
// attempts, or counting the AcquireCtx lease reuse — so the cell drives all
// three classes against one limiter and asserts the count after each.
//
// MUTATION: move `l.refused.Add(1)` into the success arm -> the "successes are
// not refusals" assertion reds; count in AcquireCtx's lease branch -> the lease
// assertion reds.
func TestRefusalsCountsOnlyRefusals8312(t *testing.T) {
	l := NewLimiter(2)

	if got := l.Refusals(); got != 0 {
		t.Fatalf("a fresh limiter reports %d refusals, want 0", got)
	}

	// Two successful acquires fill the limiter. Neither is a refusal.
	rel1, err := l.Acquire()
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	rel2, err := l.Acquire()
	if err != nil {
		t.Fatalf("second acquire: %v", err)
	}
	if got := l.Refusals(); got != 0 {
		t.Fatalf("after 2 successful acquires Refusals = %d, want 0 — the counter "+
			"is counting attempts or successes, not refusals", got)
	}

	// The third is refused.
	if _, err := l.Acquire(); err == nil {
		t.Fatal("precondition: the limiter must be at capacity, or the refusal " +
			"below never happens and this cell is vacuous")
	}
	if got := l.Refusals(); got != 1 {
		t.Fatalf("after 1 refusal Refusals = %d, want 1", got)
	}

	// A LEASED AcquireCtx is not a candidate for refusal — it reuses an
	// ancestor's admission and takes no slot — so it must not count even while
	// the limiter is full. This is the arm most likely to be wired wrong,
	// because it is the one that returns success at capacity.
	_, leased, err := l.AcquireCtx(context.Background())
	if err == nil {
		t.Fatal("precondition: an UNLEASED AcquireCtx at capacity must be refused")
	}
	if got := l.Refusals(); got != 2 {
		t.Fatalf("an unleased AcquireCtx refused at capacity must count: Refusals = %d, want 2", got)
	}
	_ = leased

	// Now with a lease: reuse, no slot, no refusal.
	rel1()
	relLease, ctx, err := l.AcquireCtx(context.Background())
	if err != nil {
		t.Fatalf("leased acquire setup: %v", err)
	}
	defer relLease()
	rel2()
	// Fill the limiter again so a NON-lease call here would be refused.
	// The lease holder occupies one of the two slots; take the other so the
	// limiter is genuinely FULL. Asserted rather than assumed — a fixture that
	// did not reach capacity would make the lease assertion below vacuous, and
	// "the fixture never entered the state it claimed" is the recurring defect
	// in this area (#8312's failed sweep recorded session_count 1 for its N=0
	// stage).
	relFill, err := l.Acquire()
	if err != nil {
		t.Fatalf("filling the last slot: %v", err)
	}
	defer relFill()
	if l.InFlight() != l.Cap() {
		t.Fatalf("limiter is %d/%d, not at capacity — the lease assertion below "+
			"would pass without the lease doing anything", l.InFlight(), l.Cap())
	}
	if _, err := l.Acquire(); err == nil {
		t.Fatal("an UNLEASED acquire must be refused here, or 'at capacity' is not true")
	}

	before := l.Refusals()
	if _, _, err := l.AcquireCtx(ctx); err != nil {
		t.Fatalf("a leased AcquireCtx must succeed even at capacity: %v", err)
	}
	if got := l.Refusals(); got != before {
		t.Errorf("a leased AcquireCtx bumped Refusals from %d to %d; the lease path "+
			"was never a candidate for refusal, so counting it inflates the number "+
			"with calls the cap does not govern", before, got)
	}
}

// TestRefusalsIsRaceFreeUnderConcurrentAcquire8312 — the counter is read by a
// Prometheus scraper while handlers write it, so it must be an atomic and not a
// plain int. Run with -race this cell reds on a plain counter.
//
// The bound matters: with capacity 1 and N goroutines each doing one acquire,
// successes + refusals is exactly N, so the assertion is an EQUALITY rather
// than a range and cannot be satisfied by a lost update.
func TestRefusalsIsRaceFreeUnderConcurrentAcquire8312(t *testing.T) {
	const n = 200
	l := NewLimiter(1)

	var wg sync.WaitGroup
	var okCount int64
	var mu sync.Mutex
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rel, err := l.Acquire()
			if err == nil {
				mu.Lock()
				okCount++
				mu.Unlock()
				rel()
			}
			_ = l.Refusals() // concurrent read, as the scraper does
		}()
	}
	wg.Wait()

	if got := uint64(okCount) + l.Refusals(); got != n {
		t.Errorf("successes(%d) + refusals(%d) = %d, want exactly %d — a lost "+
			"update means the counter is not atomic", okCount, l.Refusals(), got, n)
	}
	if l.Refusals() == 0 {
		t.Skip("no contention observed on this run; the equality above is the real " +
			"assertion and it held, but nothing was refused so the counter was not exercised")
	}
}

// TestMultiSlotAcquireIsNotAvailableOnThisLimiter8312 answers #7294 item 2's
// last acceptance criterion — "whatever weighting lands states what a
// multi-slot acquire does to the fail-fast semantics" — as an executable
// demonstration rather than a paragraph.
//
// A weighted model charges an expensive walk W>1 slots. There is no atomic
// multi-send on a Go channel, so W slots means W non-blocking sends, and this
// cell drives the partial-acquisition failure that follows: a caller that wants
// 3 slots out of 4, when 2 are already held, TAKES ONE, FAILS, and must give it
// back. In that window a third caller that would have been admitted is refused
// by a request that was itself refused.
//
// That is not a tuning question, it is a semantics change: today a refusal
// never costs another caller a slot. It is why a weight table cannot be layered
// onto this limiter without replacing the channel with a mutex + counter, and
// why the capacity would then have to be re-derived — a list weighted at the
// full budget can never be admitted beside anything else.
//
// MUTATION: none needed — the assertions describe the CURRENT primitive, and
// the cell fails if a future change makes multi-slot acquisition atomic (at
// which point this analysis, and the issue's conclusion, must be revisited).
func TestMultiSlotAcquireIsNotAvailableOnThisLimiter8312(t *testing.T) {
	l := NewLimiter(4)
	held1, _ := l.Acquire()
	held2, _ := l.Acquire()
	defer held1()
	defer held2()

	// A "weight 3" acquire, spelled the only way the primitive allows.
	var taken []func()
	for i := 0; i < 3; i++ {
		rel, err := l.Acquire()
		if err != nil {
			break
		}
		taken = append(taken, rel)
	}
	if len(taken) != 2 {
		t.Fatalf("expected a PARTIAL acquisition of 2 of the 3 requested slots, got %d — "+
			"the fixture is not in the state this cell is about", len(taken))
	}
	// The partial holder now occupies the whole remaining budget while having
	// been refused. A concurrent single-slot caller is refused BY IT.
	if _, err := l.Acquire(); err == nil {
		t.Error("a single-slot caller was admitted while a refused multi-slot caller " +
			"held the remaining budget; if that ever becomes true the partial-" +
			"acquisition hazard below has been fixed and #7294 item 2 can be revisited")
	}
	for _, rel := range taken {
		rel()
	}
	// After the failed multi-slot acquire releases, the budget is whole again —
	// which is what makes the hazard a WINDOW rather than a leak.
	rel, err := l.Acquire()
	if err != nil {
		t.Fatalf("the budget must be intact after a failed multi-slot acquire releases: %v", err)
	}
	rel()
}
