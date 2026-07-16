package diagcmd

import (
	"context"
	"errors"
	"testing"
)

// TestAcquireCtx_5880 pins the in-process admission-lease semantics (#5880):
// nested in-process delegation (a context carrying THIS limiter's lease) reuses
// the ancestor's slot without re-acquiring, while a DISTINCT external request
// (no lease) is still bounded — the lease is per-request-graph, never a global
// disable. Release is idempotent + cancellation-safe on both paths.
//
// FAIL-ON-REVERT: drop the lease check in AcquireCtx (always Acquire) → at
// capacity 1 the lease-reuse acquire below gets ErrBusy → the "lease reuse
// acquire" fatal fires RED.
func TestAcquireCtx_5880(t *testing.T) {
	l := NewLimiter(1)

	// Boundary acquire (no lease yet) — takes the single slot, stamps the lease.
	rel1, leased, err := l.AcquireCtx(context.Background())
	if err != nil {
		t.Fatalf("first AcquireCtx: %v", err)
	}
	if l.InFlight() != 1 {
		t.Fatalf("after boundary acquire InFlight=%d, want 1", l.InFlight())
	}

	// A DISTINCT external request (fresh, unstamped context) at capacity 1 is
	// still bounded — the lease must NOT globally disable the limiter.
	if _, _, err := l.AcquireCtx(context.Background()); !errors.Is(err, ErrBusy) {
		t.Fatalf("distinct external request at cap 1: err=%v, want ErrBusy "+
			"(the lease must not globally open the limiter)", err)
	}

	// Nested in-process delegation carrying the lease reuses the slot — no
	// second charge, ctx unchanged.
	rel2, leased2, err := l.AcquireCtx(leased)
	if err != nil {
		t.Fatalf("lease reuse AcquireCtx self-rejected at cap 1: %v", err)
	}
	if l.InFlight() != 1 {
		t.Fatalf("lease reuse took an extra slot: InFlight=%d, want 1", l.InFlight())
	}
	if leased2 != leased {
		t.Errorf("lease reuse must return the context unchanged")
	}

	// The lease-reuse release is a no-op — it must not free the ancestor's slot.
	rel2()
	if l.InFlight() != 1 {
		t.Fatalf("lease-reuse release freed a slot: InFlight=%d, want 1", l.InFlight())
	}

	// The real release frees the one slot and is idempotent (double release safe:
	// it must not over-release and free another caller's slot).
	rel1()
	rel1()
	if l.InFlight() != 0 {
		t.Fatalf("after release (incl. double) InFlight=%d, want 0", l.InFlight())
	}

	// A fresh acquire succeeds again now the slot is free.
	rel3, _, err := l.AcquireCtx(context.Background())
	if err != nil {
		t.Fatalf("re-acquire after release: %v", err)
	}
	rel3()
}

// TestAcquireCtx_PerLimiterKey_5880 confirms a lease is scoped to its OWN
// limiter: a lease taken on limiter A does not let a nested acquire on a
// different limiter B skip B's admission.
func TestAcquireCtx_PerLimiterKey_5880(t *testing.T) {
	a := NewLimiter(1)
	b := NewLimiter(1)

	relA, leasedA, err := a.AcquireCtx(context.Background())
	if err != nil {
		t.Fatalf("acquire A: %v", err)
	}
	defer relA()

	// Fill B to capacity so a re-acquire would fail if the A-lease wrongly
	// applied to B.
	relB, _, err := b.AcquireCtx(context.Background())
	if err != nil {
		t.Fatalf("acquire B: %v", err)
	}
	defer relB()

	// The A-lease context must NOT satisfy B — B is at capacity, so a nested
	// acquire on B carrying only the A-lease must be bounded.
	if _, _, err := b.AcquireCtx(leasedA); !errors.Is(err, ErrBusy) {
		t.Fatalf("A-lease wrongly reused B's admission: err=%v, want ErrBusy", err)
	}
}
