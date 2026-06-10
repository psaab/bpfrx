package api

import (
	"context"
	"testing"
	"time"
)

// runTimeout derives its deadline from the parent ctx via
// context.WithTimeout(parent, 15s) — the effective deadline is the
// earlier of the two. The timeout test passes a short parent deadline
// so the kill path is exercised without waiting out the real 15s
// constant (same precedent as the pkg/grpcapi helper tests; the
// pkg/daemon contract reference ships untested).

// TestPingExecTimeout pins the request-sized ping budget (#1819):
// count × 1s + 15s slack, floored at the previous 30s bound, capped at
// the 150s diag ceiling. Counts above 100 cannot reach the formula
// today (the handler clamps first) but the ceiling must hold anyway.
// Mirror of the pkg/grpcapi table — keep the two in sync.
func TestPingExecTimeout(t *testing.T) {
	cases := []struct {
		count int
		want  time.Duration
	}{
		{1, 30 * time.Second},    // 16s formula, floored at the old bound
		{5, 30 * time.Second},    // default count, floored
		{15, 30 * time.Second},   // 30s formula == floor
		{16, 31 * time.Second},   // first count past the floor
		{60, 75 * time.Second},   // the count>~30 case the 30s bound killed
		{100, 115 * time.Second}, // clamp maximum
		{135, 150 * time.Second}, // formula == ceiling
		{200, 150 * time.Second}, // ceiling holds past the clamp
		{1 << 30, 150 * time.Second},
	}
	for _, c := range cases {
		if got := pingExecTimeout(c.count); got != c.want {
			t.Errorf("pingExecTimeout(%d) = %v, want %v", c.count, got, c.want)
		}
	}
}

// TestDiagTracerouteTimeoutNotTighterThanBefore pins the #1819
// no-tightening invariant: the shared traceroute budget must never
// drop below the pre-#1819 HTTP bound (60s) and must respect the diag
// ceiling.
func TestDiagTracerouteTimeoutNotTighterThanBefore(t *testing.T) {
	if diagTracerouteTimeout < 60*time.Second {
		t.Fatalf("diagTracerouteTimeout = %v, tighter than the pre-#1819 60s bound", diagTracerouteTimeout)
	}
	if diagTracerouteTimeout > diagExecCeiling {
		t.Fatalf("diagTracerouteTimeout = %v exceeds diagExecCeiling %v", diagTracerouteTimeout, diagExecCeiling)
	}
}

func TestRunTimeoutSuccess(t *testing.T) {
	if err := runTimeout(context.Background(), "true"); err != nil {
		t.Fatalf("runTimeout(true): %v", err)
	}
}

func TestRunTimeoutKillsHungCommand(t *testing.T) {
	parent, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := runTimeout(parent, "sleep", "30")
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("runTimeout: want error for killed command, got nil")
	}
	// Bound: 200ms deadline + 5s WaitDelay worst case, with slack.
	if elapsed > 10*time.Second {
		t.Fatalf("runTimeout took %v, command was not killed by the deadline", elapsed)
	}
}
