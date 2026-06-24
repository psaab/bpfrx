package rpm

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// scriptedProber returns a probeFn that yields the next result from
// seq on each call: false = lost probe (error), true = received. Once
// seq is exhausted it repeats the last element (so a short script can
// drive a longer probe-count without panicking).
func scriptedProber(seq []bool) func(ctx context.Context, test *config.RPMTest, key string) (time.Duration, error) {
	var mu sync.Mutex
	i := 0
	return func(ctx context.Context, test *config.RPMTest, key string) (time.Duration, error) {
		mu.Lock()
		defer mu.Unlock()
		ok := seq[len(seq)-1]
		if i < len(seq) {
			ok = seq[i]
		}
		i++
		if ok {
			return time.Millisecond, nil
		}
		return 0, fmt.Errorf("scripted loss")
	}
}

// newTestManager builds a Manager with the test prober seam and a
// transition recorder. It seeds a single result under key "p/t" with
// the given starting status, mirroring Apply's initialization.
func newTestManager(t *testing.T, startStatus string, seq []bool) (*Manager, *[]string) {
	t.Helper()
	m := New()
	m.probeFn = scriptedProber(seq)
	m.results["p/t"] = &ProbeResult{
		ProbeName:  "p",
		TestName:   "t",
		LastStatus: startStatus,
	}
	var mu sync.Mutex
	var transitions []string
	m.SetTransitionCallback(func(tr Transition) {
		mu.Lock()
		defer mu.Unlock()
		transitions = append(transitions, tr.Status)
	})
	return m, &transitions
}

// TestRunSingleTestOneTransitionPerCycle is the core #2527 regression:
// a fail,fail,pass,fail,fail cycle (probeCount=5, threshold=2) must fire
// EXACTLY ONE transition (to "fail") — not three. Against the pre-fix
// per-probe firing this asserts 3 transitions and FAILS.
func TestRunSingleTestOneTransitionPerCycle(t *testing.T) {
	seq := []bool{false, false, true, false, false}
	m, transitions := newTestManager(t, "pass", seq)

	m.runSingleTest(context.Background(), "p", &config.RPMTest{Name: "t"}, "p/t", 5, 0, 2)

	if len(*transitions) != 1 {
		t.Fatalf("expected exactly 1 transition per cycle, got %d: %v",
			len(*transitions), *transitions)
	}
	if (*transitions)[0] != "fail" {
		t.Fatalf("expected the single transition to be \"fail\", got %q", (*transitions)[0])
	}
	if got := m.results["p/t"].LastStatus; got != "fail" {
		t.Fatalf("expected LastStatus=fail after the cycle, got %q", got)
	}
}

// TestRunSingleTestTransientLossBelowThreshold: a mostly-pass cycle with
// a single transient loss below threshold must fire NO transition (the
// test was already passing and never crosses the successive-loss bar).
func TestRunSingleTestTransientLossBelowThreshold(t *testing.T) {
	seq := []bool{true, true, false, true, true}
	m, transitions := newTestManager(t, "pass", seq)

	m.runSingleTest(context.Background(), "p", &config.RPMTest{Name: "t"}, "p/t", 5, 0, 2)

	if len(*transitions) != 0 {
		t.Fatalf("expected no transition for transient sub-threshold loss, got %d: %v",
			len(*transitions), *transitions)
	}
	if got := m.results["p/t"].LastStatus; got != "pass" {
		t.Fatalf("expected LastStatus to stay pass, got %q", got)
	}
}

// TestRunSingleTestRecovery: a fully-passing cycle following a failed
// state fires exactly one "pass" transition.
func TestRunSingleTestRecovery(t *testing.T) {
	seq := []bool{true, true, true, true, true}
	m, transitions := newTestManager(t, "fail", seq)
	// Simulate carry-over from a prior failed cycle.
	m.results["p/t"].SuccFail = 4

	m.runSingleTest(context.Background(), "p", &config.RPMTest{Name: "t"}, "p/t", 5, 0, 2)

	if len(*transitions) != 1 || (*transitions)[0] != "pass" {
		t.Fatalf("expected exactly 1 \"pass\" transition on recovery, got %v", *transitions)
	}
	if got := m.results["p/t"].SuccFail; got != 0 {
		t.Fatalf("expected SuccFail reset to 0 on recovery, got %d", got)
	}
}

// TestRunSingleTestProbeCountOne preserves the degenerate single-probe
// behavior across the relevant cases.
func TestRunSingleTestProbeCountOne(t *testing.T) {
	t.Run("single-pass-fires-pass-from-unknown", func(t *testing.T) {
		m, transitions := newTestManager(t, "unknown", []bool{true})
		m.runSingleTest(context.Background(), "p", &config.RPMTest{Name: "t"}, "p/t", 1, 0, 1)
		if len(*transitions) != 1 || (*transitions)[0] != "pass" {
			t.Fatalf("expected one pass transition, got %v", *transitions)
		}
	})

	t.Run("single-fail-threshold-1-fires-fail", func(t *testing.T) {
		m, transitions := newTestManager(t, "pass", []bool{false})
		m.runSingleTest(context.Background(), "p", &config.RPMTest{Name: "t"}, "p/t", 1, 0, 1)
		if len(*transitions) != 1 || (*transitions)[0] != "fail" {
			t.Fatalf("expected one fail transition, got %v", *transitions)
		}
	})

	t.Run("single-fail-below-threshold-holds", func(t *testing.T) {
		// threshold 3, one fail: must NOT transition and must hold the
		// initial unknown state — a single lost probe is not a failure.
		m, transitions := newTestManager(t, "unknown", []bool{false})
		m.runSingleTest(context.Background(), "p", &config.RPMTest{Name: "t"}, "p/t", 1, 0, 3)
		if len(*transitions) != 0 {
			t.Fatalf("expected no transition below threshold, got %v", *transitions)
		}
		if got := m.results["p/t"].LastStatus; got != "unknown" {
			t.Fatalf("expected status to hold unknown, got %q", got)
		}
	})
}

// TestRunSingleTestCrossCycleSuccessiveLoss verifies the successive-loss
// counter still accumulates ACROSS cycles when threshold > probeCount,
// firing a single fail once the consecutive run finally crosses the bar.
func TestRunSingleTestCrossCycleSuccessiveLoss(t *testing.T) {
	// probeCount=2, threshold=3: one cycle of two losses cannot trip
	// (2 < 3); the second cycle's first loss makes it 3 and trips once.
	m, transitions := newTestManager(t, "pass", []bool{false})

	m.runSingleTest(context.Background(), "p", &config.RPMTest{Name: "t"}, "p/t", 2, 0, 3)
	if len(*transitions) != 0 {
		t.Fatalf("cycle 1: 2<3 successive losses must not trip, got %v", *transitions)
	}
	if got := m.results["p/t"].SuccFail; got != 2 {
		t.Fatalf("cycle 1: expected SuccFail=2 carried, got %d", got)
	}

	m.runSingleTest(context.Background(), "p", &config.RPMTest{Name: "t"}, "p/t", 2, 0, 3)
	if len(*transitions) != 1 || (*transitions)[0] != "fail" {
		t.Fatalf("cycle 2: expected exactly one fail once run reaches 3, got %v", *transitions)
	}
}
