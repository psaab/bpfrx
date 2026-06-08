package daemon

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// #1780 Path A: the periodic neighbor-maintenance loop must survive a phase
// whose netlink/probe syscall wedges. These tests pin the guarantees the fix
// rests on:
//
//   1. runGuardedNeighborPhase NEVER blocks its caller — the phase body runs in
//      a goroutine, so a hung phase cannot freeze the for-select loop.
//   2. While a phase is in flight the guard SKIPS relaunch (no overlapping
//      pass, no per-tick goroutine/socket leak), and relaunches once the prior
//      pass returns.
//   3. End-to-end, neighborPeriodicLoop keeps firing the clean ticker while a
//      resolve phase is wedged — the real no-freeze property, not just the
//      helper in isolation (Codex #1781 r1).
//   4. NeighborPeriodicPhaseAges advances for a stalled phase, reports nothing
//      until the loop has started, and omits the HA-only warm phase when not
//      clustered (Codex #1781 r1).

// waitFor polls cond until true or the deadline elapses; fatals on timeout.
func waitFor(t *testing.T, d time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out after %s waiting for: %s", d, what)
}

func TestRunGuardedNeighborPhaseDoesNotBlockCaller(t *testing.T) {
	d := &Daemon{startTime: time.Now()}
	var inFlight atomic.Bool
	var lastSuccess atomic.Int64

	release := make(chan struct{})
	started := make(chan struct{})

	// A phase that blocks until released models a wedged netlink syscall.
	callReturned := make(chan struct{})
	go func() {
		d.runGuardedNeighborPhase(&inFlight, &lastSuccess, func() {
			close(started)
			<-release
		})
		close(callReturned)
	}()

	// The call itself must return immediately even though the phase body is
	// still blocked — that is the whole point: the for-select loop is freed.
	select {
	case <-callReturned:
	case <-time.After(2 * time.Second):
		t.Fatal("runGuardedNeighborPhase blocked its caller on a hung phase")
	}

	// The phase body is running and in-flight is held.
	<-started
	if !inFlight.Load() {
		t.Fatal("in-flight flag not set while phase body runs")
	}
	if lastSuccess.Load() != 0 {
		t.Fatal("last-success recorded before the phase completed")
	}

	// A second call while in flight must SKIP: no new goroutine, fn not run.
	var secondRan atomic.Bool
	d.runGuardedNeighborPhase(&inFlight, &lastSuccess, func() { secondRan.Store(true) })
	time.Sleep(20 * time.Millisecond)
	if secondRan.Load() {
		t.Fatal("overlapping pass launched while prior pass still in flight")
	}

	// Release the stuck phase; in-flight clears and last-success records.
	close(release)
	waitFor(t, 2*time.Second, "in-flight to clear after phase returns", func() bool {
		return !inFlight.Load()
	})
	if lastSuccess.Load() == 0 {
		t.Fatal("last-success not recorded after the phase completed")
	}

	// Now a subsequent call relaunches (guard self-healed).
	var thirdRan atomic.Bool
	var wg sync.WaitGroup
	wg.Add(1)
	d.runGuardedNeighborPhase(&inFlight, &lastSuccess, func() {
		thirdRan.Store(true)
		wg.Done()
	})
	wg.Wait()
	if !thirdRan.Load() {
		t.Fatal("guard did not relaunch the phase after the prior pass returned")
	}
}

// TestNeighborPeriodicLoopKeepsTickingWhilePhaseWedged drives the real loop
// core with fast intervals and a resolve phase that wedges forever (via the
// real guard), and asserts the clean ticker keeps firing — the end-to-end
// no-freeze property a stuck phase must not break.
func TestNeighborPeriodicLoopKeepsTickingWhilePhaseWedged(t *testing.T) {
	d := &Daemon{startTime: time.Now()}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var cleanCount atomic.Int64
	var resolveStarted atomic.Bool
	release := make(chan struct{})

	// resolveTick dispatches a phase that wedges forever (models a stuck
	// netlink syscall) through the real guarded-goroutine helper.
	resolveTick := func() {
		d.runGuardedNeighborPhase(&d.resolveNeighborsInFlight, &d.resolveLastSuccessNanos, func() {
			resolveStarted.Store(true)
			<-release
		})
	}
	cleanTick := func() { cleanCount.Add(1) }

	go d.neighborPeriodicLoop(ctx, 5*time.Millisecond, 8*time.Millisecond, cleanTick, resolveTick)

	// Even though the resolve phase wedges on its first fire, the clean ticker
	// must keep firing: the loop is not frozen.
	waitFor(t, 2*time.Second, "clean ticks to accumulate while resolve is wedged", func() bool {
		return cleanCount.Load() >= 5
	})
	if !resolveStarted.Load() {
		t.Fatal("resolve phase never started")
	}
	// The wedged resolve phase stayed in flight — no relaunch, no panic, and
	// crucially the loop kept servicing the clean ticker.
	if !d.resolveNeighborsInFlight.Load() {
		t.Fatal("expected the wedged resolve phase to remain in-flight")
	}

	cancel()
	close(release)
}

func TestNeighborPeriodicPhaseAgesReflectsStall(t *testing.T) {
	// startTime in the past so a never-run phase reports a non-trivial age.
	d := &Daemon{startTime: time.Now().Add(-30 * time.Second)}

	// Before the loop starts, the accessor reports nothing — a daemon that
	// never starts the loop must not surface forever-climbing false "wedges".
	if ages := d.NeighborPeriodicPhaseAges(); ages != nil {
		t.Fatalf("expected nil phase ages before loop start, got %v", ages)
	}

	d.neighborPeriodicLoopStarted.Store(true)

	// All phases never-run: each reports ~age-since-start (~30s), proving a
	// phase that never completes still flags rather than reading zero. warm is
	// omitted because d.cluster == nil (HA-only phase).
	ages := d.NeighborPeriodicPhaseAges()
	for _, phase := range []string{"resolve", "force_probe", "clean_failed"} {
		if a, ok := ages[phase]; !ok {
			t.Fatalf("phase %q missing from age map", phase)
		} else if a < 25 {
			t.Fatalf("never-run phase %q reported age %.1fs; want ~30s since start", phase, a)
		}
	}
	if _, ok := ages["warm"]; ok {
		t.Fatal("warm phase reported on a non-clustered daemon; it is HA-only")
	}

	// Mark resolve just-completed; its age drops near zero while the others
	// keep climbing from start — the healthy-vs-stalled contrast operators
	// read off the gauge.
	d.resolveLastSuccessNanos.Store(time.Now().UnixNano())
	ages = d.NeighborPeriodicPhaseAges()
	if ages["resolve"] > 2 {
		t.Fatalf("just-completed resolve phase reported age %.1fs; want ~0", ages["resolve"])
	}
	if ages["force_probe"] < 25 {
		t.Fatalf("stalled force_probe phase reported age %.1fs; want ~30s", ages["force_probe"])
	}

	// A last-success timestamp in the future (models a backward clock step)
	// must clamp to 0, not report a negative age (Copilot #1781 r2).
	d.cleanFailedLastSuccessNanos.Store(time.Now().Add(10 * time.Second).UnixNano())
	if got := d.NeighborPeriodicPhaseAges()["clean_failed"]; got < 0 {
		t.Fatalf("backward-clock-step age not clamped: got %.3fs, want >= 0", got)
	}
}
