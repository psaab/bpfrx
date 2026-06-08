package daemon

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// #1780 Path A: the periodic neighbor-maintenance loop must survive a phase
// whose netlink/probe syscall wedges. These tests pin the three guarantees the
// fix rests on:
//
//   1. runGuardedNeighborPhase NEVER blocks its caller — the phase body runs in
//      a goroutine, so a hung phase cannot freeze the for-select loop.
//   2. While a phase is in flight the guard SKIPS relaunch (no overlapping
//      pass, no per-tick goroutine/socket leak), and relaunches once the prior
//      pass returns.
//   3. NeighborPeriodicPhaseAges advances for a stalled phase (its last-success
//      timestamp stops updating) while a healthy phase stays near zero — the
//      observable watchdog signal.

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

func TestNeighborPeriodicPhaseAgesReflectsStall(t *testing.T) {
	// startTime in the past so a never-run phase reports a non-trivial age.
	d := &Daemon{startTime: time.Now().Add(-30 * time.Second)}

	// All phases never-run: each reports ~age-since-start (~30s), proving a
	// phase that never completes still flags rather than reading zero.
	ages := d.NeighborPeriodicPhaseAges()
	for _, phase := range []string{"resolve", "force_probe", "clean_failed", "warm"} {
		if a, ok := ages[phase]; !ok {
			t.Fatalf("phase %q missing from age map", phase)
		} else if a < 25 {
			t.Fatalf("never-run phase %q reported age %.1fs; want ~30s since start", phase, a)
		}
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
}
