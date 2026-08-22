package cluster

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
)

// #7257 — StartHeartbeat published m.hbSender/m.hbReceiver under m.mu, RELEASED
// the lock, and then dereferenced the fields it had just written:
//
//	m.mu.Unlock()
//	m.hbReceiver.start()   // unlocked read
//	m.hbSender.start()     // unlocked read
//
// while StopHeartbeat nils both under the lock. Two outcomes, both live:
//
//  1. nil-deref panic, if the stop lands in that gap;
//  2. a sender/receiver pair started AFTER a stop already captured and nilled
//     the handles — running with nothing able to stop it, on a torn-down
//     cluster. That one is worse than the panic: it is silent.
//
// Reachable because startHeartbeatWithRetry runs on a bare `go` goroutine that
// is NOT in clusterCommsWG (unlike the sync constructor), so stopClusterComms
// never joins it — it only cancels the context and calls StopHeartbeat.
//
// CI has no path to it: make test-go's race gate (test-race-dp) runs -race
// under a fixed -run filter and nothing in that set drives startClusterComms
// with a control-link endpoint, so the heartbeat path is never raced.

// TestStartHeartbeatDoesNotRaceStopHeartbeat7257 is the race probe.
//
// The BOUNDED side is the expensive one. StartHeartbeat creates two UDP
// sockets; StopHeartbeat is nearly free. A first draft bounded the stops and
// looped the starts "until done", and the logged rate gave it away immediately:
// 1 start against 200 stops — the cheap loop ran to completion inside the
// expensive loop's first pass, so the window was raced approximately once.
// Bounding the starts and looping the stops until they signal done is what
// makes every start contend.
//
// The count is logged rather than assumed, so a future change that makes
// StartHeartbeat slower turns a degenerate probe into a visible one instead of
// a quiet pass.
//
// The assertion is the race detector, so this is only meaningful under -race.
// RED on revert: restore the unlocked `m.hbReceiver.start()` / `m.hbSender.start()`
// pair after the Unlock and `go test -race -run TestStartHeartbeatDoesNotRaceStopHeartbeat7257
// ./pkg/cluster/` reports WARNING: DATA RACE naming StartHeartbeat and StopHeartbeat.
func TestStartHeartbeatDoesNotRaceStopHeartbeat7257(t *testing.T) {
	m := NewManager(0, 1)

	const startAttempts = 60
	var stops, starts atomic.Int64
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)

	// BOUNDED, expensive side: a fixed number of starts.
	go func() {
		defer wg.Done()
		defer close(done)
		for i := 0; i < startAttempts; i++ {
			// Loopback both ways: the bind succeeds without a cluster peer.
			// A superseded start is a valid outcome here, not a failure — it
			// is the outcome this whole change exists to produce.
			if err := m.StartHeartbeat("127.0.0.1", "127.0.0.1", ""); err == nil ||
				errors.Is(err, ErrHeartbeatStartSuperseded) {
				starts.Add(1)
			}
		}
	}()
	// UNBOUNDED, cheap side: keep tearing down until the starts are finished,
	// so each start is contended rather than running alone.
	go func() {
		defer wg.Done()
		for {
			select {
			case <-done:
				return
			default:
			}
			m.StopHeartbeat()
			stops.Add(1)
		}
	}()
	wg.Wait()
	m.StopHeartbeat()

	if got := starts.Load(); got < startAttempts {
		t.Fatalf("only %d of %d starts completed — the probe under-exercised its window", got, startAttempts)
	}
	if stops.Load() < starts.Load() {
		t.Fatalf("#7257 probe is degenerate: %d stops against %d starts — the teardown side "+
			"must out-run the start side or the window is barely contended",
			stops.Load(), starts.Load())
	}
	t.Logf("#7257 race probe: %d starts against %d stops (%.1f stops/start)",
		starts.Load(), stops.Load(), float64(stops.Load())/float64(starts.Load()))
}

// TestStartHeartbeatSupersededByStopDoesNotPublish7257 is the deterministic
// half. The race detector is probabilistic and only runs under -race, so the
// start-after-stop outcome needs an assertion that depends on neither.
//
// A start that a teardown overtook must not install a heartbeat. Before #7257
// it did: StopHeartbeat captured and nilled the handles, the in-flight start
// then wrote its own pair into the freshly-nilled fields and spawned their
// goroutines, and nothing held a handle to stop them. Silent, and on a cluster
// that has been torn down.
//
// The teardown is landed through hbStartInWindowHook rather than with a sleep.
// The first version of this test slept 2 ms and hoped the stop would land
// during socket creation; it did not, and the test PASSED against a build with
// the epoch guard removed — vacuous by exactly the margin the sleep was wrong
// by. The hook fires inside the guarded window by construction, so there is no
// timing to get right.
//
// RED on revert: drop the `m.hbEpoch != startEpoch` check from StartHeartbeat's
// publish critical section and both assertions fire.
func TestStartHeartbeatSupersededByStopDoesNotPublish7257(t *testing.T) {
	m := NewManager(0, 1)
	t.Cleanup(m.StopHeartbeat)

	var fired atomic.Int64
	m.mu.Lock()
	m.hbStartInWindowHook = func() {
		// Only the first start is superseded; a hook that fired forever would
		// make the negative control below unreachable.
		if fired.Add(1) == 1 {
			m.StopHeartbeat()
		}
	}
	m.mu.Unlock()

	err := m.StartHeartbeat("127.0.0.1", "127.0.0.1", "")
	if fired.Load() == 0 {
		t.Fatal("setup: the in-window hook never fired, so no teardown was landed in the window")
	}
	if !errors.Is(err, ErrHeartbeatStartSuperseded) {
		t.Fatalf("#7257: StartHeartbeat = %v, want ErrHeartbeatStartSuperseded — a start the "+
			"teardown overtook must decline to publish", err)
	}
	if m.HeartbeatRunning() {
		t.Fatal("#7257: a heartbeat is running after the teardown that superseded its start — " +
			"the pair was published into the nilled fields and nothing holds a handle to stop it")
	}
}

// TestStartHeartbeatStillPublishesWithoutAContendingStop7257 is the negative
// control. The epoch guard must refuse ONLY a superseded start; an ordinary one
// must still install a heartbeat, or the fix would be a heartbeat that never
// starts — which no other test in this package would catch, because they all
// call StartHeartbeat and check its error rather than the resulting state.
func TestStartHeartbeatStillPublishesWithoutAContendingStop7257(t *testing.T) {
	m := NewManager(0, 1)
	t.Cleanup(m.StopHeartbeat)

	if err := m.StartHeartbeat("127.0.0.1", "127.0.0.1", ""); err != nil {
		t.Fatalf("StartHeartbeat() = %v, want nil with no contending teardown", err)
	}
	if !m.HeartbeatRunning() {
		t.Fatal("an uncontended StartHeartbeat must leave a heartbeat running")
	}
}

// TestRestartHeartbeatSurvivesTheEpochGuard7257 pins the trap the epoch capture
// had to be placed around. StartHeartbeat performs its OWN idempotent teardown
// (#4033) before creating sockets, and that teardown bumps the tenure too.
// Capturing the tenure at function ENTRY would compare against a value the call
// had itself invalidated, so every start — including every restart — would
// refuse to publish and the heartbeat would silently never come up.
//
// RestartHeartbeat is the caller that makes this concrete: it stops, then
// starts, in one call.
//
// RED on revert: move the `startEpoch` capture above the internal
// `m.StopHeartbeat()` and this fails on the running assertion.
func TestRestartHeartbeatSurvivesTheEpochGuard7257(t *testing.T) {
	m := NewManager(0, 1)
	t.Cleanup(m.StopHeartbeat)

	if err := m.StartHeartbeat("127.0.0.1", "127.0.0.1", ""); err != nil {
		t.Fatalf("setup StartHeartbeat: %v", err)
	}
	if !m.RestartHeartbeat() {
		t.Fatal("RestartHeartbeat reported nothing running after a successful start")
	}
	if !m.HeartbeatRunning() {
		t.Fatal("#7257: the heartbeat is not running after a restart — the epoch guard " +
			"refused a start that its own idempotent teardown superseded")
	}
}
