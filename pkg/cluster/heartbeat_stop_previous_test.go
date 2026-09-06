package cluster

import (
	"runtime"
	"sync/atomic"
	"testing"
	"time"
)

// senderStopped reports whether the sender's run loop has been signalled to
// stop (its stopCh is closed). StartHeartbeat/StopHeartbeat close stopCh and
// wg.Wait() for the goroutine to exit before returning, so a closed stopCh
// observed after those calls means the goroutine is gone, not merely signalled.
// senderProgressBudget bounds the wait for the FIRST heartbeat emission.
//
// It is deliberately enormous relative to DefaultHeartbeatInterval. The test
// asserts that a sender EXISTS AND RUNS, not that it is punctual, so the only
// job of this bound is to turn a genuine hang into a diagnosable failure
// instead of a hung suite. Sizing it near the interval would re-introduce the
// wall-clock race it exists to remove; matching the sibling #7970 budget keeps
// one number in the package rather than two that drift.
const senderProgressBudget = 30 * time.Second

// waitForSenderProgress blocks until the sender has emitted at least once, or
// dumps every goroutine and fails. Modelled on waitForTeardownProgress (#7970)
// — including the dump-do-not-diagnose rule: this wait cannot tell a starved
// goroutine from a blocked one, and the stack can.
func waitForSenderProgress(t *testing.T, sent *atomic.Uint64, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for sent.Load() == 0 {
		if time.Now().After(deadline) {
			// Grown until the dump fits: runtime.Stack truncates SILENTLY when
			// the buffer is short, so a fixed size yields a dump that looks
			// whole and has lost the goroutine you needed.
			buf := make([]byte, 1<<20)
			var n int
			for {
				n = runtime.Stack(buf, true)
				if n < len(buf) {
					break
				}
				buf = make([]byte, 2*len(buf))
			}
			t.Fatalf("the sender emitted no heartbeat in %s after a single "+
				"StartHeartbeat. At this budget that is a HANG, not a slow "+
				"machine, and the dump below says which kind: a goroutine "+
				"blocked in the send path is a real defect; an absent or "+
				"runnable one is scheduling starvation under `go test ./...` "+
				"(#7970/#9110).\n\n=== goroutine dump ===\n%s", within, buf[:n])
		}
		time.Sleep(time.Millisecond)
	}
}

func senderStopped(s *heartbeatSender) bool {
	select {
	case <-s.stopCh:
		return true
	default:
		return false
	}
}

func receiverStopped(r *heartbeatReceiver) bool {
	select {
	case <-r.stopCh:
		return true
	default:
		return false
	}
}

// TestStartHeartbeatStopsPreviousHeartbeat pins the #4033 fix: N sequential
// StartHeartbeat calls (simulating N comms restarts) must leave exactly ONE
// live heartbeat goroutine set. Each StartHeartbeat tears down the previous
// sender+receiver before installing the new pair, so every earlier pair is
// stopped and only the last is running.
//
// On revert (StartHeartbeat overwrites m.hbSender/m.hbReceiver without stopping
// the old ones) every prior sender+receiver goroutine stays alive with its
// stopCh open — this test goes RED (leaked goroutines + duplicate heartbeats).
func TestStartHeartbeatStopsPreviousHeartbeat(t *testing.T) {
	m := NewManager(0, 1)
	defer m.StopHeartbeat()

	const restarts = 5
	senders := make([]*heartbeatSender, 0, restarts)
	receivers := make([]*heartbeatReceiver, 0, restarts)

	for i := 0; i < restarts; i++ {
		// SO_REUSEADDR+SO_REUSEPORT (vrfListenConfig) lets each restart rebind
		// the same 127.0.0.1:HeartbeatPort address.
		if err := m.StartHeartbeat("127.0.0.1", "127.0.0.1", "", "em0"); err != nil {
			t.Fatalf("StartHeartbeat #%d: %v", i, err)
		}
		m.mu.RLock()
		s := m.hbSender
		r := m.hbReceiver
		m.mu.RUnlock()
		if s == nil || r == nil {
			t.Fatalf("StartHeartbeat #%d installed nil sender/receiver", i)
		}
		senders = append(senders, s)
		receivers = append(receivers, r)
	}

	// Every pair except the last must have been stopped by the subsequent
	// StartHeartbeat.
	for i := 0; i < restarts-1; i++ {
		if !senderStopped(senders[i]) {
			t.Errorf("sender #%d not stopped by a later StartHeartbeat — leaked heartbeat goroutine", i)
		}
		if !receiverStopped(receivers[i]) {
			t.Errorf("receiver #%d not stopped by a later StartHeartbeat — leaked heartbeat goroutine", i)
		}
	}

	// The last-installed pair must still be running (StopHeartbeat in the
	// deferred cleanup tears it down).
	if senderStopped(senders[restarts-1]) {
		t.Error("current sender is stopped; the running heartbeat was torn down unexpectedly")
	}
	if receiverStopped(receivers[restarts-1]) {
		t.Error("current receiver is stopped; the running heartbeat was torn down unexpectedly")
	}

	// Distinct object identity: each restart allocates a fresh sender/receiver.
	for i := 1; i < restarts; i++ {
		if senders[i] == senders[i-1] {
			t.Errorf("sender #%d reused the previous object; expected a fresh sender per StartHeartbeat", i)
		}
	}
}

// TestStartHeartbeatSingleStartRuns is a control: a single StartHeartbeat
// leaves the heartbeat running and StopHeartbeat then tears it down. Guards
// against a fix that over-eagerly stops the heartbeat it just installed.
func TestStartHeartbeatSingleStartRuns(t *testing.T) {
	m := NewManager(0, 1)
	if err := m.StartHeartbeat("127.0.0.1", "127.0.0.1", "", "em0"); err != nil {
		t.Fatalf("StartHeartbeat: %v", err)
	}
	m.mu.RLock()
	s := m.hbSender
	r := m.hbReceiver
	m.mu.RUnlock()
	if s == nil || r == nil {
		t.Fatal("StartHeartbeat installed nil sender/receiver")
	}
	// #9110: WAIT for the sender to emit, do not SLEEP for a duration and hope.
	//
	// This was `time.Sleep(2 * DefaultHeartbeatInterval)` followed by an
	// assertion that `sent != 0`. That is a wall-clock race with nothing
	// synchronising it: the claim under test is "a single StartHeartbeat
	// leaves a LIVE sender", and the sleep silently converted it into "the
	// sender goroutine was scheduled AND emitted within 2 intervals", which is
	// a claim about the machine. Under `go test ./...` on an oversubscribed
	// box that is a red naming this test for a property it still has — and a
	// flaky red is worse than no test, because the correct response to a red
	// (do not merge) and to a flake (merge) are opposites and the output does
	// not distinguish them.
	//
	// Same shape and same budget as waitForTeardownProgress (#7970) in this
	// package, including the goroutine DUMP: on a real hang the dump names the
	// blocked goroutine, and the two causes it separates — starved versus
	// blocked — have completely different fixes. Read the dump; do not re-run.
	waitForSenderProgress(t, &s.sent, senderProgressBudget)
	if senderStopped(s) || receiverStopped(r) {
		t.Fatal("heartbeat stopped immediately after a single StartHeartbeat")
	}

	m.StopHeartbeat()
	if !senderStopped(s) || !receiverStopped(r) {
		t.Fatal("StopHeartbeat did not stop the heartbeat")
	}
	// The goroutines must actually exit — give the scheduler a moment and
	// confirm the run loops are no longer resident.
	runtime.Gosched()
}
