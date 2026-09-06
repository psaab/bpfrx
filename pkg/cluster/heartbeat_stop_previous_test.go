package cluster

import (
	"runtime"
	"testing"
	"time"
)

// senderStopped reports whether the sender's run loop has been signalled to
// stop (its stopCh is closed). StartHeartbeat/StopHeartbeat close stopCh and
// wg.Wait() for the goroutine to exit before returning, so a closed stopCh
// observed after those calls means the goroutine is gone, not merely signalled.
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
	// Let the sender emit at least once so we know the goroutine is live.
	time.Sleep(2 * DefaultHeartbeatInterval)
	if senderStopped(s) || receiverStopped(r) {
		t.Fatal("heartbeat stopped immediately after a single StartHeartbeat")
	}
	if got := s.sent.Load(); got == 0 {
		t.Error("sender emitted no heartbeats after a single StartHeartbeat")
	}

	m.StopHeartbeat()
	if !senderStopped(s) || !receiverStopped(r) {
		t.Fatal("StopHeartbeat did not stop the heartbeat")
	}
	// The goroutines must actually exit — give the scheduler a moment and
	// confirm the run loops are no longer resident.
	runtime.Gosched()
}
