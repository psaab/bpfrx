package cluster

import "testing"

// TestHeartbeatNonceIsIncarnationScoped_6169 pins the Stage-0 half of the fix:
// the sender's anti-replay session is drawn once per DAEMON incarnation, not
// once per heartbeatSender. A per-sender session let a single long-lived daemon
// mint more than a ringful of sessions under ONE boot epoch (every VRF rebind
// and comms restart mints one), which the epoch floor cannot separate — so the
// ring stayed churnable within an incarnation.
func TestHeartbeatNonceIsIncarnationScoped_6169(t *testing.T) {
	m := NewManager(0, 42)
	session0, counter0 := m.heartbeatNonce()
	if counter0 != 1 {
		t.Fatalf("first counter = %d, want 1", counter0)
	}
	prev := counter0
	for i := 0; i < 100; i++ {
		session, counter := m.heartbeatNonce()
		if session != session0 {
			t.Fatalf("session changed within one incarnation: %#x then %#x", session0, session)
		}
		if counter <= prev {
			t.Fatalf("counter did not advance: %d then %d", prev, counter)
		}
		prev = counter
	}
	// A heartbeat restart builds a new sender; the nonce must NOT be re-drawn.
	s1 := newHeartbeatSender(m, nil, nil, DefaultHeartbeatInterval)
	s2 := newHeartbeatSender(m, nil, nil, DefaultHeartbeatInterval)
	_ = s1
	_ = s2
	session, counter := m.heartbeatNonce()
	if session != session0 {
		t.Fatalf("session re-drawn across a heartbeat restart: %#x then %#x", session0, session)
	}
	if counter <= prev {
		t.Fatalf("counter restarted across a heartbeat restart: %d then %d", prev, counter)
	}
	// A new daemon incarnation (new Manager) draws a fresh session, so the peer
	// still sees a never-seen session after a real restart.
	if other, _ := NewManager(0, 42).heartbeatNonce(); other == session0 {
		t.Fatal("a new Manager reused the previous incarnation's session id")
	}
}
