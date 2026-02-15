package conntrack

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/psaab/bpfrx/pkg/dataplane"
)

// mockGCDP is a minimal mock dataplane for GC testing.
// Embeds DataPlane interface to satisfy the full contract; only the methods
// used by sweep() are implemented — others will panic if called.
type mockGCDP struct {
	dataplane.DataPlane // embedded interface satisfies all methods
	mu                  sync.Mutex
	v4sessions          map[dataplane.SessionKey]dataplane.SessionValue
	v6sessions          map[dataplane.SessionKeyV6]dataplane.SessionValueV6
	deleted             []dataplane.SessionKey
	deletedV6           []dataplane.SessionKeyV6
}

func (m *mockGCDP) IterateSessions(fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, v := range m.v4sessions {
		if !fn(k, v) {
			break
		}
	}
	return nil
}

func (m *mockGCDP) DeleteSession(key dataplane.SessionKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deleted = append(m.deleted, key)
	delete(m.v4sessions, key)
	return nil
}

func (m *mockGCDP) IterateSessionsV6(fn func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, v := range m.v6sessions {
		if !fn(k, v) {
			break
		}
	}
	return nil
}

func (m *mockGCDP) DeleteSessionV6(key dataplane.SessionKeyV6) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deletedV6 = append(m.deletedV6, key)
	delete(m.v6sessions, key)
	return nil
}

func (m *mockGCDP) DeleteDNATEntry(_ dataplane.DNATKey) error       { return nil }
func (m *mockGCDP) DeleteDNATEntryV6(_ dataplane.DNATKeyV6) error   { return nil }
func (m *mockGCDP) GetPersistentNAT() *dataplane.PersistentNATTable { return nil }

func TestGCDeleteCallbackV4(t *testing.T) {
	now := monotonicSeconds()
	fwdKey := dataplane.SessionKey{SrcIP: [4]byte{10, 0, 1, 1}, DstIP: [4]byte{10, 0, 2, 1}, Protocol: 6, SrcPort: 1000, DstPort: 80}
	revKey := dataplane.SessionKey{SrcIP: [4]byte{10, 0, 2, 1}, DstIP: [4]byte{10, 0, 1, 1}, Protocol: 6, SrcPort: 80, DstPort: 1000}

	dp := &mockGCDP{
		v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{
			fwdKey: {
				State: dataplane.SessStateEstablished, IsReverse: 0,
				LastSeen: now - 200, Timeout: 100, // expired
				ReverseKey: revKey,
			},
			revKey: {
				State: dataplane.SessStateEstablished, IsReverse: 1,
				LastSeen: now - 200, Timeout: 100,
			},
		},
		v6sessions: map[dataplane.SessionKeyV6]dataplane.SessionValueV6{},
	}

	gc := NewGC(dp, time.Minute) // interval doesn't matter for direct sweep call

	var callbackKeys []dataplane.SessionKey
	gc.OnDeleteV4 = func(key dataplane.SessionKey) {
		callbackKeys = append(callbackKeys, key)
	}

	gc.sweep()

	// Callback should fire exactly once (for the forward entry only)
	if len(callbackKeys) != 1 {
		t.Fatalf("expected 1 callback, got %d", len(callbackKeys))
	}
	if callbackKeys[0] != fwdKey {
		t.Fatalf("callback key mismatch: got %+v, want %+v", callbackKeys[0], fwdKey)
	}
}

func TestGCDeleteCallbackV6(t *testing.T) {
	now := monotonicSeconds()
	fwdKey := dataplane.SessionKeyV6{SrcIP: [16]byte{0x20, 0x01}, Protocol: 6, SrcPort: 1000, DstPort: 80}
	revKey := dataplane.SessionKeyV6{SrcIP: [16]byte{0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, Protocol: 6, SrcPort: 80, DstPort: 1000}

	dp := &mockGCDP{
		v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{},
		v6sessions: map[dataplane.SessionKeyV6]dataplane.SessionValueV6{
			fwdKey: {
				State: dataplane.SessStateEstablished, IsReverse: 0,
				LastSeen: now - 200, Timeout: 100,
				ReverseKey: revKey,
			},
			revKey: {
				State: dataplane.SessStateEstablished, IsReverse: 1,
				LastSeen: now - 200, Timeout: 100,
			},
		},
	}

	gc := NewGC(dp, time.Minute)

	var callbackKeys []dataplane.SessionKeyV6
	gc.OnDeleteV6 = func(key dataplane.SessionKeyV6) {
		callbackKeys = append(callbackKeys, key)
	}

	gc.sweep()

	if len(callbackKeys) != 1 {
		t.Fatalf("expected 1 v6 callback, got %d", len(callbackKeys))
	}
	if callbackKeys[0] != fwdKey {
		t.Fatalf("v6 callback key mismatch")
	}
}

func TestGCDeleteCallbackNil(t *testing.T) {
	now := monotonicSeconds()
	dp := &mockGCDP{
		v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{
			{Protocol: 6}: {
				IsReverse: 0, LastSeen: now - 200, Timeout: 100,
				ReverseKey: dataplane.SessionKey{Protocol: 6, SrcPort: 1},
			},
		},
		v6sessions: map[dataplane.SessionKeyV6]dataplane.SessionValueV6{},
	}

	gc := NewGC(dp, time.Minute)
	// No callback set — should not panic
	gc.sweep()

	if len(dp.deleted) == 0 {
		t.Fatal("expected deletions even without callback")
	}
}

func TestGCRunWithCallbacks(t *testing.T) {
	now := monotonicSeconds()
	dp := &mockGCDP{
		v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{
			{Protocol: 6, SrcPort: 1}: {
				IsReverse: 0, LastSeen: now - 200, Timeout: 100,
				ReverseKey: dataplane.SessionKey{Protocol: 6, SrcPort: 2},
			},
		},
		v6sessions: map[dataplane.SessionKeyV6]dataplane.SessionValueV6{},
	}

	gc := NewGC(dp, 50*time.Millisecond)

	var mu sync.Mutex
	var called int
	gc.OnDeleteV4 = func(key dataplane.SessionKey) {
		mu.Lock()
		called++
		mu.Unlock()
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	gc.Run(ctx)

	mu.Lock()
	defer mu.Unlock()
	if called != 1 {
		t.Fatalf("expected 1 callback from Run, got %d", called)
	}
}
