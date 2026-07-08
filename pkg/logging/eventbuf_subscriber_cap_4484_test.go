package logging

import "testing"

// TestTrySubscribeCap pins #4484 L-2: TrySubscribe enforces a bound on the
// number of concurrent subscribers so the untrusted REST SSE surface cannot
// grow the fan-out set (and its per-event O(N) cost) without limit. Subscribe
// stays unbounded for the trusted internal consumers but its subscribers count
// toward the same cap.
//
// RED on revert: dropping the `len(eb.subs) >= eb.maxSubs` guard in
// TrySubscribe (or setting maxSubs to 0) lets the (cap+1)-th TrySubscribe
// return a non-nil subscription and this test fails.
func TestTrySubscribeCap(t *testing.T) {
	eb := NewEventBuffer(16)
	if eb.maxSubs <= 0 {
		t.Fatalf("NewEventBuffer must set a positive maxSubs, got %d", eb.maxSubs)
	}

	// Fill the cap via TrySubscribe; every one must succeed.
	subs := make([]*Subscription, 0, eb.maxSubs)
	for i := 0; i < eb.maxSubs; i++ {
		s := eb.TrySubscribe(4)
		if s == nil {
			t.Fatalf("TrySubscribe #%d returned nil below the cap %d", i, eb.maxSubs)
		}
		subs = append(subs, s)
	}

	// One past the cap must be rejected.
	if over := eb.TrySubscribe(4); over != nil {
		over.Close()
		t.Fatalf("TrySubscribe past the cap %d must return nil", eb.maxSubs)
	}

	// Closing one frees a slot; TrySubscribe succeeds again.
	subs[0].Close()
	freed := eb.TrySubscribe(4)
	if freed == nil {
		t.Fatalf("TrySubscribe must succeed after a slot is freed")
	}
	freed.Close()
	for _, s := range subs[1:] {
		s.Close()
	}
}

// TestSubscribeUnboundedForTrustedCallers asserts the trusted Subscribe entry
// point is NOT gated by the cap (a live cluster/CLI consumer must never be
// rejected), but its subscribers still count against TrySubscribe.
func TestSubscribeUnboundedForTrustedCallers(t *testing.T) {
	eb := NewEventBuffer(16)

	// Saturate the cap using the trusted Subscribe path.
	for i := 0; i < eb.maxSubs; i++ {
		if s := eb.Subscribe(4); s == nil {
			t.Fatalf("Subscribe must never return nil (call #%d)", i)
		}
	}
	// Subscribe still succeeds beyond the cap.
	if s := eb.Subscribe(4); s == nil {
		t.Fatalf("Subscribe must stay unbounded past the cap")
	}
	// But the untrusted TrySubscribe path now sees a full set and rejects.
	if over := eb.TrySubscribe(4); over != nil {
		over.Close()
		t.Fatalf("TrySubscribe must reject when Subscribe callers already fill the cap")
	}
}
