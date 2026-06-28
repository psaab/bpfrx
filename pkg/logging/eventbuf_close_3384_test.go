package logging

import (
	"testing"
	"time"
)

// TestSubscriptionCloseClosesChannel guards #3384: Subscription.Close is
// documented to "unsubscribe and close the channel". Before the fix it only
// unsubscribed, so a consumer ranging over sub.C until it closes blocked
// forever.
//
// FAIL-ON-REVERT: dropping close(s.C) from Close makes the post-Close receive
// block, tripping the timeout below.
func TestSubscriptionCloseClosesChannel(t *testing.T) {
	eb := NewEventBuffer(8)
	sub := eb.Subscribe(4)

	exited := make(chan struct{})
	go func() {
		// A consumer that follows the documented contract: range until the
		// channel closes. This returns only if Close() actually closes C.
		for range sub.C {
		}
		close(exited)
	}()

	sub.Close()

	select {
	case <-exited:
	case <-time.After(2 * time.Second):
		t.Fatal("subscriber goroutine did not exit after Close — channel was not closed")
	}

	// A receive on a closed channel returns the zero value with ok == false.
	if _, ok := <-sub.C; ok {
		t.Fatal("receive after Close returned ok == true; channel not closed")
	}
}

// TestSubscriptionDoubleCloseSafe verifies the sync.Once guard: the in-tree
// consumers Close via defer and some also Close explicitly, so a double Close
// must not panic with close-of-closed-channel.
func TestSubscriptionDoubleCloseSafe(t *testing.T) {
	eb := NewEventBuffer(8)
	sub := eb.Subscribe(4)

	sub.Close()
	sub.Close() // must not panic
}

// TestSubscriptionCloseNoSendOnClosedRace exercises the unsubscribe-then-close
// ordering against a concurrent Add. unsubscribe runs under the write lock and
// removes the subscription before close(C), so Add can never send on a closed
// channel. Run with -race to catch a regression.
func TestSubscriptionCloseNoSendOnClosedRace(t *testing.T) {
	eb := NewEventBuffer(8)
	sub := eb.Subscribe(1)

	done := make(chan struct{})
	go func() {
		for i := 0; i < 10000; i++ {
			eb.Add(EventRecord{Type: "SESSION_OPEN"})
		}
		close(done)
	}()

	// Close while Add is hammering the fan-out. No panic / race allowed.
	sub.Close()
	<-done
}
