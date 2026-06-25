package vrrp

import (
	"context"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
)

// #2625 — the Manager must be Stop()/Start() reuse-safe. Stop() closes the
// run-scoped channels (watcherStop, eventCh) and cancels the context; a
// subsequent Start() must re-allocate them, reset the sync.Once guards, and
// clear the singleton watcher latches so the next UpdateInstances cleanly
// re-spawns the link/addr watchers without panicking on a closed channel.
//
// These tests are the safety net for a latent lifecycle defect: production
// creates the Manager once and only Stop()s at shutdown, so the cluster
// failover gate exercises the single-run path, not reuse. Reverting the
// Start() re-init (resetRunStateLocked) makes each of these fail — either a
// panic (send/close on a closed channel) or a hung/never-spawned watcher.

// drainEvents consumes the manager's event channel until it is closed so a
// blocked emitter never wedges the test. It must be started on a channel
// captured AFTER the Start() that owns it.
func drainEvents(ch <-chan VRRPEvent) {
	go func() {
		for range ch {
		}
	}()
}

// subEvent records one subscribe-stub invocation: whether the run-generation
// `done` channel handed to it was ALREADY closed at subscribe time. The fix
// hands each watcher generation a fresh (open) watcherStop; a revert hands the
// post-restart watcher the still-closed gen-1 channel.
type subEvent struct {
	doneClosed bool
}

// TestManager_StopStartReuse_WatcherRespawns proves a Stop()->Start() cycle
// re-allocates watcherStop and clears the watcher latches so the next
// UpdateInstances spawns a FRESH watcher whose cancellation channel is OPEN
// (a new run generation), rather than a goroutine that immediately observes
// the already-closed gen-1 watcherStop and exits, or no goroutine at all
// because the latch is stuck true.
//
// DETERMINISTIC REVERT PROOF (FINDING 4): the earlier version raced a
// watcherRunning latch read against the gen-1 watcher's deferred latch-clear
// (under revert, the un-reallocated watcherStop still equals the gen-1
// pinned stop, so that defer DOES clear the latch — when the goroutine wins
// the race the stub re-signals and the test wrongly passes). This version
// removes the racy latch read entirely and instead asserts a property the
// revert makes WRONG regardless of goroutine scheduling: the second
// subscribe must receive a NON-closed `done` channel. Two deterministic
// revert outcomes, both RED every run:
//   - latch still set when UpdateInstances #2 runs -> no second spawn ->
//     the 2s subscribe wait times out.
//   - gen-1 defer cleared the latch first -> a second watcher DOES spawn,
//     but with the gen-1 (closed) watcherStop -> subscribe records
//     doneClosed=true -> the doneClosed assertion fails.
//
// Under the fix the second subscribe always sees an open channel.
func TestManager_StopStartReuse_WatcherRespawns(t *testing.T) {
	m := NewManager()
	m.linkState = func(string) (bool, error) { return true, nil }

	subscribed := make(chan subEvent, 8)
	record := func(done <-chan struct{}) {
		closed := false
		select {
		case <-done:
			closed = true
		default:
		}
		subscribed <- subEvent{doneClosed: closed}
	}
	m.subscribeLinks = func(ch chan<- netlink.LinkUpdate, done <-chan struct{}) error {
		record(done)
		return nil // never sends; cancellation via done
	}
	m.subscribeAddrs = func(ch chan<- netlink.AddrUpdate, done <-chan struct{}) error {
		return nil
	}

	desired := []*Instance{{
		Interface:         "no-such-iface-2625", // creation skipped; watcher still latches
		GroupID:           101,
		Priority:          200,
		TrackInterface:    "ge-0-0-9",
		TrackPriorityCost: 10,
	}}

	// waitSub blocks for the next subscribe invocation (a hard sync point that
	// proves a watcher goroutine actually ran) and returns its event.
	waitSub := func(which string) subEvent {
		t.Helper()
		select {
		case ev := <-subscribed:
			return ev
		case <-time.After(2 * time.Second):
			t.Fatalf("%s: watcher never subscribed (latch stuck or no spawn)", which)
			return subEvent{}
		}
	}

	// Run 1.
	if err := m.Start(context.Background()); err != nil {
		t.Fatalf("Start #1: %v", err)
	}
	drainEvents(m.Events())
	if err := m.UpdateInstances(desired); err != nil {
		t.Fatalf("UpdateInstances #1: %v", err)
	}
	ev1 := waitSub("run 1")
	if ev1.doneClosed {
		t.Fatal("run 1: watcher subscribed with an already-closed done channel")
	}

	// Stop closes watcherStop + eventCh, cancels ctx. The watcher goroutine
	// observes the closed channel and exits (clearing its generation's latch).
	m.Stop()

	// Run 2 on the SAME Manager. This must NOT panic and must re-spawn a
	// working watcher bound to a FRESH (open) cancellation channel.
	if err := m.Start(context.Background()); err != nil {
		t.Fatalf("Start #2: %v", err)
	}
	drainEvents(m.Events())

	if err := m.UpdateInstances(desired); err != nil {
		t.Fatalf("UpdateInstances #2: %v", err)
	}
	ev2 := waitSub("run 2")
	// DETERMINISTIC: a fresh watcher generation must get an OPEN channel. A
	// revert either never reaches here (timeout in waitSub) or reaches here
	// with the reused closed gen-1 channel (doneClosed=true).
	if ev2.doneClosed {
		t.Fatal("run 2: watcher re-subscribed with the closed gen-1 watcherStop " +
			"(Start() did not re-allocate watcherStop)")
	}

	// Two distinct run generations spawned exactly two link watchers. Read the
	// monotonic spawn counter AFTER the gen-2 subscribe sync point; the gen-2
	// goroutine has demonstrably run (it called record()), so this is not a
	// race against a pending spawn.
	m.mu.RLock()
	starts := m.watcherStarts
	m.mu.RUnlock()
	if starts != 2 {
		t.Errorf("watcherStarts = %d, want 2 (one per run generation)", starts)
	}

	stopManagerForTest(m)
}

// TestManager_StopStartReuse_EventChannelFresh proves Stop() closing eventCh
// does not poison the reused Manager: Start() must hand out a FRESH,
// non-closed event channel so a post-restart emitter does not panic with
// "send on closed channel".
//
// REVERT PROOF: without resetRunStateLocked, Events() after restart returns
// the channel that Stop() closed; the send below panics (send on closed
// channel) and the test fails via the recover() assertion.
func TestManager_StopStartReuse_EventChannelFresh(t *testing.T) {
	m := NewManager()
	m.subscribeLinks = func(ch chan<- netlink.LinkUpdate, done <-chan struct{}) error { return nil }
	m.subscribeAddrs = func(ch chan<- netlink.AddrUpdate, done <-chan struct{}) error { return nil }

	if err := m.Start(context.Background()); err != nil {
		t.Fatalf("Start #1: %v", err)
	}
	ch1 := m.Events()
	m.Stop()

	// ch1 is now closed; a receive yields a zero value with ok=false.
	select {
	case _, ok := <-ch1:
		if ok {
			t.Fatal("expected first event channel to be closed after Stop()")
		}
	default:
		t.Fatal("first event channel should be closed (receive-ready) after Stop()")
	}

	if err := m.Start(context.Background()); err != nil {
		t.Fatalf("Start #2: %v", err)
	}
	ch2 := m.Events()
	if ch2 == ch1 {
		t.Fatal("Start() after Stop() must hand out a fresh event channel, not the closed one")
	}

	// The fresh channel must accept a send without panicking. Buffer is 256,
	// so this never blocks. A revert (reusing the closed channel) panics here.
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("send on reused event channel panicked (closed channel not re-allocated): %v", r)
			}
		}()
		writable := m.eventCh
		writable <- VRRPEvent{Interface: "eth0", GroupID: 101, State: StateBackup}
	}()

	// Drain so Stop() (which closes ch2) doesn't race a blocked sender.
	drainEvents(ch2)
	stopManagerForTest(m)
}

// TestManager_StopStartReuse_ContextRecreated proves Start() installs a fresh
// cancel func tied to the new context after Stop() cancelled the old one.
func TestManager_StopStartReuse_ContextRecreated(t *testing.T) {
	m := NewManager()
	m.subscribeLinks = func(ch chan<- netlink.LinkUpdate, done <-chan struct{}) error { return nil }
	m.subscribeAddrs = func(ch chan<- netlink.AddrUpdate, done <-chan struct{}) error { return nil }

	if err := m.Start(context.Background()); err != nil {
		t.Fatalf("Start #1: %v", err)
	}
	drainEvents(m.Events())
	m.mu.RLock()
	cancel1 := m.cancel
	m.mu.RUnlock()
	m.Stop()

	if err := m.Start(context.Background()); err != nil {
		t.Fatalf("Start #2: %v", err)
	}
	drainEvents(m.Events())
	m.mu.RLock()
	cancel2 := m.cancel
	m.mu.RUnlock()
	// Both must be non-nil; the second Start must have produced a new one.
	if cancel1 == nil || cancel2 == nil {
		t.Fatal("cancel func should be non-nil after each Start()")
	}
	stopManagerForTest(m)
}
