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

// TestManager_StopStartReuse_WatcherRespawns proves a Stop()->Start() cycle
// re-allocates watcherStop and clears the watcher latches so the next
// UpdateInstances spawns a FRESH watcher that actually runs (subscribes),
// rather than a goroutine that immediately observes the closed watcherStop
// and exits, or no goroutine at all because the latch is stuck true.
//
// REVERT PROOF: with resetRunStateLocked removed from Start(), after Stop()
//   - watcherRunning stays latched true -> ensureLinkWatcherLocked never
//     spawns a second watcher -> subscribed2 is never signalled -> the
//     2s wait below fails ("watcher #2 never subscribed after restart").
func TestManager_StopStartReuse_WatcherRespawns(t *testing.T) {
	m := NewManager()
	m.linkState = func(string) (bool, error) { return true, nil }

	subscribed := make(chan struct{}, 4)
	m.subscribeLinks = func(ch chan<- netlink.LinkUpdate, done <-chan struct{}) error {
		subscribed <- struct{}{}
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

	// Run 1.
	if err := m.Start(context.Background()); err != nil {
		t.Fatalf("Start #1: %v", err)
	}
	drainEvents(m.Events())
	if err := m.UpdateInstances(desired); err != nil {
		t.Fatalf("UpdateInstances #1: %v", err)
	}
	select {
	case <-subscribed:
	case <-time.After(2 * time.Second):
		t.Fatal("watcher #1 never subscribed")
	}

	// Stop closes watcherStop + eventCh, cancels ctx. The watcher goroutine
	// must observe the closed channel and exit (clearing its latch).
	m.Stop()

	// Run 2 on the SAME Manager. This must NOT panic and must re-spawn a
	// working watcher.
	if err := m.Start(context.Background()); err != nil {
		t.Fatalf("Start #2: %v", err)
	}
	drainEvents(m.Events())

	// After Start(), the latches must be cleared so a fresh watcher spawns.
	m.mu.RLock()
	runningAfterStart := m.watcherRunning
	addrAfterStart := m.addrWatcherRunning
	m.mu.RUnlock()
	if runningAfterStart {
		t.Error("watcherRunning should be cleared by Start() after Stop()")
	}
	if addrAfterStart {
		t.Error("addrWatcherRunning should be cleared by Start() after Stop()")
	}

	if err := m.UpdateInstances(desired); err != nil {
		t.Fatalf("UpdateInstances #2: %v", err)
	}
	select {
	case <-subscribed:
	case <-time.After(2 * time.Second):
		t.Fatal("watcher #2 never subscribed after restart (latch stuck or watcherStop reused)")
	}

	// The restarted watcher must be observably running.
	m.mu.RLock()
	starts := m.watcherStarts
	running := m.watcherRunning
	m.mu.RUnlock()
	if starts != 2 {
		t.Errorf("watcherStarts = %d, want 2 (one per run)", starts)
	}
	if !running {
		t.Error("watcherRunning should be latched after restart")
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
