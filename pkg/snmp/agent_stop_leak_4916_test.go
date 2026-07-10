package snmp

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// #4916: Agent.Stop() previously only set stopped + closed the socket. It did
// not cancel the ctx-watcher goroutine (so on a day-2 disable, with the daemon
// context still live, `<-ctx.Done()` blocked forever) and did not stop/drain
// the trap worker (which ranged an unclosed channel forever and could deliver a
// queued trap to a removed/rotated receiver after Stop). Each disable/re-enable
// cycle leaked another goroutine pair.

// TestStop_CancelsWatcherContext proves Stop cancels the lifecycle context the
// ctx-watcher goroutine waits on. RED on revert: drop the a.lifeCancel() call in
// Stop and the modeled watcher never unblocks, so this times out.
func TestStop_CancelsWatcherContext(t *testing.T) {
	a := &Agent{}
	ctx, cancel := context.WithCancel(context.Background())
	a.lifeCancel = cancel

	// Model the goroutine Start() spawns: it blocks until the lifecycle
	// context is cancelled, then would call a.Stop().
	watcherDone := make(chan struct{})
	go func() {
		<-ctx.Done()
		close(watcherDone)
	}()

	a.Stop()

	select {
	case <-watcherDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop did not cancel the lifecycle context — the ctx-watcher goroutine would leak (#4916)")
	}
}

// TestStop_StopsTrapWorkerNoPostDelivery proves Stop() stops the trap worker
// (no goroutine leak) and that a queued backlog is ABANDONED — no trap is
// delivered to a removed/rotated receiver after Stop. RED on revert: restore
// `for job := range a.trapQueue` + a Stop that neither signals nor waits, and
// the worker drains the backlog after Stop (a second delivery is observed) and
// never joins (Stop hangs / the goroutine leaks).
func TestStop_StopsTrapWorkerNoPostDelivery(t *testing.T) {
	var calls, delivered atomic.Int64
	entered := make(chan struct{}, 64)
	release := make(chan struct{})
	// #5023: inject the mock sender on THIS Agent, not a shared package global
	// (which would race the running trap worker's read under -race).
	sender := func(target string, pkt []byte) error {
		n := calls.Add(1)
		entered <- struct{}{} // signal every send attempt
		if n == 1 {
			<-release // hold the first send until the test releases it
		}
		delivered.Add(1)
		return nil
	}

	a := &Agent{startTime: time.Now(), trapSender: sender}
	// Enqueue a backlog. The worker starts, dequeues the first job, and blocks
	// inside the sender; the rest sit in the queue behind it.
	for i := 0; i < 8; i++ {
		a.enqueueTrap(trapJob{target: "192.0.2.9:162", pkt: []byte{1}})
	}

	// Wait until the worker is actually blocked in the first send.
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("trap worker never entered the sender")
	}

	// Stop concurrently (it waits for the worker), then release the in-flight
	// send so the worker can observe the stop signal on its next loop.
	stopped := make(chan struct{})
	go func() { a.Stop(); close(stopped) }()
	time.Sleep(50 * time.Millisecond) // let Stop set stopped + close trapStop
	close(release)

	// No queued trap may begin delivery after Stop. The only permitted send is
	// the one already in flight when Stop was called (send #1); any SECOND
	// sender entry is a post-Stop delivery of the abandoned backlog.
	select {
	case <-entered:
		t.Fatal("a queued trap was delivered after Stop — the worker did not abandon its backlog (#4916)")
	case <-time.After(500 * time.Millisecond):
		// good: no further delivery
	}

	// Stop must return: the worker joined (no goroutine leak).
	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop did not return — the trap worker leaked (Stop never stops/awaits it)")
	}
	if got := delivered.Load(); got != 1 {
		t.Fatalf("delivered = %d, want exactly 1 (only the in-flight send may complete)", got)
	}

	// Idempotent: a second Stop (ctx-watcher + day-2 reconcile both call it)
	// must not panic or block.
	a.Stop()

	// A trap enqueued after Stop must be dropped, never delivered.
	before := a.trapsDropped.Load()
	a.enqueueTrap(trapJob{target: "192.0.2.9:162", pkt: []byte{1}})
	if a.trapsDropped.Load() != before+1 {
		t.Fatal("post-Stop enqueue was not dropped")
	}
	if got := delivered.Load(); got != 1 {
		t.Fatalf("a post-Stop enqueue was delivered: delivered = %d, want 1", got)
	}
}
