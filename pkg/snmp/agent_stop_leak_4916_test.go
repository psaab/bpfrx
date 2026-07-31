package snmp

import (
	"context"
	"sync"
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

// TestStop_CountsAbandonedTrapBacklog is the C180-026 RED-on-revert guard. When
// Stop() abandons the queued trap backlog (#4916 safety: no post-Stop
// delivery), those discarded traps MUST be accounted for in trapsDropped —
// otherwise the drop total under-reports, claiming zero drops while link-state
// traps are silently discarded during SNMP disable / target rotation /
// shutdown. RED on revert: remove the countAbandonedTraps drain (and the
// dequeued-but-unsent Add(1)) from trapWorker and the worker returns on stop
// without counting, so trapsDropped stays 0 and the assertion below FAILS.
func TestStop_CountsAbandonedTrapBacklog(t *testing.T) {
	const total = 8 // 1 delivered in-flight + 7 abandoned in the queue buffer
	var calls, delivered atomic.Int64
	entered := make(chan struct{}, 64)
	release := make(chan struct{})
	sender := func(target string, pkt []byte) error {
		n := calls.Add(1)
		entered <- struct{}{}
		if n == 1 {
			<-release // hold the first send so the rest of the backlog buffers
		}
		delivered.Add(1)
		return nil
	}

	a := &Agent{startTime: time.Now(), trapSender: sender}
	if got := a.trapsDropped.Load(); got != 0 {
		t.Fatalf("fresh agent trapsDropped = %d, want 0", got)
	}
	// Enqueue the backlog: the worker dequeues job #1 and blocks in the sender;
	// the remaining total-1 jobs sit buffered behind it (queue depth is 256, so
	// none are dropped queue-full here).
	for i := 0; i < total; i++ {
		a.enqueueTrap(trapJob{target: "192.0.2.9:162", pkt: []byte{1}})
	}

	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("trap worker never entered the sender")
	}

	stopped := make(chan struct{})
	go func() { a.Stop(); close(stopped) }()
	time.Sleep(50 * time.Millisecond) // let Stop set stopped + close trapStop
	close(release)

	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop did not return — the trap worker leaked")
	}

	// Exactly one trap was delivered (the in-flight send); every other queued
	// trap was abandoned AND counted. Accepted == delivered + dropped == total,
	// so no queued trap is silently lost from the accounting.
	if got := delivered.Load(); got != 1 {
		t.Fatalf("delivered = %d, want exactly 1 (only the in-flight send may complete)", got)
	}
	if got := a.trapsDropped.Load(); got != total-1 {
		t.Fatalf("trapsDropped = %d, want %d — the abandoned trap backlog was not counted on Stop (C180-026)",
			got, total-1)
	}
}

// TestStop_AccountingExactUnderConcurrentEnqueue is the C180-026 exactness
// INVARIANT guard (run under -race). It hammers enqueueTrap concurrently with
// Stop across many iterations and asserts that EVERY enqueue call resolves to
// exactly one of delivered or trapsDropped, so
//
//	totalEnqueues == delivered + trapsDropped
//
// with no orphaned job. This holds because enqueueTrap publishes to the queue
// under the same a.mu that Stop takes to set stopped / close trapStop: an
// enqueue and a Stop are strictly serialized, so a job admitted to the queue is
// buffered before close(trapStop) is observable (the shutdown drain counts it)
// and a job that loses the race sees stopped and drops+counts.
//
// NOTE on strength: this is an invariant + data-race guard, NOT a deterministic
// fail-on-revert. The exactness itself is guaranteed by the lock discipline
// (send-under-a.mu) and reasoned about in enqueueTrap's comment; the common
// backlog case is deterministically pinned by TestStop_CountsAbandonedTrapBacklog.
// Reverting the fix (moving the send back OUTSIDE the a.mu critical section)
// reopens the orphan window, but that window — an enqueue whose send lands only
// AFTER countAbandonedTraps has already drained an empty queue and the worker
// has exited — is too narrow to hit reliably from a test without a production
// seam, so this stress loop does not deterministically go RED on revert. It DOES
// catch gross regressions and any data race the fix might introduce.
func TestStop_AccountingExactUnderConcurrentEnqueue(t *testing.T) {
	const (
		iterations = 300
		seed       = 4  // jobs enqueued before the race, to start the worker
		burst      = 24 // jobs enqueued concurrently with Stop
	)
	for it := 0; it < iterations; it++ {
		var delivered atomic.Int64
		// Instant sender: the worker drains fast, so the shutdown window (worker
		// about to exit while enqueues still arrive) is exercised across the many
		// interleavings the iterations sample.
		sender := func(target string, pkt []byte) error {
			delivered.Add(1)
			return nil
		}
		a := &Agent{startTime: time.Now(), trapSender: sender}

		for i := 0; i < seed; i++ {
			a.enqueueTrap(trapJob{target: "192.0.2.9:162", pkt: []byte{1}})
		}

		var wg sync.WaitGroup
		wg.Add(burst)
		for i := 0; i < burst; i++ {
			go func() {
				defer wg.Done()
				a.enqueueTrap(trapJob{target: "192.0.2.9:162", pkt: []byte{1}})
			}()
		}
		stopDone := make(chan struct{})
		go func() { a.Stop(); close(stopDone) }()

		// After every enqueue call has returned AND Stop has joined the worker,
		// all delivered/dropped accounting is complete: worker-side counts are
		// published before trapWG.Done (hence before Stop returns) and
		// enqueue-side drops are synchronous within each returned call.
		wg.Wait()
		<-stopDone

		total := int64(seed + burst)
		got := delivered.Load() + int64(a.trapsDropped.Load())
		if got != total {
			t.Fatalf("iteration %d: delivered(%d) + trapsDropped(%d) = %d, want %d — a job was neither delivered nor counted (shutdown accounting not exact)",
				it, delivered.Load(), a.trapsDropped.Load(), got, total)
		}
	}
}
