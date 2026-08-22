package daemon

import (
	"context"
	"strings"
	"testing"
	"time"
)

// #5250 (A7-b1 F4). waitLocalFailoverCommitReady polled with a bare
// `time.Sleep(10 * time.Millisecond)` and no cancellation of any kind, so a
// `systemctl stop xpfd` landing while a manual failover transfer was settling
// held the shutdown for the remainder of localFailoverCommitTimeout (1s by
// default) plus the dwell delay.
//
// The wait now selects on d.applyCancelCtx().Done() — the daemon's DAEMON-STOP
// context, a child of the SIGTERM/SIGINT signal context (#2926), which is what
// actually fires on shutdown (d.daemonCtx is context.Background() in production
// and never cancelled). Reverting either wait to time.Sleep makes this test
// RED at the deadline.
func TestWaitLocalFailoverCommitReadyAbortsOnDaemonStop(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	d := &Daemon{
		cluster:                    newClusterManager(true),
		localFailoverCommitReady:   make(map[int]bool),
		localFailoverCommitTimeout: 30 * time.Second, // never reached
		localFailoverCommitDelay:   0,
		applyCancelContext:         ctx,
	}

	done := make(chan error, 1)
	go func() { done <- d.waitLocalFailoverCommitReady([]int{0}) }()

	// The RG never becomes ready, so without cancellation this sits for the
	// full 30s timeout.
	time.Sleep(30 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a cancelled wait must return an ERROR — the caller " +
				"(cluster.requestPeerFailover) aborts the transfer on a non-nil " +
				"return, and committing a transfer this node can no longer verify " +
				"is the fail-OPEN direction")
		}
		if !strings.Contains(err.Error(), "daemon stopping") {
			t.Fatalf("error = %v, want the daemon-stopping reason (a plain timeout "+
				"here would mean it burned the whole window and never saw the cancel)", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("waitLocalFailoverCommitReady ignored daemon stop: it is sleeping " +
			"without a cancellation select again")
	}
}

// The dwell delay is abortable too, not just the poll: a wait that has already
// observed readiness and is dwelling must still yield to shutdown.
func TestWaitLocalFailoverCommitReadyAbortsDuringTheDwellDelay(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	d := &Daemon{
		cluster:                    newClusterManager(true),
		localFailoverCommitReady:   make(map[int]bool),
		localFailoverCommitTimeout: 30 * time.Second,
		localFailoverCommitDelay:   30 * time.Second, // the dwell is the long wait
		applyCancelContext:         ctx,
	}
	d.setLocalFailoverCommitReady(0, true) // ready immediately -> straight to dwell

	done := make(chan error, 1)
	go func() { done <- d.waitLocalFailoverCommitReady([]int{0}) }()

	time.Sleep(30 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "daemon stopping") {
			t.Fatalf("error = %v, want the daemon-stopping reason from the dwell wait", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the dwell delay ignored daemon stop: it is a bare time.Sleep again")
	}
}

// With no daemon-stop context wired (early boot, and every pre-existing unit
// test in this file), applyCancelCtx() returns context.Background() — the wait
// must behave exactly as before.
func TestWaitLocalFailoverCommitReadyUnwiredContextStillTimesOut(t *testing.T) {
	d := &Daemon{
		cluster:                    newClusterManager(true),
		localFailoverCommitReady:   make(map[int]bool),
		localFailoverCommitTimeout: 30 * time.Millisecond,
		localFailoverCommitDelay:   0,
	}
	err := d.waitLocalFailoverCommitReady([]int{0})
	if err == nil || !strings.Contains(err.Error(), "timed out waiting for local failover activation settle") {
		t.Fatalf("error = %v, want the ordinary settle timeout", err)
	}
}
