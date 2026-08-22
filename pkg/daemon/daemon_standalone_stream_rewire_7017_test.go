// #7017: on a STANDALONE (no-cluster) daemon the userspace event-stream
// callbacks were installed exactly once and never re-installed when the
// helper's EventStream instance was REPLACED.
//
// The clustered path was fixed for this in #6743 r6-F4 — the
// `es != wired` re-install inside eventStreamFallbackLoop — but the standalone
// arm of runUserspaceEventStream called wireUserspaceEventStreamCallbacks and
// RETURNED with it, and never ran that loop. The asymmetry was stated in-tree
// as a KNOWN GAP rather than fixed.
//
// Failure mode: a commit-confirmed rollback tears down the armed backend's
// stream (pkg/dataplane/userspace/process.go) and the corrected re-arm
// constructs a NEW one. On master the replacement got no SetOnEvent /
// SetOnFullResync / dataplane-event callback, so every helper event from that
// point landed in the callback-not-ready queue: RT_FLOW session records stopped
// reaching `show log`, syslog and the flow exporter for the rest of the process
// lifetime, recoverable only by restarting the daemon.
package daemon

import (
	"context"
	"testing"
	"time"

	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// TestRunUserspaceEventStream_StandaloneRewiresReplacementStream is the
// standalone twin of TestEventStreamFallbackLoop_RewiresReplacementStream, and
// binds the #7017 hunk and only that hunk.
//
// The FIRST ack proves the arm still wires at all (the pre-existing behaviour
// this must not regress); the SECOND, on a different stream instance the
// backend publishes afterwards, is the property #7017 adds. On a standalone
// daemon handleEventStreamDelta takes its "ignored (no cluster/sync)" arm and
// ACKs, so an ack proves only that the CALLBACK ran — which is exactly the
// property under test.
//
// Fail-on-revert: restore `d.wireUserspaceEventStreamCallbacks(ctx); return`
// in place of the watch loop and the second ack never comes back. Measured at
// origin/master aa3780666: the first ack lands, the second times out at the
// wiring deadline (85s under `-timeout 90s`); with the loop the second ack
// lands on the next 500 ms tick and the whole test takes 0.5s.
func TestRunUserspaceEventStream_StandaloneRewiresReplacementStream(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	first, firstPath := startEventStreamForRewireTest(t, ctx, "first.sock")
	replacement, replacementPath := startEventStreamForRewireTest(t, ctx, "replacement.sock")

	d := &Daemon{store: storeWithActiveConfigForDrainTest(t)}
	if d.cluster != nil || d.getSessionSync() != nil {
		t.Fatal("test setup: this must take the STANDALONE arm (no cluster, no session sync)")
	}

	backend := &replaceableStreamDP{}
	backend.es.Store(first)
	d.setDataplane(backend)

	done := make(chan struct{})
	go func() {
		defer close(done)
		d.runUserspaceEventStream(ctx)
	}()

	firstConn, err := dialEventStreamForRewireTest(t, firstPath)
	if err != nil {
		t.Fatalf("dial first event stream: %v", err)
	}
	defer firstConn.Close()
	writeEventFrameForWiringTest(t, firstConn, dpuserspace.EventTypeSessionOpen, 1,
		buildSessionOpenFrameV4PayloadForWiringTest())
	waitForAckSeqForWiringTest(t, firstConn, 1)

	// The commit-confirmed rollback + corrected re-arm: the published backend
	// now exposes a DIFFERENT stream instance, with no callbacks on it.
	backend.es.Store(replacement)

	replacementConn, err := dialEventStreamForRewireTest(t, replacementPath)
	if err != nil {
		t.Fatalf("dial replacement event stream: %v", err)
	}
	defer replacementConn.Close()
	writeEventFrameForWiringTest(t, replacementConn, dpuserspace.EventTypeSessionOpen, 1,
		buildSessionOpenFrameV4PayloadForWiringTest())
	// SetOnEvent flushes the callback-not-ready queue, so this does not race the
	// loop's next tick: the ack arrives whenever the re-install lands.
	waitForAckSeqForWiringTest(t, replacementConn, 1)

	cancel()
	<-done
}

// TestRunUserspaceEventStream_StandaloneReturnsOnContextCancel pins the
// shutdown join. #7017 turns the standalone arm from a function that RETURNED
// after wiring into one that loops for the life of ctx, and daemon_run.go
// registers that goroutine on the run WaitGroup. runShutdownSequence calls
// stop() and only then wg.Wait(), so the loop must observe the cancellation and
// return — otherwise the daemon would hang in wg.Wait() forever on every stop.
//
// Fail-on-revert: drop the `case <-ctx.Done(): return` arm from the select in
// watchUserspaceEventStreamCallbacks and this test fails on its deadline
// instead of joining.
func TestRunUserspaceEventStream_StandaloneReturnsOnContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	es, _ := startEventStreamForRewireTest(t, ctx, "shutdown.sock")
	d := &Daemon{store: storeWithActiveConfigForDrainTest(t)}
	backend := &replaceableStreamDP{}
	backend.es.Store(es)
	d.setDataplane(backend)

	done := make(chan struct{})
	go func() {
		defer close(done)
		d.runUserspaceEventStream(ctx)
	}()

	// Let it reach the loop and install, so the cancel is observed from inside
	// the 500 ms select rather than before the first iteration.
	time.Sleep(100 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("standalone event-stream arm did not return within 5s of ctx cancel; " +
			"runShutdownSequence's wg.Wait() would hang on every daemon stop (#7017)")
	}
}
