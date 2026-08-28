package daemon

// host_inbound_conntrack_retry_6802_test.go — #6802.
//
// A failed host-inbound conntrack revocation had NO return value, no dirty flag,
// no counter, no metric, and no periodic reconcile that re-ran it. Every ticker
// under pkg/daemon was enumerated when the issue was measured and none re-runs
// applyConfig / applyHostInboundFilter / the flush, so the only re-attempt was
// the next externally-triggered apply — itself gated on InstallHostInbound
// succeeding.
//
// The failure direction is what makes that a defect rather than a tradeoff: the
// stale entry rides the chain's leading `ct state established,related accept`,
// so a now-DENIED host-inbound flow keeps working. It fails OPEN, and stayed
// open until the flow closed or timed out.
//
// The pre-existing #5566 test's conntrackDeleteFilters stub always returns
// (0, nil), so before these cells NO test exercised the delete-error path at all.

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vishvananda/netlink"

	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"golang.org/x/sync/semaphore"
)

// installConntrackDeleteStub replaces the delete seam and records every call.
// It returns an ACCESSOR, not a pointer to the counter.
//
// #7825: it used to take a mutex around the increment and then return
// `&calls` — a raw *int whose mutex was captured by the closure and never
// handed out. So the write was synchronised and every READ was not, while the
// reassert loop the test starts was still writing. `go test -race
// ./pkg/daemon/` reported a DATA RACE between the loop's increment and the
// test's own `*calls` read, deterministically, in two tests.
//
// A mutex held on one side of a publish establishes no happens-before for a
// reader that does not take it — the same shape as #7012 (`d.mgmt` published
// under staleCertMu on the write side only), which was fixed by making the
// unguarded form unrepresentable rather than by guarding the four readers then
// known.
//
// Returning `func() int` does that here: there is no pointer to dereference, so
// a caller cannot read the counter without going through the lock, and a future
// call site cannot reintroduce the bug by omission.
func installConntrackDeleteStub(t *testing.T, err error) func() int {
	t.Helper()
	orig := conntrackDeleteFilters
	var mu sync.Mutex
	calls := 0
	conntrackDeleteFilters = func(netlink.InetFamily, ...netlink.CustomConntrackFilter) (uint, error) {
		mu.Lock()
		calls++
		mu.Unlock()
		return 0, err
	}
	t.Cleanup(func() { conntrackDeleteFilters = orig })
	return func() int {
		mu.Lock()
		defer mu.Unlock()
		return calls
	}
}

func flushReq6802() hostInboundConntrackFlushRequest {
	cfg := hostInboundFlushTestConfig()
	views := dpuserspace.BuildZoneHostInboundViews(cfg)
	unzonedV4, unzonedV6 := unzonedHostAddrsForTest6802(cfg)
	return hostInboundConntrackFlushRequest{
		views:     views,
		unzonedV4: unzonedV4,
		unzonedV6: unzonedV6,
	}
}

// unzonedHostAddrsForTest6802 mirrors the #5566 test's own derivation. The
// values only need to make buildHostInboundConntrackFlushFilter return non-nil —
// a nil filter short-circuits the flush and every assertion here would pass
// vacuously, which the cells guard against by asserting the delete seam was
// actually reached.
func unzonedHostAddrsForTest6802(cfg *config.Config) ([]string, []string) {
	return []string{"10.0.61.1"}, nil
}

// TestFlushReportsItsOutcome6802 is PAIRED on the seam that had no failing
// fixture at all: the same flush, a failing delete and a succeeding one,
// opposite returns.
//
// The success leg matters because "returns false on failure" is satisfied by a
// flush that returns false always — which would arm the retry owner on every
// apply on every healthy node, a conntrack dump every 30s forever.
func TestFlushReportsItsOutcome6802(t *testing.T) {
	req := flushReq6802()

	t.Run("delete-fails", func(t *testing.T) {
		calls := installConntrackDeleteStub(t, errors.New("simulated: conntrack subsystem unavailable"))
		d := &Daemon{}
		if d.flushDeniedHostInboundConntrack(req.views, req.unzonedV4, req.unzonedV6, nil) {
			t.Fatal("flushDeniedHostInboundConntrack reported SUCCESS while every " +
				"conntrack delete failed — a now-denied host-inbound flow keeps " +
				"its old authorization and nothing records it (#6802)")
		}
		// Both families must still be attempted: their stale entries are
		// independent, and abandoning v6 because v4 failed would leave half the
		// revocation undone for a reason unrelated to v6.
		if calls() != 2 {
			t.Fatalf("conntrack delete attempted %d times, want 2 (one per "+
				"address family) — a failure in one family must not abandon the "+
				"other", calls())
		}
	})

	t.Run("delete-succeeds", func(t *testing.T) {
		installConntrackDeleteStub(t, nil)
		d := &Daemon{}
		if !d.flushDeniedHostInboundConntrack(req.views, req.unzonedV4, req.unzonedV6, nil) {
			t.Fatal("flushDeniedHostInboundConntrack reported FAILURE on a clean " +
				"delete — the retry owner would re-drive a conntrack dump every " +
				"30s on a healthy node")
		}
	})
}

// TestFailedFlushRetainsDebtAndSuccessClearsIt6802 pins the state a retry needs.
// Reporting the failure is only half: before #6802 nothing kept the desired set,
// so even a caller that SAW the failure had nothing to re-drive.
func TestFailedFlushRetainsDebtAndSuccessClearsIt6802(t *testing.T) {
	d := &Daemon{}
	req := flushReq6802()

	d.noteHostInboundConntrackFlush(req, false)
	if !d.HostInboundConntrackRevocationOwed() {
		t.Fatal("a FAILED revocation left no retry debt, so nothing can re-drive " +
			"it and the now-denied flow stays authorized (#6802)")
	}
	if got := d.HostInboundConntrackFlushFailures(); got != 1 {
		t.Fatalf("flush failures = %d, want 1 — a failure counted nowhere is "+
			"invisible to an operator", got)
	}

	d.noteHostInboundConntrackFlush(req, true)
	if d.HostInboundConntrackRevocationOwed() {
		t.Fatal("debt survived a SUCCESSFUL revocation — the owner would re-drive " +
			"a revocation whose target no longer exists")
	}
	if got := d.HostInboundConntrackFlushFailures(); got != 1 {
		t.Fatalf("a SUCCESS bumped the failure counter to %d", got)
	}
}

// TestRetryReDrivesTheOwedRequest6802 is the retry-owner cell, and it is PAIRED:
// with debt the owner acts, without it the owner must not touch conntrack.
//
// The no-debt leg is what keeps the always-on loop free — an owner that dumped
// conntrack every tick regardless would be a permanent cost on every healthy
// node.
func TestRetryReDrivesTheOwedRequest6802(t *testing.T) {
	t.Run("with-debt", func(t *testing.T) {
		calls := installConntrackDeleteStub(t, errors.New("still failing"))
		d := &Daemon{applySem: semaphore.NewWeighted(1)}
		d.noteHostInboundConntrackFlush(flushReq6802(), false)
		before := calls()

		d.retryHostInboundConntrackFlushOnce(context.Background())

		if calls() <= before {
			t.Fatal("the retry owner did not re-drive the owed revocation — " +
				"no ticker under pkg/daemon re-runs the flush, so without this " +
				"the only re-attempt is the next externally-triggered apply (#6802)")
		}
		if !d.HostInboundConntrackRevocationOwed() {
			t.Fatal("a retry that FAILED AGAIN cleared the debt, so it would " +
				"never be retried a third time")
		}
	})

	t.Run("no-debt", func(t *testing.T) {
		calls := installConntrackDeleteStub(t, nil)
		d := &Daemon{applySem: semaphore.NewWeighted(1)}

		d.retryHostInboundConntrackFlushOnce(context.Background())

		if calls() != 0 {
			t.Fatalf("the retry owner dumped conntrack %d times with NO debt "+
				"owed — the always-on loop must be free on a healthy node", calls())
		}
	})

	t.Run("retry-that-succeeds-clears-the-debt", func(t *testing.T) {
		installConntrackDeleteStub(t, nil)
		d := &Daemon{applySem: semaphore.NewWeighted(1)}
		d.noteHostInboundConntrackFlush(flushReq6802(), false)

		d.retryHostInboundConntrackFlushOnce(context.Background())

		if d.HostInboundConntrackRevocationOwed() {
			t.Fatal("a SUCCESSFUL retry did not clear the debt — the owner would " +
				"re-drive it forever")
		}
	})
}

// TestRetryRechecksTheDebtInsideTheSemaphore6802 pins the #4001 ordering.
//
// The outer check is an optimisation; the inner one is the correctness gate. A
// tick that blocked behind an in-flight commit may find that the commit's own
// flush already succeeded and cleared the debt — re-driving then is a conntrack
// dump for nothing, against a desired set that is no longer current.
//
// Every other cell drives the retry single-threaded, where the semaphore is
// invisible by construction, so this is the only cell that can see it.
func TestRetryRechecksTheDebtInsideTheSemaphore6802(t *testing.T) {
	calls := installConntrackDeleteStub(t, nil)
	d := &Daemon{applySem: semaphore.NewWeighted(1)}
	d.noteHostInboundConntrackFlush(flushReq6802(), false)

	if err := d.applySem.Acquire(context.Background(), 1); err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	before := calls()

	started := make(chan struct{})
	done := make(chan struct{})
	go func() {
		close(started)
		d.retryHostInboundConntrackFlushOnce(context.Background())
		close(done)
	}()
	<-started

	// Simulate the commit this tick queued behind having flushed successfully.
	d.noteHostInboundConntrackFlush(flushReq6802(), true)
	d.applySem.Release(1)
	<-done

	if calls() != before {
		t.Fatalf("the retry dumped conntrack %d extra times after the commit it "+
			"queued behind had already cleared the debt — re-checking INSIDE the "+
			"semaphore is what prevents that (#6802)", calls()-before)
	}
}

// TestRetryLoopTicks6802 binds the loop BODY, and
// TestRunStartsHostInboundConntrackReassertLoop6802 (below) binds its START. They fail for different reasons: this reds if the
// ticker is wired to the wrong function, that one reds if Run never launches it.
func TestRetryLoopTicks6802(t *testing.T) {
	calls := installConntrackDeleteStub(t, errors.New("still failing"))
	d := &Daemon{applySem: semaphore.NewWeighted(1)}
	d.noteHostInboundConntrackFlush(flushReq6802(), false)

	orig := hostInboundConntrackReassertInterval
	hostInboundConntrackReassertInterval = 5 * time.Millisecond
	t.Cleanup(func() { hostInboundConntrackReassertInterval = orig })

	ctx, cancel := context.WithCancel(context.Background())
	loopDone := make(chan struct{})
	go func() { d.hostInboundConntrackReassertLoop(ctx); close(loopDone) }()

	deadline := time.Now().Add(5 * time.Second)
	for calls() == 0 {
		if time.Now().After(deadline) {
			cancel()
			<-loopDone
			t.Fatal("the retry loop never re-drove the owed revocation (#6802)")
		}
		time.Sleep(2 * time.Millisecond)
	}
	cancel()
	select {
	case <-loopDone:
	case <-time.After(5 * time.Second):
		t.Fatal("hostInboundConntrackReassertLoop did not return on cancellation")
	}
}

// TestRunStartsHostInboundConntrackReassertLoop6802 is the LOOP-START cell.
//
// It exists because every cell above drives retryHostInboundConntrackFlushOnce
// or the loop function DIRECTLY, so a Run that never launched the owner would
// pass all of them — and "no retry owner" is the entire issue. #6793 shipped
// this exact gap: its matrix came back green on the loop-start question because
// nothing bound it.
//
// Run() itself cannot be driven from a unit test (netlink, a dataplane, sockets,
// listeners), so the start is asserted at the source, the way #6791 does for
// fabricIPVLANReassertLoop. Comments are stripped first: a source-scanning gate
// that greps for a line its own doc comment quotes is satisfied by the comment.
//
// FAIL-ON-REVERT: delete the `d.hostInboundConntrackReassertLoop(ctx)` goroutine
// from Run, or gate it behind a mode check, and this reds.
func TestRunStartsHostInboundConntrackReassertLoop6802(t *testing.T) {
	src := stripLineComments6791(readDaemonSource(t, "daemon_run.go"))

	const call = "d.hostInboundConntrackReassertLoop(ctx)"
	if !strings.Contains(src, call) {
		t.Fatalf("Run does not start hostInboundConntrackReassertLoop; a failed " +
			"host-inbound conntrack revocation has no retry owner (#6802) and a " +
			"now-denied host service stays reachable on its established kernel " +
			"connection until it closes or an operator commits again")
	}
	// …and it must be UNCONDITIONAL. The revocation is driven from every real
	// apply on standalone AND cluster nodes, so a mode gate would leave one of
	// them with no owner — the same defect, narrowed.
	idx := strings.Index(src, call)
	window := src[clampZero6791(idx-400):idx]
	for _, gate := range []string{
		"if d.cluster != nil",
		"if d.isCluster",
		"if d.opts.ClusterEnabled",
	} {
		if strings.Contains(window, gate) {
			t.Errorf("hostInboundConntrackReassertLoop is started behind %q; the "+
				"host-inbound conntrack revocation runs on standalone nodes too "+
				"and needs the same retry owner", gate)
		}
	}
}

// TestDaemonWiresHostInboundConntrackMetrics6802 binds the OBSERVABILITY half of
// the fix to a production caller.
//
// The issue's finding was not only "no retry owner" — it was that the failure
// left no return value, no dirty flag, no counter, NO METRIC and no retry. An
// exported HostInboundConntrackRevocationOwed / HostInboundConntrackFlushFailures
// that nothing calls satisfies none of that: it is the #6852 shape (an exported
// method with no production caller), and the accessor tests would stay green
// with the operator still blind.
//
// startHTTPServer builds the api.Config inline and launches a goroutine, so it
// cannot be driven from a unit test; the assignment is asserted at the source
// with comments stripped, the same instrument the loop-start cell uses.
//
// FAIL-ON-REVERT: drop either assignment from daemon_run_servers.go and this
// reds, while every behavioural cell in this file stays green.
func TestDaemonWiresHostInboundConntrackMetrics6802(t *testing.T) {
	src := stripLineComments6791(readDaemonSource(t, "daemon_run_servers.go"))

	for _, want := range []string{
		"HostInboundConntrackRevocationOwedFn: d.HostInboundConntrackRevocationOwed",
		"HostInboundConntrackFlushFailuresFn:  d.HostInboundConntrackFlushFailures",
	} {
		if !strings.Contains(src, want) {
			t.Errorf("daemon does not wire %q into the REST/metrics server; the "+
				"accessor has no production caller, so a failed host-inbound "+
				"conntrack revocation is still invisible to an operator (#6802, "+
				"and the #6852 no-production-caller shape)", want)
		}
	}
}

// TestApplyHostInboundFilterRecordsTheFlushOutcome6802 is the CALL-SITE half of
// the wiring binding, and it exists because nothing else in this file can see it.
//
// Every behavioural cell above calls noteHostInboundConntrackFlush directly, so
// they all stay green if applyHostInboundFilter goes back to calling
// flushDeniedHostInboundConntrack and DISCARDING its return — which is the whole
// fix undone, with the debt never armed on the one path that arms it in
// production. That is the repeated "bind the wiring, not the function it calls"
// failure; the #6791 fabric fix hit the identical shape.
//
// applyHostInboundFilter cannot be driven from a unit test (it needs a real nft
// install path), so the wiring is asserted at the source with comments stripped.
//
// FAIL-ON-REVERT: change the call site back to a bare
// `d.flushDeniedHostInboundConntrack(views, unzonedV4, unzonedV6, wgListenPorts)`
// and this reds while every other cell in the file stays green.
func TestApplyHostInboundFilterRecordsTheFlushOutcome6802(t *testing.T) {
	src := stripLineComments6791(readDaemonSource(t, "daemon_nft.go"))

	const note = "d.noteHostInboundConntrackFlush("
	i := strings.Index(src, note)
	if i < 0 {
		t.Fatalf("applyHostInboundFilter does not record the flush outcome; a " +
			"failed host-inbound conntrack revocation arms no debt on the one " +
			"path that arms it in production, so the retry owner never runs " +
			"(#6802)")
	}
	// The recorded outcome must be the flush's OWN return value. A call that
	// passed a constant, or recorded an outcome derived from something else,
	// would arm or clear the debt without reference to whether the revocation
	// actually happened.
	end := strings.Index(src[i:], "\n\tslog.")
	if end < 0 {
		end = len(src) - i
	}
	if !strings.Contains(src[i:i+end], "d.flushDeniedHostInboundConntrack(") {
		t.Errorf("the outcome recorded by applyHostInboundFilter does not come " +
			"from flushDeniedHostInboundConntrack's return value; the debt would " +
			"be armed or cleared independently of whether the revocation " +
			"succeeded (#6802)")
	}
}
