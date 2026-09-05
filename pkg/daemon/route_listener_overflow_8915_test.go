package daemon

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/coalesce"
)

// newTestLoop8915 returns a coalescer with an INJECTED clock and the advance
// helper the cells drive it with.
//
// The clock is not a convenience. `Tick` fires only once `now - dirtySince >=
// debounce` and `now - lastActuation >= throttle`, so a Tick taken
// immediately after a Mark does NOT actuate -- which is what the control below
// caught when this file first used the real clock, and it would otherwise have
// read as "the error callback does not mark".
func newTestLoop8915(count *int) (*coalesce.Loop, func()) {
	now := time.Unix(0, 0)
	loop := coalesce.New(func(context.Context) bool {
		*count++
		return true
	})
	loop.SetClock(func() time.Time { return now })
	advance := func() { now = now.Add(time.Hour) }
	return loop, advance
}

// #8915: a netlink overflow drops the ONLY FIB refresh edge the daemon has,
// and before this fix nothing periodic recovered it.
//
// THE THREE LINKS, all of which have to hold for the defect to exist, and all
// of which are re-checked by the cells below rather than trusted:
//
//  1. `loop.Mark()` has exactly one call site in production -- the
//     `case upd := <-updates` arm. The netlink channel is the sole source of
//     refresh edges.
//  2. `updates` is bounded at 256; on overflow the kernel drops route messages
//     and reports ENOBUFS to `ErrorCallback`, which only `slog.Debug`d it.
//  3. The coalescer's 100ms ticker is a SWEEP, not a periodic actuate: `Tick`
//     fires only `if !l.dirtySince.IsZero()`.
//
// Link 3 is the one that turns a dropped message into an indefinitely stale
// FIB, and it is the one that reads wrong -- a 100ms ticker looks like a
// periodic refresh. The control below measures it instead of reading it.

// The control for link 3. An unmarked loop must actuate ZERO times no matter
// how many times it is swept, and exactly once after a single mark.
//
// Without this, "the error callback marks" is satisfied by a loop that would
// have actuated anyway, and the cell would be measuring the coalescer rather
// than the fix.
func TestCoalescerTickIsASweepNotAPeriodicActuate8915(t *testing.T) {
	var actuations int
	loop, advance := newTestLoop8915(&actuations)
	ctx := context.Background()

	for i := 0; i < 50; i++ {
		advance()
		loop.Tick(ctx)
	}
	if actuations != 0 {
		t.Fatalf("CONTROL FAILED: %d actuation(s) from 50 sweeps with NO mark. "+
			"The coalescer ticker is a periodic actuate after all, which means a "+
			"dropped netlink message WOULD self-heal and #8915's premise is wrong. "+
			"Re-derive the issue before trusting the fix", actuations)
	}

	loop.Mark()
	advance()
	loop.Tick(ctx)
	if actuations != 1 {
		t.Fatalf("CONTROL FAILED: after ONE mark and one sweep, actuations=%d, want 1. "+
			"The loop does not actuate on a mark, so the cell below cannot tell a "+
			"marking error callback from a non-marking one", actuations)
	}
}

// The fix: the subscription's error callback must produce a refresh edge.
//
// This drives the callback the daemon actually installs, rather than a
// re-implementation of it -- a hand-rolled `func(err error)` in the test would
// pass whatever production does. `routeListenerErrorCallback` is the seam, and
// production passes the same function to RouteSubscribeWithOptions.
func TestNetlinkErrorForcesAFibRefresh8915(t *testing.T) {
	d := &Daemon{}
	var actuations int
	loop, advance := newTestLoop8915(&actuations)
	ctx := context.Background()

	cb := d.routeListenerErrorCallback(loop)

	// NON-VACUITY: nothing has marked yet, so a sweep must not actuate. If it
	// does, the assertion after the callback proves nothing.
	advance()
	loop.Tick(ctx)
	if actuations != 0 {
		t.Fatalf("NON-VACUITY: %d actuation(s) before the error callback ran", actuations)
	}

	cb(errors.New("no buffer space available"))
	advance()
	loop.Tick(ctx)

	if actuations != 1 {
		t.Errorf("#8915: a netlink subscription error did NOT produce a FIB refresh "+
			"(actuations=%d, want 1).\n"+
			"  `updates` is bounded at 256 and `loop.Mark()` has exactly one other "+
			"call site -- the update arm -- so the messages the kernel dropped ARE "+
			"the refresh edges. With no mark here the helper FIB stays stale until "+
			"the next route event that happens not to be dropped, which on a "+
			"churning box is precisely when it is least likely to arrive: the same "+
			"churn that overflowed the queue is what delays the next event.\n"+
			"  The coalescer cannot recover it either -- see "+
			"TestCoalescerTickIsASweepNotAPeriodicActuate8915: an unmarked loop "+
			"sweeps forever and never actuates.", actuations)
	}
	if got := d.RouteListenerErrors(); got != 1 {
		t.Errorf("#8915: RouteListenerErrors()=%d, want 1. The recovery must be "+
			"OBSERVABLE -- before this fix the overflow was a Debug line, so a "+
			"stale FIB had no counter pointing at it and looked like a routing "+
			"problem rather than a dropped-edge one", got)
	}
}

// The mark must not be conditional on the error text. The callback's contract
// is "the subscription had a problem", every such condition can leave a gap in
// the update stream, and a refresh is idempotent.
func TestEveryNetlinkErrorMarks8915(t *testing.T) {
	for _, err := range []error{
		errors.New("no buffer space available"),
		errors.New("ENOBUFS"),
		errors.New("connection reset by peer"),
		errors.New("something the netlink library has not invented yet"),
	} {
		d := &Daemon{}
		var actuations int
		loop, advance := newTestLoop8915(&actuations)
		d.routeListenerErrorCallback(loop)(err)
		advance()
		loop.Tick(context.Background())
		if actuations != 1 {
			t.Errorf("#8915: error %q did not force a refresh (actuations=%d). "+
				"Discriminating on the errno makes recovery depend on matching a "+
				"string the netlink library does not promise, and the failure mode "+
				"of guessing wrong is a silently stale FIB", err, actuations)
		}
	}
}
