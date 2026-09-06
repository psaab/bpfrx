package daemon

import (
	"errors"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
)

// #9036: a remote failover superseded by a concurrent ResetFailover performed
// NO demotion, and must not be ACKed `applied`.
//
// The chain, and why every link looked correct on its own:
//
//  1. pkg/cluster returns FailoverSuperseded before the SecondaryHold write —
//     correct, #5246: the reset is the operator's newer intent.
//  2. the daemon wiring DISARMED the fence barrier — correct in isolation,
//     #8000: nothing will ever actuate it, and leaving it armed makes the
//     applied-ack burn the fence timeout and blame the fencing path.
//  3. waitFailoverActuated returns nil when no barrier is armed — correct,
//     and the reason step 2 chose disarming.
//  4. sync_failover.go sends failoverAckApplied when the wait returns nil —
//     correct, #5640: a clean fence means the peer may promote.
//
// Four correct steps composing into: **the peer promotes while this node is
// still Primary.** #8000 removed the only thing on the wire that distinguished
// "fenced" from "never happened", and the typed FailoverSuperseded that could
// have carried the distinction was collapsed to nil at the callback boundary.
//
// BIND THE WIRING, NOT THE FUNCTION. These cells drive the INSTALLED closures
// (ss.OnRemoteFailover / ss.OnRemoteFailoverBatch) and then read the barrier
// the ack path reads. Calling failFailoverActuation directly would pass against
// a build where the wiring never calls it — which is precisely the defect
// shape: in #9036 the helper that should have been called was the WRONG one,
// not a missing one, so a cell that exercised the primitive would have been
// green throughout.
func TestSupersededRemoteFailoverAcksFailedNotApplied9036(t *testing.T) {
	for _, tc := range []struct {
		name string
		call func(t *testing.T, d *Daemon, ss *cluster.SessionSync, reqID uint64)
	}{
		{"singular", func(t *testing.T, d *Daemon, ss *cluster.SessionSync, reqID uint64) {
			if err := ss.OnRemoteFailover(0, reqID); err != nil {
				t.Fatalf("OnRemoteFailover: %v — #5246 makes a reset winning a non-error", err)
			}
		}},
		{"batch", func(t *testing.T, d *Daemon, ss *cluster.SessionSync, reqID uint64) {
			if err := ss.OnRemoteFailoverBatch([]int{0}, reqID); err != nil {
				t.Fatalf("OnRemoteFailoverBatch: %v", err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := newBarrier8000Daemon(t, 0)
			ss := cluster.NewSessionSync("127.0.0.1:4785", "127.0.0.1:4785", nil)
			d.wireSessionSyncFailoverCallbacks(ss)
			const reqID = uint64(9036)

			resetDuringFailoverHook(t, d.cluster, 0, func() { tc.call(t, d, ss, reqID) })

			// THE INVARIANT. sync_failover.go sends failoverAckApplied exactly
			// when this returns nil, so nil here IS the two-owner window.
			start := time.Now()
			err := d.waitFailoverActuated(0, reqID)
			if err == nil {
				t.Fatalf("waitFailoverActuated = nil after a supersede: the ack path sends " +
					"failoverAckApplied on nil, so the peer promotes while this node is " +
					"still Primary and never demoted (#9036, #5640)")
			}
			if !errors.Is(err, cluster.ErrFailoverSuperseded) {
				t.Errorf("waitFailoverActuated = %v, want ErrFailoverSuperseded. A fence "+
					"TIMEOUT would also downgrade the ack correctly, but it blames the "+
					"fencing path for a concurrent reset — the misdiagnosis #8000 "+
					"removed and this fix must not reintroduce", err)
			}
			// #8000's assertion, kept verbatim: the verdict must arrive without
			// burning the fence timeout.
			if elapsed := time.Since(start); elapsed > barrier8000Timeout/2 {
				t.Errorf("waitFailoverActuated took %v (timeout %v): the barrier was left "+
					"armed and the wait expired. Reporting the right verdict AFTER "+
					"burning the timeout gives back what #8000 bought", elapsed,
					barrier8000Timeout)
			}

			// CONTROL: the RG must be UNTOUCHED. If a future change made the
			// supersede demote after all, the assertions above would still pass
			// while the premise -- "this request performed no demotion" -- had
			// silently stopped being true.
			if !d.cluster.IsLocalPrimary(0) {
				t.Error("RG0 is no longer local-primary: the supersede performed a " +
					"demotion, so this cell is no longer testing what it claims (#9036)")
			}
		})
	}
}

// The mutant that must SURVIVE: an uncontested remote failover still holds its
// barrier and still ACKs applied only after the fence actuates.
//
// Without this, a "fix" that resolved every barrier with ErrFailoverSuperseded
// — defeating #5640 entirely and making every transfer-out report failed —
// passes the cell above.
func TestUncontestedRemoteFailoverStillFences9036(t *testing.T) {
	d := newBarrier8000Daemon(t, 0)
	ss := cluster.NewSessionSync("127.0.0.1:4785", "127.0.0.1:4785", nil)
	d.wireSessionSyncFailoverCallbacks(ss)
	const reqID = uint64(9037)

	if err := ss.OnRemoteFailover(0, reqID); err != nil {
		t.Fatalf("uncontested OnRemoteFailover: %v", err)
	}
	err := d.waitFailoverActuated(0, reqID)
	if err == nil {
		t.Fatal("uncontested remote failover left no armed barrier: the applied-ack " +
			"would return before the local demotion actuated (#5640)")
	}
	if errors.Is(err, cluster.ErrFailoverSuperseded) {
		t.Errorf("uncontested failover resolved as SUPERSEDED (%v): the supersede "+
			"verdict must be scoped to requests a reset actually won, or every "+
			"transfer-out reports failed and no failover can ever complete (#9036)", err)
	}
}
