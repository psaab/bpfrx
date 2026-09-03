package cluster

import (
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// #7842: the send-queue-overflow replay is what makes the mirror sweep a
// BACKSTOP rather than a duplicate, and before this file it had no test at all.
//
// `syncBackfillNeeded` had ZERO test references while its sibling arm
// `forceResync` had 35 — so every assertion about the recovery path was resting
// on comments. That matters beyond tidiness: #7842 proposes deleting the mirror
// walk on the grounds that the delta stream is authoritative, and with no guard
// here that deletion is green. The mechanism these cells pin is the reason it is
// not safe to delete.
//
// The shape of the recovery is easy to miss by reading: nothing replays a
// message. The sweep recovers by DECLINING TO ADVANCE `lastSweepTime` when a
// queue push failed, so the next sweep re-walks the identical
// `Created >= threshold` window and re-sends whatever was dropped.

// The two timestamps are deliberately in the PAST and deliberately DIFFERENT
// from the sweep's own `monotonicSeconds()`.
//
// A first draft of this file used `now` for both `lastSweepTime` and `Created`,
// and a mutation that let the sweep advance the window on overflow ESCAPED:
// advancing to `now` is indistinguishable from holding at `now`, and a session
// with `Created == now` still satisfies the advanced filter. The fixture has to
// place the window strictly behind the sweep's clock so that an advance moves
// the sessions OUT of the next sweep's `Created >= threshold` filter. That is
// what makes both assertions below able to fail.
func sweepReplayFixture(t *testing.T, base uint64) (*SessionSync, int) {
	t.Helper()
	now := base - 5 // session creation: inside the window, behind the sweep clock
	dp := &mockSweepDP{
		v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{
			{SrcIP: [4]byte{10, 0, 1, 1}, DstIP: [4]byte{10, 0, 2, 1}, Protocol: 6, SrcPort: 1000, DstPort: 80}: {
				State: dataplane.SessStateEstablished, Created: now, IsReverse: 0,
			},
			{SrcIP: [4]byte{10, 0, 1, 2}, DstIP: [4]byte{10, 0, 2, 2}, Protocol: 6, SrcPort: 2000, DstPort: 443}: {
				State: dataplane.SessStateEstablished, Created: now, IsReverse: 0,
			},
		},
		sessionCounter: 1,
	}
	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
	ss.stats.Connected.Store(true)
	ss.IsPrimaryFn = func() bool { return true }
	ss.lastSweepTime = base - 10 // window opens strictly before the sessions
	return ss, len(dp.v4sessions)
}

// fillSendQueue saturates the bounded channel so the next queueMessage takes its
// `default:` overflow branch. Filling rather than shrinking the channel keeps the
// test on the real capacity the daemon runs with.
func fillSendQueue(ss *SessionSync) {
	for len(ss.sendCh) < cap(ss.sendCh) {
		ss.sendCh <- []byte{}
	}
}

// TestSweepOverflowArmsBackfillAndReplaysTheWindow_7842 pins all three halves of
// the recovery: the arm, the refusal to advance the window, and the re-send.
//
// RED on revert: delete the `if overflow { s.syncBackfillNeeded.Store(true); ...
// return count }` early return in syncSweep and the window advances, so the
// replay assertion fails — which is precisely the state #7842 option 2 would
// leave the code in.
func TestSweepOverflowArmsBackfillAndReplaysTheWindow_7842(t *testing.T) {
	base := monotonicSeconds()
	ss, want := sweepReplayFixture(t, base)
	openedAt := base - 10

	fillSendQueue(ss)
	ss.syncSweep()

	if !ss.syncBackfillNeeded.Load() {
		t.Error("a sweep whose queue pushes failed must arm syncBackfillNeeded — that flag " +
			"is the only record that something was dropped, and the sweep is its only consumer")
	}
	if ss.stats.Errors.Load() == 0 {
		t.Error("a dropped queue push must count an Error — this is the counter #7842 says to measure")
	}
	if ss.lastSweepTime != openedAt {
		t.Errorf("lastSweepTime advanced to %d after an overflow (want it held at %d); "+
			"holding the window IS the recovery — advance it and the dropped sessions are "+
			"outside the next sweep's `Created >= threshold` filter forever",
			ss.lastSweepTime, openedAt)
	}

	// Drain and sweep again: the same window must be re-walked and re-sent.
	for len(ss.sendCh) > 0 {
		<-ss.sendCh
	}
	before := ss.stats.SessionsSent.Load()
	ss.syncSweep()
	if got := int(ss.stats.SessionsSent.Load() - before); got != want {
		t.Errorf("replay re-sent %d sessions, want %d — the recovery is a re-walk of the "+
			"UNADVANCED window, so every session dropped by the overflow must come back", got, want)
	}
	if ss.syncBackfillNeeded.Load() {
		t.Error("a clean sweep while replaying must clear syncBackfillNeeded; leaving it armed " +
			"pins the sweep at the active cadence forever")
	}
}

// TestDeltaStreamOverflowArmsTheSweepReplay_7842 is the cell that decides #7842
// option 2, and it is deliberately about the DELTA path rather than the sweep.
//
// QueueSessionV4 is what the userspace delta stream calls
// (queueUserspaceSessionDeltas -> queueDeltaSink.openV4 -> QueueSessionV4), and
// it shares one bounded channel with the sweep. So a dropped DELTA arms the
// SWEEP's replay. That is the whole argument: the mirror walk is not merely a
// second copy of what the delta stream sent, it is the delta stream's only
// recovery path for a daemon->peer drop. The helper's FullResync does not cover
// this — it repairs helper->daemon loss, and by this point the daemon has
// already consumed and acked the delta.
//
// RED on revert: drop the syncBackfillNeeded arm from queueMessage's overflow
// branch and a delta dropped on a full queue becomes unrecoverable and silent.
func TestDeltaStreamOverflowArmsTheSweepReplay_7842(t *testing.T) {
	base := monotonicSeconds()
	ss, _ := sweepReplayFixture(t, base)

	if ss.syncBackfillNeeded.Load() {
		t.Fatal("fixture starts with the arm already set; the assertion below would be vacuous")
	}
	fillSendQueue(ss)

	// The delta stream's own entry point, not the sweep's.
	ss.QueueSessionV4(
		dataplane.SessionKey{SrcIP: [4]byte{10, 0, 9, 9}, DstIP: [4]byte{10, 0, 9, 1}, Protocol: 6, SrcPort: 5555, DstPort: 80},
		dataplane.SessionValue{State: dataplane.SessStateEstablished, Created: base - 5, IsReverse: 0},
	)

	if !ss.syncBackfillNeeded.Load() {
		t.Error("a DELTA dropped by the shared send queue must arm the sweep replay — if it " +
			"does not, the delta stream has no recovery path of its own and #7842 option 2 " +
			"(skip the mirror walk) would make the drop permanent and silent")
	}
	if ss.stats.Errors.Load() == 0 {
		t.Error("a dropped delta must count an Error")
	}
}
