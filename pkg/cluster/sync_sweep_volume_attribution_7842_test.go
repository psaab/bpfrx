package cluster

import (
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// #7842 asks for the sweep-vs-delta-stream duplication to be settled by
// measuring "stats.SessionsSent and stats.Errors at a realistic connection
// rate". That measurement CANNOT settle it, and this file is the fix plus its
// guard.
//
// Both producers call `queueMessage(msg, &s.stats.SessionsSent, source)` --
// the sweep at sync_conn_sweep.go and the delta stream via QueueSessionV4/V6 at
// sync_conn_write.go -- so `SessionsSent` is their SUM. The `source` string is
// consumed in exactly one place, the send-queue-overflow warning, so nothing
// separates a backstop duplicate from an authoritative original. Two runs on
// the loss cluster produced totals that could not be attributed for precisely
// that reason before this counter existed.
//
// `SweepSessionsSent` is a SUB-TOTAL, not a second population: a sweep send
// increments both counters, so the delta stream's share is the difference. The
// cells below pin that relationship from both sides, because a sub-total is
// only meaningful if the thing it is a subset OF still counts the same.

func attributionFixture(t *testing.T, base uint64) (*SessionSync, int) {
	t.Helper()
	created := base - 5
	dp := &mockSweepDP{
		v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{
			{SrcIP: [4]byte{10, 0, 1, 1}, DstIP: [4]byte{10, 0, 2, 1}, Protocol: 6, SrcPort: 1000, DstPort: 80}: {
				State: dataplane.SessStateEstablished, Created: created, IsReverse: 0,
			},
			{SrcIP: [4]byte{10, 0, 1, 2}, DstIP: [4]byte{10, 0, 2, 2}, Protocol: 6, SrcPort: 2000, DstPort: 443}: {
				State: dataplane.SessStateEstablished, Created: created, IsReverse: 0,
			},
		},
		sessionCounter: 1,
	}
	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
	ss.stats.Connected.Store(true)
	ss.IsPrimaryFn = func() bool { return true }
	ss.lastSweepTime = base - 10
	return ss, len(dp.v4sessions)
}

// A sweep send must increment BOTH the total and the sweep sub-total.
//
// RED on revert: delete `s.stats.SweepSessionsSent.Add(1)` from syncSweep and
// the sub-total stays 0 while the total moves — which is exactly the
// unattributable state that made #7842's prescribed measurement useless.
func TestSweepSendsAreAttributedToTheSweep_7842(t *testing.T) {
	base := monotonicSeconds()
	ss, want := attributionFixture(t, base)

	if got := ss.stats.SweepSessionsSent.Load(); got != 0 {
		t.Fatalf("premise: sweep sub-total must start at 0, got %d", got)
	}
	sent := ss.syncSweep()
	if sent != want {
		t.Fatalf("premise broken: sweep queued %d of %d sessions — the fixture is not "+
			"exercising the send path and every assertion below would be vacuous", sent, want)
	}

	total := ss.stats.SessionsSent.Load()
	sweep := ss.stats.SweepSessionsSent.Load()
	if total != uint64(want) {
		t.Errorf("SessionsSent = %d, want %d — the existing total must be unchanged by "+
			"the attribution change", total, want)
	}
	if sweep != uint64(want) {
		t.Errorf("SweepSessionsSent = %d, want %d. Every sweep send must be attributable, "+
			"or #7842's volume question stays undecidable: a duplicate and an original are "+
			"indistinguishable in SessionsSent alone", sweep, want)
	}
	if total-sweep != 0 {
		t.Errorf("derived delta-stream share = %d, want 0 — this sweep-only fixture sent "+
			"nothing through QueueSessionV4", total-sweep)
	}
}

// The other side of the sub-total, and the cell that keeps the one above from
// passing for the wrong reason: a DELTA-STREAM send must move the total and
// must NOT move the sweep sub-total.
//
// Without this, incrementing SweepSessionsSent unconditionally inside
// queueMessage would satisfy the first cell while making the counter mean
// "everything", which is the same unattributable state in a new name.
func TestDeltaStreamSendsAreNotAttributedToTheSweep_7842(t *testing.T) {
	base := monotonicSeconds()
	ss, _ := attributionFixture(t, base)

	key := dataplane.SessionKey{
		SrcIP: [4]byte{10, 0, 9, 9}, DstIP: [4]byte{10, 0, 8, 8},
		Protocol: 6, SrcPort: 4444, DstPort: 8080,
	}
	val := dataplane.SessionValue{State: dataplane.SessStateEstablished, Created: base - 5}

	ss.QueueSessionV4(key, val)

	total := ss.stats.SessionsSent.Load()
	sweep := ss.stats.SweepSessionsSent.Load()
	if total != 1 {
		t.Fatalf("premise broken: QueueSessionV4 sent %d messages, want 1 — the fixture is "+
			"not exercising the delta-stream path", total)
	}
	if sweep != 0 {
		t.Errorf("SweepSessionsSent = %d after a DELTA-STREAM send, want 0. The sub-total "+
			"must attribute only the mirror walk; counting both producers reproduces the "+
			"exact ambiguity #7842 is stuck on", sweep)
	}
	if total-sweep != 1 {
		t.Errorf("derived delta-stream share = %d, want 1", total-sweep)
	}
}

// The snapshot is the only way an operator or a test harness reads these, so a
// counter that moves but is not carried across is not observable. `Stats()`
// builds SyncStatsSnapshot field by field, which is exactly the shape where a
// new field is silently dropped.
func TestSweepSubTotalReachesTheStatsSnapshot_7842(t *testing.T) {
	base := monotonicSeconds()
	ss, want := attributionFixture(t, base)
	if sent := ss.syncSweep(); sent != want {
		t.Fatalf("premise broken: sweep queued %d of %d", sent, want)
	}
	snap := ss.Stats()
	if snap.SweepSessionsSent != uint64(want) {
		t.Errorf("SyncStatsSnapshot.SweepSessionsSent = %d, want %d — the counter moves but "+
			"does not reach the snapshot, so nothing outside pkg/cluster can read it",
			snap.SweepSessionsSent, want)
	}
	if snap.SessionsSent != uint64(want) {
		t.Errorf("SyncStatsSnapshot.SessionsSent = %d, want %d", snap.SessionsSent, want)
	}
}
