package cluster

import (
	"errors"
	"net"
	"os"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/dataplane"
)

// #6031 — the cold-prime bulk window must be delimited from TABLE-TRUTH, not
// from the best-effort BPF display mirror the local session store walks.
//
// On the userspace dataplane `s.sessions.ForEachV4/V6` iterates the BPF
// conntrack maps the Rust helper publishes for `show security flow session`
// (publish_bpf_conntrack_entry), NOT the helper's authoritative in-process
// SessionTable. The mirror can be under-populated (publish gating at table cap
// / on install_failed, periodic-refresh lag). Since #5085 removed the
// empty-bulk reconcile skip, an under-populated window is not a missed
// optimisation — the receiver treats every absent key as stale and DELETES it.

func bulkSourceKey(a, b byte, sport uint16) dataplane.SessionKey {
	return dataplane.SessionKey{
		SrcIP:    [4]byte{10, 0, 5, a},
		DstIP:    [4]byte{10, 0, 6, b},
		Protocol: 6,
		SrcPort:  sport,
		DstPort:  80,
	}
}

// newBulkSourcePair builds the #5085 primary/standby pair: the sender owns RG5
// (zone 5), the receiver owns RG1 and holds sessions in both zones.
func newBulkSourcePair(t *testing.T, senderStore, receiverStore map[dataplane.SessionKey]dataplane.SessionValue) (*SessionSync, *SessionSync, *mockSweepDP) {
	t.Helper()
	senderDP := &mockSweepDP{v4sessions: senderStore}
	senderSS := NewSessionSync(":0", "10.0.0.2:4785", senderDP)
	senderSS.IsPrimaryFn = func() bool { return true }
	senderSS.IsPrimaryForRGFn = func(rgID int) bool { return rgID == 5 }
	senderSS.SetZoneRGMap(map[uint16]int{5: 5})

	receiverDP := &mockSweepDP{v4sessions: receiverStore}
	receiverSS := NewSessionSync(":0", "10.0.0.3:4785", receiverDP)
	receiverSS.IsPrimaryFn = func() bool { return false }
	receiverSS.IsPrimaryForRGFn = func(rgID int) bool { return rgID == 1 }
	receiverSS.SetZoneRGMap(map[uint16]int{1: 1, 5: 5})
	return senderSS, receiverSS, receiverDP
}

// TestBulkSyncSourcesWindowFromTableTruthNotMirror_6031 is the fail-on-revert
// guard for the residual itself.
//
// The primary's helper holds TWO live sessions for its owned RG. Its BPF
// display mirror — the store BulkSync used to walk — has only one of them:
// `mirrorOnly`. `tableTruth` is live but was never published (table cap /
// install_failed / refresh lag). The standby holds BOTH.
//
// RED on revert: drop the BulkSessionSource consultation from BulkSync (walk
// the store as before) and `tableTruth` is absent from the window, so the
// receiver reconciles a LIVE peer-owned session away.
func TestBulkSyncSourcesWindowFromTableTruthNotMirror_6031(t *testing.T) {
	mirrorOnly := bulkSourceKey(1, 1, 1000)
	tableTruth := bulkSourceKey(2, 2, 2000)
	localC := dataplane.SessionKey{SrcIP: [4]byte{10, 0, 1, 1}, DstIP: [4]byte{10, 0, 2, 1}, Protocol: 6, SrcPort: 3000, DstPort: 22}
	live := dataplane.SessionValue{State: dataplane.SessStateEstablished, IngressZone: 5}

	senderSS, receiverSS, receiverDP := newBulkSourcePair(t,
		// The MIRROR is missing tableTruth — the drift this issue is about.
		map[dataplane.SessionKey]dataplane.SessionValue{mirrorOnly: live},
		map[dataplane.SessionKey]dataplane.SessionValue{
			mirrorOnly: live,
			tableTruth: live,
			localC:     {State: dataplane.SessStateEstablished, IngressZone: 1},
		})

	calls := 0
	senderSS.BulkSessionSource = func() (*BulkSessionSnapshot, error) {
		calls++
		return &BulkSessionSnapshot{V4: []dataplane.SessionEntryV4{
			{Key: mirrorOnly, Value: live},
			{Key: tableTruth, Value: live},
		}}, nil
	}

	pumpBulk(t, senderSS, receiverSS)

	if calls != 1 {
		t.Fatalf("BulkSessionSource consulted %d times, want exactly 1 per window", calls)
	}
	if _, ok := receiverDP.v4sessions[tableTruth]; !ok {
		t.Fatal("#6031: a LIVE peer-owned session absent from the primary's BPF display mirror " +
			"but present in table-truth was reconciled away — the cold-prime window must be " +
			"sourced from the authoritative export, not the mirror")
	}
	if _, ok := receiverDP.v4sessions[mirrorOnly]; !ok {
		t.Fatal("a live peer-owned session present in the window must survive")
	}
	if _, ok := receiverDP.v4sessions[localC]; !ok {
		t.Fatal("the standby's own session (our RG) must never be reconciled")
	}
}

// TestBulkSyncSourceOverridesMirrorPhantom_6031 is the other drift direction: a
// PHANTOM in the mirror (an entry the helper published but that is no longer in
// the authoritative table). The window must not carry it, so the standby's copy
// is reconciled away rather than being kept alive by a stale display record.
func TestBulkSyncSourceOverridesMirrorPhantom_6031(t *testing.T) {
	realSession := bulkSourceKey(1, 1, 1000)
	phantom := bulkSourceKey(3, 3, 3000)
	live := dataplane.SessionValue{State: dataplane.SessStateEstablished, IngressZone: 5}

	senderSS, receiverSS, receiverDP := newBulkSourcePair(t,
		map[dataplane.SessionKey]dataplane.SessionValue{realSession: live, phantom: live},
		map[dataplane.SessionKey]dataplane.SessionValue{realSession: live, phantom: live})

	senderSS.BulkSessionSource = func() (*BulkSessionSnapshot, error) {
		return &BulkSessionSnapshot{V4: []dataplane.SessionEntryV4{{Key: realSession, Value: live}}}, nil
	}

	pumpBulk(t, senderSS, receiverSS)

	if _, ok := receiverDP.v4sessions[phantom]; ok {
		t.Fatal("#6031: a mirror PHANTOM the authoritative table no longer holds must not be " +
			"framed into the window — the standby kept a session the primary has closed")
	}
	if _, ok := receiverDP.v4sessions[realSession]; !ok {
		t.Fatal("the authoritative session must survive")
	}
}

// TestBulkSyncEmptySnapshotIsAuthoritative_6031 pins the distinction the source
// contract turns on: an EMPTY snapshot is an authoritative "I own nothing", not
// an absent source. It must produce a real BulkStart/BulkEnd window that
// reconciles — NOT a silent fall-back to the mirror, which here still holds
// sessions and would keep the standby's stale copy alive.
func TestBulkSyncEmptySnapshotIsAuthoritative_6031(t *testing.T) {
	stale := bulkSourceKey(2, 2, 2000)
	live := dataplane.SessionValue{State: dataplane.SessStateEstablished, IngressZone: 5}

	senderSS, receiverSS, receiverDP := newBulkSourcePair(t,
		// The mirror still lists it; table-truth says we own nothing.
		map[dataplane.SessionKey]dataplane.SessionValue{stale: live},
		map[dataplane.SessionKey]dataplane.SessionValue{stale: live})

	senderSS.BulkSessionSource = func() (*BulkSessionSnapshot, error) {
		return &BulkSessionSnapshot{}, nil
	}

	pumpBulk(t, senderSS, receiverSS)

	if _, ok := receiverDP.v4sessions[stale]; ok {
		t.Fatal("#6031: an EMPTY authoritative snapshot must reconcile the standby's stale " +
			"peer-owned sessions away — it was treated as an absent source and the mirror " +
			"walk kept the session alive")
	}
}

// TestBulkSyncNilSnapshotFallsBackToStore_6031 pins the compatibility arm: a
// source that reports "no authoritative source right now" (nil, nil) — no
// userspace runtime, no committed config — must leave the pre-#6031 store walk
// in place rather than sending an empty window that deletes live sessions.
func TestBulkSyncNilSnapshotFallsBackToStore_6031(t *testing.T) {
	fromStore := bulkSourceKey(1, 1, 1000)
	live := dataplane.SessionValue{State: dataplane.SessStateEstablished, IngressZone: 5}

	senderSS, receiverSS, receiverDP := newBulkSourcePair(t,
		map[dataplane.SessionKey]dataplane.SessionValue{fromStore: live},
		map[dataplane.SessionKey]dataplane.SessionValue{fromStore: live})

	senderSS.BulkSessionSource = func() (*BulkSessionSnapshot, error) { return nil, nil }

	pumpBulk(t, senderSS, receiverSS)

	if _, ok := receiverDP.v4sessions[fromStore]; !ok {
		t.Fatal("#6031: a (nil, nil) source means no authoritative snapshot is available and " +
			"BulkSync must fall back to the session-store walk — instead an empty window " +
			"reconciled a live session away")
	}
}

// TestBulkSyncSourceErrorAbortsWithoutOpeningWindow_6031 pins the error
// posture, which is the whole reason the contract has three cases rather than
// two. When the authoritative export FAILS, falling back to the mirror would
// reconcile the peer against exactly the source this change decided is not
// authoritative — the unrecoverable direction. BulkSync must abort, and it must
// abort BEFORE writing BulkStart: a window the receiver has opened but that is
// never completed with a full session set is the same hazard.
//
// Every doBulkSync caller re-arms and retries on error (handleNewConnection's
// needColdPrime latch, the survivor re-drive, the #82 sweep re-drive), so
// aborting costs a round, not the reconcile.
func TestBulkSyncSourceErrorAbortsWithoutOpeningWindow_6031(t *testing.T) {
	live := dataplane.SessionValue{State: dataplane.SessStateEstablished, IngressZone: 5}
	senderSS, _, _ := newBulkSourcePair(t,
		map[dataplane.SessionKey]dataplane.SessionValue{bulkSourceKey(1, 1, 1000): live},
		nil)

	injected := errors.New("helper control socket refused export_owner_rg_sessions")
	senderSS.BulkSessionSource = func() (*BulkSessionSnapshot, error) { return nil, injected }

	local, peer := net.Pipe()
	defer local.Close()
	defer peer.Close()
	senderSS.mu.Lock()
	senderSS.conn0 = local
	senderSS.mu.Unlock()

	before := senderSS.stats.BulkSyncs.Load()
	err := senderSS.BulkSync()
	if err == nil {
		t.Fatal("#6031: BulkSync succeeded although the authoritative session source FAILED — " +
			"the window would have been reconciled against the mirror we just distrusted")
	}
	if !errors.Is(err, injected) {
		t.Fatalf("BulkSync error = %v, want it to carry the source failure", err)
	}
	if got := senderSS.stats.BulkSyncs.Load(); got != before {
		t.Fatalf("BulkSyncs counter moved (%d -> %d) on an aborted bulk", before, got)
	}
	// Nothing may have been written: a BulkStart the receiver acts on but that
	// no BulkEnd completes is its own hazard.
	if err := peer.SetReadDeadline(time.Now().Add(150 * time.Millisecond)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	buf := make([]byte, 1)
	if n, rerr := peer.Read(buf); rerr == nil || !errors.Is(rerr, os.ErrDeadlineExceeded) {
		t.Fatalf("#6031: sender wrote %d byte(s) (read err %v) before aborting — the source must "+
			"be resolved BEFORE the BulkStart marker opens a window", n, rerr)
	}
}

// countBulkSessionFrames drives senderSS.BulkSync() over a pipe and returns how
// many syncMsgSessionV4/V6 frames the window carried. Asserting on the WIRE is
// the honest question for a filtering rule: it does not depend on what the
// receiver's fake store chooses to install.
func countBulkSessionFrames(t *testing.T, senderSS *SessionSync) int {
	t.Helper()
	local, peer := net.Pipe()
	defer local.Close()
	defer peer.Close()
	senderSS.mu.Lock()
	senderSS.conn0 = local
	senderSS.mu.Unlock()

	errCh := make(chan error, 1)
	go func() { errCh <- senderSS.BulkSync() }()

	sessions := 0
	deadline := time.Now().Add(5 * time.Second)
	for {
		if err := peer.SetReadDeadline(deadline); err != nil {
			t.Fatalf("set read deadline: %v", err)
		}
		mt, _, err := readSyncFrame(peer)
		if err != nil {
			t.Fatalf("reading bulk frame: %v", err)
		}
		if mt == syncMsgSessionV4 || mt == syncMsgSessionV6 {
			sessions++
		}
		if mt == syncMsgBulkEnd {
			break
		}
	}
	if err := <-errCh; err != nil {
		t.Fatalf("BulkSync returned error: %v", err)
	}
	return sessions
}

// TestBulkSyncSnapshotSkipsReverseEntries_6031 pins that the shared per-session
// send path still applies the reverse-entry rule to a SUPPLIED snapshot: only
// forward sessions belong on the wire. The receiver's reconcile candidate set
// skips reverse entries too, so a framed reverse entry is an unmatchable key.
//
// RED on revert: drop the `val.IsReverse != 0` guard from the snapshot path and
// the frame count is 2.
func TestBulkSyncSnapshotSkipsReverseEntries_6031(t *testing.T) {
	fwd := bulkSourceKey(1, 1, 1000)
	rev := bulkSourceKey(9, 9, 9000)
	live := dataplane.SessionValue{State: dataplane.SessStateEstablished, IngressZone: 5}

	senderSS, _, _ := newBulkSourcePair(t, map[dataplane.SessionKey]dataplane.SessionValue{}, nil)
	senderSS.BulkSessionSource = func() (*BulkSessionSnapshot, error) {
		return &BulkSessionSnapshot{V4: []dataplane.SessionEntryV4{
			{Key: fwd, Value: live},
			{Key: rev, Value: dataplane.SessionValue{State: dataplane.SessStateEstablished, IngressZone: 5, IsReverse: 1}},
		}}, nil
	}

	if got := countBulkSessionFrames(t, senderSS); got != 1 {
		t.Fatalf("bulk window carried %d session frames, want 1 — a REVERSE entry must not be "+
			"framed from a supplied snapshot", got)
	}
}

// TestBulkSyncSnapshotBypassesZoneFilter_6031 pins the deliberate filtering
// change. The store walk can only approximate ownership with ShouldSyncZone (a
// zone->RG config map); the source has already applied the per-session OWNER-RG
// and origin filter the helper's export performs. Re-applying the zone
// approximation on top would silently drop sessions the authoritative export
// says we own — a session whose zone is not in this node's zone->RG map (a
// day-2 zone, a fabric-redirect wire alias) would vanish from the window and be
// reconciled away on the standby.
//
// RED on revert: apply ShouldSyncZone to the snapshot path too and the frame
// count drops to 0.
func TestBulkSyncSnapshotBypassesZoneFilter_6031(t *testing.T) {
	// Zone 77 is NOT in the sender's zone->RG map, so ShouldSyncZone is false
	// for it: IsPrimaryForRGFn is set, the lookup misses, and the IsPrimaryFn
	// fallback is only reached when the map has no entry — which is exactly the
	// shape a day-2 zone has before the map is refreshed.
	unmapped := bulkSourceKey(4, 4, 4000)
	senderSS, _, _ := newBulkSourcePair(t, map[dataplane.SessionKey]dataplane.SessionValue{}, nil)
	senderSS.IsPrimaryFn = func() bool { return false }
	senderSS.BulkSessionSource = func() (*BulkSessionSnapshot, error) {
		return &BulkSessionSnapshot{V4: []dataplane.SessionEntryV4{
			{Key: unmapped, Value: dataplane.SessionValue{State: dataplane.SessStateEstablished, IngressZone: 77}},
		}}, nil
	}
	if !senderSS.ShouldSyncZone(77) == false {
		t.Fatal("precondition: zone 77 must NOT pass ShouldSyncZone for this test to mean anything")
	}

	if got := countBulkSessionFrames(t, senderSS); got != 1 {
		t.Fatalf("bulk window carried %d session frames, want 1 — a supplied snapshot is already "+
			"owner-RG filtered and must not be re-filtered by the zone approximation", got)
	}
}
