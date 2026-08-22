package cluster

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/dataplane"
)

// #6031: doBulkSync must frame its authoritative cold-prime window from TABLE
// TRUTH, not from the backend session store.
//
// Under the userspace dataplane that store is the `sessions`/`sessions_v6` BPF
// conntrack DISPLAY mirror. The Rust helper publishes a conntrack row from only
// three sites — the host-inbound (LocalMiss) install, the missing-neighbor seed,
// and the reverse-companion repair. The ordinary TRANSIT forward install
// (userspace-dp afxdp/poll_descriptor, "#4800: the single place a locally
// learned transit forward flow is installed") writes only the shim steering map
// and the shared session tables, so a transit session is STRUCTURALLY absent
// from the mirror the store walk reads.
//
// The standby's copy of that same session IS in its mirror, because the Go
// receive path writes it (userspace.Manager.SetClusterSyncedSessionV4 ->
// bpfShim.SetSessionV4), and reconcileStaleSessions scans exactly that map.
// Since #5085 removed the empty-bulk skip, an eligible session absent from the
// window is DELETED — so a mirror-framed window destroys precisely the live
// peer-owned transit sessions the standby needs at failover.
//
// The mirror-sourced loss was measured at base with this same harness: the
// window carried 1 session (the host-inbound row) and the receiver logged
// "reconcile stale sessions applied stale_v4=1 deleted_v4=1", deleting the live
// transit session.

// The sessions the scenarios below share.
var (
	// transitLive is a live, locally-learned TRANSIT session on the primary. It
	// is absent from the primary's conntrack mirror by construction and present
	// only in table truth.
	transitLive = dataplane.SessionKey{SrcIP: [4]byte{10, 0, 61, 50}, DstIP: [4]byte{172, 16, 80, 200}, Protocol: 6, SrcPort: 40000, DstPort: 5201}
	// hostInboundMirrored is a host-inbound session, one of the few populations
	// the helper DOES mirror to conntrack.
	hostInboundMirrored = dataplane.SessionKey{SrcIP: [4]byte{10, 0, 61, 9}, DstIP: [4]byte{10, 0, 61, 1}, Protocol: 6, SrcPort: 51000, DstPort: 22}
	// staleOnStandby closed on the primary and its delete never landed. #5085
	// requires the authoritative window to reconcile it away; the #6031 fix must
	// not weaken that.
	staleOnStandby = dataplane.SessionKey{SrcIP: [4]byte{10, 0, 61, 77}, DstIP: [4]byte{172, 16, 80, 200}, Protocol: 6, SrcPort: 41000, DstPort: 5201}
	// standbyOwnLocal lives in an RG the standby itself owns and must never be
	// touched by a peer's window.
	standbyOwnLocal = dataplane.SessionKey{SrcIP: [4]byte{10, 0, 1, 1}, DstIP: [4]byte{10, 0, 2, 1}, Protocol: 6, SrcPort: 3000, DstPort: 22}
)

func establishedIn(zone uint16) dataplane.SessionValue {
	return dataplane.SessionValue{State: dataplane.SessStateEstablished, IngressZone: zone}
}

// newBulk6031Primary builds the PRIMARY: owner of RG/zone 5, whose conntrack
// mirror holds only the host-inbound row — the transit session is not there.
func newBulk6031Primary(t *testing.T) (*SessionSync, *mockSweepDP) {
	t.Helper()
	dp := &mockSweepDP{
		v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{
			hostInboundMirrored: establishedIn(5),
		},
	}
	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
	ss.IsPrimaryFn = func() bool { return true }
	ss.IsPrimaryForRGFn = func(rgID int) bool { return rgID == 5 }
	ss.SetZoneRGMap(map[uint16]int{5: 5})
	return ss, dp
}

// newBulk6031Standby builds the STANDBY: owner of RG/zone 1, holding the live
// transit session and a stale one for the peer-owned zone 5, plus its own.
func newBulk6031Standby(t *testing.T) (*SessionSync, *mockSweepDP) {
	t.Helper()
	dp := &mockSweepDP{
		v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{
			transitLive:     establishedIn(5),
			staleOnStandby:  establishedIn(5),
			standbyOwnLocal: establishedIn(1),
		},
	}
	ss := NewSessionSync(":0", "10.0.0.3:4785", dp)
	ss.IsPrimaryFn = func() bool { return false }
	ss.IsPrimaryForRGFn = func(rgID int) bool { return rgID == 1 }
	ss.SetZoneRGMap(map[uint16]int{1: 1, 5: 5})
	return ss, dp
}

// TestDoBulkSyncFramesTableTruthNotTheMirror6031 is the #6031 fail-on-revert
// test. The primary's table truth holds a live TRANSIT session its conntrack
// mirror does not; the standby holds that session. After cold prime the transit
// session MUST survive — while the genuinely stale one is still reconciled away,
// so the #5085 property is intact.
//
// RED-on-revert: drop the BulkSnapshotSource branch from doBulkSync (or make it
// fall back to BulkSync) and the window is framed from the primary's mirror,
// which lacks transitLive — the receiver deletes it and the first assertion
// fires.
func TestDoBulkSyncFramesTableTruthNotTheMirror6031(t *testing.T) {
	senderSS, senderDP := newBulk6031Primary(t)
	receiverSS, receiverDP := newBulk6031Standby(t)

	// TABLE TRUTH: the live transit session the mirror cannot see. Asserting the
	// mirror's blindness explicitly keeps this fixture honest — if a future
	// change starts mirroring transit sessions, this test must be re-derived
	// rather than silently passing for the wrong reason.
	if _, mirrored := senderDP.v4sessions[transitLive]; mirrored {
		t.Fatal("fixture: the primary's conntrack mirror must NOT hold the transit session")
	}
	senderSS.BulkSnapshotSource = func() (BulkSnapshot, error) {
		return BulkSnapshot{V4: []dataplane.SessionEntryV4{
			{Key: transitLive, Value: establishedIn(5)},
		}}, nil
	}

	pumpBulk(t, senderSS, receiverSS)

	if _, ok := receiverDP.v4sessions[transitLive]; !ok {
		t.Fatal("#6031: the live peer-owned TRANSIT session must survive cold prime — " +
			"the window was framed from the BPF conntrack mirror, which never holds a transit session")
	}
	if _, ok := receiverDP.v4sessions[staleOnStandby]; ok {
		t.Fatal("#5085: a stale peer-owned session absent from the authoritative window must still be reconciled away")
	}
	if _, ok := receiverDP.v4sessions[standbyOwnLocal]; !ok {
		t.Fatal("the standby's own session (our RG) must never be reconciled")
	}
}

// TestDoBulkSyncFailsClosedWhenSnapshotSourceErrors6031 pins the fail direction.
// A table-truth source that errors must NOT degrade into the mirror walk: an
// incomplete authoritative window DELETES live sessions, whereas framing no
// window merely defers the reconcile and every doBulkSync caller re-arms its
// cold-prime / resync obligation for the next attempt.
//
// RED-on-revert: fall back to s.BulkSync() on a source error and the mirror
// window ships — the receiver deletes transitLive and the survival assertion
// fires.
func TestDoBulkSyncFailsClosedWhenSnapshotSourceErrors6031(t *testing.T) {
	senderSS, _ := newBulk6031Primary(t)
	receiverSS, receiverDP := newBulk6031Standby(t)

	// A LIVE connection is what makes this bite: with the peer wired, a fallback
	// to the store walk would actually frame the mirror window and the receiver
	// would delete transitLive. Without a connection the fallback would fail on
	// "no peer connection" and the test would pass for the wrong reason.
	local, peer := net.Pipe()
	defer local.Close()
	defer peer.Close()
	senderSS.mu.Lock()
	senderSS.conn0 = local
	senderSS.mu.Unlock()

	// Dispatch anything the sender writes into the receiver, so a fallback
	// window is genuinely delivered and reconciled rather than blocking on the
	// unbuffered pipe.
	framesDone := make(chan struct{})
	frames := make(chan byte, 16)
	go func() {
		defer close(framesDone)
		for {
			if err := peer.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
				return
			}
			mt, payload, err := readSyncFrame(peer)
			if err != nil {
				return
			}
			select {
			case frames <- byte(mt):
			default:
			}
			receiverSS.handleMessage(nil, mt, payload)
		}
	}()

	boom := errors.New("helper control socket timed out")
	senderSS.BulkSnapshotSource = func() (BulkSnapshot, error) { return BulkSnapshot{}, boom }

	err := senderSS.doBulkSync()
	if err == nil {
		t.Fatal("#6031: doBulkSync must return the snapshot-source error, not swallow it")
	}
	if !errors.Is(err, boom) {
		t.Fatalf("doBulkSync error = %v, want it to wrap %v", err, boom)
	}
	peer.Close()
	<-framesDone

	if len(frames) != 0 {
		t.Fatalf("#6031: a failed table-truth snapshot must frame NO window; %d frame(s) were written — "+
			"the mirror fallback shipped an authoritative window built from an incomplete source", len(frames))
	}
	// And nothing on the receiver was reconciled — including the live transit
	// session a mirror-sourced fallback would have destroyed.
	for _, key := range []dataplane.SessionKey{transitLive, staleOnStandby, standbyOwnLocal} {
		if _, ok := receiverDP.v4sessions[key]; !ok {
			t.Fatalf("no bulk window was framed, so the receiver must be untouched; session %v was deleted", key)
		}
	}
}

// TestBulkSyncSnapshotFramesEntriesVerbatim6031 pins that a caller-supplied
// snapshot is NOT re-filtered by ShouldSyncZone.
//
// The caller (daemon walkUserspaceSessionDeltas) already applies the strictly
// more precise owner-RG filter the incremental delta path uses. Re-applying the
// coarser zone filter on top could drop an entry the incremental path admits —
// a fabric-redirect wire alias, or a session whose owner RG this node holds but
// whose ingress zone maps elsewhere — and every entry missing from the window is
// DELETED on the receiver. The two paths must admit ONE set.
//
// RED-on-revert: reinstate the ShouldSyncZone filter inside snapshotBulkWalk and
// the zone-9 entry is dropped from the window, so the receiver deletes it.
func TestBulkSyncSnapshotFramesEntriesVerbatim6031(t *testing.T) {
	// Primary for RG/zone 5 only. Zone 9 must be MAPPED to an RG this node does
	// not own: an UNMAPPED zone falls through ShouldSyncZone to IsPrimaryFn,
	// which is true here, and the test would sample the passing point.
	senderDP := &mockSweepDP{
		v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{
			hostInboundMirrored: establishedIn(5),
		},
	}
	senderSS := NewSessionSync(":0", "10.0.0.2:4785", senderDP)
	senderSS.IsPrimaryFn = func() bool { return true }
	senderSS.IsPrimaryForRGFn = func(rgID int) bool { return rgID == 5 }
	senderSS.SetZoneRGMap(map[uint16]int{5: 5, 9: 9})

	notOurZone := dataplane.SessionKey{SrcIP: [4]byte{10, 0, 9, 9}, DstIP: [4]byte{172, 16, 80, 9}, Protocol: 6, SrcPort: 42000, DstPort: 5201}
	receiverDP := &mockSweepDP{
		v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{
			notOurZone: establishedIn(9),
		},
	}
	receiverSS := NewSessionSync(":0", "10.0.0.3:4785", receiverDP)
	receiverSS.IsPrimaryFn = func() bool { return false }
	// The receiver owns neither zone, so zone 9 is reconcile-eligible there.
	receiverSS.IsPrimaryForRGFn = func(rgID int) bool { return rgID == 1 }
	receiverSS.SetZoneRGMap(map[uint16]int{1: 1, 5: 5, 9: 9})

	if senderSS.ShouldSyncZone(9) {
		t.Fatal("fixture: the sender must NOT own zone 9, or this proves nothing")
	}
	senderSS.BulkSnapshotSource = func() (BulkSnapshot, error) {
		return BulkSnapshot{V4: []dataplane.SessionEntryV4{
			{Key: notOurZone, Value: establishedIn(9)},
		}}, nil
	}

	pumpBulk(t, senderSS, receiverSS)

	if _, ok := receiverDP.v4sessions[notOurZone]; !ok {
		t.Fatal("#6031: a caller-supplied snapshot entry must be framed verbatim — " +
			"re-applying ShouldSyncZone dropped it from the window, so the receiver deleted it")
	}
}

// TestBulkSyncStoreWalkStillFiltersZoneAndReverse6031 guards the OTHER walk: the
// unwired path (no BulkSnapshotSource) must keep BulkSync's original store-walk
// filtering, because the refactor that introduced bulkWalk moved those two
// predicates out of the send loop. A reverse entry and a zone this node does not
// own must both stay out of the window.
func TestBulkSyncStoreWalkStillFiltersZoneAndReverse6031(t *testing.T) {
	reverseOurZone := dataplane.SessionKey{SrcIP: [4]byte{172, 16, 80, 200}, DstIP: [4]byte{10, 0, 61, 50}, Protocol: 6, SrcPort: 5201, DstPort: 40000}
	foreignZone := dataplane.SessionKey{SrcIP: [4]byte{10, 0, 9, 9}, DstIP: [4]byte{172, 16, 80, 9}, Protocol: 6, SrcPort: 42000, DstPort: 5201}

	senderDP := &mockSweepDP{
		v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{
			hostInboundMirrored: establishedIn(5),
			foreignZone:         establishedIn(9),
			reverseOurZone: {
				State:       dataplane.SessStateEstablished,
				IngressZone: 5,
				IsReverse:   1,
			},
		},
	}
	senderSS := NewSessionSync(":0", "10.0.0.2:4785", senderDP)
	senderSS.IsPrimaryFn = func() bool { return true }
	senderSS.IsPrimaryForRGFn = func(rgID int) bool { return rgID == 5 }
	senderSS.SetZoneRGMap(map[uint16]int{5: 5, 9: 9})
	// No BulkSnapshotSource: this exercises the store walk.

	// The receiver holds all three; only the one the window carries survives.
	receiverDP := &mockSweepDP{
		v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{
			hostInboundMirrored: establishedIn(5),
			foreignZone:         establishedIn(9),
		},
	}
	receiverSS := NewSessionSync(":0", "10.0.0.3:4785", receiverDP)
	receiverSS.IsPrimaryFn = func() bool { return false }
	receiverSS.IsPrimaryForRGFn = func(rgID int) bool { return rgID == 1 }
	receiverSS.SetZoneRGMap(map[uint16]int{1: 1, 5: 5, 9: 9})

	pumpBulk(t, senderSS, receiverSS)

	if _, ok := receiverDP.v4sessions[hostInboundMirrored]; !ok {
		t.Fatal("the store walk must still frame an owned forward session")
	}
	if _, ok := receiverDP.v4sessions[foreignZone]; ok {
		t.Fatal("the store walk must still drop a zone this node does not own — " +
			"framing it would install a foreign-zone session on the peer")
	}
	if _, ok := receiverDP.v4sessions[reverseOurZone]; ok {
		t.Fatal("the store walk must still drop reverse entries; the receiver synthesizes its own companion")
	}
}
