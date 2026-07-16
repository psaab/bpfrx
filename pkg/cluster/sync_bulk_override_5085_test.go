package cluster

import (
	"encoding/binary"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/dataplane"
)

// pumpBulk drives senderSS.doBulkSync() over a net.Pipe and dispatches every
// framed message the sender writes into receiverSS.handleMessage. It returns
// after the receiver has processed the terminating BulkEnd — at which point the
// receiver's SYNCHRONOUS reconcileStaleSessions has already run — so callers can
// assert on the receiver's session table immediately. It fails the test if the
// sender errors or no BulkEnd arrives.
//
// This exercises the real #5085 seam end to end: the PRIMARY's doBulkSync frames
// the authoritative snapshot on the wire, and the STANDBY reconciles against
// exactly that window.
func pumpBulk(t *testing.T, senderSS, receiverSS *SessionSync) {
	t.Helper()
	local, peer := net.Pipe()
	defer local.Close()
	defer peer.Close()

	senderSS.mu.Lock()
	senderSS.conn0 = local
	senderSS.mu.Unlock()

	errCh := make(chan error, 1)
	go func() { errCh <- senderSS.doBulkSync() }()

	deadline := time.Now().Add(5 * time.Second)
	for {
		if err := peer.SetReadDeadline(deadline); err != nil {
			t.Fatalf("set read deadline: %v", err)
		}
		mt, payload, err := readSyncFrame(peer)
		if err != nil {
			t.Fatalf("reading bulk frame from sender: %v", err)
		}
		// nil conn: the receiver's BulkEnd handler skips sendBulkAck on a nil
		// conn, so no ack is written back into the pipe (no deadlock).
		receiverSS.handleMessage(nil, mt, payload)
		if mt == syncMsgBulkEnd {
			break
		}
	}
	if err := <-errCh; err != nil {
		t.Fatalf("doBulkSync returned error: %v", err)
	}
}

// TestDoBulkSyncOverrideReconcilesStalePeerSession_5085 is the #5085
// fail-on-revert test. The standby ALREADY HOLDS a stale peer-owned session
// (staleB) whose delete it missed; the primary's authoritative cold-prime
// snapshot does NOT include it. After doBulkSync completes, the stale session
// MUST be reconciled away, the still-live peer session (freshA) MUST survive,
// and the standby's own local session (localC) MUST be untouched.
//
// A BulkSyncOverride is set (a no-op fast-population pre-step, exactly the
// production wiring shape that regressed) to prove the fix holds through the
// override branch: doBulkSync now ALWAYS runs the authoritative BulkSync window
// afterwards.
//
// RED-on-revert: revert the change and doBulkSync's override path sends an EMPTY
// BulkStart/BulkEnd (sendBulkMarkers) again — freshA is never framed, the
// receiver's empty-bulk skip suppresses reconciliation, and staleB SURVIVES.
func TestDoBulkSyncOverrideReconcilesStalePeerSession_5085(t *testing.T) {
	freshA := dataplane.SessionKey{SrcIP: [4]byte{10, 0, 5, 1}, DstIP: [4]byte{10, 0, 6, 1}, Protocol: 6, SrcPort: 1000, DstPort: 80}
	staleB := dataplane.SessionKey{SrcIP: [4]byte{10, 0, 5, 2}, DstIP: [4]byte{10, 0, 6, 2}, Protocol: 6, SrcPort: 2000, DstPort: 443}
	localC := dataplane.SessionKey{SrcIP: [4]byte{10, 0, 1, 1}, DstIP: [4]byte{10, 0, 2, 1}, Protocol: 6, SrcPort: 3000, DstPort: 22}

	// PRIMARY (sender): owns RG 5 (zone 5). Its live table holds only freshA —
	// staleB's session was closed and its delete never reached the standby.
	senderDP := &mockSweepDP{
		v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{
			freshA: {State: dataplane.SessStateEstablished, IsReverse: 0, IngressZone: 5},
		},
	}
	senderSS := NewSessionSync(":0", "10.0.0.2:4785", senderDP)
	senderSS.IsPrimaryFn = func() bool { return true }
	senderSS.IsPrimaryForRGFn = func(rgID int) bool { return rgID == 5 }
	senderSS.SetZoneRGMap(map[uint16]int{5: 5})
	// Fast-population override (no-op here): the same wiring SHAPE that
	// historically sent empty markers. The trailing BulkSync must still make
	// the window authoritative.
	senderSS.BulkSyncOverride = func() error { return nil }

	// STANDBY (receiver): peer owns RG 5 (reconcile-eligible), we own RG 1.
	// Holds freshA + a STALE peer-owned session (staleB) + our own localC.
	receiverDP := &mockSweepDP{
		v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{
			freshA: {State: dataplane.SessStateEstablished, IsReverse: 0, IngressZone: 5},
			staleB: {State: dataplane.SessStateEstablished, IsReverse: 0, IngressZone: 5},
			localC: {State: dataplane.SessStateEstablished, IsReverse: 0, IngressZone: 1},
		},
	}
	receiverSS := NewSessionSync(":0", "10.0.0.3:4785", receiverDP)
	receiverSS.IsPrimaryFn = func() bool { return false }
	receiverSS.IsPrimaryForRGFn = func(rgID int) bool { return rgID == 1 }
	receiverSS.SetZoneRGMap(map[uint16]int{1: 1, 5: 5})

	pumpBulk(t, senderSS, receiverSS)

	if _, ok := receiverDP.v4sessions[staleB]; ok {
		t.Fatal("#5085: stale peer-owned session absent from the authoritative cold-prime snapshot must be reconciled away")
	}
	if _, ok := receiverDP.v4sessions[freshA]; !ok {
		t.Fatal("live peer-owned session present in the snapshot must survive")
	}
	if _, ok := receiverDP.v4sessions[localC]; !ok {
		t.Fatal("standby's own local session (our RG) must never be reconciled")
	}
}

// TestDoBulkSyncEmptyAuthoritativeReconcilesEligibleAbsent_5085 proves the
// empty-snapshot arm end to end: the primary genuinely holds NO syncable
// sessions, so doBulkSync frames an EMPTY-but-authoritative BulkStart/BulkEnd
// window. Every eligible-absent stale peer-owned session on the standby MUST be
// reconciled away; the standby's own session survives.
//
// RED-on-revert: the override path sends empty markers AND the receiver's
// empty-bulk skip returns before reconciling, so the stale session SURVIVES.
func TestDoBulkSyncEmptyAuthoritativeReconcilesEligibleAbsent_5085(t *testing.T) {
	staleB := dataplane.SessionKey{SrcIP: [4]byte{10, 0, 5, 2}, DstIP: [4]byte{10, 0, 6, 2}, Protocol: 6, SrcPort: 2000, DstPort: 443}
	localC := dataplane.SessionKey{SrcIP: [4]byte{10, 0, 1, 1}, DstIP: [4]byte{10, 0, 2, 1}, Protocol: 6, SrcPort: 3000, DstPort: 22}

	// PRIMARY: empty live table (no syncable sessions).
	senderDP := &mockSweepDP{v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{}}
	senderSS := NewSessionSync(":0", "10.0.0.2:4785", senderDP)
	senderSS.IsPrimaryFn = func() bool { return true }
	senderSS.IsPrimaryForRGFn = func(rgID int) bool { return rgID == 5 }
	senderSS.SetZoneRGMap(map[uint16]int{5: 5})
	senderSS.BulkSyncOverride = func() error { return nil }

	// STANDBY: holds a stale peer-owned session + a local one.
	receiverDP := &mockSweepDP{
		v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{
			staleB: {State: dataplane.SessStateEstablished, IsReverse: 0, IngressZone: 5},
			localC: {State: dataplane.SessStateEstablished, IsReverse: 0, IngressZone: 1},
		},
	}
	receiverSS := NewSessionSync(":0", "10.0.0.3:4785", receiverDP)
	receiverSS.IsPrimaryFn = func() bool { return false }
	receiverSS.IsPrimaryForRGFn = func(rgID int) bool { return rgID == 1 }
	receiverSS.SetZoneRGMap(map[uint16]int{1: 1, 5: 5})

	pumpBulk(t, senderSS, receiverSS)

	if _, ok := receiverDP.v4sessions[staleB]; ok {
		t.Fatal("#5085: a genuinely-empty authoritative snapshot must delete all eligible-absent stale peer-owned sessions")
	}
	if _, ok := receiverDP.v4sessions[localC]; !ok {
		t.Fatal("standby's own local session (our RG) must never be reconciled")
	}
}

// TestDoBulkSyncSpuriousBulkEndDoesNotReconcile_5085 guards the #5272 invariant
// against the #5085 change: removing the empty-bulk reconcile skip must NOT let
// a spurious no-transfer BulkEnd reconcile. A BulkEnd that arrives with NO
// preceding BulkStart (bulkInProgress == false) must be dropped — no reconcile,
// no completion flag, no callback — even though it carries an empty received
// set (which the reconcile path would otherwise now act on).
func TestDoBulkSyncSpuriousBulkEndDoesNotReconcile_5085(t *testing.T) {
	staleB := dataplane.SessionKey{SrcIP: [4]byte{10, 0, 5, 2}, DstIP: [4]byte{10, 0, 6, 2}, Protocol: 6, SrcPort: 2000, DstPort: 443}
	dp := &mockSweepDP{
		v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{
			staleB: {State: dataplane.SessStateEstablished, IsReverse: 0, IngressZone: 5},
		},
	}
	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
	ss.IsPrimaryFn = func() bool { return false }
	ss.IsPrimaryForRGFn = func(rgID int) bool { return false } // peer owns zone 5 → eligible
	ss.SetZoneRGMap(map[uint16]int{5: 5})

	var calledMu sync.Mutex
	called := false
	ss.OnBulkSyncReceived = func() {
		calledMu.Lock()
		called = true
		calledMu.Unlock()
	}

	// Spurious BulkEnd (epoch 42) with NO preceding BulkStart.
	var spuriousBuf [8]byte
	binary.LittleEndian.PutUint64(spuriousBuf[:], 42)
	ss.handleMessage(nil, syncMsgBulkEnd, spuriousBuf[:])

	time.Sleep(50 * time.Millisecond)
	if _, ok := dp.v4sessions[staleB]; !ok {
		t.Fatal("#5272: a spurious no-transfer BulkEnd must NOT reconcile — the eligible session must survive")
	}
	if ss.BulkEverCompleted() {
		t.Fatal("#5272: a spurious no-transfer BulkEnd must NOT set bulkEverCompleted")
	}
	calledMu.Lock()
	fired := called
	calledMu.Unlock()
	if fired {
		t.Fatal("#5272: a spurious no-transfer BulkEnd must NOT fire OnBulkSyncReceived")
	}
}
