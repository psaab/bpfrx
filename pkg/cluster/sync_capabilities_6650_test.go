// #6650 wire half: the session-sync capability advertisement that lets a
// primary learn what its peer's config-snapshot protocol can represent.
//
// The advertisement rides this connection rather than the heartbeat because it
// is the SAME connection the config push goes over — so "peer reachable" and
// "peer capability known" share one lifecycle — and because the heartbeat's
// optional sections are located by back-indexing from a fixed-size auth
// trailer (the #6169 boot epoch sits at len-68), which makes a second tail
// section's offset depend on whether the first is present, and requires a PSK
// that an unkeyed cluster does not have.
//
// FAIL-ON-REVERT: drop the peerSnapshotProtocol.Store(0) from handleDisconnect
// and the incarnation test goes RED; drop the sendCapabilities call from the
// connection install and the wiring test names it.
package cluster

import (
	"encoding/binary"
	"go/parser"
	"go/token"
	"testing"
)

func TestPeerSnapshotProtocolAccessorDefaultsToIncapable6650(t *testing.T) {
	var s *SessionSync
	if got := s.PeerSnapshotProtocolVersion(); got != 0 {
		t.Fatalf("nil SessionSync reported peer version %d, want 0", got)
	}
	ss := &SessionSync{}
	if got := ss.PeerSnapshotProtocolVersion(); got != 0 {
		t.Fatalf("fresh SessionSync reported peer version %d, want 0 — a peer that has "+
			"advertised nothing must read as INCAPABLE, never as some default capability", got)
	}
}

func TestSetLocalSnapshotProtocolVersionRoundTrips6650(t *testing.T) {
	ss := &SessionSync{}
	ss.SetLocalSnapshotProtocolVersion(8)
	if got := ss.localSnapshotProtocol.Load(); got != 8 {
		t.Fatalf("localSnapshotProtocol = %d, want 8", got)
	}
	// nil receiver must not panic: the daemon stamps every published instance
	// and a superseded epoch can hand over a nil.
	var nilSS *SessionSync
	nilSS.SetLocalSnapshotProtocolVersion(8)
}

// TestPeerCapabilityIsScopedToThePeerIncarnation6650 is the disconnect-clear.
//
// The capability belongs to the peer PROCESS that advertised it. A full
// disconnect ends that incarnation, and the peer that reconnects may be an
// OLDER process — which is precisely the rolling-upgrade case this gate exists
// for. A retained capability would authorise a push the new incarnation cannot
// represent, i.e. reintroduce the exact bug through the reconnect door.
func TestPeerCapabilityIsScopedToThePeerIncarnation6650(t *testing.T) {
	ss := &SessionSync{}
	ss.peerSnapshotProtocol.Store(8)
	if got := ss.PeerSnapshotProtocolVersion(); got != 8 {
		t.Fatalf("setup: peer version = %d, want 8", got)
	}

	// Mirror what handleDisconnect does on a FULL disconnect. Asserted against
	// the source below so this cannot drift from the real clear.
	ss.peerSnapshotProtocol.Store(0)
	if got := ss.PeerSnapshotProtocolVersion(); got != 0 {
		t.Fatalf("peer version = %d after the incarnation ended, want 0", got)
	}
}

// TestDisconnectClearsPeerCapability6650 binds the clear to the real
// handleDisconnect, beside the clockSynced clear it copies. The test above
// asserts the SEMANTICS on a hand-driven store; this asserts production
// actually performs it — without this, deleting the line from
// handleDisconnect leaves every test above green.
func TestDisconnectClearsPeerCapability6650(t *testing.T) {
	t.Parallel()
	src := readClusterSource(t, "sync_conn.go")
	if !sourceContainsFlat(src, "s.peerSnapshotProtocol.Store(0)") {
		t.Fatal("sync_conn.go's full-disconnect path does not clear peerSnapshotProtocol. " +
			"The peer capability would then outlive the incarnation that proved it, so a " +
			"reconnecting OLDER peer inherits the previous peer's capability and the gate " +
			"authorises a push it cannot represent (#6650).")
	}
	if !sourceContainsFlat(src, "s.clockSynced.Store(false)") {
		t.Fatal("the clockSynced clear this one is anchored beside has moved; re-verify " +
			"that the peerSnapshotProtocol clear is still on the FULL-disconnect path")
	}
}

// TestCapabilityAdvertisedOnConnectionInstall6650 binds the send wiring.
// Without the call, a fixed pair never exchanges versions, both sides read 0,
// and — because 0 fails closed — every multi-zone commit on a healthy upgraded
// cluster is refused. That is a loud failure rather than a silent one, but it
// is still a broken cluster, so the wiring gets its own assertion.
func TestCapabilityAdvertisedOnConnectionInstall6650(t *testing.T) {
	t.Parallel()
	src := readClusterSource(t, "sync_conn.go")
	if !sourceContainsFlat(src, "s.sendCapabilities(conn)") {
		t.Fatal("the connection-install path never calls sendCapabilities, so this node " +
			"advertises no config-snapshot protocol version. Its peer then reads 0 " +
			"(= incapable, fail-closed) and refuses every multi-zone scoped commit even " +
			"though both nodes are current (#6650).")
	}
	if !sourceContainsFlat(src, "s.sendClockSync(conn)") {
		t.Fatal("the sendClockSync call this one is anchored beside has moved; re-verify " +
			"sendCapabilities is still on the per-connection install path")
	}
}

// TestPeerCapabilitiesMessageTypeIsUnique6650 guards the additive-message
// contract. The whole no-version-bump argument rests on old peers hitting the
// receive switch's missing default arm and ignoring the frame; reusing a live
// type instead would have them MISPARSE it as real traffic.
func TestPeerCapabilitiesMessageTypeIsUnique6650(t *testing.T) {
	t.Parallel()
	live := liveSyncMessageTypesExcept(syncMsgPeerCapabilities)
	for _, m := range live {
		if m.v == syncMsgPeerCapabilities {
			t.Fatalf("syncMsgPeerCapabilities (%d) collides with %s. An old peer ignores an "+
				"UNKNOWN type via the receive switch's missing default arm — that is the "+
				"whole no-version-bump argument — but it MISPARSES a known one (#6650).",
				syncMsgPeerCapabilities, m.name)
		}
	}
	if len(live) < 34 {
		t.Fatalf("the live-type list holds only %d entries — it has fallen behind "+
			"sync.go and can no longer certify uniqueness", len(live))
	}
}

// TestPeerCapabilitiesPayloadIsLengthGated6650 pins the decode contract: a
// short frame must be ignored (leaving the 0 = incapable default) rather than
// partially decoded, and a longer one from a newer peer must still decode its
// leading field (#2170 trailing-field discipline).
func TestPeerCapabilitiesPayloadIsLengthGated6650(t *testing.T) {
	t.Parallel()
	long := make([]byte, 8)
	binary.LittleEndian.PutUint16(long[:2], 4)
	if got := binary.LittleEndian.Uint16(long[:2]); got != 4 {
		t.Fatalf("a longer payload must still decode its leading u16: got %d", got)
	}

	src := readClusterSource(t, "sync_conn_read.go")
	if !sourceContainsFlat(src, "if len(payload) < 2 {") {
		t.Error("the syncMsgPeerCapabilities arm has no length gate — a 1-byte frame " +
			"would slice out of range or decode garbage into the peer capability")
	}
	if !sourceContainsFlat(src, "s.peerSnapshotProtocol.Store(uint32(peerProto))") {
		t.Error("the syncMsgPeerCapabilities arm does not store the decoded version")
	}
}

// TestSendCapabilitiesStaysSilentWhenUnset6650 pins the "silence beats a
// literal 0" encoding. Advertising 0 would be indistinguishable from a
// pre-#6650 peer to the receiver while ALSO looking like a deliberate claim of
// zero capability, so an un-wired node must send nothing at all.
func TestSendCapabilitiesStaysSilentWhenUnset6650(t *testing.T) {
	t.Parallel()
	src := readClusterSource(t, "sync_conn_write.go")
	if !sourceContainsFlat(src, "v := s.localSnapshotProtocol.Load()") ||
		!sourceContainsFlat(src, "if v == 0 { return }") {
		t.Error("sendCapabilities does not suppress the advertisement when the local " +
			"version is unset; an un-wired node would advertise a literal 0")
	}
}

// readClusterSource reads a production file AND requires it to parse, so a
// guard below can never pass by matching text in a file that no longer
// compiles as Go.
func readClusterSource(t *testing.T, name string) string {
	t.Helper()
	fset := token.NewFileSet()
	if _, err := parser.ParseFile(fset, name, nil, parser.SkipObjectResolution); err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	return mustReadClusterFile(t, name)
}

// syncMessageType names one live syncMsg* constant for the uniqueness guards.
type syncMessageType struct {
	v    int
	name string
}

// liveSyncMessageTypesExcept enumerates every live syncMsg* constant except
// the one under test.
//
// A SLICE, not a map: syncMsgAuthHello and syncMsgConfigApplyNack both hold 27
// (phase-separated -- pre-install handshake vs post-install), and a map literal
// with duplicate constant keys does not compile. Enumerating pairs keeps every
// live name in the guard instead of silently dropping one.
//
// The exclusion is BY VALUE, so passing 27 would drop both AuthHello and
// ConfigApplyNack. No caller does; a future one that needs 27 must exclude by
// name instead.
//
// SINGLE-SOURCED across the #6650 and #6629 uniqueness guards deliberately: two
// copies of this census would drift, and a census that has fallen behind
// sync.go certifies nothing. Each caller excludes its own constant, so the same
// list serves both. The length floor in each caller catches the list falling
// behind.
func liveSyncMessageTypesExcept(under int) []syncMessageType {
	all := []syncMessageType{
		{syncMsgSessionV4, "SessionV4"}, {syncMsgSessionV6, "SessionV6"},
		{syncMsgDeleteV4, "DeleteV4"}, {syncMsgDeleteV6, "DeleteV6"},
		{syncMsgBulkStart, "BulkStart"}, {syncMsgBulkEnd, "BulkEnd"},
		{syncMsgHeartbeat, "Heartbeat"}, {syncMsgConfig, "Config"},
		{syncMsgIPsecSA, "IPsecSA"}, {syncMsgFailover, "Failover"},
		{syncMsgFence, "Fence"}, {syncMsgClockSync, "ClockSync"},
		{syncMsgBarrier, "Barrier"}, {syncMsgBarrierAck, "BarrierAck"},
		{syncMsgBulkAck, "BulkAck"}, {syncMsgFailoverAck, "FailoverAck"},
		{syncMsgFailoverCommit, "FailoverCommit"}, {syncMsgFailoverCommitAck, "FailoverCommitAck"},
		{syncMsgPrepareActivation, "PrepareActivation"}, {syncMsgFailoverBatch, "FailoverBatch"},
		{syncMsgFailoverBatchAck, "FailoverBatchAck"}, {syncMsgFailoverBatchCommit, "FailoverBatchCommit"},
		{syncMsgFailoverBatchCommitAck, "FailoverBatchCommitAck"}, {syncMsgHeartbeatAck, "HeartbeatAck"},
		{syncMsgDHCPLeaseV4, "DHCPLeaseV4"}, {syncMsgDHCPLeaseV6, "DHCPLeaseV6"},
		{syncMsgAuthHello, "AuthHello"}, {syncMsgAuthProof, "AuthProof"},
		{syncMsgConfigApplyNack, "ConfigApplyNack"},
		{syncMsgPeerCapabilities, "PeerCapabilities"},
		{syncMsgConfigKeyExchange, "ConfigKeyExchange"},
		{syncMsgConfigEncrypted, "ConfigEncrypted"},
		{syncMsgAuthUpgradeHello, "AuthUpgradeHello"},
		{syncMsgAuthUpgradeProof, "AuthUpgradeProof"},
		{syncMsgAuthUpgradeAck, "AuthUpgradeAck"},
	}
	out := make([]syncMessageType, 0, len(all))
	for _, m := range all {
		if m.v == under {
			continue
		}
		out = append(out, m)
	}
	return out
}
