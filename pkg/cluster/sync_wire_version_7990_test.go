package cluster

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// TestPeerSessionSyncWireDecoding7990 pins the trailing-field decode across all
// three generations of the capabilities frame that exist in the wild.
//
// The property is not "the new field decodes" — it is that ADDING it did not
// disturb the two fields already there. #6650's version and #7147's flags must
// still decode from their own generation's payload length, or a rolling upgrade
// past this change breaks the two gates that already depend on them.
func TestPeerSessionSyncWireDecoding7990(t *testing.T) {
	t.Parallel()
	s := &SessionSync{}
	if got := s.PeerSessionSyncWireVersion(); got != 0 {
		t.Errorf("a peer that advertised nothing reported wire version %d, want 0 (UNKNOWN)", got)
	}

	// A pre-#7147 peer: 2 bytes, snapshot version only.
	twoByte := make([]byte, 2)
	binary.LittleEndian.PutUint16(twoByte, 8)
	s.handleMessage(nil, syncMsgPeerCapabilities, twoByte)
	if s.PeerSnapshotProtocolVersion() != 8 {
		t.Errorf("#6650 version = %d, want 8 — adding the #7990 field broke the 2-byte decode",
			s.PeerSnapshotProtocolVersion())
	}
	if got := s.PeerSessionSyncWireVersion(); got != 0 {
		t.Errorf("a 2-byte frame yielded wire version %d, want 0 — a pre-#7990 peer "+
			"advertises nothing and must not be read as advertising a version", got)
	}

	// A #7147 peer: 3 bytes, version + flags, still no wire version.
	threeByte := append(append([]byte{}, twoByte...), capFlagFenceAck)
	s.handleMessage(nil, syncMsgPeerCapabilities, threeByte)
	if !s.PeerFenceAckCapable() {
		t.Error("#7147 flags stopped decoding from a 3-byte frame after #7990 was added")
	}
	if got := s.PeerSessionSyncWireVersion(); got != 0 {
		t.Errorf("a 3-byte (pre-#7990) frame yielded wire version %d, want 0", got)
	}

	// A #7990 peer: 5 bytes.
	fiveByte := append(append([]byte{}, threeByte...), 0, 0)
	binary.LittleEndian.PutUint16(fiveByte[3:5], 7)
	s.handleMessage(nil, syncMsgPeerCapabilities, fiveByte)
	if got := s.PeerSessionSyncWireVersion(); got != 7 {
		t.Errorf("wire version = %d, want 7", got)
	}
	if s.PeerSnapshotProtocolVersion() != 8 || !s.PeerFenceAckCapable() {
		t.Error("the #6650 version or #7147 flags were disturbed by the 5-byte decode")
	}

	// A DOWNGRADE on reconnect must revoke it. A retained version is the worst
	// of the three fields to keep: it would let the drain gate certify
	// compatibility against a version the reconnected peer no longer speaks.
	s.handleMessage(nil, syncMsgPeerCapabilities, threeByte)
	if got := s.PeerSessionSyncWireVersion(); got != 0 {
		t.Errorf("wire version %d survived a peer re-advertising without it", got)
	}
}

// TestThisBuildAdvertisesSessionSyncWire7990 binds the WIRING. The decode above
// stays green with sendCapabilities never writing the field at all — in which
// case no peer can ever learn this node's version and the gate is dead on both
// sides. Drives the real writer over a pipe and feeds the bytes back through the
// real reader.
func TestThisBuildAdvertisesSessionSyncWire7990(t *testing.T) {
	t.Parallel()
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	s := &SessionSync{}
	s.SetLocalSnapshotProtocolVersion(3)
	go func() {
		_ = server.SetWriteDeadline(time.Now().Add(5 * time.Second))
		s.sendCapabilities(server)
	}()

	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	hdr := make([]byte, syncHeaderSize)
	if _, err := readFullTest(client, hdr); err != nil {
		t.Fatalf("read header: %v", err)
	}
	if hdr[4] != syncMsgPeerCapabilities {
		t.Fatalf("msgType = %d, want syncMsgPeerCapabilities (%d)", hdr[4], syncMsgPeerCapabilities)
	}
	n := binary.LittleEndian.Uint32(hdr[8:12])
	if n < 5 {
		t.Fatalf("capabilities payload is %d bytes; this build does not advertise its "+
			"session-sync wire version, so no peer can gate on it (#7990)", n)
	}
	payload := make([]byte, n)
	if _, err := readFullTest(client, payload); err != nil {
		t.Fatalf("read payload: %v", err)
	}

	// Round-trip through the real reader, and assert it equals the CONSTANT —
	// not a literal. Pinning a literal here would encode which side is trusted,
	// and the whole point is that the advertised value and the frames this
	// process writes cannot disagree.
	peer := &SessionSync{}
	peer.handleMessage(nil, syncMsgPeerCapabilities, payload)
	if got := peer.PeerSessionSyncWireVersion(); got != SessionSyncWireVersion {
		t.Errorf("advertised wire version = %d, want SessionSyncWireVersion (%d)",
			got, SessionSyncWireVersion)
	}
	if got := peer.PeerSnapshotProtocolVersion(); got != 3 {
		t.Errorf("the #6650 field did not survive the round trip: got %d, want 3", got)
	}
}

func readFullTest(c net.Conn, buf []byte) (int, error) {
	off := 0
	for off < len(buf) {
		n, err := c.Read(buf[off:])
		off += n
		if err != nil {
			return off, err
		}
	}
	return off, nil
}

// TestSessionSyncWireCompatible7990 is the total verdict table.
//
// The row that carries the design is UNKNOWN -> PERMIT. Refusing there would
// make the gate fire on every roll from a pre-#7990 release and on no real
// skew — the worst possible calibration, and the reason this is dual-accept
// (#4107 / #4126) rather than fail-closed.
func TestSessionSyncWireCompatible7990(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		peer uint16
		want bool
	}{
		{"unknown peer permits", 0, true},
		{"matching version permits", SessionSyncWireVersion, true},
		{"differing version refuses", SessionSyncWireVersion + 1, false},
		{"an older differing version refuses", SessionSyncWireVersion + 40000, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ok, reason := SessionSyncWireCompatible(tc.peer)
			if ok != tc.want {
				t.Errorf("SessionSyncWireCompatible(%d) = %v, want %v (%s)", tc.peer, ok, tc.want, reason)
			}
			if reason == "" {
				t.Error("verdict returned no reason; the drain gate puts it in the operator's error")
			}
		})
	}
}

// The local advertisement must be the constant the mixed-base image gate reads
// from `xpfd protocol-versions`, or the two upgrade paths gate on different
// numbers for the same property.
func TestAdvertisedWireVersionIsTheGatedConstant7990(t *testing.T) {
	t.Parallel()
	if SessionSyncWireVersion == 0 {
		t.Fatal("SessionSyncWireVersion is 0, which PeerSessionSyncWireVersion reserves for " +
			"UNKNOWN — a real 0 would make every peer read as un-advertised")
	}
}
