package cluster

import (
	"encoding/binary"
	"testing"

	"github.com/psaab/bpfrx/pkg/dataplane"
)

func TestSyncHeaderEncoding(t *testing.T) {
	// Test that writeMsg produces valid headers
	key := dataplane.SessionKey{
		SrcIP:    [4]byte{10, 0, 1, 1},
		DstIP:    [4]byte{10, 0, 2, 1},
		SrcPort:  12345,
		DstPort:  80,
		Protocol: 6,
	}

	msg := encodeDeleteV4(key)

	// Check header
	if string(msg[0:4]) != "BPSY" {
		t.Fatalf("bad magic: %q", msg[0:4])
	}
	if msg[4] != syncMsgDeleteV4 {
		t.Fatalf("bad type: %d", msg[4])
	}
	length := binary.LittleEndian.Uint32(msg[8:12])
	if length != 16 {
		t.Fatalf("bad length: %d", length)
	}

	// Check payload
	payload := msg[syncHeaderSize:]
	if payload[0] != 10 || payload[1] != 0 || payload[2] != 1 || payload[3] != 1 {
		t.Fatalf("bad src IP in payload")
	}
	if payload[4] != 10 || payload[5] != 0 || payload[6] != 2 || payload[7] != 1 {
		t.Fatalf("bad dst IP in payload")
	}
	port := binary.LittleEndian.Uint16(payload[8:10])
	if port != 12345 {
		t.Fatalf("bad src port: %d", port)
	}
}

func TestEncodeSessionV4(t *testing.T) {
	key := dataplane.SessionKey{
		SrcIP:    [4]byte{192, 168, 1, 1},
		DstIP:    [4]byte{10, 0, 0, 1},
		SrcPort:  1024,
		DstPort:  443,
		Protocol: 6,
	}
	val := dataplane.SessionValue{
		State:       dataplane.SessStateEstablished,
		Flags:       dataplane.SessFlagSNAT,
		Created:     1000,
		LastSeen:    2000,
		Timeout:     3600,
		PolicyID:    1,
		IngressZone: 1,
		EgressZone:  2,
		NATSrcIP:    0x0100000a, // 10.0.0.1 in native endian
		FwdPackets:  100,
		FwdBytes:    50000,
	}

	msg := encodeSessionV4(key, val)

	// Verify magic and type
	if string(msg[0:4]) != "BPSY" {
		t.Fatalf("bad magic: %q", msg[0:4])
	}
	if msg[4] != syncMsgSessionV4 {
		t.Fatalf("bad type: %d", msg[4])
	}

	// Verify payload has correct key at start
	payload := msg[syncHeaderSize:]
	if payload[0] != 192 || payload[1] != 168 {
		t.Fatalf("bad src IP start in payload")
	}
}

func TestEncodeDeleteV6(t *testing.T) {
	key := dataplane.SessionKeyV6{
		SrcIP:    [16]byte{0x20, 0x01, 0x0d, 0xb8},
		DstIP:    [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
		SrcPort:  8080,
		DstPort:  443,
		Protocol: 6,
	}

	msg := encodeDeleteV6(key)

	if string(msg[0:4]) != "BPSY" {
		t.Fatalf("bad magic")
	}
	if msg[4] != syncMsgDeleteV6 {
		t.Fatalf("bad type: %d", msg[4])
	}
	length := binary.LittleEndian.Uint32(msg[8:12])
	if length != 40 {
		t.Fatalf("bad length: %d", length)
	}
}

func TestEncodeSessionV6(t *testing.T) {
	key := dataplane.SessionKeyV6{
		SrcIP:    [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
		DstIP:    [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2},
		SrcPort:  9090,
		DstPort:  80,
		Protocol: 6,
	}
	val := dataplane.SessionValueV6{
		State:   dataplane.SessStateEstablished,
		Created: 5000,
		Timeout: 1800,
	}

	msg := encodeSessionV6(key, val)

	if string(msg[0:4]) != "BPSY" {
		t.Fatalf("bad magic")
	}
	if msg[4] != syncMsgSessionV6 {
		t.Fatalf("bad type: %d", msg[4])
	}
}

func TestSyncStatsInit(t *testing.T) {
	ss := NewSessionSync(":4785", "10.0.0.2:4785", nil)
	stats := ss.Stats()
	if stats.Connected.Load() {
		t.Fatal("should not be connected initially")
	}
	if stats.SessionsSent.Load() != 0 {
		t.Fatal("sessions sent should be 0")
	}
}

func TestQueueWithoutConnection(t *testing.T) {
	ss := NewSessionSync(":4785", "10.0.0.2:4785", nil)
	// Should not panic with no connection
	key := dataplane.SessionKey{Protocol: 6}
	val := dataplane.SessionValue{}
	ss.QueueSessionV4(key, val)
	// Message should be dropped since not connected
	if ss.stats.SessionsSent.Load() != 0 {
		t.Fatal("should not count sent when not connected")
	}
}

func TestFormatStats(t *testing.T) {
	ss := NewSessionSync(":4785", "10.0.0.2:4785", nil)
	ss.stats.SessionsSent.Store(100)
	ss.stats.SessionsReceived.Store(50)
	out := ss.FormatStats()
	if out == "" {
		t.Fatal("format stats should produce output")
	}
}

func TestDecodeSessionV4RoundTrip(t *testing.T) {
	key := dataplane.SessionKey{
		SrcIP:    [4]byte{192, 168, 1, 1},
		DstIP:    [4]byte{10, 0, 0, 1},
		SrcPort:  1024,
		DstPort:  443,
		Protocol: 6,
	}
	val := dataplane.SessionValue{
		State:       dataplane.SessStateEstablished,
		Flags:       dataplane.SessFlagSNAT,
		TCPState:    3,
		Created:     1000,
		LastSeen:    2000,
		Timeout:     3600,
		PolicyID:    42,
		IngressZone: 1,
		EgressZone:  2,
		NATSrcIP:    0x0100000a,
		NATDstIP:    0x0200000a,
		NATSrcPort:  5000,
		NATDstPort:  80,
		FwdPackets:  100,
		FwdBytes:    50000,
		RevPackets:  80,
		RevBytes:    40000,
		ReverseKey: dataplane.SessionKey{
			SrcIP:    [4]byte{10, 0, 0, 1},
			DstIP:    [4]byte{192, 168, 1, 1},
			SrcPort:  443,
			DstPort:  1024,
			Protocol: 6,
		},
		ALGType:  1,
		LogFlags: 2,
	}

	payload := encodeSessionV4Payload(key, val)
	dKey, dVal, ok := decodeSessionV4Payload(payload)
	if !ok {
		t.Fatal("decode failed")
	}

	if dKey != key {
		t.Fatalf("key mismatch: got %+v, want %+v", dKey, key)
	}
	if dVal.State != val.State {
		t.Fatalf("State mismatch: %d vs %d", dVal.State, val.State)
	}
	if dVal.Flags != val.Flags {
		t.Fatalf("Flags mismatch: %d vs %d", dVal.Flags, val.Flags)
	}
	if dVal.TCPState != val.TCPState {
		t.Fatalf("TCPState mismatch")
	}
	if dVal.Created != val.Created || dVal.LastSeen != val.LastSeen {
		t.Fatalf("timestamps mismatch")
	}
	if dVal.Timeout != val.Timeout || dVal.PolicyID != val.PolicyID {
		t.Fatalf("timeout/policy mismatch")
	}
	if dVal.IngressZone != val.IngressZone || dVal.EgressZone != val.EgressZone {
		t.Fatalf("zone mismatch")
	}
	if dVal.NATSrcIP != val.NATSrcIP || dVal.NATDstIP != val.NATDstIP {
		t.Fatalf("NAT IP mismatch")
	}
	if dVal.NATSrcPort != val.NATSrcPort || dVal.NATDstPort != val.NATDstPort {
		t.Fatalf("NAT port mismatch")
	}
	if dVal.FwdPackets != val.FwdPackets || dVal.FwdBytes != val.FwdBytes {
		t.Fatalf("fwd counter mismatch")
	}
	if dVal.RevPackets != val.RevPackets || dVal.RevBytes != val.RevBytes {
		t.Fatalf("rev counter mismatch")
	}
	if dVal.ReverseKey != val.ReverseKey {
		t.Fatalf("reverse key mismatch: got %+v", dVal.ReverseKey)
	}
	if dVal.ALGType != val.ALGType || dVal.LogFlags != val.LogFlags {
		t.Fatalf("ALG/log mismatch")
	}
}

func TestDecodeSessionV6RoundTrip(t *testing.T) {
	key := dataplane.SessionKeyV6{
		SrcIP:    [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
		DstIP:    [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2},
		SrcPort:  9090,
		DstPort:  80,
		Protocol: 6,
	}
	val := dataplane.SessionValueV6{
		State:       dataplane.SessStateEstablished,
		Flags:       dataplane.SessFlagDNAT,
		TCPState:    2,
		Created:     5000,
		LastSeen:    6000,
		Timeout:     1800,
		PolicyID:    10,
		IngressZone: 3,
		EgressZone:  4,
		NATSrcIP:    [16]byte{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
		NATSrcPort:  4000,
		FwdPackets:  200,
		FwdBytes:    100000,
		ALGType:     2,
	}

	payload := encodeSessionV6Payload(key, val)
	dKey, dVal, ok := decodeSessionV6Payload(payload)
	if !ok {
		t.Fatal("decode failed")
	}

	if dKey != key {
		t.Fatalf("key mismatch: got %+v, want %+v", dKey, key)
	}
	if dVal.State != val.State {
		t.Fatalf("State mismatch")
	}
	if dVal.Flags != val.Flags {
		t.Fatalf("Flags mismatch")
	}
	if dVal.Created != val.Created || dVal.Timeout != val.Timeout {
		t.Fatalf("timestamps mismatch")
	}
	if dVal.NATSrcIP != val.NATSrcIP {
		t.Fatalf("NAT src IP mismatch")
	}
	if dVal.NATSrcPort != val.NATSrcPort {
		t.Fatalf("NAT src port mismatch")
	}
	if dVal.FwdPackets != val.FwdPackets || dVal.FwdBytes != val.FwdBytes {
		t.Fatalf("fwd counter mismatch")
	}
}

func TestDecodeSessionV4Short(t *testing.T) {
	// Too short for even a key
	_, _, ok := decodeSessionV4Payload([]byte{1, 2, 3})
	if ok {
		t.Fatal("should fail on short payload")
	}
}

func TestDecodeSessionV6Short(t *testing.T) {
	_, _, ok := decodeSessionV6Payload([]byte{1, 2, 3})
	if ok {
		t.Fatal("should fail on short payload")
	}
}

func TestIPsecSAPayloadRoundTrip(t *testing.T) {
	names := []string{"vpn-site-a", "vpn-site-b", "tunnel-corp"}
	payload := encodeIPsecSAPayload(names)
	decoded := decodeIPsecSAPayload(payload)

	if len(decoded) != len(names) {
		t.Fatalf("count mismatch: got %d, want %d", len(decoded), len(names))
	}
	for i, name := range names {
		if decoded[i] != name {
			t.Fatalf("name[%d] mismatch: got %q, want %q", i, decoded[i], name)
		}
	}
}

func TestIPsecSAPayloadEmpty(t *testing.T) {
	payload := encodeIPsecSAPayload(nil)
	decoded := decodeIPsecSAPayload(payload)
	if len(decoded) != 0 {
		t.Fatalf("expected empty, got %d", len(decoded))
	}
}

func TestPeerIPsecSAs(t *testing.T) {
	ss := NewSessionSync(":4785", "10.0.0.2:4785", nil)

	// Initially empty
	if names := ss.PeerIPsecSAs(); len(names) != 0 {
		t.Fatal("should be empty initially")
	}

	// Simulate receiving IPsec SA list
	ss.handleMessage(syncMsgIPsecSA, encodeIPsecSAPayload([]string{"vpn-a", "vpn-b"}))

	names := ss.PeerIPsecSAs()
	if len(names) != 2 {
		t.Fatalf("got %d names, want 2", len(names))
	}
	if names[0] != "vpn-a" || names[1] != "vpn-b" {
		t.Fatalf("unexpected names: %v", names)
	}
}

func TestSetDataPlane(t *testing.T) {
	ss := NewSessionSync(":4785", "10.0.0.2:4785", nil)
	if ss.dp != nil {
		t.Fatal("dp should be nil initially")
	}

	// Simulate handleMessage without dp — should not crash
	key := dataplane.SessionKey{Protocol: 6, SrcIP: [4]byte{1, 2, 3, 4}, DstIP: [4]byte{5, 6, 7, 8}}
	val := dataplane.SessionValue{State: 1}
	payload := encodeSessionV4Payload(key, val)
	ss.handleMessage(syncMsgSessionV4, payload)

	if ss.stats.SessionsReceived.Load() != 1 {
		t.Fatal("should count received")
	}
	if ss.stats.SessionsInstalled.Load() != 0 {
		t.Fatal("should not install without dp")
	}
}

func TestHandleMessageDeleteV4(t *testing.T) {
	ss := NewSessionSync(":4785", "10.0.0.2:4785", nil)
	// Without dp, should not crash
	key := dataplane.SessionKey{Protocol: 6}
	msg := encodeDeleteV4(key)
	ss.handleMessage(syncMsgDeleteV4, msg[syncHeaderSize:])
	if ss.stats.DeletesReceived.Load() != 1 {
		t.Fatal("should count delete received")
	}
}
