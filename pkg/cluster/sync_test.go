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
