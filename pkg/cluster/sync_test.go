package cluster

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

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

// --- Sync sweep tests ---

// mockSweepDP is a minimal mock for testing sync sweep.
// Embeds DataPlane interface; only IterateSessions/V6 are implemented.
type mockSweepDP struct {
	dataplane.DataPlane
	v4sessions     map[dataplane.SessionKey]dataplane.SessionValue
	v6sessions     map[dataplane.SessionKeyV6]dataplane.SessionValueV6
	sessionCounter uint64
}

func (m *mockSweepDP) ReadGlobalCounter(index uint32) (uint64, error) {
	return m.sessionCounter, nil
}

func (m *mockSweepDP) IterateSessions(fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	for k, v := range m.v4sessions {
		if !fn(k, v) {
			break
		}
	}
	return nil
}

func (m *mockSweepDP) IterateSessionsV6(fn func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	for k, v := range m.v6sessions {
		if !fn(k, v) {
			break
		}
	}
	return nil
}

func (m *mockSweepDP) BatchIterateSessions(fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	return m.IterateSessions(fn)
}

func (m *mockSweepDP) BatchIterateSessionsV6(fn func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	return m.IterateSessionsV6(fn)
}

func (m *mockSweepDP) GetSessionV4(key dataplane.SessionKey) (dataplane.SessionValue, error) {
	if v, ok := m.v4sessions[key]; ok {
		return v, nil
	}
	return dataplane.SessionValue{}, fmt.Errorf("not found")
}

func (m *mockSweepDP) GetSessionV6(key dataplane.SessionKeyV6) (dataplane.SessionValueV6, error) {
	if v, ok := m.v6sessions[key]; ok {
		return v, nil
	}
	return dataplane.SessionValueV6{}, fmt.Errorf("not found")
}

func (m *mockSweepDP) SetSessionV4(key dataplane.SessionKey, val dataplane.SessionValue) error {
	if m.v4sessions == nil {
		m.v4sessions = make(map[dataplane.SessionKey]dataplane.SessionValue)
	}
	m.v4sessions[key] = val
	return nil
}

func (m *mockSweepDP) SetSessionV6(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) error {
	if m.v6sessions == nil {
		m.v6sessions = make(map[dataplane.SessionKeyV6]dataplane.SessionValueV6)
	}
	m.v6sessions[key] = val
	return nil
}

func (m *mockSweepDP) DeleteSession(key dataplane.SessionKey) error {
	delete(m.v4sessions, key)
	return nil
}

func (m *mockSweepDP) DeleteSessionV6(key dataplane.SessionKeyV6) error {
	delete(m.v6sessions, key)
	return nil
}

func (m *mockSweepDP) DeleteDNATEntry(key dataplane.DNATKey) error {
	return nil
}

func (m *mockSweepDP) DeleteDNATEntryV6(key dataplane.DNATKeyV6) error {
	return nil
}

func (m *mockSweepDP) SetDNATEntry(key dataplane.DNATKey, val dataplane.DNATValue) error {
	return nil
}

func (m *mockSweepDP) SetDNATEntryV6(key dataplane.DNATKeyV6, val dataplane.DNATValueV6) error {
	return nil
}

func TestSyncSweepNewSessions(t *testing.T) {
	now := monotonicSeconds()
	dp := &mockSweepDP{
		v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{
			{SrcIP: [4]byte{10, 0, 1, 1}, DstIP: [4]byte{10, 0, 2, 1}, Protocol: 6, SrcPort: 1000, DstPort: 80}: {
				State: dataplane.SessStateEstablished, Created: now, IsReverse: 0,
			},
			{SrcIP: [4]byte{10, 0, 1, 2}, DstIP: [4]byte{10, 0, 2, 2}, Protocol: 6, SrcPort: 2000, DstPort: 443}: {
				State: dataplane.SessStateEstablished, Created: now - 100, IsReverse: 0, // old session
			},
		},
		sessionCounter: 1,
	}

	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
	ss.stats.Connected.Store(true)
	ss.IsPrimaryFn = func() bool { return true }
	ss.lastSweepTime = now // only sessions created at or after 'now' should sync

	ss.syncSweep()

	// Should have synced exactly 1 session (the one with Created == now)
	if ss.stats.SessionsSent.Load() != 1 {
		t.Fatalf("expected 1 session sent, got %d", ss.stats.SessionsSent.Load())
	}
}

func TestSyncSweepSkipsReverse(t *testing.T) {
	now := monotonicSeconds()
	dp := &mockSweepDP{
		v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{
			{SrcIP: [4]byte{10, 0, 1, 1}, Protocol: 6}: {
				Created: now, IsReverse: 1, // reverse entry
			},
		},
		sessionCounter: 1,
	}

	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
	ss.stats.Connected.Store(true)
	ss.IsPrimaryFn = func() bool { return true }
	ss.lastSweepTime = now

	ss.syncSweep()

	if ss.stats.SessionsSent.Load() != 0 {
		t.Fatal("should not sync reverse entries")
	}
}

func TestSyncSweepSkipsWhenNotPrimary(t *testing.T) {
	now := monotonicSeconds()
	dp := &mockSweepDP{
		v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{
			{Protocol: 6}: {Created: now, IsReverse: 0},
		},
		sessionCounter: 1,
	}

	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
	ss.stats.Connected.Store(true)
	ss.IsPrimaryFn = func() bool { return false }
	ss.lastSweepTime = now

	ss.syncSweep()

	if ss.stats.SessionsSent.Load() != 0 {
		t.Fatal("should not sync when not primary")
	}
}

func TestSyncSweepSkipsWhenDisconnected(t *testing.T) {
	now := monotonicSeconds()
	dp := &mockSweepDP{
		v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{
			{Protocol: 6}: {Created: now, IsReverse: 0},
		},
		sessionCounter: 1,
	}

	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
	ss.stats.Connected.Store(false)
	ss.IsPrimaryFn = func() bool { return true }
	ss.lastSweepTime = now

	ss.syncSweep()

	if ss.stats.SessionsSent.Load() != 0 {
		t.Fatal("should not sync when disconnected")
	}
}

func TestBulkEndTriggersCallback(t *testing.T) {
	ss := NewSessionSync(":4785", "10.0.0.2:4785", nil)

	called := make(chan struct{}, 1)
	ss.OnBulkSyncReceived = func() {
		called <- struct{}{}
	}

	// Simulate receiving BulkEnd message.
	ss.handleMessage(syncMsgBulkEnd, nil)

	select {
	case <-called:
		// OK
	case <-time.After(time.Second):
		t.Fatal("OnBulkSyncReceived callback not called within 1s")
	}
}

func TestBulkEndWithoutCallback(t *testing.T) {
	ss := NewSessionSync(":4785", "10.0.0.2:4785", nil)
	// Should not panic when callback is nil.
	ss.handleMessage(syncMsgBulkEnd, nil)
}

func TestSyncSweepV6(t *testing.T) {
	now := monotonicSeconds()
	dp := &mockSweepDP{
		v6sessions: map[dataplane.SessionKeyV6]dataplane.SessionValueV6{
			{SrcIP: [16]byte{0x20, 0x01}, Protocol: 6}: {
				Created: now, IsReverse: 0,
			},
		},
		sessionCounter: 1,
	}

	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
	ss.stats.Connected.Store(true)
	ss.IsPrimaryFn = func() bool { return true }
	ss.lastSweepTime = now

	ss.syncSweep()

	if ss.stats.SessionsSent.Load() != 1 {
		t.Fatalf("expected 1 v6 session sent, got %d", ss.stats.SessionsSent.Load())
	}
}

func TestShouldSyncZoneFallback(t *testing.T) {
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	ss.IsPrimaryFn = func() bool { return true }

	// No IsPrimaryForRGFn or zoneRGMap — should fall back to IsPrimaryFn.
	if !ss.ShouldSyncZone(1) {
		t.Fatal("expected ShouldSyncZone to return true via fallback")
	}

	ss.IsPrimaryFn = func() bool { return false }
	if ss.ShouldSyncZone(1) {
		t.Fatal("expected ShouldSyncZone to return false via fallback")
	}
}

func TestShouldSyncZonePerRG(t *testing.T) {
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	ss.IsPrimaryFn = func() bool { return false } // not primary for RG 0
	ss.IsPrimaryForRGFn = func(rgID int) bool {
		return rgID == 1 // primary for RG 1 only
	}
	ss.SetZoneRGMap(map[uint16]int{
		1: 1, // zone 1 → RG 1
		2: 2, // zone 2 → RG 2
	})

	// Zone 1 → RG 1 (primary) → should sync
	if !ss.ShouldSyncZone(1) {
		t.Fatal("zone 1 should sync (RG 1 is primary)")
	}

	// Zone 2 → RG 2 (not primary) → should not sync
	if ss.ShouldSyncZone(2) {
		t.Fatal("zone 2 should not sync (RG 2 is not primary)")
	}

	// Zone 3 → not in map → falls back to IsPrimaryFn (false)
	if ss.ShouldSyncZone(3) {
		t.Fatal("zone 3 should not sync (fallback to IsPrimaryFn=false)")
	}
}

func TestSyncSweepPerRG(t *testing.T) {
	now := monotonicSeconds()
	dp := &mockSweepDP{
		v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{
			// Session in zone 1 (RG 1 — primary)
			{SrcIP: [4]byte{10, 0, 1, 1}, DstIP: [4]byte{10, 0, 2, 1}, Protocol: 6, SrcPort: 1000, DstPort: 80}: {
				State: dataplane.SessStateEstablished, Created: now, IsReverse: 0, IngressZone: 1,
			},
			// Session in zone 2 (RG 2 — not primary)
			{SrcIP: [4]byte{10, 0, 3, 1}, DstIP: [4]byte{10, 0, 4, 1}, Protocol: 6, SrcPort: 2000, DstPort: 443}: {
				State: dataplane.SessStateEstablished, Created: now, IsReverse: 0, IngressZone: 2,
			},
		},
		sessionCounter: 1,
	}

	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
	ss.stats.Connected.Store(true)
	ss.IsPrimaryFn = func() bool { return false }
	ss.IsPrimaryForRGFn = func(rgID int) bool {
		return rgID == 1 // primary for RG 1 only
	}
	ss.SetZoneRGMap(map[uint16]int{
		1: 1, // zone 1 → RG 1
		2: 2, // zone 2 → RG 2
	})
	ss.lastSweepTime = now

	ss.syncSweep()

	// Only the session in zone 1 (RG 1) should be synced
	if ss.stats.SessionsSent.Load() != 1 {
		t.Fatalf("expected 1 session synced (zone 1/RG 1), got %d", ss.stats.SessionsSent.Load())
	}
}

func TestSyncSweepPerRGV6(t *testing.T) {
	now := monotonicSeconds()
	dp := &mockSweepDP{
		v6sessions: map[dataplane.SessionKeyV6]dataplane.SessionValueV6{
			// Session in zone 1 (RG 1 — primary)
			{SrcIP: [16]byte{0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, Protocol: 6}: {
				Created: now, IsReverse: 0, IngressZone: 1,
			},
			// Session in zone 2 (RG 2 — not primary)
			{SrcIP: [16]byte{0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}, Protocol: 6}: {
				Created: now, IsReverse: 0, IngressZone: 2,
			},
		},
		sessionCounter: 1,
	}

	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
	ss.stats.Connected.Store(true)
	ss.IsPrimaryFn = func() bool { return false }
	ss.IsPrimaryForRGFn = func(rgID int) bool {
		return rgID == 1
	}
	ss.SetZoneRGMap(map[uint16]int{1: 1, 2: 2})
	ss.lastSweepTime = now

	ss.syncSweep()

	if ss.stats.SessionsSent.Load() != 1 {
		t.Fatalf("expected 1 v6 session synced, got %d", ss.stats.SessionsSent.Load())
	}
}

// shortWriteConn is a mock net.Conn that returns short writes (1 byte at a time).
type shortWriteConn struct {
	net.Conn
	mu  sync.Mutex
	buf []byte
}

func (c *shortWriteConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(b) == 0 {
		return 0, nil
	}
	// Only write 1 byte at a time to simulate short writes.
	c.buf = append(c.buf, b[0])
	return 1, nil
}

func (c *shortWriteConn) bytes() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.buf...)
}

func TestWriteFullShortWrites(t *testing.T) {
	sw := &shortWriteConn{}

	// Use writeMsg which calls writeFull internally.
	payload := []byte("hello world")
	err := writeMsg(sw, syncMsgConfig, payload)
	if err != nil {
		t.Fatalf("writeMsg failed: %v", err)
	}

	got := sw.bytes()
	expected := syncHeaderSize + len(payload)
	if len(got) != expected {
		t.Fatalf("expected %d bytes, got %d", expected, len(got))
	}

	// Verify header.
	if string(got[0:4]) != "BPSY" {
		t.Fatalf("bad magic: %q", got[0:4])
	}
	if got[4] != syncMsgConfig {
		t.Fatalf("bad msg type: %d", got[4])
	}
	pLen := binary.LittleEndian.Uint32(got[8:12])
	if int(pLen) != len(payload) {
		t.Fatalf("bad payload length: %d", pLen)
	}

	// Verify payload.
	if string(got[syncHeaderSize:]) != "hello world" {
		t.Fatalf("bad payload: %q", got[syncHeaderSize:])
	}
}

func TestWriteFullDirectShortWrites(t *testing.T) {
	sw := &shortWriteConn{}

	// Write a pre-encoded session message through writeFull directly.
	key := dataplane.SessionKey{
		SrcIP:    [4]byte{10, 0, 1, 1},
		DstIP:    [4]byte{10, 0, 2, 1},
		SrcPort:  12345,
		DstPort:  80,
		Protocol: 6,
	}
	val := dataplane.SessionValue{State: dataplane.SessStateEstablished}
	msg := encodeSessionV4(key, val)

	err := writeFull(sw, msg)
	if err != nil {
		t.Fatalf("writeFull failed: %v", err)
	}

	got := sw.bytes()
	if len(got) != len(msg) {
		t.Fatalf("expected %d bytes, got %d", len(msg), len(got))
	}

	// Verify byte-for-byte match.
	for i := range msg {
		if got[i] != msg[i] {
			t.Fatalf("byte mismatch at offset %d: got %02x, want %02x", i, got[i], msg[i])
		}
	}
}

// countingWriter wraps a net.Conn and counts sync messages written.
type countingWriter struct {
	net.Conn
	sessionMsgs int
}

func (c *countingWriter) Write(b []byte) (int, error) {
	// Count session messages by checking the magic + type in headers.
	if len(b) >= syncHeaderSize && string(b[0:4]) == "BPSY" {
		if b[4] == syncMsgSessionV4 || b[4] == syncMsgSessionV6 {
			c.sessionMsgs++
		}
	}
	return len(b), nil // discard
}

func TestBulkSyncRGFiltering(t *testing.T) {
	dp := &mockSweepDP{
		v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{
			// Forward session in zone 1 (RG 1 — primary) — should sync
			{SrcIP: [4]byte{10, 0, 1, 1}, DstIP: [4]byte{10, 0, 2, 1}, Protocol: 6, SrcPort: 1000, DstPort: 80}: {
				State: dataplane.SessStateEstablished, IsReverse: 0, IngressZone: 1,
			},
			// Reverse session in zone 1 — should be skipped (reverse)
			{SrcIP: [4]byte{10, 0, 2, 1}, DstIP: [4]byte{10, 0, 1, 1}, Protocol: 6, SrcPort: 80, DstPort: 1000}: {
				State: dataplane.SessStateEstablished, IsReverse: 1, IngressZone: 1,
			},
			// Forward session in zone 2 (RG 2 — not primary) — should skip
			{SrcIP: [4]byte{10, 0, 3, 1}, DstIP: [4]byte{10, 0, 4, 1}, Protocol: 6, SrcPort: 2000, DstPort: 443}: {
				State: dataplane.SessStateEstablished, IsReverse: 0, IngressZone: 2,
			},
		},
		v6sessions: map[dataplane.SessionKeyV6]dataplane.SessionValueV6{
			// Forward v6 session in zone 1 (RG 1 — primary) — should sync
			{SrcIP: [16]byte{0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, Protocol: 6}: {
				IsReverse: 0, IngressZone: 1,
			},
			// Reverse v6 session — should be skipped
			{SrcIP: [16]byte{0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}, Protocol: 6}: {
				IsReverse: 1, IngressZone: 1,
			},
		},
	}

	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
	ss.IsPrimaryFn = func() bool { return false }
	ss.IsPrimaryForRGFn = func(rgID int) bool {
		return rgID == 1 // primary for RG 1 only
	}
	ss.SetZoneRGMap(map[uint16]int{
		1: 1, // zone 1 → RG 1
		2: 2, // zone 2 → RG 2
	})

	cw := &countingWriter{}
	ss.mu.Lock()
	ss.conn = cw
	ss.mu.Unlock()

	err := ss.BulkSync()
	if err != nil {
		t.Fatalf("BulkSync failed: %v", err)
	}

	// Should only sync 2 sessions: 1 v4 forward in zone 1 + 1 v6 forward in zone 1
	if cw.sessionMsgs != 2 {
		t.Fatalf("expected 2 session messages (1 v4 + 1 v6 in owned RG), got %d", cw.sessionMsgs)
	}
}

func TestBulkSyncSkipsReverseEntries(t *testing.T) {
	dp := &mockSweepDP{
		v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{
			{SrcIP: [4]byte{10, 0, 1, 1}, Protocol: 6, SrcPort: 1000, DstPort: 80}: {
				IsReverse: 0, IngressZone: 1,
			},
			{SrcIP: [4]byte{10, 0, 2, 1}, Protocol: 6, SrcPort: 80, DstPort: 1000}: {
				IsReverse: 1, IngressZone: 1,
			},
		},
	}

	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
	ss.IsPrimaryFn = func() bool { return true }

	cw := &countingWriter{}
	ss.mu.Lock()
	ss.conn = cw
	ss.mu.Unlock()

	err := ss.BulkSync()
	if err != nil {
		t.Fatalf("BulkSync failed: %v", err)
	}

	// Only forward entry should be sent
	if cw.sessionMsgs != 1 {
		t.Fatalf("expected 1 session message (forward only), got %d", cw.sessionMsgs)
	}
}

func TestReconcileStaleSessions(t *testing.T) {
	// Simulate: we're secondary for zone 2 (RG 2 owned by peer).
	// We have 3 sessions in zone 2: sessionA, sessionB, sessionC.
	// Peer sends bulk with only sessionA — sessionB and sessionC are stale.
	staleKeyB := dataplane.SessionKey{SrcIP: [4]byte{10, 0, 3, 2}, DstIP: [4]byte{10, 0, 4, 2}, Protocol: 6, SrcPort: 2000, DstPort: 443}
	staleKeyC := dataplane.SessionKey{SrcIP: [4]byte{10, 0, 3, 3}, DstIP: [4]byte{10, 0, 4, 3}, Protocol: 6, SrcPort: 3000, DstPort: 80}
	freshKeyA := dataplane.SessionKey{SrcIP: [4]byte{10, 0, 3, 1}, DstIP: [4]byte{10, 0, 4, 1}, Protocol: 6, SrcPort: 1000, DstPort: 80}
	// Session in zone 1 (locally owned) — should NOT be deleted.
	localKey := dataplane.SessionKey{SrcIP: [4]byte{10, 0, 1, 1}, DstIP: [4]byte{10, 0, 2, 1}, Protocol: 6, SrcPort: 5000, DstPort: 22}

	dp := &mockSweepDP{
		v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{
			freshKeyA: {IsReverse: 0, IngressZone: 2},
			staleKeyB: {IsReverse: 0, IngressZone: 2},
			staleKeyC: {IsReverse: 0, IngressZone: 2},
			localKey:  {IsReverse: 0, IngressZone: 1},
		},
	}

	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
	ss.IsPrimaryFn = func() bool { return false }
	ss.IsPrimaryForRGFn = func(rgID int) bool {
		return rgID == 1 // we're primary for RG 1 (zone 1), peer owns RG 2 (zone 2)
	}
	ss.SetZoneRGMap(map[uint16]int{1: 1, 2: 2})

	// Simulate bulk receive: BulkStart → sessionA → BulkEnd.
	ss.handleMessage(syncMsgBulkStart, nil)

	// Send freshKeyA as a session message.
	payload := encodeSessionV4Payload(freshKeyA, dataplane.SessionValue{IsReverse: 0, IngressZone: 2})
	ss.handleMessage(syncMsgSessionV4, payload)

	ss.handleMessage(syncMsgBulkEnd, nil)

	// freshKeyA should remain.
	if _, ok := dp.v4sessions[freshKeyA]; !ok {
		t.Fatal("freshKeyA should not be deleted")
	}

	// staleKeyB and staleKeyC should be deleted.
	if _, ok := dp.v4sessions[staleKeyB]; ok {
		t.Fatal("staleKeyB should be deleted (not in bulk)")
	}
	if _, ok := dp.v4sessions[staleKeyC]; ok {
		t.Fatal("staleKeyC should be deleted (not in bulk)")
	}

	// localKey (zone 1, our RG) should NOT be touched.
	if _, ok := dp.v4sessions[localKey]; !ok {
		t.Fatal("localKey should not be deleted (our RG)")
	}
}

func TestReconcileStaleSessionsV6(t *testing.T) {
	staleKey := dataplane.SessionKeyV6{SrcIP: [16]byte{0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}, Protocol: 6, SrcPort: 2000, DstPort: 80}
	freshKey := dataplane.SessionKeyV6{SrcIP: [16]byte{0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, Protocol: 6, SrcPort: 1000, DstPort: 80}

	dp := &mockSweepDP{
		v6sessions: map[dataplane.SessionKeyV6]dataplane.SessionValueV6{
			freshKey: {IsReverse: 0, IngressZone: 2},
			staleKey: {IsReverse: 0, IngressZone: 2},
		},
	}

	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
	ss.IsPrimaryFn = func() bool { return false }
	ss.IsPrimaryForRGFn = func(rgID int) bool { return rgID == 1 }
	ss.SetZoneRGMap(map[uint16]int{1: 1, 2: 2})

	ss.handleMessage(syncMsgBulkStart, nil)
	payload := encodeSessionV6Payload(freshKey, dataplane.SessionValueV6{IsReverse: 0, IngressZone: 2})
	ss.handleMessage(syncMsgSessionV6, payload)
	ss.handleMessage(syncMsgBulkEnd, nil)

	if _, ok := dp.v6sessions[freshKey]; !ok {
		t.Fatal("freshKey should remain")
	}
	if _, ok := dp.v6sessions[staleKey]; ok {
		t.Fatal("staleKey should be deleted")
	}
}

func TestReconcileNoBulkInProgress(t *testing.T) {
	// If no bulk was in progress, reconciliation should be a no-op.
	key := dataplane.SessionKey{SrcIP: [4]byte{10, 0, 1, 1}, Protocol: 6}
	dp := &mockSweepDP{
		v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{
			key: {IsReverse: 0, IngressZone: 2},
		},
	}

	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
	ss.IsPrimaryFn = func() bool { return false }
	ss.IsPrimaryForRGFn = func(rgID int) bool { return false }
	ss.SetZoneRGMap(map[uint16]int{2: 2})

	// Call BulkEnd WITHOUT BulkStart — reconciliation should not run.
	ss.handleMessage(syncMsgBulkEnd, nil)

	if _, ok := dp.v4sessions[key]; !ok {
		t.Fatal("session should not be deleted when no bulk was in progress")
	}
}

func TestHandleDisconnectStaleConn(t *testing.T) {
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)

	// Create two pipe connections to simulate conn A and conn B.
	connA1, connA2 := net.Pipe()
	defer connA1.Close()
	defer connA2.Close()
	connB1, connB2 := net.Pipe()
	defer connB1.Close()
	defer connB2.Close()

	// Set conn A as the active connection.
	ss.mu.Lock()
	ss.conn = connA1
	ss.stats.Connected.Store(true)
	ss.mu.Unlock()

	// Replace conn A with conn B (simulates accept/connect race).
	ss.mu.Lock()
	ss.conn = connB1
	ss.mu.Unlock()

	// Conn A's goroutine calls handleDisconnect with stale conn A.
	// This should NOT close conn B.
	ss.handleDisconnect(connA1)

	ss.mu.Lock()
	currentConn := ss.conn
	ss.mu.Unlock()

	if currentConn != connB1 {
		t.Fatal("handleDisconnect(staleConn) should not replace the active connection")
	}
	if !ss.stats.Connected.Load() {
		t.Fatal("handleDisconnect(staleConn) should not mark as disconnected")
	}

	// Now disconnect with the actual conn B — should work.
	ss.handleDisconnect(connB1)

	ss.mu.Lock()
	currentConn = ss.conn
	ss.mu.Unlock()

	if currentConn != nil {
		t.Fatal("handleDisconnect(activeConn) should clear s.conn")
	}
	if ss.stats.Connected.Load() {
		t.Fatal("handleDisconnect(activeConn) should mark as disconnected")
	}
}

func TestHandleDisconnectAlreadyNil(t *testing.T) {
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)

	connA1, connA2 := net.Pipe()
	defer connA1.Close()
	defer connA2.Close()

	// conn is nil, calling handleDisconnect should not panic.
	ss.handleDisconnect(connA1)

	if ss.stats.Connected.Load() {
		t.Fatal("should remain disconnected")
	}
}

func TestSetZoneRGMap(t *testing.T) {
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)

	// Set map
	m := map[uint16]int{1: 1, 2: 2, 3: 0}
	ss.SetZoneRGMap(m)

	// Verify internal state
	ss.zoneRGMu.RLock()
	if len(ss.zoneRGMap) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(ss.zoneRGMap))
	}
	if ss.zoneRGMap[1] != 1 {
		t.Fatalf("zone 1 should map to RG 1")
	}
	ss.zoneRGMu.RUnlock()

	// Replace map
	ss.SetZoneRGMap(map[uint16]int{5: 3})
	ss.zoneRGMu.RLock()
	if len(ss.zoneRGMap) != 1 {
		t.Fatalf("expected 1 entry after replace, got %d", len(ss.zoneRGMap))
	}
	ss.zoneRGMu.RUnlock()
}

func TestConcurrentSyncWriters(t *testing.T) {
	// Verify that concurrent writers cannot produce corrupted/interleaved messages.
	// 5 goroutines write sessions via sendCh, 5 write control messages via writeMsg.
	// Receiver verifies every message has valid framing (magic + correct length).

	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	ss.mu.Lock()
	ss.conn = clientConn
	ss.stats.Connected.Store(true)
	ss.mu.Unlock()

	const writersPerType = 5
	const msgsPerWriter = 50
	totalExpected := writersPerType*msgsPerWriter*2 // session + control

	// Receiver: read all messages and verify framing.
	type result struct {
		count int
		err   error
	}
	recvDone := make(chan result, 1)
	go func() {
		hdr := make([]byte, syncHeaderSize)
		count := 0
		for count < totalExpected {
			if _, err := io.ReadFull(serverConn, hdr); err != nil {
				recvDone <- result{count, fmt.Errorf("read header #%d: %w", count, err)}
				return
			}
			if string(hdr[0:4]) != "BPSY" {
				recvDone <- result{count, fmt.Errorf("bad magic at msg #%d: %x", count, hdr[0:4])}
				return
			}
			pLen := binary.LittleEndian.Uint32(hdr[8:12])
			if pLen > 1<<20 {
				recvDone <- result{count, fmt.Errorf("unreasonable length at msg #%d: %d", count, pLen)}
				return
			}
			if pLen > 0 {
				payload := make([]byte, pLen)
				if _, err := io.ReadFull(serverConn, payload); err != nil {
					recvDone <- result{count, fmt.Errorf("read payload #%d: %w", count, err)}
					return
				}
			}
			count++
		}
		recvDone <- result{count, nil}
	}()

	// Spawn writers.
	var wg sync.WaitGroup

	// Session writers: pre-encode and push to sendCh.
	for i := 0; i < writersPerType; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			key := dataplane.SessionKey{Protocol: 6, SrcPort: 1000, DstPort: 80}
			val := dataplane.SessionValue{State: dataplane.SessStateEstablished}
			for j := 0; j < msgsPerWriter; j++ {
				msg := encodeSessionV4(key, val)
				ss.sendCh <- msg
			}
		}()
	}

	// Control writers: write config/failover/fence directly.
	for i := 0; i < writersPerType; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < msgsPerWriter; j++ {
				var err error
				switch id % 3 {
				case 0:
					ss.writeMu.Lock()
					err = writeMsg(clientConn, syncMsgConfig, []byte("test config data"))
					ss.writeMu.Unlock()
				case 1:
					ss.writeMu.Lock()
					err = writeMsg(clientConn, syncMsgFailover, []byte{0})
					ss.writeMu.Unlock()
				case 2:
					ss.writeMu.Lock()
					err = writeMsg(clientConn, syncMsgFence, nil)
					ss.writeMu.Unlock()
				}
				if err != nil {
					t.Errorf("write error: %v", err)
					return
				}
			}
		}(i)
	}

	// Drain sendCh via sendLoop-like logic (read from channel, write under writeMu).
	drainDone := make(chan struct{})
	go func() {
		defer close(drainDone)
		sent := 0
		for sent < writersPerType*msgsPerWriter {
			msg := <-ss.sendCh
			ss.writeMu.Lock()
			_, err := clientConn.Write(msg)
			ss.writeMu.Unlock()
			if err != nil {
				t.Errorf("drain write error: %v", err)
				return
			}
			sent++
		}
	}()

	wg.Wait()
	<-drainDone

	select {
	case r := <-recvDone:
		if r.err != nil {
			t.Fatalf("receiver error after %d messages: %v", r.count, r.err)
		}
		if r.count != totalExpected {
			t.Fatalf("expected %d messages, got %d", totalExpected, r.count)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("receiver timed out")
	}
}
