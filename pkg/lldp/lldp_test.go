package lldp

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func TestEncodeTLV(t *testing.T) {
	// End TLV: type=0, length=0 → 0x0000
	end, err := EncodeTLV(tlvEnd, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(end) != 2 {
		t.Fatalf("expected 2 bytes, got %d", len(end))
	}
	if end[0] != 0 || end[1] != 0 {
		t.Fatalf("expected 0x0000 for end TLV, got %02x%02x", end[0], end[1])
	}

	// System Name TLV: type=5, value="test"
	name, err := EncodeTLV(tlvSystemName, []byte("test"))
	if err != nil {
		t.Fatal(err)
	}
	if len(name) != 6 {
		t.Fatalf("expected 6 bytes, got %d", len(name))
	}
	header := binary.BigEndian.Uint16(name[:2])
	tlvType := int(header >> 9)
	tlvLen := int(header & 0x1ff)
	if tlvType != tlvSystemName {
		t.Errorf("expected type %d, got %d", tlvSystemName, tlvType)
	}
	if tlvLen != 4 {
		t.Errorf("expected length 4, got %d", tlvLen)
	}
	if string(name[2:]) != "test" {
		t.Errorf("expected value 'test', got %q", string(name[2:]))
	}
}

func TestEncodeTLV_FailsClosedOnOverlength(t *testing.T) {
	// 511 bytes: the maximum a 9-bit length can express — accepted, and the
	// encoded header length matches.
	maxVal := make([]byte, maxTLVValueLen) // 511
	enc, err := EncodeTLV(tlvSystemDesc, maxVal)
	if err != nil {
		t.Fatalf("511-byte value should encode, got: %v", err)
	}
	if got := int(binary.BigEndian.Uint16(enc[:2]) & 0x1ff); got != maxTLVValueLen {
		t.Fatalf("encoded length should be %d, got %d", maxTLVValueLen, got)
	}
	// 512 and 600 bytes: would wrap the 9-bit length field — must be REJECTED,
	// not silently masked into a malformed frame (#2036).
	for _, n := range []int{maxTLVValueLen + 1, 600} {
		if _, err := EncodeTLV(tlvSystemDesc, make([]byte, n)); err == nil {
			t.Errorf("a %d-byte value must be rejected (would wrap the 9-bit length), got nil error", n)
		}
	}
}

func TestBuildFrame_FailsClosedOnOverlengthIdentity(t *testing.T) {
	mac := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	// An overlength variable-length identity TLV (system description) must fail
	// the whole frame rather than emit a malformed advertisement.
	huge := string(make([]byte, 600))
	if _, err := BuildFrame(mac, "trust0", 120, "xpf", huge); err == nil {
		t.Fatal("BuildFrame must fail closed on an overlength system-description TLV")
	}
	// An overlength port name must also fail closed (not panic), since portName
	// is caller-supplied and BuildFrame now routes it through EncodeTLV (#2036).
	if _, err := BuildFrame(mac, huge, 120, "xpf", "ok"); err == nil {
		t.Fatal("BuildFrame must fail closed on an overlength port name TLV")
	}
	// A bounded frame still builds cleanly.
	if _, err := BuildFrame(mac, "trust0", 120, "xpf", "ok"); err != nil {
		t.Fatalf("bounded frame should build, got: %v", err)
	}
}

func TestEncodeChassisID(t *testing.T) {
	mac := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	val := encodeChassisID(mac)
	if len(val) != 7 {
		t.Fatalf("expected 7 bytes, got %d", len(val))
	}
	if val[0] != chassisSubtypeMACAddr {
		t.Errorf("expected subtype %d, got %d", chassisSubtypeMACAddr, val[0])
	}
	if net.HardwareAddr(val[1:7]).String() != mac.String() {
		t.Errorf("MAC mismatch: got %s", net.HardwareAddr(val[1:7]))
	}
}

func TestEncodePortID(t *testing.T) {
	val := encodePortID("eth0")
	if len(val) != 5 {
		t.Fatalf("expected 5 bytes, got %d", len(val))
	}
	if val[0] != portSubtypeIfName {
		t.Errorf("expected subtype %d, got %d", portSubtypeIfName, val[0])
	}
	if string(val[1:]) != "eth0" {
		t.Errorf("expected 'eth0', got %q", string(val[1:]))
	}
}

func TestEncodeTTL(t *testing.T) {
	val := encodeTTL(120)
	if len(val) != 2 {
		t.Fatalf("expected 2 bytes, got %d", len(val))
	}
	ttl := binary.BigEndian.Uint16(val)
	if ttl != 120 {
		t.Errorf("expected TTL 120, got %d", ttl)
	}
}

func TestBuildFrame(t *testing.T) {
	mac := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	frame, err := BuildFrame(mac, "trust0", 120, "xpf", "stateful firewall")
	if err != nil {
		t.Fatal(err)
	}

	// Check Ethernet header.
	if len(frame) < ethHdrLen {
		t.Fatalf("frame too short: %d bytes", len(frame))
	}

	// Destination MAC = LLDP multicast.
	if net.HardwareAddr(frame[:6]).String() != LLDPMulticast.String() {
		t.Errorf("dst MAC: got %s, want %s",
			net.HardwareAddr(frame[:6]), LLDPMulticast)
	}

	// Source MAC.
	if net.HardwareAddr(frame[6:12]).String() != mac.String() {
		t.Errorf("src MAC: got %s, want %s",
			net.HardwareAddr(frame[6:12]), mac)
	}

	// EtherType.
	etherType := binary.BigEndian.Uint16(frame[12:14])
	if etherType != etherTypeLLDP {
		t.Errorf("ethertype: got 0x%04x, want 0x%04x", etherType, etherTypeLLDP)
	}

	// Parse TLVs from the frame.
	neighbor := ParseTLVs(frame[ethHdrLen:])
	if neighbor == nil {
		t.Fatal("ParseTLVs returned nil for valid frame")
	}
	if neighbor.ChassisID != mac.String() {
		t.Errorf("chassis ID: got %s, want %s", neighbor.ChassisID, mac.String())
	}
	if neighbor.PortID != "trust0" {
		t.Errorf("port ID: got %s, want trust0", neighbor.PortID)
	}
	if neighbor.TTL != 120 {
		t.Errorf("TTL: got %d, want 120", neighbor.TTL)
	}
	if neighbor.SystemName != "xpf" {
		t.Errorf("system name: got %s, want xpf", neighbor.SystemName)
	}
	if neighbor.SystemDesc != "stateful firewall" {
		t.Errorf("system desc: got %s, want 'stateful firewall'", neighbor.SystemDesc)
	}
	if neighbor.PortDesc != "trust0" {
		t.Errorf("port desc: got %s, want trust0", neighbor.PortDesc)
	}
}

func TestParseTLVs_Incomplete(t *testing.T) {
	// Missing Port ID — should return nil.
	mac := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	var data []byte
	data = append(data, mustEncodeTLV(tlvChassisID, encodeChassisID(mac))...)
	data = append(data, mustEncodeTLV(tlvTTL, encodeTTL(60))...)
	data = append(data, mustEncodeTLV(tlvEnd, nil)...)

	n := ParseTLVs(data)
	if n != nil {
		t.Error("expected nil for incomplete TLVs (missing Port ID)")
	}
}

func TestParseTLVs_Truncated(t *testing.T) {
	// Header says 100 bytes but only 2 bytes available.
	data, err := EncodeTLV(tlvSystemName, []byte("test"))
	if err != nil {
		t.Fatal(err)
	}
	// Corrupt the length to be larger than available.
	binary.BigEndian.PutUint16(data[:2], uint16(tlvSystemName)<<9|100)

	n := ParseTLVs(data)
	if n != nil {
		t.Error("expected nil for truncated TLV data")
	}
}

func TestParseTLVs_Empty(t *testing.T) {
	n := ParseTLVs(nil)
	if n != nil {
		t.Error("expected nil for empty data")
	}
}

// rawTLV builds a single TLV with an explicit (possibly short) value so a
// truncated mandatory TLV can be constructed directly. tlvLen is the 9-bit
// length field written to the header; value is the body that follows it.
func rawTLV(tlvType int, value []byte) []byte {
	header := uint16(tlvType&0x7f)<<9 | uint16(len(value)&0x1ff)
	out := make([]byte, 2+len(value))
	binary.BigEndian.PutUint16(out[:2], header)
	copy(out[2:], value)
	return out
}

// TestParseTLVs_TruncatedMandatory asserts that a mandatory TLV whose value is
// too short to yield a valid identifier is treated as absent, so the frame is
// rejected rather than cached under an empty key (#2551). Before the fix each
// hasX flag was set unconditionally, so these frames were ACCEPTED with empty
// ChassisID/PortID (or TTL 0) — these subtests FAIL on the pre-#2551 code,
// proving fail-on-revert.
func TestParseTLVs_TruncatedMandatory(t *testing.T) {
	mac := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	goodChassis := mustEncodeTLV(tlvChassisID, encodeChassisID(mac))
	goodPort := mustEncodeTLV(tlvPortID, encodePortID("trust0"))
	goodTTL := mustEncodeTLV(tlvTTL, encodeTTL(120))
	end := mustEncodeTLV(tlvEnd, nil)

	cases := []struct {
		name string
		data []byte
	}{
		{
			// Chassis ID = subtype byte only (len 1), no identifier.
			name: "chassis-id-len-1",
			data: concat(rawTLV(tlvChassisID, []byte{chassisSubtypeMACAddr}), goodPort, goodTTL, end),
		},
		{
			// Chassis ID = empty value (len 0).
			name: "chassis-id-len-0",
			data: concat(rawTLV(tlvChassisID, nil), goodPort, goodTTL, end),
		},
		{
			// Chassis ID MAC subtype but value short of the 6-byte address
			// (subtype + 4 of 6 MAC bytes = len 5, < 7).
			name: "chassis-id-mac-subtype-truncated",
			data: concat(rawTLV(tlvChassisID, []byte{chassisSubtypeMACAddr, 0xaa, 0xbb, 0xcc, 0xdd}), goodPort, goodTTL, end),
		},
		{
			// Port ID = subtype byte only, no identifier.
			name: "port-id-len-1",
			data: concat(goodChassis, rawTLV(tlvPortID, []byte{portSubtypeIfName}), goodTTL, end),
		},
		{
			// TTL value is 1 byte, can't form the 2-byte hold time.
			name: "ttl-len-1",
			data: concat(goodChassis, goodPort, rawTLV(tlvTTL, []byte{0x05}), end),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			n := ParseTLVs(tc.data)
			if n != nil {
				t.Errorf("expected nil for truncated mandatory TLV, got neighbor "+
					"chassis=%q port=%q ttl=%d", n.ChassisID, n.PortID, n.TTL)
			}
		})
	}
}

// TestParseTLVs_ValidShutdownTTL asserts that a well-formed advert carrying a
// 2-byte TTL of 0 (a legitimate LLDP shutdown frame) is still accepted: the
// hasTTL gate is "the 2-byte value parsed", not "TTL != 0". A truncated TTL
// (covered above) is rejected; a parsed 0 is not.
func TestParseTLVs_ValidShutdownTTL(t *testing.T) {
	mac := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	data := concat(
		mustEncodeTLV(tlvChassisID, encodeChassisID(mac)),
		mustEncodeTLV(tlvPortID, encodePortID("trust0")),
		mustEncodeTLV(tlvTTL, encodeTTL(0)),
		mustEncodeTLV(tlvEnd, nil),
	)
	n := ParseTLVs(data)
	if n == nil {
		t.Fatal("expected a neighbor for a valid 2-byte TTL=0 shutdown advert, got nil")
	}
	if n.TTL != 0 {
		t.Errorf("TTL: got %d, want 0", n.TTL)
	}
	if n.ChassisID != mac.String() {
		t.Errorf("chassis ID: got %s, want %s", n.ChassisID, mac.String())
	}
	if n.PortID != "trust0" {
		t.Errorf("port ID: got %s, want trust0", n.PortID)
	}
}

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func TestNeighborTable(t *testing.T) {
	m := New()

	// Manually add neighbors and verify.
	m.mu.Lock()
	m.neighbors["eth0/aa:bb:cc:dd:ee:ff/port1"] = &Neighbor{
		ChassisID: "aa:bb:cc:dd:ee:ff",
		PortID:    "port1",
		TTL:       120,
		Interface: "eth0",
		LastSeen:  time.Now(),
		ExpiresAt: time.Now().Add(120 * time.Second),
	}
	m.neighbors["eth1/11:22:33:44:55:66/port2"] = &Neighbor{
		ChassisID: "11:22:33:44:55:66",
		PortID:    "port2",
		TTL:       60,
		Interface: "eth1",
		LastSeen:  time.Now(),
		ExpiresAt: time.Now().Add(60 * time.Second),
	}
	m.mu.Unlock()

	neighbors := m.Neighbors()
	if len(neighbors) != 2 {
		t.Fatalf("expected 2 neighbors, got %d", len(neighbors))
	}
	// Should be sorted by key.
	if neighbors[0].Interface != "eth0" {
		t.Errorf("first neighbor should be eth0, got %s", neighbors[0].Interface)
	}
	if neighbors[1].Interface != "eth1" {
		t.Errorf("second neighbor should be eth1, got %s", neighbors[1].Interface)
	}
}

func TestNeighborExpiry(t *testing.T) {
	m := New()

	// Add an already-expired neighbor.
	m.mu.Lock()
	m.neighbors["eth0/aa:bb:cc:dd:ee:ff/port1"] = &Neighbor{
		ChassisID: "aa:bb:cc:dd:ee:ff",
		PortID:    "port1",
		TTL:       1,
		Interface: "eth0",
		LastSeen:  time.Now().Add(-10 * time.Second),
		ExpiresAt: time.Now().Add(-5 * time.Second),
	}
	// Add a still-valid neighbor.
	m.neighbors["eth1/11:22:33:44:55:66/port2"] = &Neighbor{
		ChassisID: "11:22:33:44:55:66",
		PortID:    "port2",
		TTL:       300,
		Interface: "eth1",
		LastSeen:  time.Now(),
		ExpiresAt: time.Now().Add(300 * time.Second),
	}
	m.mu.Unlock()

	// Manually run expiry check.
	now := time.Now()
	m.mu.Lock()
	for key, n := range m.neighbors {
		if now.After(n.ExpiresAt) {
			delete(m.neighbors, key)
		}
	}
	m.mu.Unlock()

	neighbors := m.Neighbors()
	if len(neighbors) != 1 {
		t.Fatalf("expected 1 neighbor after expiry, got %d", len(neighbors))
	}
	if neighbors[0].ChassisID != "11:22:33:44:55:66" {
		t.Errorf("wrong surviving neighbor: %s", neighbors[0].ChassisID)
	}
}

func TestRoundTripTLVs(t *testing.T) {
	// Build a frame and parse it back — full round-trip test.
	mac := net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, 0x00, 0x01}
	frame, err := BuildFrame(mac, "ge-0/0/1", 300, "switch1", "Juniper EX4300")
	if err != nil {
		t.Fatal(err)
	}

	n := ParseTLVs(frame[ethHdrLen:])
	if n == nil {
		t.Fatal("ParseTLVs returned nil")
	}
	if n.ChassisID != mac.String() {
		t.Errorf("chassis: %s != %s", n.ChassisID, mac.String())
	}
	if n.PortID != "ge-0/0/1" {
		t.Errorf("port: %s != ge-0/0/1", n.PortID)
	}
	if n.TTL != 300 {
		t.Errorf("ttl: %d != 300", n.TTL)
	}
	if n.SystemName != "switch1" {
		t.Errorf("sysname: %s != switch1", n.SystemName)
	}
	if n.SystemDesc != "Juniper EX4300" {
		t.Errorf("sysdesc: %s != Juniper EX4300", n.SystemDesc)
	}
}

func TestStopIdempotent(t *testing.T) {
	m := New()
	m.Stop() // should not panic
	m.Stop() // double stop should be fine
}
