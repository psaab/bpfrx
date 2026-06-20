package dhcprelay

import (
	"encoding/binary"
	"net"
	"testing"
)

// TestBuildL2Reply_PerByte asserts EVERY byte of the Ethernet/IPv4/UDP headers
// produced by buildL2Reply, plus payload placement. A malformed-but-Sendto-
// successful frame is silently dropped by the client and the runtime broadcast
// fallback does NOT fire (#2076 §9), so per-byte coverage is the only defense.
func TestBuildL2Reply_PerByte(t *testing.T) {
	dstMAC := net.HardwareAddr{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}
	srcMAC := net.HardwareAddr{0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee}
	srcIP := net.IPv4(192, 168, 1, 1)   // giaddr
	dstIP := net.IPv4(192, 168, 1, 100) // yiaddr
	payload := []byte{0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03}

	frame := buildL2Reply(dstMAC, srcMAC, srcIP, dstIP, payload)

	udpLen := udpHeaderLen + len(payload)
	totalLen := ipv4HeaderLen + udpLen
	wantFrameLen := ethHeaderLen + totalLen
	if len(frame) != wantFrameLen {
		t.Fatalf("frame len = %d, want %d", len(frame), wantFrameLen)
	}

	// --- Ethernet header ---
	if got := frame[0:6]; !equalBytes(got, dstMAC) {
		t.Errorf("eth dst = %x, want %x", got, dstMAC)
	}
	if got := frame[6:12]; !equalBytes(got, srcMAC) {
		t.Errorf("eth src = %x, want %x", got, srcMAC)
	}
	if et := binary.BigEndian.Uint16(frame[12:14]); et != etherTypeIPv4 {
		t.Errorf("ethertype = 0x%04x, want 0x%04x", et, etherTypeIPv4)
	}

	// --- IPv4 header ---
	ip := frame[14:34]
	if ip[0] != 0x45 {
		t.Errorf("ip version/IHL = 0x%02x, want 0x45", ip[0])
	}
	if ip[1] != 0x00 {
		t.Errorf("ip DSCP/ECN = 0x%02x, want 0x00", ip[1])
	}
	if tl := binary.BigEndian.Uint16(ip[2:4]); int(tl) != totalLen {
		t.Errorf("ip total length = %d, want %d", tl, totalLen)
	}
	if id := binary.BigEndian.Uint16(ip[4:6]); id != 0 {
		t.Errorf("ip identification = %d, want 0", id)
	}
	if ff := binary.BigEndian.Uint16(ip[6:8]); ff != 0x4000 {
		t.Errorf("ip flags/frag = 0x%04x, want 0x4000 (DF)", ff)
	}
	if ip[8] != ipv4TTL {
		t.Errorf("ip TTL = %d, want %d", ip[8], ipv4TTL)
	}
	if ip[9] != ipProtoUDP {
		t.Errorf("ip proto = %d, want %d (UDP)", ip[9], ipProtoUDP)
	}
	if got := ip[12:16]; !equalBytes(got, srcIP.To4()) {
		t.Errorf("ip src = %v, want %v", net.IP(got), srcIP)
	}
	if got := ip[16:20]; !equalBytes(got, dstIP.To4()) {
		t.Errorf("ip dst = %v, want %v", net.IP(got), dstIP)
	}
	// IPv4 header checksum must VALIDATE: recompute over the header with the
	// checksum field present — the one's-complement sum must be 0xFFFF.
	if !ipv4ChecksumValid(ip) {
		t.Errorf("ip header checksum does not validate; field=0x%04x",
			binary.BigEndian.Uint16(ip[10:12]))
	}

	// --- UDP header ---
	udp := frame[34:42]
	if sp := binary.BigEndian.Uint16(udp[0:2]); sp != relayPort {
		t.Errorf("udp src port = %d, want %d", sp, relayPort)
	}
	if dp := binary.BigEndian.Uint16(udp[2:4]); dp != clientPort {
		t.Errorf("udp dst port = %d, want %d", dp, clientPort)
	}
	if ul := binary.BigEndian.Uint16(udp[4:6]); int(ul) != udpLen {
		t.Errorf("udp length = %d, want %d", ul, udpLen)
	}
	// UDP checksum MUST be 0 (legal for IPv4 per RFC 768; #2076 Q2).
	if cs := binary.BigEndian.Uint16(udp[6:8]); cs != 0 {
		t.Errorf("udp checksum = 0x%04x, want 0", cs)
	}

	// --- Payload ---
	if got := frame[42:]; !equalBytes(got, payload) {
		t.Errorf("payload = %x, want %x", got, payload)
	}
}

// TestBuildL2Reply_ChecksumNonTrivial guards against a tautology: an all-zero
// or constant checksum would still "validate" against itself in a buggy
// implementation. Two frames that differ only in destination IP must produce
// DIFFERENT IPv4 header checksums, and each must independently validate.
func TestBuildL2Reply_ChecksumNonTrivial(t *testing.T) {
	dstMAC := net.HardwareAddr{0x02, 0, 0, 0, 0, 1}
	srcMAC := net.HardwareAddr{0x02, 0, 0, 0, 0, 2}
	srcIP := net.IPv4(10, 0, 0, 1)
	payload := []byte{0x00}

	f1 := buildL2Reply(dstMAC, srcMAC, srcIP, net.IPv4(10, 0, 0, 50), payload)
	f2 := buildL2Reply(dstMAC, srcMAC, srcIP, net.IPv4(10, 0, 0, 51), payload)

	c1 := binary.BigEndian.Uint16(f1[24:26]) // ip checksum field (14+10)
	c2 := binary.BigEndian.Uint16(f2[24:26])
	if c1 == c2 {
		t.Errorf("checksums identical for different dst IPs (0x%04x) — "+
			"checksum likely not computed over the header", c1)
	}
	if c1 == 0 || c2 == 0 {
		t.Errorf("checksum is zero (c1=0x%04x c2=0x%04x) — not computed", c1, c2)
	}
	if !ipv4ChecksumValid(f1[14:34]) || !ipv4ChecksumValid(f2[14:34]) {
		t.Errorf("a frame failed checksum validation")
	}
}

// TestIPv4Checksum_KnownVector validates ipv4Checksum against a hand-computed
// reference header (a well-known RFC-791 worked example).
func TestIPv4Checksum_KnownVector(t *testing.T) {
	// Classic worked example: 45 00 00 73 00 00 40 00 40 11 00 00
	// c0 a8 00 01 c0 a8 00 c7 → checksum 0xb861.
	hdr := []byte{
		0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00,
		0x40, 0x11, 0x00, 0x00,
		0xc0, 0xa8, 0x00, 0x01,
		0xc0, 0xa8, 0x00, 0xc7,
	}
	if got := ipv4Checksum(hdr); got != 0xb861 {
		t.Errorf("ipv4Checksum = 0x%04x, want 0xb861", got)
	}
	// And the computed header must validate.
	binary.BigEndian.PutUint16(hdr[10:12], ipv4Checksum(hdr))
	if !ipv4ChecksumValid(hdr) {
		t.Errorf("computed checksum does not validate")
	}
}

// TestHtonsLocal confirms host->network conversion round-trips a known value.
func TestHtonsLocal(t *testing.T) {
	// 0x0800 in network order is bytes {0x08, 0x00}.
	got := htonsLocal(0x0800)
	b := make([]byte, 2)
	binary.NativeEndian.PutUint16(b, got)
	if b[0] != 0x08 || b[1] != 0x00 {
		t.Errorf("htonsLocal(0x0800) native bytes = %x, want 0800", b)
	}
}

// ipv4ChecksumValid recomputes the one's-complement sum over a full IPv4 header
// (checksum field included). A valid header sums to 0xFFFF.
func ipv4ChecksumValid(hdr []byte) bool {
	var sum uint32
	for i := 0; i+1 < len(hdr); i += 2 {
		sum += uint32(hdr[i])<<8 | uint32(hdr[i+1])
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return uint16(sum) == 0xffff
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestNewL2Sender_CapturesOpenMAC proves newL2Sender records the interface MAC
// at open time (the per-send fallback source). It needs CAP_NET_RAW + an
// Ethernet interface; skipped otherwise. This keeps the openMAC fallback from
// being dead/untested code.
func TestNewL2Sender_CapturesOpenMAC(t *testing.T) {
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Skipf("Interfaces: %v", err)
	}
	var target string
	for _, ifi := range ifaces {
		if len(ifi.HardwareAddr) == 6 && ifi.Flags&net.FlagLoopback == 0 {
			target = ifi.Name
			break
		}
	}
	if target == "" {
		t.Skip("no 6-byte-MAC non-loopback interface available")
	}
	s, err := newL2Sender(target)
	if err != nil {
		t.Skipf("newL2Sender(%s): %v (likely no CAP_NET_RAW)", target, err)
	}
	defer s.Close()
	if len(s.openMAC) != 6 {
		t.Errorf("openMAC not captured: %v", s.openMAC)
	}
}
