package flowexport

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// #2613: the NetFlow v9 and IPFIX templates no longer advertise
// ipClassOfService/SrcTos (5), tcpControlBits/TCPFlags (6),
// flowDirection/Direction (61), ingressInterface/InputSNMP (10) or
// egressInterface/OutputSNMP (14). The SESSION_CLOSE wire frame carries no
// real value for any of them, so advertising them made collectors ingest
// authoritative zeros.
//
// These tests are fail-on-revert pins: re-adding any of the five IEs to a
// template slice (and re-introducing the matching encoder write) shifts the
// record layout and re-fails both the template-absence walk AND the
// record-layout golden, which assert that the bytes immediately after the
// protocol byte are the packet/byte counters (carrying the REAL values), not
// a zero TOS/flags/direction/interface block.

// --- IPFIX template-absence ------------------------------------------------

// TestIPFIXTemplateDroppedFieldsAbsent walks the encoded IPFIX template set
// and asserts none of the five dropped IEs appear. The element IDs are
// asserted as literals (independent of the package constants) so a renamed or
// removed constant cannot make the test agree with itself.
func TestIPFIXTemplateDroppedFieldsAbsent(t *testing.T) {
	dropped := map[uint16]string{
		5:  "ipClassOfService",
		6:  "tcpControlBits",
		61: "flowDirection",
		10: "ingressInterface",
		14: "egressInterface",
	}
	for _, tmpl := range [][]ipfixField{ipfixTemplateV4, ipfixTemplateV6} {
		for _, f := range tmpl {
			if name, bad := dropped[f.elementID]; bad {
				t.Errorf("dropped IPFIX IE %s (%d) still advertised in template", name, f.elementID)
			}
		}
	}

	// Also walk the encoded bytes (the wire the collector parses).
	ts := encodeIPFIXTemplateSet()
	off := 4 // skip set header
	for off+4 <= len(ts) {
		off += 2 // skip template ID
		count := int(binary.BigEndian.Uint16(ts[off : off+2]))
		off += 2
		for i := 0; i < count && off+4 <= len(ts); i++ {
			eid := binary.BigEndian.Uint16(ts[off : off+2])
			if name, bad := dropped[eid]; bad {
				t.Errorf("dropped IPFIX IE %s (%d) found in encoded template set", name, eid)
			}
			off += 4
		}
	}
}

// --- record-layout fail-on-revert ------------------------------------------

// nonZeroRecord returns a FlowRecord whose dropped-field members are all set
// to a sentinel non-zero value. If any of those fields were still encoded, the
// golden offset checks below would read the sentinel instead of the real
// counters — so the test proves the dropped fields are genuinely gone, not
// merely zero.
func nonZeroRecord(v6 bool) FlowRecord {
	now := time.Unix(1_700_000_000, 0)
	r := FlowRecord{
		SrcPort: 40000, DstPort: 80, Protocol: 6,
		TOS: 0xAB, TCPFlags: 0xCD, Direction: 0x01,
		InIf: 0xDEADBEEF, OutIf: 0xFEEDFACE,
		Packets: 0x1122334455667788, Bytes: 0x99AABBCCDDEEFF00,
		StartTime: now, EndTime: now,
		SrcMask: 24, DstMask: 32,
	}
	if v6 {
		r.IsIPv6 = true
		r.SrcIP = net.ParseIP("fd00::1")
		r.DstIP = net.ParseIP("2001:db8::200")
		r.NATSrcIP = r.SrcIP
		r.NATDstIP = r.DstIP
	} else {
		r.SrcIP = net.IPv4(10, 0, 1, 100)
		r.DstIP = net.IPv4(172, 16, 80, 200)
		r.NATSrcIP = r.SrcIP
		r.NATDstIP = r.DstIP
	}
	return r
}

// TestIPFIXRecordOmitsDroppedFields encodes a record with sentinel TOS/flags/
// direction/interface values and asserts the byte immediately after the
// protocol byte is the high byte of the 8-byte packet counter (0x11), NOT the
// sentinel TOS (0xAB). Under the pre-#2613 layout the next byte was TOS.
func TestIPFIXRecordOmitsDroppedFields(t *testing.T) {
	for _, tc := range []struct {
		name    string
		v6      bool
		recSize int
		// offset of the protocol byte within the data record body
		protoOff int
	}{
		// v4 record body: src4 dst4 sport2 dport2 proto1 -> proto at body off 12
		{"v4", false, ipfixRecordSizeV4, 12},
		// v6 record body: src16 dst16 sport2 dport2 proto1 -> proto at body off 36
		{"v6", true, ipfixRecordSizeV6, 36},
	} {
		ds := encodeIPFIXDataSet([]FlowRecord{nonZeroRecord(tc.v6)})
		if got := len(ds); got != 4+tc.recSize {
			t.Fatalf("%s: encoded len = %d, want %d", tc.name, got, 4+tc.recSize)
		}
		// 4-byte set header precedes the record body.
		proto := ds[4+tc.protoOff]
		if proto != 6 {
			t.Fatalf("%s: protocol byte = 0x%02x, want 0x06", tc.name, proto)
		}
		// The byte after protocol must be the packet-counter high byte (0x11),
		// proving no TOS (0xAB) / flags / direction were written there.
		next := ds[4+tc.protoOff+1]
		if next == 0xAB || next == 0xCD || next == 0x01 {
			t.Errorf("%s: byte after protocol = 0x%02x — a dropped field (TOS/flags/dir) leaked", tc.name, next)
		}
		if next != 0x11 {
			t.Errorf("%s: byte after protocol = 0x%02x, want 0x11 (packet-counter high byte)", tc.name, next)
		}
		// And the packet/byte counters (the REAL values) round-trip.
		pktOff := 4 + tc.protoOff + 1
		if pkts := binary.BigEndian.Uint64(ds[pktOff : pktOff+8]); pkts != 0x1122334455667788 {
			t.Errorf("%s: packets = 0x%016x, want 0x1122334455667788", tc.name, pkts)
		}
	}
}

// TestNetflowRecordOmitsDroppedFields mirrors the IPFIX check for NetFlow v9.
// The v9 record writes the 8-byte packet count right after the protocol byte
// once SrcTos/TCPFlags/Direction are dropped.
func TestNetflowRecordOmitsDroppedFields(t *testing.T) {
	boot := time.Unix(1_700_000_000, 0)
	opts := DefaultV9TemplateOptions()
	for _, tc := range []struct {
		name     string
		v6       bool
		fields   []templateField
		protoOff int // protocol byte offset within the record body
	}{
		{"v4", false, netflowTemplateFieldsV4, 12},
		{"v6", true, netflowTemplateFieldsV6, 36},
	} {
		fs := encodeDataFlowSet([]FlowRecord{nonZeroRecord(tc.v6)}, boot, opts)
		recSize := recordSize(tc.fields)
		if len(fs) != 4+recSize {
			t.Fatalf("%s: flowset len = %d, want %d", tc.name, len(fs), 4+recSize)
		}
		proto := fs[4+tc.protoOff]
		if proto != 6 {
			t.Fatalf("%s: protocol byte = 0x%02x, want 0x06", tc.name, proto)
		}
		next := fs[4+tc.protoOff+1]
		if next == 0xAB || next == 0xCD || next == 0x01 {
			t.Errorf("%s: byte after protocol = 0x%02x — a dropped field leaked", tc.name, next)
		}
		if next != 0x11 {
			t.Errorf("%s: byte after protocol = 0x%02x, want 0x11 (packet-counter high byte)", tc.name, next)
		}
		pktOff := 4 + tc.protoOff + 1
		if pkts := binary.BigEndian.Uint64(fs[pktOff : pktOff+8]); pkts != 0x1122334455667788 {
			t.Errorf("%s: packets = 0x%016x, want 0x1122334455667788", tc.name, pkts)
		}
	}
}
