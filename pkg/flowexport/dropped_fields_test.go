package flowexport

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// #2613: the NetFlow v9 and IPFIX templates dropped ipClassOfService/SrcTos
// (5), tcpControlBits/TCPFlags (6), flowDirection/Direction (61),
// ingressInterface/InputSNMP (10) and egressInterface/OutputSNMP (14) because
// the SESSION_CLOSE wire frame carried no real value for any of them, so
// advertising them made collectors ingest authoritative zeros.
//
// #2749: ingressInterface/InputSNMP (10) was re-introduced with a real value
// (the ingress ifindex on the close frame since #2615), and the extended
// SESSION_CLOSE frame ([144:152]) now also threads REAL ipClassOfService/SrcTos
// (5), tcpControlBits/TCPFlags (6) and egressInterface/OutputSNMP (14). So all
// four are now advertised again WITH real values — pinned present by
// TestNetflowCosFieldsPopulated / TestIPFIXCosFieldsPopulated and the ingress
// pins. They are placed after FlowEnd (never between the protocol byte and the
// packet counter), so the proto->packet-counter adjacency the record-layout
// goldens below check is preserved.
//
// #3270: flowDirection/Direction (61) is no longer permanently absent — it is
// advertised + populated (from the per-zone sampling-direction) when
// `export-extension flow-dir` is configured. It stays absent in the BASE
// (no-extension) template, which is what these tests exercise; the conditional
// presence/value behaviour is pinned by TestV9TemplateFlowDirConditional and
// TestIPFIXTemplateFlowDirConditional. See docs/flow-export.md.
//
// These tests are fail-on-revert pins for the BASE template/record layout: the
// record-layout goldens prove the bytes immediately after the protocol byte
// are the packet/byte counters (the REAL values), never a class-of-service
// block, and that the default template advertises no flowDirection.

// --- IPFIX template-absence ------------------------------------------------

// TestIPFIXTemplateDroppedFieldsAbsent walks the encoded IPFIX template set
// and asserts none of the five dropped IEs appear. The element IDs are
// asserted as literals (independent of the package constants) so a renamed or
// removed constant cannot make the test agree with itself.
func TestIPFIXTemplateDroppedFieldsAbsent(t *testing.T) {
	// #2749: IEs 5/6/10/14 are intentionally NOT in this set — they are
	// re-introduced with real values and pinned present by the *Populated
	// tests. #3270: flowDirection (61) is absent in the BASE (no-flow-dir)
	// template exercised here; its conditional presence is pinned by
	// TestIPFIXTemplateFlowDirConditional.
	dropped := map[uint16]string{
		61: "flowDirection",
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
