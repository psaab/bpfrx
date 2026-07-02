package flowexport

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// #3746 fail-on-revert pins for the RFC 5103 biflow reverse Information
// Elements now exported by the IPFIX encoder: reverseOctetDeltaCount (IE 1)
// and reversePacketDeltaCount (IE 2), both under the reverse Private Enterprise
// Number 29305.
//
// These tests decode the emitted Template Set and Data Record off the wire and
// assert:
//   - the two reverse IEs appear in BOTH the v4 and v6 templates with the
//     enterprise bit set, PEN 29305, and length 8 (an enterprise field
//     specifier is 8 bytes, not 4);
//   - the Template Set header length equals the bytes actually consumed by the
//     walk (an off-by-one in the 8-byte enterprise-specifier sizing would drift
//     the set length and corrupt every following template);
//   - the encoded Data Record carries the reverse packet/byte counts as 8-byte
//     unsigned64 values at the reverse IEs' data offset.
//
// Reverting the reverse IEs (removing them from the template AND the encoder)
// flips these RED: the templateEnterpriseIEs walk finds no PEN-29305 fields and
// the data round-trip reads the wrong bytes / a shorter record.

// The reverse element IDs and PEN, asserted as literals independent of the
// package constants so a typo'd constant cannot make the test agree with itself.
const (
	wantReverseOctetIE  uint16 = 1
	wantReversePacketIE uint16 = 2
	wantReversePEN      uint32 = 29305
)

// ipfixSpec is one decoded Template Set field specifier.
type ipfixSpec struct {
	elementID  uint16
	length     uint16
	enterprise uint32 // 0 for an IANA IE
}

// decodeTemplateRecords walks an encoded IPFIX Template Set and returns, per
// template record, the template ID and its field specifiers. It fully handles
// the 4-byte IANA vs 8-byte enterprise (RFC 7011 §3.2) specifier widths and
// fails the test on any length drift, which is the load-bearing integrity check
// for the enterprise-specifier sizing.
func decodeTemplateRecords(t *testing.T, ts []byte) map[uint16][]ipfixSpec {
	t.Helper()
	if len(ts) < 4 {
		t.Fatalf("template set too short: %d bytes", len(ts))
	}
	setID := binary.BigEndian.Uint16(ts[0:2])
	if setID != ipfixSetIDTemplate {
		t.Fatalf("set ID = %d, want %d (template set)", setID, ipfixSetIDTemplate)
	}
	setLen := int(binary.BigEndian.Uint16(ts[2:4]))
	if setLen != len(ts) {
		t.Fatalf("template set header length = %d, want %d (encoded length) — enterprise specifier sizing drift", setLen, len(ts))
	}

	out := make(map[uint16][]ipfixSpec)
	off := 4
	for off+4 <= len(ts) {
		tmplID := binary.BigEndian.Uint16(ts[off : off+2])
		count := int(binary.BigEndian.Uint16(ts[off+2 : off+4]))
		off += 4
		specs := make([]ipfixSpec, 0, count)
		for i := 0; i < count; i++ {
			if off+4 > len(ts) {
				t.Fatalf("template %d: ran off the end at field %d/%d (specifier width drift)", tmplID, i, count)
			}
			raw := binary.BigEndian.Uint16(ts[off : off+2])
			length := binary.BigEndian.Uint16(ts[off+2 : off+4])
			off += 4
			var pen uint32
			if raw&0x8000 != 0 {
				if off+4 > len(ts) {
					t.Fatalf("template %d: enterprise field missing PEN", tmplID)
				}
				pen = binary.BigEndian.Uint32(ts[off : off+4])
				off += 4
			}
			specs = append(specs, ipfixSpec{elementID: raw & 0x7fff, length: length, enterprise: pen})
		}
		out[tmplID] = specs
	}
	if off != len(ts) {
		t.Fatalf("template walk consumed %d bytes, set is %d — specifier width drift", off, len(ts))
	}
	return out
}

// findSpec returns the specifier with the given (elementID, enterprise), which
// is required because a reverse IE reuses the forward IE's element ID (IE 1 / 2)
// and is distinguished ONLY by the enterprise PEN.
func findSpec(specs []ipfixSpec, elementID uint16, enterprise uint32) (ipfixSpec, bool) {
	for _, s := range specs {
		if s.elementID == elementID && s.enterprise == enterprise {
			return s, true
		}
	}
	return ipfixSpec{}, false
}

// TestIPFIXTemplateCarriesBiflowReverseIEs decodes both the base template and
// the flow-dir template and asserts the two reverse IEs are advertised as
// enterprise fields under PEN 29305.
func TestIPFIXTemplateCarriesBiflowReverseIEs(t *testing.T) {
	for _, includeDir := range []bool{false, true} {
		ts := encodeIPFIXTemplateSetDir(includeDir)
		tmpls := decodeTemplateRecords(t, ts)

		for _, tmplID := range []uint16{ipfixTemplateIDv4, ipfixTemplateIDv6} {
			specs, ok := tmpls[tmplID]
			if !ok {
				t.Fatalf("includeDir=%v: template %d missing from set", includeDir, tmplID)
			}
			// reverseOctetDeltaCount (IE 1, PEN 29305, 8B).
			if s, ok := findSpec(specs, wantReverseOctetIE, wantReversePEN); !ok {
				t.Errorf("includeDir=%v tmpl %d: reverseOctetDeltaCount (IE %d, PEN %d) absent",
					includeDir, tmplID, wantReverseOctetIE, wantReversePEN)
			} else if s.length != 8 {
				t.Errorf("includeDir=%v tmpl %d: reverseOctetDeltaCount length = %d, want 8", includeDir, tmplID, s.length)
			}
			// reversePacketDeltaCount (IE 2, PEN 29305, 8B).
			if s, ok := findSpec(specs, wantReversePacketIE, wantReversePEN); !ok {
				t.Errorf("includeDir=%v tmpl %d: reversePacketDeltaCount (IE %d, PEN %d) absent",
					includeDir, tmplID, wantReversePacketIE, wantReversePEN)
			} else if s.length != 8 {
				t.Errorf("includeDir=%v tmpl %d: reversePacketDeltaCount length = %d, want 8", includeDir, tmplID, s.length)
			}
			// The forward octet/packet IEs (same element IDs, IANA) must still
			// be present as NON-enterprise fields — the reverse IEs must not
			// have displaced them.
			if _, ok := findSpec(specs, ipfixOctetDeltaCount, 0); !ok {
				t.Errorf("includeDir=%v tmpl %d: forward octetDeltaCount (IANA IE 1) missing", includeDir, tmplID)
			}
			if _, ok := findSpec(specs, ipfixPacketDeltaCount, 0); !ok {
				t.Errorf("includeDir=%v tmpl %d: forward packetDeltaCount (IANA IE 2) missing", includeDir, tmplID)
			}
		}
	}
}

// ipfixReverseDataOffset returns the byte offset of the reverse IE with the
// given element ID within a DATA record body, walking the template by data
// value length (f.length) and matching on the enterprise PEN.
func ipfixReverseDataOffset(fields []ipfixField, elementID uint16) (int, bool) {
	off := 0
	for _, f := range fields {
		if f.elementID == elementID && f.enterprise == ipfixReversePEN {
			return off, true
		}
		off += int(f.length)
	}
	return 0, false
}

// TestIPFIXRecordCarriesBiflowReverseCounts encodes a record with distinct
// reverse packet/byte sentinels (both > 2^32 to prove the full 8-byte u64
// round-trip) and asserts they land at the reverse IEs' data offset.
func TestIPFIXRecordCarriesBiflowReverseCounts(t *testing.T) {
	const (
		revPkts  uint64 = 0x0000_00AA_BBCC_DDEE // 733007751150
		revBytes uint64 = 0x1122_3344_5566_7788
	)
	now := time.Unix(1_700_000_000, 0)
	for _, tc := range []struct {
		name   string
		v6     bool
		fields []ipfixField
	}{
		{"v4", false, ipfixTemplateV4},
		{"v6", true, ipfixTemplateV6},
	} {
		rec := FlowRecord{
			SrcPort: 40000, DstPort: 80, Protocol: 6,
			Packets: 10, Bytes: 5000,
			RevPackets: revPkts, RevBytes: revBytes,
			StartTime: now, EndTime: now, IsIPv6: tc.v6,
		}
		if tc.v6 {
			rec.SrcIP = net.ParseIP("fd00::1")
			rec.DstIP = net.ParseIP("2001:db8::200")
		} else {
			rec.SrcIP = net.IPv4(10, 0, 1, 100)
			rec.DstIP = net.IPv4(172, 16, 80, 200)
		}
		rec.NATSrcIP = rec.SrcIP
		rec.NATDstIP = rec.DstIP

		pktOff, ok := ipfixReverseDataOffset(tc.fields, ipfixReversePacketDeltaCount)
		if !ok {
			t.Fatalf("%s: template missing reversePacketDeltaCount", tc.name)
		}
		octOff, ok := ipfixReverseDataOffset(tc.fields, ipfixReverseOctetDeltaCount)
		if !ok {
			t.Fatalf("%s: template missing reverseOctetDeltaCount", tc.name)
		}

		ds := encodeIPFIXDataSet([]FlowRecord{rec})
		// 4-byte set header precedes the record body.
		if gotPkts := binary.BigEndian.Uint64(ds[4+pktOff : 4+pktOff+8]); gotPkts != revPkts {
			t.Errorf("%s: encoded reversePacketDeltaCount = %#x, want %#x (encoder write reverted)", tc.name, gotPkts, revPkts)
		}
		if gotBytes := binary.BigEndian.Uint64(ds[4+octOff : 4+octOff+8]); gotBytes != revBytes {
			t.Errorf("%s: encoded reverseOctetDeltaCount = %#x, want %#x (encoder write reverted)", tc.name, gotBytes, revBytes)
		}
	}
}

// TestIPFIXExportSessionCloseWiresReverseCounts pins the ExportSessionClose
// plumbing: the reverse counters on the SESSION_CLOSE EventRecord
// (rec.RevSessionPkts / rec.RevSessionBytes, produced since #2501) must reach
// the FlowRecord the exporter batches. Reverting the RevPackets/RevBytes
// assignment leaves them 0.
func TestIPFIXExportSessionCloseWiresReverseCounts(t *testing.T) {
	rec, sd := closeRecordForMask(false)
	rec.RevSessionPkts = 4242
	rec.RevSessionBytes = 9_000_000

	var e IPFIXExporter
	e.ExportSessionClose(rec, sd)
	v4recs, _ := e.batch.drain()
	if len(v4recs) != 1 {
		t.Fatalf("drained %d records, want 1", len(v4recs))
	}
	if v4recs[0].RevPackets != 4242 || v4recs[0].RevBytes != 9_000_000 {
		t.Fatalf("FlowRecord reverse = pkts %d / bytes %d, want 4242 / 9000000 (ExportSessionClose plumbing reverted)",
			v4recs[0].RevPackets, v4recs[0].RevBytes)
	}
}

// TestIPFIXBiflowReverseWireLoopback exercises the full exporter wire path
// (NewIPFIXExporter -> sendTemplates / sendRecords) over a loopback UDP
// collector, mirroring the #2609 sequence-number harness, and asserts the
// reverse IEs survive on the real wire in BOTH the template and the data
// record.
func TestIPFIXBiflowReverseWireLoopback(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer pc.Close()

	ec := &ExportConfig{Collectors: []CollectorConfig{{Address: pc.LocalAddr().String()}}}
	e, err := NewIPFIXExporter(ec)
	if err != nil {
		t.Fatalf("NewIPFIXExporter: %v", err)
	}
	defer e.Close()

	readPkt := func() []byte {
		buf := make([]byte, 4096)
		if err := pc.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Fatalf("SetReadDeadline: %v", err)
		}
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			t.Fatalf("collector read: %v", err)
		}
		return buf[:n]
	}

	// 1) Template packet: 16-byte IPFIX header precedes the template set.
	e.sendTemplates()
	tpkt := readPkt()
	if len(tpkt) < 16 {
		t.Fatalf("short template packet: %d bytes", len(tpkt))
	}
	tmpls := decodeTemplateRecords(t, tpkt[16:])
	specs := tmpls[ipfixTemplateIDv4]
	if _, ok := findSpec(specs, wantReverseOctetIE, wantReversePEN); !ok {
		t.Error("wire template: reverseOctetDeltaCount (PEN 29305) absent")
	}
	if _, ok := findSpec(specs, wantReversePacketIE, wantReversePEN); !ok {
		t.Error("wire template: reversePacketDeltaCount (PEN 29305) absent")
	}

	// 2) Data packet: reverse counts round-trip on the real wire.
	const revPkts, revBytes uint64 = 0xAABBCCDD, 0x1_0000_0002
	e.sendRecords([]FlowRecord{{
		SrcIP: net.IPv4(10, 0, 0, 1), DstIP: net.IPv4(10, 0, 0, 2),
		SrcPort: 1000, DstPort: 80, Protocol: 6,
		Packets: 3, Bytes: 300, RevPackets: revPkts, RevBytes: revBytes,
		StartTime: time.Now(), EndTime: time.Now(),
	}})
	dpkt := readPkt()
	// 16-byte IPFIX header + 4-byte set header precede the record body.
	body := dpkt[16+4:]
	pktOff, _ := ipfixReverseDataOffset(ipfixTemplateV4, ipfixReversePacketDeltaCount)
	octOff, _ := ipfixReverseDataOffset(ipfixTemplateV4, ipfixReverseOctetDeltaCount)
	if got := binary.BigEndian.Uint64(body[pktOff : pktOff+8]); got != revPkts {
		t.Errorf("wire reversePacketDeltaCount = %#x, want %#x", got, revPkts)
	}
	if got := binary.BigEndian.Uint64(body[octOff : octOff+8]); got != revBytes {
		t.Errorf("wire reverseOctetDeltaCount = %#x, want %#x", got, revBytes)
	}
}
