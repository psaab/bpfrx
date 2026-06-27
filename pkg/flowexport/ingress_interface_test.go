package flowexport

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/logging"
)

// #2749 fail-on-revert pins: ingressInterface (NetFlow IE 10 / IPFIX
// ingressInterface, an SNMP ifIndex) is re-introduced with a REAL value — the
// ingress ifindex carried on the SESSION_CLOSE wire frame since #2615. These
// tests assert the IE is advertised in the templates AND that the encoded
// record carries the session's ingress ifindex (not zero). Reverting the
// template field, the encoder write, or the SessionCloseData->FlowRecord
// plumbing flips any of them RED.
//
// #2749 also re-introduces SrcTos (5) / TCPFlags (6) / OutputSNMP (14) with
// real values — pinned by cos_fields_test.go. Only flowDirection (61) remains
// absent (no per-flow direction source yet); that absence is pinned by
// dropped_fields_test.go.

const testIngressIfindex uint32 = 0xDEADBEEF

// closeRecordWithIfindex builds a SESSION_CLOSE EventRecord + SessionCloseData
// pair carrying a known non-zero ingress ifindex, matching what the daemon
// flow-export callbacks construct.
func closeRecordWithIfindex(v6 bool) (logging.EventRecord, SessionCloseData) {
	rec := logging.EventRecord{
		Type:           "SESSION_CLOSE",
		Time:           time.Unix(1_700_000_100, 0),
		Created:        1_700_000_000,
		SessionPkts:    0x1122334455667788,
		SessionBytes:   0x99AABBCCDDEEFF00,
		IngressIfindex: testIngressIfindex,
	}
	sd := SessionCloseData{
		SrcPort:  40000,
		DstPort:  80,
		Protocol: 6,
		IsIPv6:   v6,
		// #2749: the daemon callback copies rec.IngressIfindex here.
		InIf: rec.IngressIfindex,
	}
	if v6 {
		sd.SrcIP = net.ParseIP("fd00::1")
		sd.DstIP = net.ParseIP("2001:db8::200")
	} else {
		sd.SrcIP = net.IPv4(10, 0, 1, 100)
		sd.DstIP = net.IPv4(172, 16, 80, 200)
	}
	return rec, sd
}

func netflowTemplateHasIE(fields []templateField, ie uint16) bool {
	for _, f := range fields {
		if f.fieldType == ie {
			return true
		}
	}
	return false
}

func ipfixTemplateHasIE(fields []ipfixField, ie uint16) bool {
	for _, f := range fields {
		if f.elementID == ie {
			return true
		}
	}
	return false
}

// netflowFieldBodyOffset returns the byte offset of the named IE within the
// record body, walking the template in order (the encoder writes fields in
// the same order).
func netflowFieldBodyOffset(fields []templateField, ie uint16) (int, bool) {
	off := 0
	for _, f := range fields {
		if f.fieldType == ie {
			return off, true
		}
		off += int(f.fieldLen)
	}
	return 0, false
}

func ipfixFieldBodyOffset(fields []ipfixField, ie uint16) (int, bool) {
	off := 0
	for _, f := range fields {
		if f.elementID == ie {
			return off, true
		}
		off += int(f.length)
	}
	return 0, false
}

// TestNetflowIngressInterfacePopulated asserts IE 10 is advertised and the
// encoded v9 record carries the real ingress ifindex at the IE's offset.
func TestNetflowIngressInterfacePopulated(t *testing.T) {
	boot := time.Unix(1_700_000_000, 0)
	opts := DefaultV9TemplateOptions()
	for _, tc := range []struct {
		name   string
		v6     bool
		fields []templateField
	}{
		{"v4", false, netflowTemplateFieldsV4},
		{"v6", true, netflowTemplateFieldsV6},
	} {
		ifOff, ok := netflowFieldBodyOffset(tc.fields, fieldInputSNMP)
		if !ok {
			t.Fatalf("%s: template missing ingressInterface (IE 10)", tc.name)
		}

		var e Exporter
		rec, sd := closeRecordWithIfindex(tc.v6)
		e.ExportSessionClose(rec, sd)
		v4recs, v6recs := e.batch.drain()
		recs := v4recs
		if tc.v6 {
			recs = v6recs
		}
		if len(recs) != 1 {
			t.Fatalf("%s: drained %d records, want 1", tc.name, len(recs))
		}
		if recs[0].InIf != testIngressIfindex {
			t.Fatalf("%s: FlowRecord.InIf = 0x%08x, want 0x%08x (population reverted)",
				tc.name, recs[0].InIf, testIngressIfindex)
		}

		fs := encodeDataFlowSet(recs, boot, opts)
		// 4-byte set header precedes the record body.
		got := binary.BigEndian.Uint32(fs[4+ifOff : 4+ifOff+4])
		if got != testIngressIfindex {
			t.Fatalf("%s: encoded ingressInterface = 0x%08x, want 0x%08x (encoder write reverted)",
				tc.name, got, testIngressIfindex)
		}
	}
}

// TestIPFIXIngressInterfacePopulated mirrors the check for IPFIX.
func TestIPFIXIngressInterfacePopulated(t *testing.T) {
	for _, tc := range []struct {
		name   string
		v6     bool
		fields []ipfixField
	}{
		{"v4", false, ipfixTemplateV4},
		{"v6", true, ipfixTemplateV6},
	} {
		ifOff, ok := ipfixFieldBodyOffset(tc.fields, ipfixIngressInterface)
		if !ok {
			t.Fatalf("%s: template missing ingressInterface (IE 10)", tc.name)
		}

		var e IPFIXExporter
		rec, sd := closeRecordWithIfindex(tc.v6)
		e.ExportSessionClose(rec, sd)
		v4recs, v6recs := e.batch.drain()
		recs := v4recs
		if tc.v6 {
			recs = v6recs
		}
		if len(recs) != 1 {
			t.Fatalf("%s: drained %d records, want 1", tc.name, len(recs))
		}
		if recs[0].InIf != testIngressIfindex {
			t.Fatalf("%s: FlowRecord.InIf = 0x%08x, want 0x%08x (population reverted)",
				tc.name, recs[0].InIf, testIngressIfindex)
		}

		ds := encodeIPFIXDataSet(recs)
		got := binary.BigEndian.Uint32(ds[4+ifOff : 4+ifOff+4])
		if got != testIngressIfindex {
			t.Fatalf("%s: encoded ingressInterface = 0x%08x, want 0x%08x (encoder write reverted)",
				tc.name, got, testIngressIfindex)
		}
	}
}
