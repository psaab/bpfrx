package flowexport

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/logging"
)

// #2749 fail-on-revert pins: the class-of-service / egress-interface fields the
// SESSION_CLOSE wire frame's extended [144:152] block now carries are
// re-introduced with REAL values — NetFlow v9 srcTos (IE 5) / tcpFlags (IE 6) /
// OutputSNMP (IE 14) and the IPFIX ipClassOfService / tcpControlBits /
// egressInterface. These tests assert the IEs are advertised AND that the
// encoded record carries the session's real ToS / TCP flags / egress ifindex
// (not zero). Reverting the template field, the encoder write, or the
// SessionCloseData->FlowRecord plumbing flips any of them RED. flowDirection
// (IE 61) stays absent (pinned by dropped_fields_test.go).

const (
	testCosTOS      uint8  = 0xB8 // DSCP EF (46) << 2
	testCosTCPFlags uint8  = 0x13 // SYN|FIN|ACK
	testCosEgressIf uint32 = 0xFEEDFACE
)

// closeRecordWithCos builds a SESSION_CLOSE EventRecord + SessionCloseData pair
// carrying known non-zero ToS / TCP flags / egress ifindex, matching what the
// daemon flow-export callbacks construct from the extended close frame.
func closeRecordWithCos(v6 bool) (logging.EventRecord, SessionCloseData) {
	rec := logging.EventRecord{
		Type:           "SESSION_CLOSE",
		Time:           time.Unix(1_700_000_100, 0),
		Created:        1_700_000_000,
		SessionPkts:    0x1122334455667788,
		SessionBytes:   0x99AABBCCDDEEFF00,
		TOS:            testCosTOS,
		TCPControlBits: testCosTCPFlags,
		EgressIfindex:  testCosEgressIf,
	}
	sd := SessionCloseData{
		SrcPort:  40000,
		DstPort:  80,
		Protocol: 6,
		IsIPv6:   v6,
		// The daemon callback copies these off the EventRecord.
		TOS:      rec.TOS,
		TCPFlags: rec.TCPControlBits,
		OutIf:    rec.EgressIfindex,
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

// TestNetflowCosFieldsPopulated asserts IE 5/6/14 are advertised and the
// encoded v9 record carries the real ToS / TCP flags / egress ifindex.
func TestNetflowCosFieldsPopulated(t *testing.T) {
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
		tosOff, ok1 := netflowFieldBodyOffset(tc.fields, fieldSrcTos)
		flagsOff, ok2 := netflowFieldBodyOffset(tc.fields, fieldTCPFlags)
		egrOff, ok3 := netflowFieldBodyOffset(tc.fields, fieldOutputSNMP)
		if !ok1 || !ok2 || !ok3 {
			t.Fatalf("%s: template missing one of SrcTos(5)/TCPFlags(6)/OutputSNMP(14)", tc.name)
		}

		var e Exporter
		rec, sd := closeRecordWithCos(tc.v6)
		e.ExportSessionClose(rec, sd)
		v4recs, v6recs := e.batch.drain()
		recs := v4recs
		if tc.v6 {
			recs = v6recs
		}
		if len(recs) != 1 {
			t.Fatalf("%s: drained %d records, want 1", tc.name, len(recs))
		}
		if recs[0].TOS != testCosTOS || recs[0].TCPFlags != testCosTCPFlags || recs[0].OutIf != testCosEgressIf {
			t.Fatalf("%s: FlowRecord CoS = {TOS:0x%02x TCPFlags:0x%02x OutIf:0x%08x}, want {0x%02x 0x%02x 0x%08x} (population reverted)",
				tc.name, recs[0].TOS, recs[0].TCPFlags, recs[0].OutIf, testCosTOS, testCosTCPFlags, testCosEgressIf)
		}

		fs := encodeDataFlowSet(recs, boot, opts)
		if got := fs[4+tosOff]; got != testCosTOS {
			t.Fatalf("%s: encoded srcTos = 0x%02x, want 0x%02x (encoder write reverted)", tc.name, got, testCosTOS)
		}
		if got := fs[4+flagsOff]; got != testCosTCPFlags {
			t.Fatalf("%s: encoded tcpFlags = 0x%02x, want 0x%02x (encoder write reverted)", tc.name, got, testCosTCPFlags)
		}
		if got := binary.BigEndian.Uint32(fs[4+egrOff : 4+egrOff+4]); got != testCosEgressIf {
			t.Fatalf("%s: encoded OutputSNMP = 0x%08x, want 0x%08x (encoder write reverted)", tc.name, got, testCosEgressIf)
		}
	}
}

// TestIPFIXCosFieldsPopulated mirrors the check for IPFIX (tcpControlBits is a
// 2-byte unsigned16 IE there).
func TestIPFIXCosFieldsPopulated(t *testing.T) {
	for _, tc := range []struct {
		name   string
		v6     bool
		fields []ipfixField
	}{
		{"v4", false, ipfixTemplateV4},
		{"v6", true, ipfixTemplateV6},
	} {
		tosOff, ok1 := ipfixFieldBodyOffset(tc.fields, ipfixIPClassOfService)
		flagsOff, ok2 := ipfixFieldBodyOffset(tc.fields, ipfixTCPControlBits)
		egrOff, ok3 := ipfixFieldBodyOffset(tc.fields, ipfixEgressInterface)
		if !ok1 || !ok2 || !ok3 {
			t.Fatalf("%s: template missing one of ipClassOfService(5)/tcpControlBits(6)/egressInterface(14)", tc.name)
		}

		var e IPFIXExporter
		rec, sd := closeRecordWithCos(tc.v6)
		e.ExportSessionClose(rec, sd)
		v4recs, v6recs := e.batch.drain()
		recs := v4recs
		if tc.v6 {
			recs = v6recs
		}
		if len(recs) != 1 {
			t.Fatalf("%s: drained %d records, want 1", tc.name, len(recs))
		}
		if recs[0].TOS != testCosTOS || recs[0].TCPFlags != testCosTCPFlags || recs[0].OutIf != testCosEgressIf {
			t.Fatalf("%s: FlowRecord CoS population reverted", tc.name)
		}

		ds := encodeIPFIXDataSet(recs)
		if got := ds[4+tosOff]; got != testCosTOS {
			t.Fatalf("%s: encoded ipClassOfService = 0x%02x, want 0x%02x", tc.name, got, testCosTOS)
		}
		// tcpControlBits is unsigned16: low byte carries the u8 flag value.
		if got := binary.BigEndian.Uint16(ds[4+flagsOff : 4+flagsOff+2]); got != uint16(testCosTCPFlags) {
			t.Fatalf("%s: encoded tcpControlBits = 0x%04x, want 0x%04x", tc.name, got, uint16(testCosTCPFlags))
		}
		if got := binary.BigEndian.Uint32(ds[4+egrOff : 4+egrOff+4]); got != testCosEgressIf {
			t.Fatalf("%s: encoded egressInterface = 0x%08x, want 0x%08x", tc.name, got, testCosEgressIf)
		}
	}
}
