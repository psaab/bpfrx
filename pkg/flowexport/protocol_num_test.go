package flowexport

import (
	"net"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/logging"
)

// #3939 fail-on-revert pins: the exported protocolIdentifier (NetFlow v9 IE 4 /
// IPFIX IE 4) must come from the record's raw numeric IP protocol
// (rec.ProtocolNum, 0-255), NOT from the daemon callback's protocol-NAME
// lookup. The old parseProtocol() name table covered only TCP/UDP/ICMP/ICMPv6,
// so GRE (47), ESP (50), AH (51) and every other protocol exported as 0 and
// were misattributed at the collector.
//
// These tests deliberately set the pre-#3939 lossy value (SessionCloseData.
// Protocol = 0, exactly what parseProtocol returned for GRE/ESP/AH) on the
// SessionCloseData while carrying the real number on rec.ProtocolNum. A correct
// exporter ignores the lossy sd.Protocol and encodes rec.ProtocolNum. Reverting
// the exporter to `Protocol: evt.Protocol` makes EVERY case encode 0 → RED.

// protocolNumCases covers the tunnel/other protocols that regressed to 0 plus
// the TCP/UDP/ICMP names that always resolved, proving both keep the right
// number.
var protocolNumCases = []struct {
	name  string
	proto uint8
}{
	{"ICMP", 1},
	{"TCP", 6},
	{"UDP", 17},
	{"GRE", 47},
	{"ESP", 50},
	{"AH", 51},
}

// closeRecordForProto builds a SESSION_CLOSE EventRecord carrying the real
// numeric protocol on rec.ProtocolNum, paired with a SessionCloseData whose
// Protocol field holds the pre-#3939 lossy 0. Reverting the fix makes the
// exporter read the lossy 0 instead of the record's number.
func closeRecordForProto(proto uint8, v6 bool) (logging.EventRecord, SessionCloseData) {
	rec := logging.EventRecord{
		Type:        "SESSION_CLOSE",
		Time:        time.Unix(1_700_000_100, 0),
		Created:     1_700_000_000,
		ProtocolNum: proto, // authoritative numeric protocol the dataplane stamped
	}
	sd := SessionCloseData{
		SrcPort:  40000,
		DstPort:  80,
		Protocol: 0, // pre-#3939 lossy value (parseProtocol dropped GRE/ESP/AH to 0)
		IsIPv6:   v6,
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

// TestNetflowProtocolIdentifierFromProtocolNum asserts the encoded NetFlow v9
// protocolIdentifier (IE 4) equals rec.ProtocolNum for every protocol,
// including GRE/ESP/AH which regressed to 0 under the name lookup (#3939).
func TestNetflowProtocolIdentifierFromProtocolNum(t *testing.T) {
	boot := time.Unix(1_700_000_000, 0)
	opts := DefaultV9TemplateOptions()
	for _, fam := range []struct {
		label  string
		v6     bool
		fields []templateField
	}{
		{"v4", false, netflowTemplateFieldsV4},
		{"v6", true, netflowTemplateFieldsV6},
	} {
		protoOff, ok := netflowFieldBodyOffset(fam.fields, fieldProtocol)
		if !ok {
			t.Fatalf("%s: template missing protocolIdentifier (IE 4)", fam.label)
		}
		for _, tc := range protocolNumCases {
			var e Exporter
			rec, sd := closeRecordForProto(tc.proto, fam.v6)
			e.ExportSessionClose(rec, sd)
			v4recs, v6recs := e.batch.drain()
			recs := v4recs
			if fam.v6 {
				recs = v6recs
			}
			if len(recs) != 1 {
				t.Fatalf("%s/%s: drained %d records, want 1", fam.label, tc.name, len(recs))
			}
			if recs[0].Protocol != tc.proto {
				t.Fatalf("%s/%s: FlowRecord.Protocol = %d, want %d (exporter must source rec.ProtocolNum)",
					fam.label, tc.name, recs[0].Protocol, tc.proto)
			}
			fs := encodeDataFlowSet(recs, boot, opts)
			if got := fs[4+protoOff]; got != tc.proto {
				t.Fatalf("%s/%s: encoded protocolIdentifier = %d, want %d "+
					"(#3939: name-lookup drops GRE/ESP/AH to 0)", fam.label, tc.name, got, tc.proto)
			}
		}
	}
}

// TestIPFIXProtocolIdentifierFromProtocolNum mirrors the check for IPFIX
// (protocolIdentifier IE 4, 1 byte).
func TestIPFIXProtocolIdentifierFromProtocolNum(t *testing.T) {
	for _, fam := range []struct {
		label  string
		v6     bool
		fields []ipfixField
	}{
		{"v4", false, ipfixTemplateV4},
		{"v6", true, ipfixTemplateV6},
	} {
		protoOff, ok := ipfixFieldBodyOffset(fam.fields, ipfixProtocolIdentifier)
		if !ok {
			t.Fatalf("%s: template missing protocolIdentifier (IE 4)", fam.label)
		}
		for _, tc := range protocolNumCases {
			var e IPFIXExporter
			rec, sd := closeRecordForProto(tc.proto, fam.v6)
			e.ExportSessionClose(rec, sd)
			v4recs, v6recs := e.batch.drain()
			recs := v4recs
			if fam.v6 {
				recs = v6recs
			}
			if len(recs) != 1 {
				t.Fatalf("%s/%s: drained %d records, want 1", fam.label, tc.name, len(recs))
			}
			if recs[0].Protocol != tc.proto {
				t.Fatalf("%s/%s: FlowRecord.Protocol = %d, want %d (exporter must source rec.ProtocolNum)",
					fam.label, tc.name, recs[0].Protocol, tc.proto)
			}
			ds := encodeIPFIXDataSet(recs)
			if got := ds[4+protoOff]; got != tc.proto {
				t.Fatalf("%s/%s: encoded protocolIdentifier = %d, want %d "+
					"(#3939: name-lookup drops GRE/ESP/AH to 0)", fam.label, tc.name, got, tc.proto)
			}
		}
	}
}
