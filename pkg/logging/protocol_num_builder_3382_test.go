package logging

import (
	"net"
	"testing"
)

// rawProtoFrame builds a minimal POLICY_DENY raw event frame with the IP
// protocol byte at the wire offset (data[53], per the rawEvent layout asserted
// in binary_test.go) set to proto. It mirrors the other raw-frame helpers in
// this package (rawSessionFrame / rawPolicyDenyFrame).
func rawProtoFrame(proto byte) []byte {
	data := make([]byte, rawEventWireSize)
	data[40] = 0x30 // src port 12345
	data[41] = 0x39
	data[42] = 0x01 // dst port 443
	data[43] = 0xbb
	data[52] = eventTypePolicyDeny
	data[53] = proto
	data[55] = addrFamilyInet
	copy(data[8:12], net.ParseIP("203.0.113.7").To4())
	copy(data[24:28], net.ParseIP("8.8.8.8").To4())
	return data
}

// TestEventRecordProtocolNumPopulatedByBuilders pins the #3382 numeric-protocol
// builder contract. The MonitorPacketDrop matcher compares rec.ProtocolNum, but
// the matcher test injects a hand-built EventRecord and therefore does NOT
// exercise the two production builders. If `ProtocolNum: evt.Protocol` were
// dropped from either builder, the matcher test would stay green while the
// proto-41 bug silently returned. This test feeds a RAW event through BOTH
// builders and asserts ProtocolNum equals the raw protocol byte.
//
// Protocol 41 (IPv6-encap) is the load-bearing case: protoName(41)="IPV6" is
// NOT reversible (appid.ProtocolNumber("ipv6") is one-way), so carrying the raw
// number is the only correct source — re-deriving it from the rendered name is
// impossible. Protocol 6 (TCP) covers the reversible/named case.
//
// FAIL-ON-REVERT: removing `ProtocolNum: evt.Protocol` from either builder
// turns that builder's assertion RED.
func TestEventRecordProtocolNumPopulatedByBuilders(t *testing.T) {
	for _, proto := range []byte{41, 6} {
		// ProcessRawEvent (live ring path): record lands in the buffer.
		t.Run("ProcessRawEvent", func(t *testing.T) {
			er := NewEventReader(nil, NewEventBuffer(16))
			if ok := er.ProcessRawEvent(rawProtoFrame(proto)); !ok {
				t.Fatalf("ProcessRawEvent returned false")
			}
			recs := er.buffer.Latest(1)
			if len(recs) != 1 {
				t.Fatalf("buffer count = %d, want 1", len(recs))
			}
			if recs[0].ProtocolNum != proto {
				t.Errorf("ProcessRawEvent: ProtocolNum = %d, want %d (raw protocol byte)", recs[0].ProtocolNum, proto)
			}
		})

		// DecodeRawEventRecord (decode path): returns the record directly.
		t.Run("DecodeRawEventRecord", func(t *testing.T) {
			rec, ok := DecodeRawEventRecord(rawProtoFrame(proto))
			if !ok {
				t.Fatalf("DecodeRawEventRecord returned ok=false")
			}
			if rec.ProtocolNum != proto {
				t.Errorf("DecodeRawEventRecord: ProtocolNum = %d, want %d (raw protocol byte)", rec.ProtocolNum, proto)
			}
		})
	}
}
