package logging

import (
	"encoding/binary"
	"net"
	"testing"
)

// extendedSessionFrame builds a #4915 EXTENDED (160-byte) RT_FLOW session frame
// (SESSION_CREATE or SESSION_CLOSE) carrying `sessionID` at the additive
// [152:160] slot, plus a minimal valid 5-tuple and the per-policy SYSLOG gate
// byte set (offset 135) so the live logEvent path buffers the record. Slice the
// return to rawEventExtSize (152) or rawEventWireSize (144) to model a legacy
// pre-#4915 helper frame that never carried the session-id slot.
func extendedSessionFrame(eventType uint8, sessionID uint64) []byte {
	data := make([]byte, rawEventSessionIDSize) // 160
	data[52] = eventType
	data[53] = 6 // TCP
	data[55] = addrFamilyInet
	binary.BigEndian.PutUint16(data[40:42], 12345) // src port
	binary.BigEndian.PutUint16(data[42:44], 443)   // dst port
	copy(data[8:12], net.ParseIP("10.0.1.102").To4())
	copy(data[24:28], net.ParseIP("172.16.80.200").To4())
	data[rawEventLogSyslogOffset] = 1 // per-policy SYSLOG gate open
	binary.LittleEndian.PutUint64(
		data[rawEventSessionIDOffset:rawEventSessionIDOffset+8], sessionID)
	return data
}

// TestDecodeRawEventCarriesSessionID is the #4915 fail-on-revert pin: a 160-byte
// SESSION_CREATE / SESSION_CLOSE frame must decode the dataplane's stable session
// id from the additive [152:160] slot into EventRecord.SessionID. Reverting the
// ringbuf read (or the Rust encoder write) leaves SessionID 0 and flips this RED.
func TestDecodeRawEventCarriesSessionID(t *testing.T) {
	const sid = uint64(0xA1B2C3D4E5F60708)
	for _, et := range []struct {
		name string
		typ  uint8
	}{
		{"SESSION_CLOSE", eventTypeSessionClose},
		{"SESSION_OPEN", eventTypeSessionOpen},
	} {
		t.Run(et.name, func(t *testing.T) {
			rec, ok := DecodeRawEventRecord(extendedSessionFrame(et.typ, sid))
			if !ok {
				t.Fatalf("DecodeRawEventRecord rejected a valid 160-byte %s frame", et.name)
			}
			if rec.SessionID != sid {
				t.Fatalf("rec.SessionID = %#x, want %#x ([152:160] read reverted)",
					rec.SessionID, sid)
			}
		})
	}
}

// TestDecodeRawEventLegacyFrameSessionIDAbsent is the #4915 both-sides-length
// back-compat pin: a short legacy session frame from a pre-#4915 helper (152 or
// 144 bytes) must still decode — the minimum acceptance stays at rawEventWireSize
// (144) — and leave SessionID at the 0 "unknown" default rather than crash
// reading past the buffer. This proves the new-daemon/old-helper rolling-upgrade
// direction is safe.
func TestDecodeRawEventLegacyFrameSessionIDAbsent(t *testing.T) {
	full := extendedSessionFrame(eventTypeSessionClose, 0xDEADBEEFCAFEF00D)
	for _, sz := range []int{rawEventExtSize, rawEventWireSize} { // 152, 144
		legacy := full[:sz]
		rec, ok := DecodeRawEventRecord(legacy)
		if !ok {
			t.Fatalf("DecodeRawEventRecord rejected a legacy %d-byte SESSION_CLOSE frame", sz)
		}
		if rec.SessionID != 0 {
			t.Fatalf("legacy %d-byte frame must leave SessionID 0 (absent), got %#x",
				sz, rec.SessionID)
		}
	}
}

// TestLiveEventSessionIDAndEventSeq pins the live logEvent (ProcessRawEvent)
// path: a 160-byte session frame surfaces the REAL wire SessionID while EventSeq
// carries the per-event ordinal (distinct from the id); a legacy (<160) frame
// falls SessionID back to that ordinal, byte-identical to pre-#4915, so the
// change is strictly additive — nothing observable moves until a new helper
// emits a 160-byte frame.
func TestLiveEventSessionIDAndEventSeq(t *testing.T) {
	buffer := NewEventBuffer(16)
	reader := NewEventReader(nil, buffer)

	const sid = uint64(0x0102030405060708)
	if !reader.ProcessRawEvent(extendedSessionFrame(eventTypeSessionClose, sid)) {
		t.Fatal("ProcessRawEvent(160-byte close) returned false")
	}
	recs := buffer.Latest(16)
	if len(recs) != 1 {
		t.Fatalf("want 1 buffered record, got %d", len(recs))
	}
	if recs[0].SessionID != sid {
		t.Fatalf("live SessionID = %#x, want the real wire id %#x", recs[0].SessionID, sid)
	}
	if recs[0].EventSeq == 0 {
		t.Fatal("EventSeq must be a non-zero per-event ordinal")
	}
	if recs[0].SessionID == recs[0].EventSeq {
		t.Fatal("a real 160-byte session frame's SessionID must be the wire id, not the ordinal")
	}

	// A legacy short frame (no [152:160] slot) falls SessionID back to the
	// per-event ordinal — the exact pre-#4915 behavior.
	legacy := extendedSessionFrame(eventTypeSessionClose, 0)[:rawEventExtSize]
	if !reader.ProcessRawEvent(legacy) {
		t.Fatal("ProcessRawEvent(legacy 152-byte close) returned false")
	}
	// Latest returns newest-first, so the just-processed legacy frame is recs[0].
	last := buffer.Latest(16)[0]
	if last.SessionID == 0 || last.SessionID != last.EventSeq {
		t.Fatalf("legacy frame SessionID must fall back to the ordinal: SessionID=%d EventSeq=%d",
			last.SessionID, last.EventSeq)
	}
}
