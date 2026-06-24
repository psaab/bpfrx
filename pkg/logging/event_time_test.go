package logging

import (
	"encoding/binary"
	"testing"
	"time"
)

// #2511: the live raw-event logging path (ProcessRawEvent -> logEvent) must
// honor the on-wire decision-time stamp (absolute Unix NANOSECONDS, emitted by
// the userspace-dp producer per #2465/#2470) instead of always recording the
// receive time (time.Now()). DecodeRawEventRecord already did this; logEvent
// did not, so even after #2470 the production logging path recorded RECEIVE
// time. These are fail-on-revert tests: with the eventTimeFromWire guard
// removed from logEvent (rec.Time back to time.Now()), the nonzero-timestamp
// assertion below fails.

// rawTimedFrame builds a minimal valid raw event frame carrying the supplied
// wire timestamp in the first 8 bytes (little-endian, the producer format).
func rawTimedFrame(eventType uint8, wireTS uint64) []byte {
	data := make([]byte, rawEventWireSize)
	binary.LittleEndian.PutUint64(data[0:8], wireTS)
	data[40] = 0x30 // src port 12345
	data[41] = 0x39
	data[42] = 0x01 // dst port 443
	data[43] = 0xbb
	data[52] = eventType
	data[53] = 6 // TCP
	data[55] = addrFamilyInet
	return data
}

// captureTime feeds one frame through ProcessRawEvent (-> logEvent) and returns
// the EventRecord.Time observed by a registered callback.
func captureTime(t *testing.T, frame []byte) time.Time {
	t.Helper()
	reader := NewEventReader(nil, NewEventBuffer(16))
	var got time.Time
	var fired bool
	reader.AddCallback(func(rec EventRecord, raw []byte) {
		got = rec.Time
		fired = true
	})
	if ok := reader.ProcessRawEvent(frame); !ok {
		t.Fatalf("ProcessRawEvent returned false")
	}
	if !fired {
		t.Fatalf("callback never fired")
	}
	return got
}

func TestLogEvent_HonorsWireTimestamp(t *testing.T) {
	// A specific decision time well in the past so it can never collide with
	// time.Now(): 2021-01-02T03:04:05.000000006Z.
	want := time.Date(2021, 1, 2, 3, 4, 5, 6, time.UTC)
	wireTS := uint64(want.UnixNano())

	got := captureTime(t, rawTimedFrame(eventTypeSessionOpen, wireTS))

	if !got.Equal(want) {
		t.Fatalf("logEvent recorded Time = %v, want wire decision time %v "+
			"(live path must apply nonzero on-wire nanosecond timestamp, #2511)",
			got.UTC(), want)
	}
}

func TestLogEvent_ZeroTimestampFallsBackToNow(t *testing.T) {
	before := time.Now()
	got := captureTime(t, rawTimedFrame(eventTypeSessionOpen, 0))
	after := time.Now()

	if got.Before(before) || got.After(after) {
		t.Fatalf("zero wire timestamp: Time = %v, want a recent time in "+
			"[%v, %v] (fallback to time.Now())", got, before, after)
	}
}

func TestLogEvent_OverflowTimestampFallsBackToNow(t *testing.T) {
	// A timestamp > math.MaxInt64 must not be passed to time.Unix(0, int64(.))
	// (it would wrap negative). The guard rejects it and falls back to now.
	before := time.Now()
	got := captureTime(t, rawTimedFrame(eventTypeSessionOpen, uint64(1<<63)))
	after := time.Now()

	if got.Before(before) || got.After(after) {
		t.Fatalf("overflow wire timestamp: Time = %v, want a recent time in "+
			"[%v, %v] (guard must reject > MaxInt64)", got, before, after)
	}
}

// TestLogEvent_DecodeParity asserts both paths agree on the recorded time for
// the same frame — the shared eventTimeFromWire SSOT (#2511).
func TestLogEvent_DecodeParity(t *testing.T) {
	want := time.Date(2022, 6, 1, 12, 0, 0, 123456789, time.UTC)
	frame := rawTimedFrame(eventTypeSessionOpen, uint64(want.UnixNano()))

	live := captureTime(t, frame)

	rec, ok := DecodeRawEventRecord(frame)
	if !ok {
		t.Fatalf("DecodeRawEventRecord returned false")
	}
	if !live.Equal(rec.Time) {
		t.Fatalf("live logEvent Time %v != DecodeRawEventRecord Time %v "+
			"(both must use the shared wire-timestamp guard)", live.UTC(), rec.Time.UTC())
	}
	if !live.Equal(want) {
		t.Fatalf("recorded Time %v != wire decision time %v", live.UTC(), want)
	}
}
