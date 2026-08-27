package logging

import (
	"net"
	"testing"
	"time"
)

// filter_log_syslog_routing_6859_test.go — #6859.
//
// Junos routes the two filter-log actions to different sinks: `then log` writes
// the local filter-log buffer, `then syslog` sends to the system log. xpf fanned
// EVERY filter-log event out to every syslog client, so a term an operator wrote
// as `then log` specifically to keep hits on the box was shipped to whatever
// remote collector was configured.
//
// These cells assert the routing at the two places an operator can observe it:
// a REAL UDP listener standing in for the remote collector (did the packet leave
// the box?) and the event buffer that backs `show security log` (can the operator
// still see the hit?). Asserting the local half matters as much as the remote
// one — "stop sending to syslog" would be a bad trade if it also blinded the
// local surface, and that was the open question when the issue was filed.

// rawFilterLogFrame builds a FILTER_LOG wire frame carrying the (filter, term)
// identity the #6859 gate keys on. Offsets mirror the ringbuf parser:
// [52] event type, [55] address family, [56:60] rule/filter id, [60:64] term id.
func rawFilterLogFrame6859(filterID, termID uint32) []byte {
	data := make([]byte, rawEventWireSize)
	data[40], data[41] = 0x30, 0x39 // src port
	data[42], data[43] = 0x01, 0xbb // dst port
	data[52] = eventTypeFilterLog
	data[53] = 6 // TCP
	data[55] = addrFamilyInet
	copy(data[8:12], net.ParseIP("10.0.1.1").To4())
	copy(data[24:28], net.ParseIP("10.0.2.1").To4())
	data[56] = byte(filterID)
	data[57] = byte(filterID >> 8)
	data[58] = byte(filterID >> 16)
	data[59] = byte(filterID >> 24)
	data[60] = byte(termID)
	data[61] = byte(termID >> 8)
	data[62] = byte(termID >> 16)
	data[63] = byte(termID >> 24)
	data[rawEventLogSyslogOffset] = 1
	return data
}

// collectorReader6859 wires an EventReader to a real UDP socket standing in for
// a configured remote collector, plus the event buffer that backs
// `show security log`.
func collectorReader6859(t *testing.T) (*EventReader, *EventBuffer, net.PacketConn) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })

	addr := pc.LocalAddr().(*net.UDPAddr)
	client, err := NewSyslogClient("127.0.0.1", addr.Port)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })

	buffer := NewEventBuffer(16)
	reader := NewEventReader(nil, buffer)
	reader.SetSyslogClients([]*SyslogClient{client})
	return reader, buffer, pc
}

// collectorReceived6859 reports whether the collector got a datagram. The
// deadline is a WAIT bound, not a timing assertion: the send is synchronous on
// the ProcessRawEvent goroutine, so a packet that is coming has already been
// written by the time this runs.
func collectorReceived6859(t *testing.T, pc net.PacketConn) bool {
	t.Helper()
	if err := pc.SetReadDeadline(time.Now().Add(400 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4096)
	_, _, err := pc.ReadFrom(buf)
	if err == nil {
		return true
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return false
	}
	t.Fatalf("collector read failed for a reason other than timeout: %v", err)
	return false
}

// TestThenLogDoesNotReachTheCollector6859 is the issue: a `then log` term's hit
// must not leave the box.
func TestThenLogDoesNotReachTheCollector6859(t *testing.T) {
	reader, buffer, pc := collectorReader6859(t)
	// Filter 0 term 0 carries `then log` only — absent from the map.
	reader.SetFilterTermSyslog(map[uint64]bool{})

	if ok := reader.ProcessRawEvent(rawFilterLogFrame6859(0, 0)); !ok {
		t.Fatal("ProcessRawEvent returned false")
	}

	if collectorReceived6859(t, pc) {
		t.Fatal("a `then log` filter hit was forwarded to the configured syslog " +
			"collector — the operator asked to keep it on the box (#6859)")
	}

	// The local surface must be UNCHANGED. This is the half that makes the
	// subtractive change safe, and asserting the RENDERED record (not that a
	// call happened) is the point: a gate placed one step too early would
	// suppress this too and the remote assertion above could not tell.
	recs := buffer.Latest(16)
	if len(recs) != 1 {
		t.Fatalf("`show security log` shows %d records, want 1 — suppressing the "+
			"syslog fan-out must not blind the local surface (#6859)", len(recs))
	}
	if recs[0].Type != "FILTER_LOG" {
		t.Fatalf("local record Type = %q, want FILTER_LOG", recs[0].Type)
	}
}

// TestThenSyslogStillReachesTheCollector6859 is the PAIRED control. Without it,
// "do not forward filter-log events" is satisfied by a gate that suppresses
// every one of them — which would break `then syslog`, the spelling #6853/#7668
// shipped precisely so this routing could exist.
func TestThenSyslogStillReachesTheCollector6859(t *testing.T) {
	reader, _, pc := collectorReader6859(t)
	// Filter 0 term 1 carries `then syslog`.
	reader.SetFilterTermSyslog(map[uint64]bool{FilterTermSyslogKey(0, 1): true})

	if ok := reader.ProcessRawEvent(rawFilterLogFrame6859(0, 1)); !ok {
		t.Fatal("ProcessRawEvent returned false")
	}

	if !collectorReceived6859(t, pc) {
		t.Fatal("a `then syslog` filter hit did NOT reach the configured collector — " +
			"the #6859 gate is suppressing the spelling that is supposed to go " +
			"off-box")
	}
}

// TestFilterTermIdentityDiscriminatesRouting6859 proves the gate keys on the
// TERM, not on some property shared by every filter-log event.
//
// Both events below are identical except for the term id, and they are driven
// through ONE reader with ONE map — so a gate that ignored the identity and
// answered the same way for both cannot pass. Without this cell, the two above
// are each satisfied by a constant.
func TestFilterTermIdentityDiscriminatesRouting6859(t *testing.T) {
	reader, _, pc := collectorReader6859(t)
	reader.SetFilterTermSyslog(map[uint64]bool{FilterTermSyslogKey(3, 7): true})

	if ok := reader.ProcessRawEvent(rawFilterLogFrame6859(3, 6)); !ok {
		t.Fatal("ProcessRawEvent returned false")
	}
	if collectorReceived6859(t, pc) {
		t.Fatal("term 6 (log-only) reached the collector while term 7 is the only " +
			"syslog term — the gate is not discriminating on term identity")
	}

	if ok := reader.ProcessRawEvent(rawFilterLogFrame6859(3, 7)); !ok {
		t.Fatal("ProcessRawEvent returned false")
	}
	if !collectorReceived6859(t, pc) {
		t.Fatal("term 7 (`then syslog`) did not reach the collector — the gate is " +
			"suppressing on something other than term identity")
	}
}

// TestUnwiredMapPreservesLegacyFanout6859 pins the nil-vs-empty contract.
//
// nil means "no apply has wired this yet" and MUST keep the pre-#6859 fan-out,
// so a path that never wires the map cannot silently suppress `then syslog` as
// well. An empty NON-nil map is the opposite instruction and is covered by the
// first cell above. Collapsing the two would make the whole feature depend on a
// wiring call whose absence nothing would report.
func TestUnwiredMapPreservesLegacyFanout6859(t *testing.T) {
	reader, _, pc := collectorReader6859(t)
	// Deliberately NOT calling SetFilterTermSyslog.

	if ok := reader.ProcessRawEvent(rawFilterLogFrame6859(0, 0)); !ok {
		t.Fatal("ProcessRawEvent returned false")
	}
	if !collectorReceived6859(t, pc) {
		t.Fatal("with no map wired, the filter-log fan-out must be unchanged from " +
			"pre-#6859 — nil is 'not wired', not 'suppress everything'")
	}
}

// TestNonFilterEventsAreNotGated6859 bounds the blast radius: the gate is
// FILTER_LOG-only. A session/policy/screen event has no per-term spelling to
// honour, and suppressing those would be a logging outage dressed as a parity
// fix.
func TestNonFilterEventsAreNotGated6859(t *testing.T) {
	reader, _, pc := collectorReader6859(t)
	// An empty map: every FILTER_LOG would be suppressed.
	reader.SetFilterTermSyslog(map[uint64]bool{})

	if ok := reader.ProcessRawEvent(rawSessionFrame(eventTypeSessionClose, 1)); !ok {
		t.Fatal("ProcessRawEvent returned false")
	}
	if !collectorReceived6859(t, pc) {
		t.Fatal("a SESSION_CLOSE was suppressed by the #6859 filter-log gate — the " +
			"gate must apply to FILTER_LOG only")
	}
}
