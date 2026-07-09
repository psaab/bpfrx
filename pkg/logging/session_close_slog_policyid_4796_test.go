package logging

import (
	"bytes"
	"encoding/binary"
	"log/slog"
	"net"
	"strings"
	"testing"
)

// #4796 RED-on-revert: on a SESSION_CLOSE frame, evt.PolicyID is zeroed
// (ringbuf.go's logEvent -- #2853 repurposes the [44:48] slot for the
// created-subsec-nanos) and only rec.PolicyID is repopulated, from the
// trailing [136:140] admitting-policy slot (#3056). The slog "firewall
// event" line previously logged evt.PolicyID for a close, so it always
// recorded policy_id=0 -- even though the RT_FLOW_SESSION_CLOSE record and
// the resolved policy name both correctly used rec.PolicyID.
//
// captureInfoLogs redirects slog to a buffer at Info level for the test's
// lifetime and returns the buffer (mirrors captureWarnLogs in
// pkg/configstore/plaintext_downgrade_warn_4579_test.go).
func captureInfoLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})))
	t.Cleanup(func() { slog.SetDefault(old) })
	return &buf
}

// rawSessionCloseFrame builds a SESSION_CLOSE raw event frame carrying
// admittingPolicyID at the #3056 close-only offset ([136:140] LE u32), with
// the per-policy syslog gate ([135]) set so logEvent does not suppress the
// human-facing slog line.
func rawSessionCloseFrame(admittingPolicyID uint32) []byte {
	data := make([]byte, rawEventWireSize)
	data[40], data[41] = 0x30, 0x39 // src port
	data[42], data[43] = 0x01, 0xbb // dst port
	data[52] = eventTypeSessionClose
	data[53] = 6 // TCP
	data[55] = addrFamilyInet
	copy(data[8:12], net.ParseIP("10.0.1.5").To4())
	copy(data[24:28], net.ParseIP("10.0.2.7").To4())
	data[rawEventLogSyslogOffset] = 1 // #2508 per-policy gate: log this close
	binary.LittleEndian.PutUint32(data[rawEventPolicyCloseOffset:rawEventPolicyCloseOffset+4], admittingPolicyID)
	return data
}

func TestSessionCloseSlogLine_CarriesAdmittingPolicyID(t *testing.T) {
	buf := captureInfoLogs(t)

	reader := NewEventReader(nil, NewEventBuffer(16))
	if ok := reader.ProcessRawEvent(rawSessionCloseFrame(42)); !ok {
		t.Fatalf("ProcessRawEvent returned false")
	}

	out := buf.String()
	if !strings.Contains(out, "firewall event") {
		t.Fatalf("expected a \"firewall event\" slog line, got: %s", out)
	}
	if strings.Contains(out, "policy_id=0") {
		t.Fatalf("SESSION_CLOSE slog line logged policy_id=0 (evt.PolicyID was "+
			"zeroed for the #2853 created-subsec-nanos repurpose; want the "+
			"admitting policy from rec.PolicyID): %s", out)
	}
	if !strings.Contains(out, "policy_id=42") {
		t.Fatalf("SESSION_CLOSE slog line missing policy_id=42: %s", out)
	}
}
