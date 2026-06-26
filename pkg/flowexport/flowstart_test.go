package flowexport

import (
	"net"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/logging"
)

// #2465: flowStartTime must use the real session-creation timestamp
// (rec.Created, absolute Unix seconds) as the flow StartTime, falling back to
// the packet-count heuristic only when the timestamp is absent (0).
func TestFlowStartTimeUsesRealCreated(t *testing.T) {
	end := time.Unix(1_700_000_300, 0) // close time
	created := uint32(1_700_000_000)   // 300s earlier

	rec := logging.EventRecord{
		Time:        end,
		Created:     created,
		SessionPkts: 9, // a packet count the heuristic would mis-time
		Protocol:    "TCP",
	}

	start, usedEstimate := flowStartTime(rec, 6)
	if usedEstimate {
		t.Fatal("a real created timestamp must NOT use the estimate")
	}
	if !start.Equal(time.Unix(int64(created), 0)) {
		t.Fatalf("StartTime = %v, want %v (the real created stamp)", start, time.Unix(int64(created), 0))
	}
	// The heuristic for 9 TCP packets would have been 900ms — far from the
	// real 300s age. Prove the real path is not the estimate.
	estimateStart := end.Add(-estimateSessionDuration(9, 6))
	if start.Equal(estimateStart) {
		t.Fatalf("StartTime must not equal the packet-count estimate %v", estimateStart)
	}
}

// #2465 fallback: when the close event carries no creation timestamp (0), the
// StartTime falls back to the packet-count heuristic and the bool reports it.
func TestFlowStartTimeFallsBackToEstimate(t *testing.T) {
	end := time.Unix(1_700_000_300, 0)
	rec := logging.EventRecord{
		Time:        end,
		Created:     0, // unknown
		SessionPkts: 9,
		Protocol:    "TCP",
	}
	start, usedEstimate := flowStartTime(rec, 6)
	if !usedEstimate {
		t.Fatal("a zero created timestamp must use the estimate")
	}
	want := end.Add(-estimateSessionDuration(9, 6))
	if !start.Equal(want) {
		t.Fatalf("StartTime = %v, want estimate %v", start, want)
	}
}

// #2465: a created stamp at or after the close time (clock skew) clamps to the
// EndTime so the flow never reports a negative duration.
func TestFlowStartTimeClampsFutureCreated(t *testing.T) {
	end := time.Unix(1_700_000_000, 0)
	rec := logging.EventRecord{
		Time:    end,
		Created: 1_700_000_500, // 500s AFTER the close — impossible, clamp
	}
	start, usedEstimate := flowStartTime(rec, 6)
	if usedEstimate {
		t.Fatal("a non-zero (even if skewed) created must not use the estimate")
	}
	if !start.Equal(end) {
		t.Fatalf("StartTime = %v, want clamp to EndTime %v", start, end)
	}
}

// #2465 fail-on-revert (NetFlow v9): a session-close event with a real created
// timestamp must produce a flow record whose StartTime is that timestamp, NOT
// the packet-count heuristic, and must NOT bump the estimated-duration counter.
// Reverting ExportSessionClose to `rec.Time.Add(-estimateSessionDuration(...))`
// makes the StartTime assertion fail.
func TestNetFlowExportSessionCloseUsesRealCreated(t *testing.T) {
	e, err := NewExporter(&ExportConfig{})
	if err != nil {
		t.Fatalf("NewExporter: %v", err)
	}
	end := time.Unix(1_700_000_600, 0)
	created := uint32(1_700_000_000)
	rec := logging.EventRecord{
		Time:        end,
		Type:        "SESSION_CLOSE",
		Created:     created,
		SessionPkts: 4,
		Protocol:    "TCP",
	}
	evt := SessionCloseData{
		SrcIP:    net.ParseIP("10.0.1.102"),
		DstIP:    net.ParseIP("172.16.80.200"),
		SrcPort:  12345,
		DstPort:  443,
		Protocol: 6,
	}
	e.ExportSessionClose(rec, evt)

	v4, _ := e.batch.drain()
	if len(v4) != 1 {
		t.Fatalf("expected 1 batched flow, got %d", len(v4))
	}
	if !v4[0].StartTime.Equal(time.Unix(int64(created), 0)) {
		t.Fatalf("StartTime = %v, want real created %v", v4[0].StartTime, time.Unix(int64(created), 0))
	}
	if !v4[0].EndTime.Equal(end) {
		t.Fatalf("EndTime = %v, want %v", v4[0].EndTime, end)
	}
	if got := e.EstimatedDurations(); got != 0 {
		t.Fatalf("EstimatedDurations = %d, want 0 (a real created ts was used)", got)
	}
}

// #2465 (NetFlow v9 fallback): a close with no created timestamp uses the
// estimate and bumps the estimated-duration counter.
func TestNetFlowExportSessionCloseFallbackBumpsCounter(t *testing.T) {
	e, err := NewExporter(&ExportConfig{})
	if err != nil {
		t.Fatalf("NewExporter: %v", err)
	}
	end := time.Unix(1_700_000_600, 0)
	rec := logging.EventRecord{
		Time:        end,
		Type:        "SESSION_CLOSE",
		Created:     0,
		SessionPkts: 4,
		Protocol:    "TCP",
	}
	evt := SessionCloseData{SrcIP: net.ParseIP("10.0.1.102"), DstIP: net.ParseIP("172.16.80.200"), Protocol: 6}
	e.ExportSessionClose(rec, evt)

	v4, _ := e.batch.drain()
	if len(v4) != 1 {
		t.Fatalf("expected 1 batched flow, got %d", len(v4))
	}
	want := end.Add(-estimateSessionDuration(4, 6))
	if !v4[0].StartTime.Equal(want) {
		t.Fatalf("StartTime = %v, want estimate %v", v4[0].StartTime, want)
	}
	if got := e.EstimatedDurations(); got != 1 {
		t.Fatalf("EstimatedDurations = %d, want 1 (fallback used)", got)
	}
}

// #2465 fail-on-revert (IPFIX): same contract as the NetFlow v9 test.
func TestIPFIXExportSessionCloseUsesRealCreated(t *testing.T) {
	e, err := NewIPFIXExporter(&ExportConfig{})
	if err != nil {
		t.Fatalf("NewIPFIXExporter: %v", err)
	}
	end := time.Unix(1_700_000_600, 0)
	created := uint32(1_700_000_100)
	rec := logging.EventRecord{
		Time:        end,
		Type:        "SESSION_CLOSE",
		Created:     created,
		SessionPkts: 4,
		Protocol:    "TCP",
	}
	evt := SessionCloseData{SrcIP: net.ParseIP("10.0.1.102"), DstIP: net.ParseIP("172.16.80.200"), Protocol: 6}
	e.ExportSessionClose(rec, evt)

	v4, _ := e.batch.drain()
	if len(v4) != 1 {
		t.Fatalf("expected 1 batched flow, got %d", len(v4))
	}
	if !v4[0].StartTime.Equal(time.Unix(int64(created), 0)) {
		t.Fatalf("StartTime = %v, want real created %v", v4[0].StartTime, time.Unix(int64(created), 0))
	}
	if got := e.EstimatedDurations(); got != 0 {
		t.Fatalf("EstimatedDurations = %d, want 0", got)
	}
}

// #2853 fail-on-revert: two flows created within the SAME integer second but at
// distinct sub-second offsets must keep distinct StartTimes (millisecond
// resolution) in the flow record. Before #2853 the dataplane stamped only the
// truncated second, so both flows collapsed onto the same StartTime; this test
// goes RED if flowStartTime is reverted to time.Unix(int64(rec.Created), 0)
// (i.e. drops rec.CreatedNanos).
func TestFlowStartTimeKeepsSubSecondResolution(t *testing.T) {
	end := time.Unix(1_700_000_300, 0)
	sec := uint32(1_700_000_000)

	// Two short flows opened ~600ms apart inside the same wall-clock second.
	recEarly := logging.EventRecord{
		Time: end, Type: "SESSION_CLOSE", Protocol: "UDP",
		Created: sec, CreatedNanos: 100_000_000, // .100s
	}
	recLate := logging.EventRecord{
		Time: end, Type: "SESSION_CLOSE", Protocol: "UDP",
		Created: sec, CreatedNanos: 700_000_000, // .700s
	}

	startEarly, estEarly := flowStartTime(recEarly, 17)
	startLate, estLate := flowStartTime(recLate, 17)
	if estEarly || estLate {
		t.Fatal("a real created timestamp must NOT use the estimate")
	}
	if startEarly.Equal(startLate) {
		t.Fatalf("same-second flows must have DISTINCT sub-second StartTimes; both = %v (sub-second truncated?)", startEarly)
	}
	// Exact instants — proves the nanos are combined, not discarded.
	if want := time.Unix(int64(sec), 100_000_000); !startEarly.Equal(want) {
		t.Fatalf("early StartTime = %v, want %v", startEarly, want)
	}
	if want := time.Unix(int64(sec), 700_000_000); !startLate.Equal(want) {
		t.Fatalf("late StartTime = %v, want %v", startLate, want)
	}
	// Millisecond delta survives — this is what IPFIX flowStartMilliseconds /
	// NetFlow uptimeMs render from StartTime.
	if d := startLate.Sub(startEarly); d != 600*time.Millisecond {
		t.Fatalf("sub-second delta = %v, want 600ms", d)
	}
}

// #2853 fail-on-revert (IPFIX end-to-end): two SESSION_CLOSE events in the same
// second but at distinct sub-second offsets must produce flow records whose
// exported flowStartMilliseconds differ. Reverting the dataplane stamp or
// flowStartTime to whole-second resolution makes both UnixMilli() collapse to
// sec*1000 and this assertion fails.
func TestIPFIXExportSessionCloseSubSecondStart(t *testing.T) {
	e, err := NewIPFIXExporter(&ExportConfig{})
	if err != nil {
		t.Fatalf("NewIPFIXExporter: %v", err)
	}
	end := time.Unix(1_700_000_600, 0)
	sec := uint32(1_700_000_100)
	evt := SessionCloseData{SrcIP: net.ParseIP("10.0.1.102"), DstIP: net.ParseIP("172.16.80.200"), Protocol: 6}

	e.ExportSessionClose(logging.EventRecord{
		Time: end, Type: "SESSION_CLOSE", Created: sec, CreatedNanos: 250_000_000, Protocol: "TCP",
	}, evt)
	e.ExportSessionClose(logging.EventRecord{
		Time: end, Type: "SESSION_CLOSE", Created: sec, CreatedNanos: 850_000_000, Protocol: "TCP",
	}, evt)

	v4, _ := e.batch.drain()
	if len(v4) != 2 {
		t.Fatalf("expected 2 batched flows, got %d", len(v4))
	}
	got := map[int64]bool{
		v4[0].StartTime.UnixMilli(): true,
		v4[1].StartTime.UnixMilli(): true,
	}
	if len(got) != 2 {
		t.Fatalf("same-second flows produced identical flowStartMilliseconds (sub-second truncated?): %v", got)
	}
	wantA := int64(sec)*1000 + 250
	wantB := int64(sec)*1000 + 850
	if !got[wantA] || !got[wantB] {
		t.Fatalf("flowStartMilliseconds = %v, want {%d, %d}", got, wantA, wantB)
	}
}

// #2465 (IPFIX fallback): no created ts → estimate + counter bump.
func TestIPFIXExportSessionCloseFallbackBumpsCounter(t *testing.T) {
	e, err := NewIPFIXExporter(&ExportConfig{})
	if err != nil {
		t.Fatalf("NewIPFIXExporter: %v", err)
	}
	end := time.Unix(1_700_000_600, 0)
	rec := logging.EventRecord{Time: end, Type: "SESSION_CLOSE", Created: 0, SessionPkts: 4, Protocol: "TCP"}
	evt := SessionCloseData{SrcIP: net.ParseIP("10.0.1.102"), DstIP: net.ParseIP("172.16.80.200"), Protocol: 6}
	e.ExportSessionClose(rec, evt)

	if got := e.EstimatedDurations(); got != 1 {
		t.Fatalf("EstimatedDurations = %d, want 1", got)
	}
}
