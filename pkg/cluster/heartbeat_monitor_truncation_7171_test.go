package cluster

import (
	"bytes"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

// captureSlog redirects the default slog logger into buf for the duration of
// the test. Returned as a helper so the truncation cells below can assert on
// what an operator would actually see rather than only on a return value.
func captureSlog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

// TestMonitorTruncationDetector binds the monitor-truncation warning (#7171).
//
// The detector is constructed FRESH here rather than using the package global.
// A process-lifetime sync.Once fires on test ORDER rather than on the input, so
// a cell asserting the global's log would pass or fail depending on what ran
// before it -- which is why this warning's #4434 sibling has never been
// asserted at all. A local instance makes the emission deterministic.
//
// The negative control is not decoration: without it, an implementation that
// warned unconditionally would satisfy the positive cell. The pair is the
// result -- the condition must produce the warning AND the healthy state must
// not.
func TestMonitorTruncationDetector(t *testing.T) {
	var d monitorTruncationDetector
	buf := captureSlog(t)

	// --- negative control: nothing was dropped ---
	if d.observe(3, 3) {
		t.Error("observe(3,3) reported a truncation; nothing was dropped")
	}
	if d.observe(0, 0) {
		t.Error("observe(0,0) reported a truncation on an empty monitor list")
	}
	if got := d.count(); got != 0 {
		t.Errorf("count after healthy observations = %d, want 0", got)
	}
	if buf.Len() != 0 {
		t.Errorf("healthy state emitted a warning: %q", buf.String())
	}

	// --- positive: a real truncation warns, and says what was lost ---
	if !d.observe(10, 4) {
		t.Fatal("observe(10,4) did not report a truncation")
	}
	if got := d.count(); got != 1 {
		t.Errorf("count = %d, want 1", got)
	}
	logged := buf.String()
	for _, want := range []string{
		"monitored-interface list exceeds heartbeat wire",
		"monitors=10",
		"advertised=4",
	} {
		if !strings.Contains(logged, want) {
			t.Errorf("warning does not contain %q; got %q", want, logged)
		}
	}

	// --- every occurrence is detected, even though the log fires once ---
	// A condition that RECURS is different information from one that happened
	// once. The once-guard must suppress the repeated LOG without suppressing
	// the repeated DETECTION.
	sizeAfterFirst := buf.Len()
	if !d.observe(10, 4) {
		t.Fatal("second truncation not reported")
	}
	if got := d.count(); got != 2 {
		t.Errorf("count after second truncation = %d, want 2 (detection must advance every time)", got)
	}
	if buf.Len() != sizeAfterFirst {
		t.Errorf("warning re-emitted on the second occurrence; the once-guard should suppress it")
	}
}

// TestMarshalHeartbeatBodyWiresTruncationDetector binds the DETECTOR TO THE
// PRODUCTION PATH. The cells above prove the detector behaves; this proves
// marshalHeartbeatBody actually consults it, which is the half a detector test
// cannot see -- deleting the observe call leaves every cell above green.
//
// It reads the package global's counter rather than a local instance, and
// asserts a DELTA rather than an absolute, so it does not care whether an
// earlier test in this binary already tripped it.
func TestMarshalHeartbeatBodyWiresTruncationDetector(t *testing.T) {
	base := &HeartbeatPacket{
		NodeID:    0,
		ClusterID: 1,
		Groups:    []HeartbeatGroup{{GroupID: 1, Priority: 100, Weight: 255, State: 1}},
	}

	// Negative control through the REAL marshaller: a list that fits must not
	// register a truncation.
	before := heartbeatMonitorTruncations.count()
	base.Monitors = []HeartbeatMonitor{{RGID: 1, Weight: 255, Up: true, Interface: "ge-0-0-1"}}
	marshalHeartbeatBody(base, 0)
	if got := heartbeatMonitorTruncations.count(); got != before {
		t.Errorf("a monitor list that fits registered %d truncation(s)", got-before)
	}

	// Positive through the REAL marshaller.
	var many []HeartbeatMonitor
	for i := 0; i < 200; i++ {
		many = append(many, HeartbeatMonitor{
			RGID: 1, Weight: 255, Up: i%2 == 0,
			Interface: fmt.Sprintf("ge-0-0-%d-with-a-long-name", i),
		})
	}
	base.Monitors = many
	body := marshalHeartbeatBody(base, 0)
	if got := heartbeatMonitorTruncations.count(); got != before+1 {
		t.Fatalf("marshalHeartbeatBody did not register the truncation (count delta %d, want 1)", got-before)
	}

	// And the frame it produced really is truncated, so the fixture is
	// exercising a partial fit rather than passing for some other reason.
	got, err := UnmarshalHeartbeat(body)
	if err != nil {
		t.Fatalf("unmarshal truncated frame: %v", err)
	}
	if len(got.Monitors) == 0 || len(got.Monitors) >= len(many) {
		t.Fatalf("decoded %d of %d monitors; fixture does not exercise a partial fit", len(got.Monitors), len(many))
	}
}
