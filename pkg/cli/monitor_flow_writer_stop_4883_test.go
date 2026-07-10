package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/logging"
)

// TestMonitorFlowWriterErrorClearsState_4883 is the #4883-B regression guard.
// When the flow-trace writer fails (disk-full / permission / rotation), the
// monitor goroutine used to `return` without reacquiring monitorFlow.mu to
// clear active/cancel/sub. showMonitorSecurityFlow kept reporting Active and a
// new `start` was rejected until an operator issued `stop` — audit telemetry
// silently stopped while health read green.
//
// This drives the REAL writer goroutine to a deterministic write failure: the
// trace file is seeded with content (so the writer rotates on the first line),
// the trace directory is removed out from under the open fd (so the rotation's
// rename fails), and one matching event is published. The goroutine must then
// clear the monitor state, record the error, and accept a fresh start.
//
// Goes RED on revert: without the lock+clear the monitor stays Active forever
// and the poll below times out.
func TestMonitorFlowWriterErrorClearsState_4883(t *testing.T) {
	origDir := traceLogDir
	dir := t.TempDir()
	traceLogDir = dir
	defer func() { traceLogDir = origDir }()

	// Seed the trace file so the writer's `written` counter starts > 0 and the
	// very first line trips the size-based rotation (maxSize=1 below).
	name := "trace"
	if err := os.WriteFile(filepath.Join(dir, name), []byte(strings.Repeat("x", 200)), 0o600); err != nil {
		t.Fatalf("seed trace file: %v", err)
	}

	eventBuf := logging.NewEventBuffer(64)
	c := &CLI{eventBuf: eventBuf}
	c.monitorFlow = newMonitorFlowState()
	c.monitorFlow.filename = name
	c.monitorFlow.fileSize = 1 // maxSize=1 -> the first line rotates
	c.monitorFlow.files = 2
	c.monitorFlow.filters["f"] = &monitorFlowFilter{Name: "f", Protocol: "tcp"}

	if err := c.handleMonitorSecurityFlowStart(); err != nil {
		t.Fatalf("initial start: %v", err)
	}

	// Remove the trace directory. The writer's fd stays valid (unlinked file),
	// but the next rotation's rename of the active file fails deterministically.
	if err := os.RemoveAll(dir); err != nil {
		t.Fatalf("remove trace dir: %v", err)
	}

	// Publish one matching event. Rotation fires on the first line, fails
	// (dir gone), writeLine errors, and the goroutine tears the monitor down.
	eventBuf.Add(logging.EventRecord{
		SrcAddr:  "10.0.1.5:1234",
		DstAddr:  "10.0.2.1:80",
		Protocol: "TCP",
	})

	// The goroutine runs asynchronously; poll for the state to clear.
	var active bool
	var lastErr error
	for i := 0; i < 300; i++ {
		c.monitorFlow.mu.Lock()
		active = c.monitorFlow.active
		lastErr = c.monitorFlow.lastErr
		c.monitorFlow.mu.Unlock()
		if !active {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if active {
		t.Fatal("monitor still Active after a writer error; state was not cleared " +
			"(monitor wedges Active, silently stops tracing until an operator issues stop)")
	}
	if lastErr == nil {
		t.Fatal("writer error was not recorded in monitorFlow.lastErr")
	}

	// A fresh start must now be accepted (openTraceFile recreates the dir).
	if err := c.handleMonitorSecurityFlowStart(); err != nil {
		t.Fatalf("subsequent start rejected after writer error cleared state: %v", err)
	}
	c.monitorFlow.mu.Lock()
	le := c.monitorFlow.lastErr
	active2 := c.monitorFlow.active
	c.monitorFlow.mu.Unlock()
	if le != nil {
		t.Errorf("monitorFlow.lastErr = %v after a fresh start; want cleared", le)
	}
	if !active2 {
		t.Error("monitor not Active after a successful restart")
	}
	_ = c.handleMonitorSecurityFlowStop()
}
