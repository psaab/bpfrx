package cli

import (
	"strings"
	"testing"
)

// TestMonitorPacketDropNilEventBuf guards #3381: a CLI constructed without an
// event buffer (daemonless / remote construction, eventBuf == nil) must not
// panic in `monitor security packet-drop`. Before the fix the path called
// c.eventBuf.Subscribe(256) on a nil buffer and crashed the process.
//
// FAIL-ON-REVERT: removing the `if c.eventBuf == nil` guard in
// handleMonitorSecurityPacketDrop makes Subscribe panic (recovered here ->
// t.Fatal).
func TestMonitorPacketDropNilEventBuf(t *testing.T) {
	c := &CLI{} // eventBuf is nil

	var (
		err error
		out string
	)
	out = captureStdout(t, func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("handleMonitorSecurityPacketDrop panicked on nil eventBuf: %v", r)
			}
		}()
		err = c.handleMonitorSecurityPacketDrop(nil)
	})
	if err != nil {
		t.Errorf("handleMonitorSecurityPacketDrop(nil) = %v, want nil (clean diagnostic)", err)
	}
	if !strings.Contains(out, "event buffer") {
		t.Errorf("output = %q, want a diagnostic mentioning 'event buffer'", out)
	}
}

// TestMonitorFlowStartNilEventBuf guards the sibling `monitor security flow
// start` path (#3381). The guard sits at the top of
// handleMonitorSecurityFlowStart so a nil event buffer is reported before any
// file/Subscribe work.
//
// FAIL-ON-REVERT: removing the guard makes a nil eventBuf fall through to the
// filename check (here filename is set) and then Subscribe, panicking under a
// privileged runner or returning a file-open error under an unprivileged one —
// either way the "event buffer" diagnostic disappears.
func TestMonitorFlowStartNilEventBuf(t *testing.T) {
	c := &CLI{monitorFlow: &monitorFlowState{filename: "xpf-3381-test.log"}} // eventBuf nil

	var (
		err error
		out string
	)
	out = captureStdout(t, func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("handleMonitorSecurityFlowStart panicked on nil eventBuf: %v", r)
			}
		}()
		err = c.handleMonitorSecurityFlowStart()
	})
	if err != nil {
		t.Errorf("handleMonitorSecurityFlowStart() = %v, want nil (clean diagnostic)", err)
	}
	if !strings.Contains(out, "event buffer") {
		t.Errorf("output = %q, want a diagnostic mentioning 'event buffer'", out)
	}
}
