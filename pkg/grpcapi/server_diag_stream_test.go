package grpcapi

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestStreamDiagCmdStreamsLines pins the streaming contract: each
// output line reaches sendFn in order, and a child exit error is
// delivered as a final line rather than failing the call.
func TestStreamDiagCmdStreamsLines(t *testing.T) {
	var lines []string
	err := streamDiagCmd(context.Background(), 30*time.Second,
		[]string{"sh", "-c", "echo one; echo two; exit 3"},
		func(line string) error {
			lines = append(lines, line)
			return nil
		})
	if err != nil {
		t.Fatalf("streamDiagCmd: %v", err)
	}
	if len(lines) != 3 || lines[0] != "one" || lines[1] != "two" {
		t.Fatalf("lines = %q, want [one two <exit error>]", lines)
	}
	if lines[2] != "exit status 3" {
		t.Fatalf("final line = %q, want the child exit error", lines[2])
	}
}

// TestStreamDiagCmdKillsChildOnSendError pins the #1819 prompt-kill
// path: when sendFn fails, the scanner goroutine stops reading the
// pipe, and without the explicit cancel the chatty child would block
// on writes until the full budget expired. With the cancel, the call
// must return the send error well before the 30s budget.
func TestStreamDiagCmdKillsChildOnSendError(t *testing.T) {
	sendErr := errors.New("stream closed")
	start := time.Now()
	err := streamDiagCmd(context.Background(), 30*time.Second,
		[]string{"sh", "-c", "while true; do echo x; sleep 0.1; done"},
		func(string) error { return sendErr })
	elapsed := time.Since(start)
	if !errors.Is(err, sendErr) {
		t.Fatalf("streamDiagCmd = %v, want the send error", err)
	}
	// Prompt kill: cancel fires immediately; allow generous slack for
	// process teardown + the 5s WaitDelay worst case, still far under
	// the 30s budget the old code would have burned.
	if elapsed > 10*time.Second {
		t.Fatalf("streamDiagCmd took %v after send failure, child was not killed promptly", elapsed)
	}
}

// TestClampDiagTimeout pins the ceiling streamDiagCmd applies to every
// caller-supplied budget.
func TestClampDiagTimeout(t *testing.T) {
	cases := []struct{ in, want time.Duration }{
		{time.Second, time.Second},
		{diagExecCeiling - 1, diagExecCeiling - 1},
		{diagExecCeiling, diagExecCeiling},
		{diagExecCeiling + 1, diagExecCeiling},
		{24 * time.Hour, diagExecCeiling},
	}
	for _, c := range cases {
		if got := clampDiagTimeout(c.in); got != c.want {
			t.Errorf("clampDiagTimeout(%v) = %v, want %v", c.in, got, c.want)
		}
	}
}
