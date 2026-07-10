package grpcapi

import (
	"bufio"
	"context"
	"errors"
	"testing"
	"time"
)

// TestStreamDiagCmdUnblocksOnScannerErrTooLong pins the #5060 leak fix. A
// single combined-output line larger than the scanner's max token
// (diagScanMaxBuf) makes scanner.Scan() fail with bufio.ErrTooLong. The scan
// goroutine then stops reading pr while the child keeps writing, so exec.Cmd's
// internal copy goroutine blocks in pw.Write. Before the fix the scanner-error
// path closed nothing (only the send-failure path did), so c.Wait() blocked on
// that copy goroutine forever — WaitDelay closes only the exec-owned OS pipes,
// not this io.Pipe — and the RPC + goroutine leaked past the deadline. The fix
// closes pr on EVERY scanner exit (deferred cancel()+pr.Close()), which makes
// the blocked write return ErrClosedPipe so c.Wait() and the RPC complete.
//
// Fail-on-revert: without the close this test hangs and trips the 15s deadline.
// Run with -race to catch goroutine/pipe misuse.
func TestStreamDiagCmdUnblocksOnScannerErrTooLong(t *testing.T) {
	done := make(chan error, 1)
	go func() {
		// Emit ~500 KiB as a single line (no newline) so the scanner errors
		// with ErrTooLong at diagScanMaxBuf (64 KiB) while the child still has
		// far more to write — guaranteeing the copy goroutine blocks in pw.Write.
		done <- streamDiagCmd(context.Background(), 30*time.Second,
			[]string{"sh", "-c", "head -c 500000 /dev/zero | tr '\\0' 'a'"},
			func(string) error { return nil })
	}()
	select {
	case err := <-done:
		if !errors.Is(err, bufio.ErrTooLong) {
			t.Fatalf("streamDiagCmd = %v, want bufio.ErrTooLong", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("streamDiagCmd did not return after ErrTooLong — RPC/goroutine leaked")
	}
}

// TestValidateDiagField pins the per-field length bound (#5060): a diag
// argument beyond maxDiagField is rejected at the RPC boundary so an
// unbounded field cannot reach exec / the line scanner.
func TestValidateDiagField(t *testing.T) {
	if err := validateDiagField("target", "example.com"); err != nil {
		t.Fatalf("short field rejected: %v", err)
	}
	// Exactly at the cap is allowed; one over is rejected.
	atCap := make([]byte, maxDiagField)
	for i := range atCap {
		atCap[i] = 'a'
	}
	if err := validateDiagField("target", string(atCap)); err != nil {
		t.Fatalf("field at cap rejected: %v", err)
	}
	if err := validateDiagField("target", string(atCap)+"a"); err == nil {
		t.Fatal("over-cap field accepted, want InvalidArgument")
	}
}
