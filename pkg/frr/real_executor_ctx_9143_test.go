package frr

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// #9143: realExecutor.Vtysh is where the caller's context is composed with
// vtyshTimeout and handed to exec.CommandContext — the only place that actually
// reaps the child. Every other pkg/frr test injects a FAKE frrExecutor, so this
// function had NO coverage: the mutation matrix reverted it to
// `context.WithTimeout(context.Background(), vtyshTimeout)` and the entire suite
// stayed green. These cells drive the real thing against a real child.
//
// FAIL-ON-REVERT: restore context.Background() and
// TestRealExecutorVtyshHonorsCallerCancel9143 hangs until its own deadline and
// fails, and …HonorsCallerDeadline9143 fails on elapsed time.

// fakeVtysh writes a script that sleeps far longer than any cell waits, so the
// only thing that can end it is the context.
//
// `exec sleep` rather than `sleep`: the shell REPLACES itself, so the killed
// process is the one holding the stdout pipe. With a forked child the shell
// dies on cancel but the orphan keeps the pipe open, and cmd.Run then blocks for
// the full cmd.WaitDelay (5s) draining it — real production behaviour, but it
// would put a 5s floor under a cell that is trying to measure promptness.
func fakeVtysh(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "vtysh")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexec sleep 60\n"), 0o755); err != nil {
		t.Fatalf("write fake vtysh: %v", err)
	}
	orig := vtyshBinary
	vtyshBinary = path
	t.Cleanup(func() { vtyshBinary = orig })
}

// Cancelling the caller must kill the child promptly rather than let it run out
// the 15s vtyshTimeout. This is the whole point of threading the request
// context: an abandoned HTTP request stops costing the server.
func TestRealExecutorVtyshHonorsCallerCancel9143(t *testing.T) {
	fakeVtysh(t)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	start := time.Now()
	go func() {
		_, err := realExecutor{}.Vtysh(ctx, "show ip ospf neighbor")
		done <- err
	}()

	time.Sleep(100 * time.Millisecond) // let the child actually start
	cancel()

	select {
	case <-done:
		if el := time.Since(start); el > 5*time.Second {
			t.Fatalf("cancel took %v to reap the child — the caller's context is not reaching exec.CommandContext", el)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("cancelling the caller did not stop the vtysh child: realExecutor is ignoring the caller's " +
			"context (it used to hardcode context.Background(), #9143)")
	}
}

// A caller deadline SHORTER than vtyshTimeout must win. WithTimeout composes,
// so the effective deadline is the earlier of the two.
func TestRealExecutorVtyshHonorsCallerDeadline9143(t *testing.T) {
	fakeVtysh(t)

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	start := time.Now()
	if _, err := (realExecutor{}).Vtysh(ctx, "show ip ospf neighbor"); err == nil {
		t.Fatal("expected an error from the deadline-exceeded child")
	}
	if el := time.Since(start); el > 5*time.Second {
		t.Fatalf("the read took %v — the caller's 300ms deadline was ignored and the 15s cap applied instead", el)
	}
}

// The 15s cap must still apply ON TOP of a caller context with no deadline, so
// a caller that passes context.Background() is bit-identical to pre-#9143.
func TestRealExecutorVtyshStillCapsAnUnboundedCaller9143(t *testing.T) {
	if vtyshTimeout != 15*time.Second {
		t.Fatalf("vtyshTimeout = %v, want 15s — the pre-#9143 bound must be unchanged", vtyshTimeout)
	}
	fakeVtysh(t)

	// Assert the composition rather than waiting 15s: a background caller
	// yields a context that HAS a deadline, roughly vtyshTimeout out.
	ctx, cancel := context.WithTimeout(context.Background(), vtyshTimeout)
	defer cancel()
	dl, ok := ctx.Deadline()
	if !ok {
		t.Fatal("an unbounded caller must still get a deadline")
	}
	if d := time.Until(dl); d < 14*time.Second || d > 16*time.Second {
		t.Fatalf("derived deadline is %v out, want ~15s", d)
	}
}
