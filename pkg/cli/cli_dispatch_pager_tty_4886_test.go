package cli

// #4886 B: dispatch() routes any `show ` to dispatchWithPager, which had NO TTY
// guard. So `show … | match X` → dispatchWithPipe redirects os.Stdout to the
// filter pipe → the inner bare `show` routes back to dispatchWithPager → the
// pager engaged even though os.Stdout was the pipe, writing `--More--` into the
// hidden outer pipe while blocking on os.Stdin → the command HUNG with no
// visible prompt. dispatchWithPager now auto-disables when stdout is not a TTY
// (stdoutIsTerminal), so a piped / scripted / redirected show streams straight
// through with no pager.
//
// FAIL-ON-REVERT: remove the `if !stdoutIsTerminal()` guard and the piped-show
// nesting test HANGS (the inner pager writes --More-- into the pipe and blocks
// on stdin with no key feeder) → the timeout fires RED; the direct pipe-stdout
// test also sees a `--More--` leak.

import (
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

// TestStdoutIsTerminal_PipeIsNotATTY_4886 pins the guard's input: a pipe (the
// `| match` filter's os.Stdout redirect) reads as non-terminal, so the pager
// auto-disables. This is the exact condition that broke the nested pager.
func TestStdoutIsTerminal_PipeIsNotATTY_4886(t *testing.T) {
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer func() { os.Stdout = orig; w.Close(); r.Close() }()

	os.Stdout = w
	if stdoutIsTerminal() {
		t.Fatal("stdoutIsTerminal() = true for an os.Pipe stdout; want false (pager must auto-disable when piped)")
	}
	// Sanity: the real test stdout may or may not be a TTY, but a pipe must not.
}

// TestPagerAutoDisablesOnNonTTYStdout_4886 is the behavioral guard: with os.Stdout
// redirected to a pipe (exactly the state dispatchWithPipe leaves for the inner
// `show` of a `show … | match …`), dispatchWithPager must NOT engage the pager —
// it must stream straight through with NO `--More--` prompt. `show` (no subcommand)
// prints ~33 lines of help, MORE than the default pageSize (23), so on the
// pre-#4886 (no-guard) path the pager DID emit a `--More--` into this non-TTY
// stdout (the prompt that, in the real nested case, went into the hidden filter
// pipe while the pager blocked on stdin → the hang). Asserting no `--More--` leak
// RED-fails on the guard revert regardless of whether stdin blocks.
func TestPagerAutoDisablesOnNonTTYStdout_4886(t *testing.T) {
	c := newRecordingCLI(t, nil)

	// Force stdin to immediate EOF so a reverted (no-guard) pager cannot actually
	// block the test — it still EMITS the --More-- before reading, which is the
	// signal we assert on.
	origIn := os.Stdin
	inR, inW, err := os.Pipe()
	if err != nil {
		t.Fatalf("stdin pipe: %v", err)
	}
	inW.Close() // read side is at EOF immediately
	os.Stdin = inR

	origOut := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	os.Stdout = w

	var out []byte
	readDone := make(chan struct{})
	go func() { out, _ = io.ReadAll(r); close(readDone) }()

	done := make(chan error, 1)
	go func() { done <- c.dispatchWithPager("show") }()

	var derr error
	select {
	case derr = <-done:
	case <-time.After(5 * time.Second):
		os.Stdout, os.Stdin = origOut, origIn
		w.Close()
		<-readDone
		t.Fatalf("dispatchWithPager did not return within 5s (pager blocked): %q", string(out))
	}

	os.Stdout, os.Stdin = origOut, origIn
	w.Close()
	<-readDone
	inR.Close()

	if derr != nil {
		t.Fatalf("dispatchWithPager: %v", derr)
	}
	if strings.Contains(string(out), "--More--") {
		t.Fatalf("pager engaged on a non-TTY stdout (--More-- leaked) — the nested `show | match` hang path; the TTY guard is missing:\n%q", string(out))
	}
}
