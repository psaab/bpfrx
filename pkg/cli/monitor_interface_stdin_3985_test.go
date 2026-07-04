package cli

import (
	"io"
	"testing"
	"time"
)

// fakeTTY models a raw terminal opened with VMIN=0/VTIME>0 (as setRawMode now
// configures): Read returns a queued byte immediately, and otherwise returns
// (0, nil) after a short idle timeout — the poll-with-timeout behavior the
// #3985 fix relies on to let the key-reader goroutine observe its stop signal.
type fakeTTY struct {
	ch   chan byte
	idle time.Duration
}

func (f *fakeTTY) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	select {
	case b, ok := <-f.ch:
		if !ok {
			return 0, io.EOF
		}
		p[0] = b
		return 1, nil
	case <-time.After(f.idle):
		// VTIME poll timeout with no data available.
		return 0, nil
	}
}

// TestKeyReaderLifecycle exercises the full lifecycle of the monitor's stdin
// key-reader goroutine (#3985): it forwards keys while running, stays alive
// across idle polls, and returns promptly once its done channel is closed.
//
// RED-on-revert: the pre-#3985 loop body was
//
//	for {
//	    n, err := r.Read(buf)
//	    if err != nil || n == 0 { return }
//	    keyCh <- buf[0]
//	}
//
// which has no done handling and returns on the first n==0 poll. Against this
// VMIN=0/VTIME reader it exits within one idle interval, so the "still alive
// while running" assertion below fails (the goroutine is gone). With the old
// VMIN=1/VTIME=0 termios the same loop instead blocked forever in Read after
// the monitor exited, parking the goroutine so it stole the operator's next
// keystroke — the defect this test guards against.
func TestKeyReaderLifecycle(t *testing.T) {
	tty := &fakeTTY{ch: make(chan byte, 8), idle: 2 * time.Millisecond}
	keyCh := make(chan byte, 8)
	done := make(chan struct{})
	exited := make(chan struct{})
	go func() {
		keyReader(tty, keyCh, done)
		close(exited)
	}()

	// The monitor must still receive keystrokes (e.g. 'q' to quit).
	tty.ch <- 'q'
	select {
	case k := <-keyCh:
		if k != 'q' {
			t.Fatalf("forwarded key = %q, want 'q'", k)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("key 'q' was not forwarded to the monitor")
	}

	// While done is open the reader must keep polling, not exit on an idle
	// poll. The pre-#3985 code returns on the first n==0 read and fails here.
	select {
	case <-exited:
		t.Fatal("keyReader returned while running (early-exit / leak regression — #3985)")
	case <-time.After(100 * time.Millisecond):
		// Still alive after many idle polls — correct.
	}

	// Closing done must make the goroutine return promptly: no stdin reader is
	// left competing for the operator's next keystroke.
	close(done)
	select {
	case <-exited:
		// Returned cleanly.
	case <-time.After(2 * time.Second):
		t.Fatal("keyReader did not return after done closed — leaked stdin reader (#3985)")
	}
}

// TestKeyReaderDiscardsKeyAfterDone verifies that a byte read concurrently with
// the stop signal is discarded rather than forwarded once done is closed, so a
// late monitor keystroke cannot leak past the exiting monitor.
func TestKeyReaderDiscardsKeyAfterDone(t *testing.T) {
	tty := &fakeTTY{ch: make(chan byte, 8), idle: time.Hour} // never idles out
	keyCh := make(chan byte)                                 // unbuffered: forwarding requires a live receiver
	done := make(chan struct{})
	exited := make(chan struct{})
	go func() {
		keyReader(tty, keyCh, done)
		close(exited)
	}()

	close(done)   // stop before any key is available
	tty.ch <- 'x' // key arrives after done closed

	select {
	case k := <-keyCh:
		t.Fatalf("key %q forwarded after done closed (leaked-reader keystroke theft — #3985)", k)
	case <-exited:
		// Reader returned without forwarding the post-done key — correct.
	case <-time.After(2 * time.Second):
		t.Fatal("keyReader did not return after done closed (#3985)")
	}
}

// TestStartKeyReaderStopDrains verifies the stop function returned by
// startKeyReader blocks until the reader goroutine has actually returned, and
// is safe to call more than once.
func TestStartKeyReaderStopDrains(t *testing.T) {
	tty := &fakeTTY{ch: make(chan byte, 8), idle: 2 * time.Millisecond}
	keyCh, stop := startKeyReader(tty)

	tty.ch <- 'q'
	select {
	case k := <-keyCh:
		if k != 'q' {
			t.Fatalf("forwarded key = %q, want 'q'", k)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("key not forwarded via startKeyReader")
	}

	stopped := make(chan struct{})
	go func() {
		stop()
		close(stopped)
	}()
	select {
	case <-stopped:
		// stop() returned: wg.Wait completed, so the goroutine is gone.
	case <-time.After(2 * time.Second):
		t.Fatal("stop() did not return — reader goroutine not draining (#3985)")
	}

	// Idempotent: a second stop must not panic on a re-closed channel.
	stop()
}
