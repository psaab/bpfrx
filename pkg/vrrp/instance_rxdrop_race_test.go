package vrrp

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// #2225: warnRXDrop is invoked concurrently from receiver() and
// receiverIPv6() on the AF_PACKET-fallback path (run() starts both goroutines
// when afPacketFD < 0 and an IPv6 socket exists). Both touch the shared
// lastDropWarn rate-limiter field. With lastDropWarn as a plain time.Time the
// read-modify-write was an unsynchronized data race; `go test -race` flags it.
// The fix makes lastDropWarn an atomic.Int64 of Unix nanos updated via
// CompareAndSwap.
//
// These tests are the fail-on-revert gate: under -race they are CLEAN with the
// atomic fix and DETECT the race if lastDropWarn is reverted to time.Time.

// countingHandler counts emitted log records so the dampener semantics can be
// asserted (warn at most once per interval).
type countingHandler struct {
	n *atomic.Int64
}

func (h countingHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h countingHandler) Handle(context.Context, slog.Record) error {
	h.n.Add(1)
	return nil
}
func (h countingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h countingHandler) WithGroup(string) slog.Handler      { return h }

// installCountingLogger swaps the default slog logger for one that counts
// records, returning the counter and a restore function.
func installCountingLogger(t *testing.T) (*atomic.Int64, func()) {
	t.Helper()
	var n atomic.Int64
	prev := slog.Default()
	slog.SetDefault(slog.New(countingHandler{n: &n}))
	return &n, func() { slog.SetDefault(prev) }
}

// TestWarnRXDropConcurrent drives warnRXDrop from many goroutines at once,
// mirroring the concurrent receiver()/receiverIPv6() call sites. To force the
// read-modify-WRITE branch repeatedly (so the detector observes concurrent
// writes, not just the single first write per 10s window), a companion goroutine
// continually rewinds lastDropWarn past the dampening window. Under -race this
// FAILS (race detected on lastDropWarn) if the field is reverted to an
// unsynchronized time.Time, and is CLEAN with the atomic.Int64 fix.
func TestWarnRXDropConcurrent(t *testing.T) {
	_, restore := installCountingLogger(t)
	defer restore()

	vi := &vrrpInstance{cfg: Instance{Interface: "ge-0-0-2", GroupID: 1}}

	const goroutines = 16
	const perGoroutine = 4000

	stale := time.Now().Add(-1 * time.Hour).UnixNano()
	stopRewind := make(chan struct{})
	var rewindWG sync.WaitGroup
	rewindWG.Add(1)
	go func() {
		defer rewindWG.Done()
		for {
			select {
			case <-stopRewind:
				return
			default:
				// Keep the timestamp stale so concurrent warnRXDrop callers
				// repeatedly take the write branch — this is what surfaces the
				// write/write and write/read hazard under -race.
				vi.lastDropWarn.Store(stale)
			}
		}
	}()

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				vi.warnRXDrop()
			}
		}()
	}
	wg.Wait()
	close(stopRewind)
	rewindWG.Wait()

	// All drops must be counted regardless of synchronization.
	if got := vi.rxDrops.Load(); got != goroutines*perGoroutine {
		t.Fatalf("rxDrops = %d, want %d", got, goroutines*perGoroutine)
	}
}

// TestWarnRXDropDampenerOnce verifies the rate-limiter still warns at most once
// per interval even under heavy concurrency. The CompareAndSwap in warnRXDrop
// ensures only the goroutine that swaps the stale timestamp emits the warning,
// so a burst of concurrent drops yields exactly one log line per interval.
func TestWarnRXDropDampenerOnce(t *testing.T) {
	n, restore := installCountingLogger(t)
	defer restore()

	vi := &vrrpInstance{cfg: Instance{Interface: "ge-0-0-2", GroupID: 1}}

	// First call seeds lastDropWarn from its zero value: now - 0 >> 10s, so it
	// warns once. A concurrent burst that follows immediately is within the
	// 10s window and must NOT add further warnings.
	const goroutines = 32
	const perGoroutine = 500

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				vi.warnRXDrop()
			}
		}()
	}
	wg.Wait()

	// Every call is within a single 10s interval (the test runs in well under
	// a second), so exactly one warning must have been emitted.
	if got := n.Load(); got != 1 {
		t.Fatalf("dampener emitted %d warnings within one interval, want exactly 1", got)
	}
}

// TestWarnRXDropDampenerResetsAfterInterval confirms the dampener is a delay,
// not a permanent gate: once the interval has elapsed, the next drop warns
// again. lastDropWarn is rewound past the 10s window to simulate elapsed time
// without sleeping.
func TestWarnRXDropDampenerResetsAfterInterval(t *testing.T) {
	n, restore := installCountingLogger(t)
	defer restore()

	vi := &vrrpInstance{cfg: Instance{Interface: "ge-0-0-2", GroupID: 1}}

	vi.warnRXDrop() // warns once (seeds from zero)
	if got := n.Load(); got != 1 {
		t.Fatalf("first warn count = %d, want 1", got)
	}

	// A second drop immediately after is dampened.
	vi.warnRXDrop()
	if got := n.Load(); got != 1 {
		t.Fatalf("warn count after dampened drop = %d, want 1", got)
	}

	// Rewind the last-warn timestamp past the 10s window; the next drop warns.
	vi.lastDropWarn.Store(time.Now().Add(-11 * time.Second).UnixNano())
	vi.warnRXDrop()
	if got := n.Load(); got != 2 {
		t.Fatalf("warn count after interval elapsed = %d, want 2", got)
	}
}
