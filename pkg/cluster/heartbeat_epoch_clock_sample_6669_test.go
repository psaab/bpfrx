package cluster

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// #6669 fold round 2 — WHERE refineBootEpoch samples the clock.
//
// The previous fold collapsed two clock samples into one so that `prev` and
// `prev+1` are judged against the same instant. That part was right. It took
// the single sample in the wrong PLACE: before os.ReadFile rather than after
// it, which reopened the exact hole the forward bound exists to close.
//
// The clock-credibility gate (epochClockSaneFloor) decides whether the forward
// bound applies at all, so a sample taken before a stalling read can describe a
// clock that no longer exists by the time the value is judged.

// TestRefinementSamplesTheClockAfterLoadingPersistedState_6669 is the
// fail-on-revert gate for that placement.
//
// It drives the real refineBootEpoch against a real stalling read: the state
// path is a FIFO, so os.ReadFile blocks in open(2) until a writer arrives. That
// gives a DETERMINISTIC interleaving rather than a sleep-and-hope race —
// opening the FIFO for writing cannot return until the reader has opened it, so
// when the writer runs, a sample taken before the read has already been taken
// and a sample taken after it has not. The writer corrects the clock in that
// window, exactly as NTP does on an appliance whose RTC is dead.
//
// RED-on-revert: hoist `now := epochNowNanos()` back above the os.ReadFile call
// in refineBootEpoch and this test fails — the year-2191 value is judged
// against the stale 1970 sample, the forward bound is skipped because that
// sample is below epochClockSaneFloor, and the node publishes 7e18+1 on a
// machine whose clock had already been corrected to the present.
func TestRefinementSamplesTheClockAfterLoadingPersistedState_6669(t *testing.T) {
	const (
		// A dead RTC boots the appliance near the Unix epoch. Below
		// epochClockSaneFloor, so the forward bound is skipped entirely.
		deadRTCNow = int64(5_000_000_000)
		// NTP corrects it to the present while the read is still in flight.
		correctedNow = int64(1_800_000_000_000_000_000) // ~2027
		// Year ~2191: wrong by any measure, but inside the absolute year-2200
		// band, so ONLY the forward bound can reject it.
		corrupt = uint64(7_000_000_000_000_000_000)
	)

	// Fixture preconditions — this test is only meaningful if the corrupt value
	// is invisible to the absolute band and visible to the forward bound, and
	// only once the clock is credible.
	if !epochUsableAsFloor(corrupt) {
		t.Fatalf("fixture broken: %d must be inside the absolute plausibility band", corrupt)
	}
	if !epochOrderable(corrupt, deadRTCNow) {
		t.Fatalf("fixture broken: %d must PASS at the uncredible 1970 sample (the forward bound "+
			"is skipped below epochClockSaneFloor); otherwise the stale sample would reject it "+
			"anyway and the test proves nothing", corrupt)
	}
	if epochOrderable(corrupt, correctedNow) {
		t.Fatalf("fixture broken: %d must FAIL at the corrected clock %d", corrupt, correctedNow)
	}

	path := filepath.Join(t.TempDir(), "ha-boot-epoch")
	if err := unix.Mkfifo(path, 0o644); err != nil {
		if errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EPERM) || errors.Is(err, unix.EOPNOTSUPP) {
			t.Skipf("filesystem cannot host a FIFO, so the read cannot be stalled: %v", err)
		}
		t.Fatalf("mkfifo: %v", err)
	}

	var clock atomic.Int64
	clock.Store(deadRTCNow)
	origClock := epochNowNanos
	epochNowNanos = func() int64 { return clock.Load() }
	t.Cleanup(func() { epochNowNanos = origClock })

	writerDone := make(chan error, 1)
	go func() {
		// Blocks until refineBootEpoch's os.ReadFile has opened the FIFO for
		// reading. Returning from here therefore ORDERS us strictly after any
		// clock sample taken before the read, and strictly before any sample
		// taken after it.
		f, err := os.OpenFile(path, os.O_WRONLY, 0)
		if err != nil {
			writerDone <- err
			return
		}
		// NTP lands mid-read.
		clock.Store(correctedNow)
		_, werr := f.WriteString(strconv.FormatUint(corrupt, 10) + "\n")
		cerr := f.Close()
		if werr != nil {
			writerDone <- werr
			return
		}
		writerDone <- cerr
	}()

	// The wall-clock seed this incarnation already published synchronously (see
	// Manager.heartbeatBootEpoch): a perfectly good present-day epoch.
	seed := uint64(correctedNow)
	var published atomic.Uint64
	published.Store(seed)

	refined := make(chan struct{})
	go func() {
		defer close(refined)
		refineBootEpoch(path, &published, 0)
	}()
	select {
	case <-refined:
	case <-time.After(30 * time.Second):
		t.Fatal("refineBootEpoch never returned; the FIFO read was never issued")
	}
	select {
	case err := <-writerDone:
		if err != nil {
			t.Fatalf("feeding the stalled read failed: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the FIFO writer never completed")
	}

	got := published.Load()
	if got == corrupt+1 {
		t.Fatalf("published epoch = %d: refinement chained from the year-2191 value because it "+
			"judged it against a clock sample taken BEFORE the read. The sample described a "+
			"1970 RTC that NTP had already corrected to %d by the time the value was judged, so "+
			"the forward bound was skipped on a node whose clock was in fact good. Sample after "+
			"the read returns, not before it.", got, correctedNow)
	}
	if !epochOrderable(got, correctedNow) {
		t.Fatalf("published epoch %d is not orderable by a receiver at the corrected time %d", got, correctedNow)
	}
	if got != seed {
		t.Fatalf("published epoch = %d, want the wall-clock seed %d — declining to chain must keep "+
			"the value already on the wire", got, seed)
	}
	// Declining to chain also HEALS the file, so the next boot chains normally.
	if onDisk := readEpochFile(t, path); onDisk != seed {
		t.Fatalf("persisted %d, want the healed wall-clock seed %d", onDisk, seed)
	}
}
