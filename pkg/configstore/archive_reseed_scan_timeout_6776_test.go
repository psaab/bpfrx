package configstore

import (
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// hangingArchiveReader installs an archiveDirReader that PARKS until release is
// closed, then performs the real os.ReadDir. It models the only way the reseed
// scan can actually stall: a readdir(2) that the filesystem does not answer
// (a wedged network mount under the archive path, a stalled block device). It
// returns the release func, a launch counter, and restores the seam on cleanup.
//
// The parked read has its own 5s safety valve so a REGRESSION (an unbounded
// scan) fails on the elapsed-time assertion in a few seconds instead of
// deadlocking the package suite until the go test panic timeout.
func hangingArchiveReader(t *testing.T, dir string) (release func(), launches *atomic.Int32) {
	t.Helper()
	releaseCh := make(chan struct{})
	launches = &atomic.Int32{}
	prev := archiveDirReader
	// The scan goroutine is handed this closure by value at launch
	// (maxArchiveSeq takes the reader as a parameter, #6776), so restoring the
	// package var below never races with a scan still parked inside it.
	archiveDirReader = func(string) ([]os.DirEntry, error) {
		launches.Add(1)
		select {
		case <-releaseCh:
		case <-time.After(5 * time.Second):
		}
		return os.ReadDir(dir)
	}
	var once atomic.Bool
	release = func() {
		if once.CompareAndSwap(false, true) {
			close(releaseCh)
		}
	}
	t.Cleanup(func() {
		release()
		archiveDirReader = prev
	})
	return release, launches
}

// setArchiveScanBudget shortens the #6776 reseed scan budget for the duration
// of one test.
func setArchiveScanBudget(t *testing.T, d time.Duration) {
	t.Helper()
	prev := archiveScanBudget
	archiveScanBudget = d
	t.Cleanup(func() { archiveScanBudget = prev })
}

// TestReseedScanTimeoutIsFailOpenAndSkipsArchive6776 is the primary #6776
// guard. It asserts the CHOICE this issue had to make, not merely that a
// deadline exists: when the archive-directory scan does not answer, the daemon
// FAILS OPEN — the caller is released, config work proceeds, and only archival
// is suspended — and the suspension is the #6404 skip (no below-max archive
// written at an unconfirmed seq), never a silent reseed to 0.
//
// The four properties, in the order the daemon meets them at cold boot:
//
//  1. BOUNDED. SetArchiveConfig is the boot apply's step 15b; it runs in daemon
//     PHASE 4, before the gRPC/REST/CLI listeners start in PHASE 5. It must
//     return while the filesystem is still unresponsive, or bring-up never
//     reaches the control plane.
//  2. UNCONFIRMED, not empty. The counter must not be seeded, and
//     archiveSeedDir must be cleared so a later call retries.
//  3. FAIL-OPEN. A commit landing during the stall must SUCCEED (this is the
//     choice: a firewall that will not come up because a directory did not
//     answer converts degraded storage into a total outage) while SKIPPING its
//     archive — writing at the low counter would drop a below-max archive that
//     rotateArchives prunes as stale (#6404).
//  4. RESUMES. The abandoned scan is not lost: when the filesystem answers, the
//     next call collects that result and archival resumes at the correct seq.
//
// The dir holds 3 pre-existing archives at seq 100..102 with max=4, so a
// wrongly-written below-max archive SURVIVES rotation and its presence is
// directly observable on disk — not a private-counter check.
//
// FAIL-ON-REVERT: dropping the budget (waiting for the scan) hangs step 15b
// until the 5s safety valve and reds the elapsed bound; returning true on
// timeout writes the seq-1 archive and reds the "no below-max archive"
// assertion; seeding 0 on timeout reds the recovery phase's seq-103 archive.
func TestReseedScanTimeoutIsFailOpenAndSkipsArchive6776(t *testing.T) {
	s := newTestStore(t)
	archiveDir := filepath.Join(t.TempDir(), "archive")
	base := time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)
	for seq := 100; seq <= 102; seq++ {
		ts := base.Add(time.Duration(seq) * time.Second)
		if err := writeArchive(archiveDir, 100, fmt.Sprintf("pre-%d\n", seq), ts, uint64(seq)); err != nil {
			t.Fatal(err)
		}
	}

	const budget = 150 * time.Millisecond
	setArchiveScanBudget(t, budget)
	release, launches := hangingArchiveReader(t, archiveDir)

	// (1) BOUNDED: the boot apply's SetArchiveConfig must come back while the
	// scan is still parked.
	start := time.Now()
	s.SetArchiveConfig(archiveDir, 4)
	elapsed := time.Since(start)
	if elapsed > 20*budget {
		t.Fatalf("SetArchiveConfig blocked %s on an unresponsive archive dir (budget %s): "+
			"the reseed scan is not bounded, so the boot apply never reaches the control plane",
			elapsed, budget)
	}

	// (2) UNCONFIRMED, not empty.
	if got := s.archiveSeq.Load(); got != 0 {
		t.Fatalf("after a timed-out reseed scan archiveSeq = %d, want 0 (never seeded from an unanswered scan)", got)
	}
	s.mu.RLock()
	seededDir := s.archiveSeedDir
	s.mu.RUnlock()
	if seededDir != "" {
		t.Errorf("a timed-out reseed scan must leave archiveSeedDir cleared so a later call retries, got %q", seededDir)
	}

	// (3) FAIL-OPEN: the commit succeeds; its archive is skipped.
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := s.SetFromInput("system host-name stalled-6776"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("a commit during an unresponsive archive scan must still SUCCEED "+
			"(archival is fail-open; the box must stay configurable): %v", err)
	}
	s.archiveWG.Wait()
	remain := archiveConfigText(t, archiveDir)
	if hasMarker(remain, "host-name stalled-6776") {
		t.Errorf("a commit during a timed-out scan must NOT write a below-max archive "+
			"(the seq is unconfirmed); surviving archives=%v", markerSet(remain))
	}
	if len(remain) != 3 {
		t.Errorf("the 3 pre-existing archives must be untouched by the skipped commit, got %d: %v",
			len(remain), markerSet(remain))
	}

	// (4) RESUMES: the filesystem answers, the abandoned scan's result is
	// collected by the next call, and archival resumes at the confirmed seq.
	release()
	deadline := time.Now().Add(3 * time.Second)
	for s.archiveSeq.Load() != 102 && time.Now().Before(deadline) {
		s.SetArchiveConfig(archiveDir, 4)
		time.Sleep(5 * time.Millisecond)
	}
	if got := s.archiveSeq.Load(); got != 102 {
		t.Fatalf("after the archive dir answered, the abandoned scan's result must be collected: archiveSeq = %d, want 102", got)
	}
	// Still in configure mode from the commit above (Commit does not exit it).
	if err := s.SetFromInput("system host-name recovered-6776"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("commit after recovery: %v", err)
	}
	s.archiveWG.Wait()
	if got := s.archiveSeq.Load(); got < 103 {
		t.Errorf("after recovery the commit must archive past the on-disk max (102); archiveSeq = %d, want >= 103", got)
	}
	remain = archiveConfigText(t, archiveDir)
	if !hasMarker(remain, "host-name recovered-6776") {
		t.Errorf("archival must RESUME once the scan lands; surviving archives=%v", markerSet(remain))
	}
	if n := launches.Load(); n < 1 {
		t.Errorf("expected at least one scan launch, got %d", n)
	}
}

// TestReseedScanTimeoutNeverRewindsCounter6776 isolates the one outcome the
// on-disk assertions above cannot localise: a timeout that is mistaken for a
// readable-but-empty directory would STORE the scan's zero-value seq over a
// counter this process has already advanced, rewinding it. Every archive
// written afterwards would then carry a seq below the on-disk max and be pruned
// as stale.
//
// The fixture deliberately starts the counter at 41 — NOT at 0, which is both
// the zero value of archiveScanResult.seq and the value the bug falls back to.
// A fixture starting at 0 cannot tell "left alone" from "reseeded to 0".
//
// FAIL-ON-REVERT: applying res.seq on the timeout path (or returning a
// zero-valued result as if it had succeeded) stores 0 over 41 and reds this.
func TestReseedScanTimeoutNeverRewindsCounter6776(t *testing.T) {
	s := newTestStore(t)
	archiveDir := filepath.Join(t.TempDir(), "archive")
	if err := os.MkdirAll(archiveDir, 0o700); err != nil {
		t.Fatal(err)
	}
	s.archiveSeq.Store(41)

	const budget = 100 * time.Millisecond
	setArchiveScanBudget(t, budget)
	hangingArchiveReader(t, archiveDir)

	s.SetArchiveConfig(archiveDir, 4)

	if got := s.archiveSeq.Load(); got != 41 {
		t.Fatalf("a timed-out reseed scan must leave the monotonic counter alone: archiveSeq = %d, want 41 "+
			"(a rewind to 0 makes every later archive below-max and pruned as stale)", got)
	}
}

// TestReseedScanTimeoutStallsOnceNotPerCommit6776 guards the property that
// makes the fail-open choice affordable: a persistently unresponsive archive
// directory costs ONE budget-length stall for the whole process, not one per
// commit, and leaks ONE scan goroutine, not one per commit.
//
// Without the pending-scan reuse, each call would launch its own readdir(2) and
// pay its own budget — turning a wedged mount into a permanent per-commit
// latency tax on the config plane and an unbounded goroutine leak.
//
// FAIL-ON-REVERT: dropping the reuse branch in awaitArchiveScanLocked (always
// launching a fresh scan) makes the second and third calls each block a full
// budget and each launch a scan, reding both assertions.
func TestReseedScanTimeoutStallsOnceNotPerCommit6776(t *testing.T) {
	s := newTestStore(t)
	archiveDir := filepath.Join(t.TempDir(), "archive")
	if err := os.MkdirAll(archiveDir, 0o700); err != nil {
		t.Fatal(err)
	}

	const budget = 400 * time.Millisecond
	setArchiveScanBudget(t, budget)
	_, launches := hangingArchiveReader(t, archiveDir)

	// First call pays the budget once.
	s.SetArchiveConfig(archiveDir, 4)

	// Subsequent calls must poll the already-outstanding scan without blocking.
	start := time.Now()
	for i := 0; i < 3; i++ {
		s.SetArchiveConfig(archiveDir, 4)
	}
	elapsed := time.Since(start)
	if elapsed >= budget {
		t.Errorf("3 further calls against an already-known-unresponsive archive dir took %s "+
			"(>= one budget of %s): each is re-paying the stall instead of polling the outstanding scan", elapsed, budget)
	}
	if n := launches.Load(); n != 1 {
		t.Errorf("a persistently unresponsive archive dir must leak exactly ONE scan goroutine, "+
			"launched %d (one per call is an unbounded leak)", n)
	}
}

// TestReseedScanTimeoutDoesNotHoldStoreMutex6776 pins the half of the issue
// title that is about the LOCK rather than about boot. s.mu is the global store
// mutex — it gates Load, every Commit, and every config read — and
// SetArchiveConfig takes it for WRITING across the reseed scan. An unbounded
// scan therefore stalls not just its own caller but every concurrent reader of
// the configuration.
//
// FAIL-ON-REVERT: an unbounded scan holds the write lock for the full 5s safety
// valve, so the concurrent ActiveConfig read blocks far past the budget.
func TestReseedScanTimeoutDoesNotHoldStoreMutex6776(t *testing.T) {
	s := newTestStore(t)
	archiveDir := filepath.Join(t.TempDir(), "archive")
	if err := os.MkdirAll(archiveDir, 0o700); err != nil {
		t.Fatal(err)
	}

	const budget = 200 * time.Millisecond
	setArchiveScanBudget(t, budget)
	hangingArchiveReader(t, archiveDir)

	readDone := make(chan time.Duration, 1)
	started := make(chan struct{})
	go func() {
		close(started)
		// Give SetArchiveConfig time to be inside the scan wait holding s.mu.
		time.Sleep(budget / 4)
		t0 := time.Now()
		_ = s.ActiveConfig()
		readDone <- time.Since(t0)
	}()
	<-started
	s.SetArchiveConfig(archiveDir, 4)

	select {
	case blocked := <-readDone:
		if blocked > 20*budget {
			t.Errorf("a concurrent config read blocked %s behind the reseed scan (budget %s): "+
				"the scan is holding the global store mutex unbounded", blocked, budget)
		}
	case <-time.After(20 * budget):
		t.Errorf("a concurrent config read is still blocked behind the reseed scan after %s: "+
			"the scan is holding the global store mutex unbounded", 20*budget)
	}
}

// TestReseedScanTimeoutInvalidatesSeedMarkerOnReturn6776 guards the one part of
// the timeout path the fail-open test above cannot see: clearing
// archiveSeedDir. At cold boot the marker is already empty, so clearing it is a
// no-op there and a fixture built around boot stays GREEN with the clear
// deleted. The smallest shape where deleting it changes an OUTCOME is a dir
// SWITCH: A scans cleanly (marker = A), B times out, and the process returns to
// A. If the timeout did not invalidate the marker, the return to A finds
// marker == A and SKIPS the rescan — so an on-disk max that advanced in A while
// this process was pointed at B is never picked up, the counter stays low, and
// every archive written afterwards is below-max and pruned as stale.
//
// This is the #6404-adjacent invariant (A → failed-B → A re-scans A) extended
// to the #6776 timeout: a scan that did not answer leaves the counter exactly
// as unconfirmed as a scan that errored, so it must invalidate the marker for
// the same reason.
//
// FAIL-ON-REVERT: deleting `s.archiveSeedDir = ""` from the timeout branch
// leaves the marker at dirA, the return to dirA short-circuits as
// already-seeded, the counter stays at 5, and the archive written from it
// (seq 6, below the advanced max 100..102) is pruned by rotation — reding both
// the counter signal and the rotation outcome.
func TestReseedScanTimeoutInvalidatesSeedMarkerOnReturn6776(t *testing.T) {
	dirA := t.TempDir()
	dirB := t.TempDir()
	base := time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)

	// dirA holds seqs 1..5; configuring it seeds the counter to 5 and marks
	// dirA as the successfully-scanned dir.
	for seq := 1; seq <= 5; seq++ {
		ts := base.Add(time.Duration(seq) * time.Second)
		if err := writeArchive(dirA, 100, fmt.Sprintf("a-%d\n", seq), ts, uint64(seq)); err != nil {
			t.Fatal(err)
		}
	}
	s := &Store{}
	s.SetArchiveConfig(dirA, 3)
	if got := s.archiveSeq.Load(); got != 5 || s.archiveSeedDir != dirA {
		t.Fatalf("after configuring dirA, archiveSeq=%d seedDir=%q, want 5 / %q", got, s.archiveSeedDir, dirA)
	}

	// Navigate to dirB, whose scan does NOT ANSWER (unresponsive filesystem)
	// rather than erroring.
	const budget = 100 * time.Millisecond
	setArchiveScanBudget(t, budget)
	realReader := archiveDirReader
	hangUntil := make(chan struct{})
	archiveDirReader = func(string) ([]os.DirEntry, error) {
		select {
		case <-hangUntil:
		case <-time.After(5 * time.Second):
		}
		return nil, os.ErrPermission
	}
	s.SetArchiveConfig(dirB, 3)
	archiveDirReader = realReader
	t.Cleanup(func() { close(hangUntil) })

	// While this process was pointed at dirB, an external writer advanced
	// dirA's on-disk max to 100..102.
	for seq := 100; seq <= 102; seq++ {
		ts := base.Add(time.Duration(seq) * time.Second)
		if err := writeArchive(dirA, 100, fmt.Sprintf("a-%d\n", seq), ts, uint64(seq)); err != nil {
			t.Fatal(err)
		}
	}

	// Return to dirA. The timed-out dirB scan must have invalidated
	// archiveSeedDir, so this re-scans dirA and catches up to 102.
	s.SetArchiveConfig(dirA, 3)
	// Supporting signal (non-fatal so the REAL rotation assertion is load-bearing).
	if got := s.archiveSeq.Load(); got != 102 {
		t.Errorf("returning to dirA after a TIMED-OUT dirB scan must rescan dirA and catch up to "+
			"its advanced on-disk max (102); got %d", got)
	}

	// REAL rotation outcome: an archive written with the re-seeded counter must
	// survive, and the oldest pre-existing archive (a-100) must be pruned.
	seq := s.archiveSeq.Add(1) // 103, from the reseeded 102
	ts := base.Add(time.Duration(seq) * time.Second)
	if err := writeArchive(dirA, 3, "a-return-6776\n", ts, seq); err != nil {
		t.Fatal(err)
	}
	remain := archiveContents(t, dirA)
	if !remain["a-return-6776"] {
		t.Errorf("the archive written after returning to dirA must survive rotation (its "+
			"re-seeded seq outranks the advanced pre-existing max); remain=%v", remain)
	}
	if remain["a-100"] {
		t.Errorf("the oldest pre-existing archive (a-100) must be pruned; remain=%v", remain)
	}
	if len(remain) != 3 {
		t.Errorf("want 3 archives after rotation (max=3), got %d: %v", len(remain), remain)
	}
}
