package configstore

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestArchiveConfigSeedsFromDirBeforeClaimingSeq is the #6403 guard for the
// synchronous archive mirror (Store.ArchiveConfig). archiveSeq is a
// process-global counter that SetArchiveConfig seeds from whatever dir it last
// activated — possibly a different or empty dir. ArchiveConfig, however, writes
// to the dir passed as a PARAMETER (decoupled from s.archiveDir), so the shared
// counter can sit BELOW that dir's on-disk max. The old code captured the seq
// off that stale counter (under RLock, then wrote off-lock), so it wrote an
// archive carrying a below-max seq that rotateArchives (#5523 seq-ordered
// retention) immediately prunes as stale — losing the just-written archive
// while the pre-existing higher-seq archives survive.
//
// The fix seeds the counter from the TARGET dir's on-disk max (monotonic-up,
// under the write lock) BEFORE claiming the seq, mirroring the commit path's
// ensureArchiveSeededLocked (#6404), so the claimed seq always outranks the
// dir's existing contents.
//
// This asserts the REAL rotation outcome (per the #6404-round lesson): the
// fresh archive SURVIVES and the oldest pre-existing archive is pruned — not
// just the private counter.
//
// FAIL-ON-REVERT: neutralizing the `s.archiveSeq.Store(seed)` seed leaves the
// counter at 0, so ArchiveConfig claims seq 1 (below the pre-existing 100..102);
// rotateArchives(max=3) evicts the fresh archive as the oldest and the "fresh
// archive survives" assertion goes RED.
func TestArchiveConfigSeedsFromDirBeforeClaimingSeq(t *testing.T) {
	s := newTestStore(t)
	archiveDir := filepath.Join(t.TempDir(), "archive")
	base := time.Date(2026, 6, 28, 12, 0, 0, 0, time.UTC)

	// The target dir already holds high-seq archives (100..102) — e.g. written
	// by a prior process, or before this process last had a DIFFERENT dir
	// configured. The store's process-global archiveSeq is still 0 (never
	// seeded from this dir): the stale-counter condition ArchiveConfig must
	// self-heal before it claims a seq.
	for seq := 100; seq <= 102; seq++ {
		ts := base.Add(time.Duration(seq) * time.Second)
		if err := writeArchive(archiveDir, 100, fmt.Sprintf("pre-%d\n", seq), ts, uint64(seq)); err != nil {
			t.Fatal(err)
		}
	}
	if got := s.archiveSeq.Load(); got != 0 {
		t.Fatalf("precondition: archiveSeq = %d, want 0 (never seeded from the target dir)", got)
	}

	// Put a unique marker in the active config so the archive ArchiveConfig
	// writes is identifiable in the surviving set. Archival is NOT configured
	// (s.archiveDir == ""), so this commit does not auto-archive and does not
	// bump the counter — the counter stays 0 until ArchiveConfig seeds it.
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := s.SetFromInput("system host-name archive-offlock-6403"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}

	// The synchronous mirror. With the fix it seeds from the target dir (max
	// 102) before claiming, so it archives at 103 — which outranks 100..102.
	if err := s.ArchiveConfig(archiveDir, 3); err != nil {
		t.Fatalf("ArchiveConfig: %v", err)
	}

	// Supporting signal (non-fatal so the REAL rotation assertions below are the
	// load-bearing fail-on-revert check, not just the private counter).
	if got := s.archiveSeq.Load(); got < 103 {
		t.Errorf("after ArchiveConfig, archiveSeq = %d, want >= 103 (seeded from the "+
			"on-disk max 102 before claiming the seq)", got)
	}

	// REAL rotation outcome: the fresh archive must survive and the oldest
	// pre-existing archive (seq 100) must be pruned. Without the seed the fresh
	// archive would carry seq 1 and be evicted as the oldest instead.
	remain := archiveConfigText(t, archiveDir)
	if !hasMarker(remain, "host-name archive-offlock-6403") {
		t.Errorf("the synchronous archive must survive rotation (its seeded seq outranks "+
			"the pre-existing 100..102); surviving archives=%v", markerSet(remain))
	}
	if hasMarker(remain, "pre-100") {
		t.Errorf("the oldest pre-existing archive (pre-100) must be pruned; surviving archives=%v", markerSet(remain))
	}
	if len(remain) != 3 {
		t.Errorf("want 3 archives after rotation (max=3), got %d", len(remain))
	}
}

// TestArchiveConfigClaimSeqAtomicVsConcurrentReseed reproduces the adversarial
// interleaving from the #6403 report: an ArchiveConfig write racing a
// SetArchiveConfig reseed. The synchronous writer is held MID-FLIGHT at
// archiveWriteBarrier — deliberately PAST its seq claim and lock release, before
// the actual off-lock write — and a concurrent SetArchiveConfig switches to a
// DIFFERENT dir with a much higher on-disk max, reseeding the process-global
// archiveSeq UPWARD in that off-lock window.
//
// With the fix ArchiveConfig has already seeded from its OWN target dir and
// claimed its seq under the write lock BEFORE releasing, so the concurrent
// reseed cannot retro-affect the archive it is about to write: it lands with a
// seq that outranks its dir's contents and survives rotation.
//
// FAIL-ON-REVERT: reverting to the RLock + no-seed capture makes the held
// writer claim seq 1 off the still-0 counter; the concurrent reseed to dirB's
// max is irrelevant to dirA, and the seq-1 archive is below dirA's pre-existing
// 100..102, so rotateArchives(max=3) prunes it and the survival assertion goes
// RED.
func TestArchiveConfigClaimSeqAtomicVsConcurrentReseed(t *testing.T) {
	s := newTestStore(t)
	dirA := filepath.Join(t.TempDir(), "archiveA")
	dirB := filepath.Join(t.TempDir(), "archiveB")
	base := time.Date(2026, 6, 28, 12, 0, 0, 0, time.UTC)

	// dirA (ArchiveConfig's target) holds 100..102; dirB (the concurrent
	// reseed's target) holds much-higher 500..502.
	for seq := 100; seq <= 102; seq++ {
		ts := base.Add(time.Duration(seq) * time.Second)
		if err := writeArchive(dirA, 100, fmt.Sprintf("preA-%d\n", seq), ts, uint64(seq)); err != nil {
			t.Fatal(err)
		}
	}
	for seq := 500; seq <= 502; seq++ {
		ts := base.Add(time.Duration(seq) * time.Second)
		if err := writeArchive(dirB, 100, fmt.Sprintf("preB-%d\n", seq), ts, uint64(seq)); err != nil {
			t.Fatal(err)
		}
	}

	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := s.SetFromInput("system host-name archive-race-6403"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}

	// Hold the synchronous writer mid-flight: it has already seeded from dirA
	// and claimed its seq under the write lock, released the lock, and is now
	// blocked before the off-lock write.
	release := make(chan struct{})
	started := make(chan struct{})
	var once sync.Once
	old := archiveWriteBarrier
	archiveWriteBarrier = func() {
		once.Do(func() { close(started) })
		<-release
	}
	t.Cleanup(func() { archiveWriteBarrier = old })

	archiveErr := make(chan error, 1)
	go func() { archiveErr <- s.ArchiveConfig(dirA, 3) }()

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("synchronous archive writer never reached the barrier")
	}

	// The off-lock window: a concurrent SetArchiveConfig switches to dirB and
	// reseeds the process-global counter UPWARD (to dirB's max 502). The write
	// lock is free because the held writer already released it.
	s.SetArchiveConfig(dirB, 3)
	if got := s.archiveSeq.Load(); got < 502 {
		t.Fatalf("concurrent SetArchiveConfig(dirB) should have reseeded archiveSeq to >= 502, got %d", got)
	}

	// Release the held writer; it performs its off-lock write to dirA.
	close(release)
	if err := <-archiveErr; err != nil {
		t.Fatalf("synchronous ArchiveConfig: %v", err)
	}

	// The fresh dirA archive must have survived rotation: its seq was claimed
	// from dirA's on-disk max under the write lock BEFORE the concurrent reseed,
	// so it outranks dirA's pre-existing 100..102.
	remain := archiveConfigText(t, dirA)
	if !hasMarker(remain, "host-name archive-race-6403") {
		t.Errorf("the raced synchronous archive must survive rotation (its seq was claimed "+
			"under the lock before the concurrent reseed); surviving archives in dirA=%v", markerSet(remain))
	}
	if hasMarker(remain, "preA-100") {
		t.Errorf("the oldest pre-existing dirA archive (preA-100) must be pruned; surviving archives=%v", markerSet(remain))
	}
	if len(remain) != 3 {
		t.Errorf("want 3 archives in dirA after rotation (max=3), got %d", len(remain))
	}
}

// TestArchiveConfigLockIsExclusiveAcrossSeedClaim pins the #6403 EXCLUSIVITY
// invariant that the two seed-from-target tests above do NOT: ArchiveConfig must
// hold the store WRITE lock (not RLock) across the seed scan + seq claim, so two
// concurrent PARAMETERIZED ArchiveConfig calls cannot interleave their
// Load→Store→Add of the process-global archiveSeq. Under a shared RLock both
// calls can pass their `seed > Load()` check against the same stale counter and
// then clobber each other's Store, so one claims a seq below its target dir's
// on-disk max and writes a below-max archive that rotateArchives prunes — the
// #6403 bug, silently reintroduced by a future RLock regression that the
// seed-from-target tests would still pass (they exercise a single call).
//
// The discriminator is deterministic and BOUNDED (never a hang): the first
// ArchiveConfig is held INSIDE its seed scan (the archiveDirReader seam, called
// by maxArchiveSeq under the lock) while it holds the lock; a second
// ArchiveConfig launched concurrently must NOT reach its OWN seed scan within a
// bounded window — under the exclusive Lock it blocks on s.mu.Lock(); under a
// shared RLock it would acquire the read lock and proceed to its scan.
//
// FAIL-ON-REVERT: revert ArchiveConfig's s.mu.Lock→s.mu.RLock (and the paired
// Unlock→RUnlock), keeping the seed store. The second call then reaches its scan
// while the first is blocked, secondScanEntered fires inside the window, and the
// exclusivity assertion goes clean RED. Restore to green.
func TestArchiveConfigLockIsExclusiveAcrossSeedClaim(t *testing.T) {
	s := newTestStore(t)
	dir1 := filepath.Join(t.TempDir(), "archive1")
	dir2 := filepath.Join(t.TempDir(), "archive2")
	base := time.Date(2026, 6, 28, 12, 0, 0, 0, time.UTC)

	// dir1 pre-seeded 100..102; dir2 pre-seeded 200..202. The process counter is
	// 0 (never seeded), so EACH ArchiveConfig must seed from ITS dir before
	// claiming — and must do so under an exclusive lock so the two seeds cannot
	// race and clobber the shared counter.
	for seq := 100; seq <= 102; seq++ {
		ts := base.Add(time.Duration(seq) * time.Second)
		if err := writeArchive(dir1, 100, fmt.Sprintf("pre1-%d\n", seq), ts, uint64(seq)); err != nil {
			t.Fatal(err)
		}
	}
	for seq := 200; seq <= 202; seq++ {
		ts := base.Add(time.Duration(seq) * time.Second)
		if err := writeArchive(dir2, 100, fmt.Sprintf("pre2-%d\n", seq), ts, uint64(seq)); err != nil {
			t.Fatal(err)
		}
	}

	// Some active config to format into each archive.
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := s.SetFromInput("system host-name archive-excl-6403"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}

	// Seam: block the FIRST ArchiveConfig inside its seed scan (holding the
	// store lock), and signal when a SECOND scan is entered. archiveDirReader is
	// the maxArchiveSeq reader, called under the lock; rotateArchives uses
	// os.ReadDir directly, so it never trips this hook. NOT t.Parallel — the seam
	// is a package global (the sibling tests share this seam idiom).
	firstScanEntered := make(chan struct{})
	secondScanEntered := make(chan struct{}, 1)
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseFn := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(releaseFn) // unblock the held scan even if the test fails early

	var scans atomic.Int32
	old := archiveDirReader
	archiveDirReader = func(dir string) ([]os.DirEntry, error) {
		if scans.Add(1) == 1 {
			close(firstScanEntered)
			<-release
		} else {
			select {
			case secondScanEntered <- struct{}{}:
			default:
			}
		}
		return old(dir)
	}
	t.Cleanup(func() { archiveDirReader = old })

	err1 := make(chan error, 1)
	err2 := make(chan error, 1)
	go func() { err1 <- s.ArchiveConfig(dir1, 3) }()

	// The first call is now inside its seed scan, holding the lock.
	select {
	case <-firstScanEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("first ArchiveConfig never reached its seed scan")
	}

	// Launch the second while the first holds the lock.
	go func() { err2 <- s.ArchiveConfig(dir2, 3) }()

	// EXCLUSIVITY discriminator: under the write lock the second call blocks on
	// s.mu.Lock() and cannot reach its own seed scan; under RLock it would. A
	// bounded wait, so a regression fails as a clean assertion, never a hang.
	select {
	case <-secondScanEntered:
		t.Fatal("second ArchiveConfig reached its seed scan while the first holds the " +
			"store lock — the lock is not exclusive (RLock regression). Two concurrent " +
			"seed Load→Store→Add can then clobber archiveSeq and write a below-max archive (#6403)")
	case <-time.After(500 * time.Millisecond):
		// Blocked on s.mu.Lock(), as the exclusive lock requires.
	}

	// Release the first; both now complete serially under the exclusive lock.
	releaseFn()
	for i, ec := range []chan error{err1, err2} {
		select {
		case err := <-ec:
			if err != nil {
				t.Fatalf("ArchiveConfig #%d: %v", i+1, err)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("ArchiveConfig #%d did not complete", i+1)
		}
	}

	// Correctness: each fresh archive survived rotation with a seq above its
	// dir's pre-existing max, and the two claims are strictly increasing (the
	// SERIALIZED seed+claim advanced the shared counter monotonically — the
	// first-entered call claims below the second).
	top1 := topSeqInDir(t, dir1)
	top2 := topSeqInDir(t, dir2)
	if top1 <= 102 {
		t.Errorf("dir1 fresh archive did not survive rotation: top seq %d, want > 102", top1)
	}
	if top2 <= 202 {
		t.Errorf("dir2 fresh archive did not survive rotation: top seq %d, want > 202", top2)
	}
	if top1 >= top2 {
		t.Errorf("serialized claims must be strictly increasing: dir1 top %d, dir2 top %d "+
			"(the first-entered call must claim below the second)", top1, top2)
	}
}

// topSeqInDir returns the highest parseable archive seq present in dir, for
// asserting that a dir's fresh (highest-seq) archive survived rotation.
func topSeqInDir(t *testing.T, dir string) uint64 {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var top uint64
	for _, e := range ents {
		if e.IsDir() {
			continue
		}
		if seq, ok := parseArchiveSeq(e.Name()); ok && seq > top {
			top = seq
		}
	}
	return top
}
