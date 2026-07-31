package configstore

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestCommitReseedsAfterFailedScan is the #6404 edge-1 guard: a config COMMIT
// that lands in the window AFTER a SetArchiveConfig reseed scan FAILED (dir
// activated but counter still low, archiveSeedDir un-set to retry) but BEFORE
// the next SetArchiveConfig retry must re-attempt the reseed before it captures
// its archive seq — otherwise it writes an archive carrying a below-max seq that
// rotateArchives immediately prunes as stale, losing the just-committed config's
// archive while the pre-existing higher-seq archives survive.
//
// This drives the REAL production commit path (commitWithDescriptionLocked),
// not the SetArchiveConfig retry the #6396 test exercises, and asserts the REAL
// rotation outcome: the fresh commit's archive SURVIVES and the oldest
// pre-existing archive is pruned.
//
// FAIL-ON-REVERT: dropping the ensureArchiveSeededLocked() call in the commit
// archive path leaves the counter at 0, so the commit archives at seq 1 (below
// the pre-existing 100..102); rotateArchives(max=3) evicts it as the oldest and
// the "commit's archive survives" assertion goes RED.
func TestCommitReseedsAfterFailedScan(t *testing.T) {
	s := newTestStore(t)
	archiveDir := filepath.Join(t.TempDir(), "archive")
	base := time.Date(2026, 6, 28, 12, 0, 0, 0, time.UTC)

	// The target dir already holds high-seq archives (100..102) — e.g. written
	// by a prior process, or before this process last had the dir configured.
	for seq := 100; seq <= 102; seq++ {
		ts := base.Add(time.Duration(seq) * time.Second)
		if err := writeArchive(archiveDir, 100, fmt.Sprintf("pre-%d\n", seq), ts, uint64(seq)); err != nil {
			t.Fatal(err)
		}
	}

	// Configure archival to that dir, but the reseed scan FAILS (transient
	// mount/permission error). The dir is activated (archiveDir=archiveDir,
	// archiveMax=3) yet the counter stays 0 and the dir is left un-seeded so a
	// later call retries (#6396). This is the post-scan-failure window.
	injErr := errors.New("injected: reseed ReadDir EIO")
	prev := archiveDirReader
	archiveDirReader = func(string) ([]os.DirEntry, error) { return nil, injErr }
	s.SetArchiveConfig(archiveDir, 3)
	archiveDirReader = prev
	if got := s.archiveSeq.Load(); got != 0 {
		t.Fatalf("after the failed reseed scan, archiveSeq = %d, want 0 (un-seeded)", got)
	}

	// A commit lands in the window. With the fix it re-attempts the reseed (the
	// reader is restored, so the scan now succeeds), catches the counter up to
	// 102, and archives at 103 — which outranks the pre-existing entries.
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := s.SetFromInput("system host-name reseed-commit-6404"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	// Deterministically wait for the async auto-archive writer (Add(1) ran under
	// the commit lock, so it is already registered) to finish its write+rotate.
	s.archiveWG.Wait()

	// Supporting signal (non-fatal so the REAL rotation assertions below are the
	// load-bearing fail-on-revert check, not just the private counter): the
	// reseed should have caught the counter up past the on-disk max.
	if got := s.archiveSeq.Load(); got < 103 {
		t.Errorf("after the in-window commit, archiveSeq = %d, want >= 103 "+
			"(reseeded from the on-disk max 102 before capturing the commit seq)", got)
	}

	// REAL rotation outcome: the commit's archive must survive and the oldest
	// pre-existing archive (seq 100) must be pruned. Without the reseed the
	// commit's archive would carry seq 1 and be evicted as the oldest instead.
	remain := archiveConfigText(t, archiveDir)
	if !hasMarker(remain, "host-name reseed-commit-6404") {
		t.Errorf("the committed config's archive must survive rotation (its reseeded seq "+
			"outranks the pre-existing 100..102); surviving archives=%v", markerSet(remain))
	}
	if hasMarker(remain, "pre-100") {
		t.Errorf("the oldest pre-existing archive (pre-100) must be pruned; surviving archives=%v", markerSet(remain))
	}
	if len(remain) != 3 {
		t.Errorf("want 3 archives after rotation (max=3), got %d", len(remain))
	}
}

// TestSetArchiveConfigDisableReenableSameDirRescans is the #6404 edge-2 guard:
// disabling archival (SetArchiveConfig("")) must INVALIDATE archiveSeedDir, so a
// later re-enable to the SAME dir re-scans it. If the on-disk max in that dir
// advanced while archival was off (another process/tenant wrote there), the
// re-enable must catch the counter up — otherwise fresh archives carry a
// below-max seq and are pruned as stale.
//
// The test asserts the REAL rotation outcome: after A → "" → A (with the
// on-disk max advanced during the disabled window), an archive written with the
// re-seeded counter SURVIVES and the oldest pre-existing archive is pruned.
//
// FAIL-ON-REVERT: dropping the `s.archiveSeedDir = ""` invalidation on disable
// leaves archiveSeedDir == A, so the re-enable skips the rescan, the counter
// stays at the stale low value, the fresh archive is written below the advanced
// on-disk max, and the "fresh archive survives" assertion goes RED.
func TestSetArchiveConfigDisableReenableSameDirRescans(t *testing.T) {
	dirA := t.TempDir()
	base := time.Date(2026, 6, 28, 12, 0, 0, 0, time.UTC)

	// Initial state: dirA holds seqs 1..5; configuring it seeds the counter to 5.
	for seq := 1; seq <= 5; seq++ {
		ts := base.Add(time.Duration(seq) * time.Second)
		if err := writeArchive(dirA, 100, fmt.Sprintf("a-%d\n", seq), ts, uint64(seq)); err != nil {
			t.Fatal(err)
		}
	}
	s := &Store{}
	s.SetArchiveConfig(dirA, 3)
	if got := s.archiveSeq.Load(); got != 5 {
		t.Fatalf("after configuring dirA, archiveSeq = %d, want 5", got)
	}

	// Disable archival.
	s.SetArchiveConfig("", 3)

	// While archival is OFF, another process advances the on-disk max in dirA
	// (seqs 100..102). This process's counter still reads 5.
	for seq := 100; seq <= 102; seq++ {
		ts := base.Add(time.Duration(seq) * time.Second)
		if err := writeArchive(dirA, 100, fmt.Sprintf("a-%d\n", seq), ts, uint64(seq)); err != nil {
			t.Fatal(err)
		}
	}

	// Re-enable to the SAME dir. With the invalidation this rescans dirA and
	// catches the counter up to the advanced on-disk max (102).
	s.SetArchiveConfig(dirA, 3)
	// Supporting signal (non-fatal so the REAL rotation assertions below are the
	// load-bearing fail-on-revert check, not just the private counter).
	if got := s.archiveSeq.Load(); got != 102 {
		t.Errorf("re-enabling the same dir must rescan and catch the counter up to the "+
			"advanced on-disk max (102); got %d", got)
	}

	// REAL rotation outcome: an archive written with the re-seeded counter must
	// survive and the oldest pre-existing archive (a-100) must be pruned.
	seq := s.archiveSeq.Add(1) // 103, from the reseeded 102
	ts := base.Add(time.Duration(seq) * time.Second)
	if err := writeArchive(dirA, 3, "a-new-6404\n", ts, seq); err != nil {
		t.Fatal(err)
	}
	remain := archiveContents(t, dirA)
	if !remain["a-new-6404"] {
		t.Errorf("the freshly-written archive must survive rotation (its re-seeded seq "+
			"outranks the pre-existing 100..102); remain=%v", remain)
	}
	if remain["a-100"] {
		t.Errorf("the oldest pre-existing archive (a-100) must be pruned; remain=%v", remain)
	}
	if len(remain) != 3 {
		t.Errorf("want 3 archives after rotation (max=3), got %d: %v", len(remain), remain)
	}
}

// TestSetArchiveConfigDisableReenableNoOnDiskAdvanceNoRewind guards that the
// #6404 edge-2 invalidation does NOT regress the benign disable→re-enable case:
// when nothing advanced the on-disk max while archival was off, re-enabling the
// same dir re-scans it but the monotonic-up seed must NOT rewind the counter.
// This proves the seed stays max(current, on-disk), matching #6396.
func TestSetArchiveConfigDisableReenableNoOnDiskAdvanceNoRewind(t *testing.T) {
	dirA := t.TempDir()
	base := time.Date(2026, 6, 28, 12, 0, 0, 0, time.UTC)
	for seq := 1; seq <= 5; seq++ {
		ts := base.Add(time.Duration(seq) * time.Second)
		if err := writeArchive(dirA, 100, fmt.Sprintf("a-%d\n", seq), ts, uint64(seq)); err != nil {
			t.Fatal(err)
		}
	}
	s := &Store{}
	s.SetArchiveConfig(dirA, 3)
	// Advance the process counter past the on-disk max WITHOUT writing (as a
	// stream of commits would), so a naive re-scan-and-store would rewind it.
	s.archiveSeq.Store(50)

	s.SetArchiveConfig("", 3)   // disable — clears archiveSeedDir
	s.SetArchiveConfig(dirA, 3) // re-enable — rescans, but on-disk max (5) < 50

	if got := s.archiveSeq.Load(); got != 50 {
		t.Fatalf("re-enabling a dir whose on-disk max (5) is below the counter (50) must NOT "+
			"rewind it (monotonic-up seed); got %d", got)
	}
	if s.archiveSeedDir != dirA {
		t.Fatalf("after a successful re-enable rescan, archiveSeedDir = %q, want %q", s.archiveSeedDir, dirA)
	}
}

// TestCommitDoubleScanFailureSkipsBelowMaxArchive is the #6404 Codex round-2
// MAJOR guard: when BOTH the SetArchiveConfig reseed scan AND the commit-time
// rescan fail (a persistent scan error), the commit path must NOT write an
// archive at the still-low counter. The on-disk max is unknown, so a below-max
// archive would carry a seq beneath the pre-existing entries — mis-ranked by the
// seq-ordered retention and pruned out of chronological order (or immediately,
// when the dir is full). Skipping this commit's archive (it archives on the next
// successful commit) is strictly safer.
//
// The dir holds 3 pre-existing archives and max=4, so a below-max write is NOT
// pruned — its PRESENCE is directly observable. This is the REAL rotation
// outcome (an extra, mis-seq'd file on disk), not a private-counter check.
//
// FAIL-ON-REVERT: reverting the readiness gate (writing unconditionally after
// the scan failure) makes the double-failure commit write a seq-1 archive that
// survives (4 <= max), so the dir holds 4 files including the below-max marker —
// the "no below-max archive / exactly the 3 pre-existing survive" assertions go
// RED. The recovery phase then confirms a post-recovery commit archives normally
// at the confirmed seq.
func TestCommitDoubleScanFailureSkipsBelowMaxArchive(t *testing.T) {
	s := newTestStore(t)
	archiveDir := filepath.Join(t.TempDir(), "archive")
	base := time.Date(2026, 6, 28, 12, 0, 0, 0, time.UTC)

	// The (existing) target dir already holds high-seq archives 100..102.
	for seq := 100; seq <= 102; seq++ {
		ts := base.Add(time.Duration(seq) * time.Second)
		if err := writeArchive(archiveDir, 100, fmt.Sprintf("pre-%d\n", seq), ts, uint64(seq)); err != nil {
			t.Fatal(err)
		}
	}

	// A PERSISTENT scan error: the seam fails for both the SetArchiveConfig
	// reseed AND the commit-time rescan. max=4 (> the 3 pre-existing) so a
	// below-max write would survive rotation and be directly observable.
	injErr := errors.New("injected: persistent ReadDir EIO")
	prev := archiveDirReader
	archiveDirReader = func(string) ([]os.DirEntry, error) { return nil, injErr }
	s.SetArchiveConfig(archiveDir, 4)
	if got := s.archiveSeq.Load(); got != 0 {
		t.Fatalf("after the failed reseed scan, archiveSeq = %d, want 0 (un-seeded)", got)
	}

	// A commit lands while the scan is STILL failing. The reseed cannot confirm
	// the on-disk max, so the archive must be skipped (no below-max write).
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := s.SetFromInput("system host-name dbl-fail-6404"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("commit (scan failing): %v", err)
	}
	// If a writer was (wrongly) launched, wait for it so the assertion sees the
	// settled dir; if it was correctly skipped, Wait returns immediately.
	s.archiveWG.Wait()

	remain := archiveConfigText(t, archiveDir)
	if hasMarker(remain, "host-name dbl-fail-6404") {
		t.Errorf("a commit during a persistent scan failure must NOT write a below-max "+
			"archive (the seq is unconfirmed); surviving archives=%v", markerSet(remain))
	}
	if len(remain) != 3 {
		t.Errorf("the 3 pre-existing archives must be untouched by the skipped commit, got %d: %v",
			len(remain), markerSet(remain))
	}
	for _, w := range []string{"pre-100", "pre-101", "pre-102"} {
		if !hasMarker(remain, w) {
			t.Errorf("pre-existing archive %q must remain; surviving=%v", w, markerSet(remain))
		}
	}

	// Recovery: the scan now succeeds. The next commit re-seeds from the on-disk
	// max (102) and archives at a confirmed seq (103) that survives rotation.
	archiveDirReader = prev
	if err := s.SetFromInput("system host-name recovered-6404"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("commit (scan recovered): %v", err)
	}
	s.archiveWG.Wait()

	if got := s.archiveSeq.Load(); got < 103 {
		t.Errorf("after recovery the commit must reseed past the on-disk max (102) and archive "+
			"at >= 103; archiveSeq = %d", got)
	}
	remain = archiveConfigText(t, archiveDir)
	if !hasMarker(remain, "host-name recovered-6404") {
		t.Errorf("the post-recovery commit must archive normally at the confirmed seq; surviving=%v",
			markerSet(remain))
	}
}

// TestSetArchiveConfigFailedNewDirRescansOriginalOnReturn is the #6404 adjacent
// guard (Codex): after a FAILED scan of a NEW dir, archiveSeedDir must be
// invalidated, so navigating back to the ORIGINAL dir re-scans it. Otherwise
// A → failed-B → A leaves archiveSeedDir == A and the return to A skips the
// rescan; if A's on-disk max advanced while this process was pointed at B (an
// external writer), the counter stays low and fresh archives are pruned as
// stale.
//
// FAIL-ON-REVERT: reverting the archiveSeedDir="" clear on a genuine scan error
// leaves archiveSeedDir == dirA after B's failed scan, so the return to dirA
// skips the rescan, the counter stays at dirA's stale max, and the fresh archive
// carries a below-max seq that rotation prunes — the "fresh archive survives"
// assertion goes RED.
func TestSetArchiveConfigFailedNewDirRescansOriginalOnReturn(t *testing.T) {
	dirA := t.TempDir()
	dirB := t.TempDir()
	base := time.Date(2026, 6, 28, 12, 0, 0, 0, time.UTC)

	// dirA holds seqs 1..5; configuring it seeds the counter to 5.
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

	// Navigate to dirB, but the scan of dirB FAILS (transient error).
	injErr := errors.New("injected: dirB ReadDir EIO")
	prev := archiveDirReader
	archiveDirReader = func(string) ([]os.DirEntry, error) { return nil, injErr }
	s.SetArchiveConfig(dirB, 3)
	archiveDirReader = prev

	// While this process was pointed at dirB, an external writer advanced dirA's
	// on-disk max to 100..102.
	for seq := 100; seq <= 102; seq++ {
		ts := base.Add(time.Duration(seq) * time.Second)
		if err := writeArchive(dirA, 100, fmt.Sprintf("a-%d\n", seq), ts, uint64(seq)); err != nil {
			t.Fatal(err)
		}
	}

	// Return to dirA. The failed dirB scan must have invalidated archiveSeedDir,
	// so this re-scans dirA and catches the counter up to the advanced max (102).
	s.SetArchiveConfig(dirA, 3)
	// Supporting signal (non-fatal so the REAL rotation assertion is load-bearing).
	if got := s.archiveSeq.Load(); got != 102 {
		t.Errorf("returning to dirA after a failed dirB scan must rescan dirA and catch up to "+
			"its advanced on-disk max (102); got %d", got)
	}

	// REAL rotation outcome: an archive written with the re-seeded counter must
	// survive and the oldest pre-existing archive (a-100) must be pruned.
	seq := s.archiveSeq.Add(1) // 103, from the reseeded 102
	ts := base.Add(time.Duration(seq) * time.Second)
	if err := writeArchive(dirA, 3, "a-return-6404\n", ts, seq); err != nil {
		t.Fatal(err)
	}
	remain := archiveContents(t, dirA)
	if !remain["a-return-6404"] {
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

// archiveConfigText reads dir and returns the raw contents of every archive
// file present, for asserting rotation outcomes on multi-line config text (the
// commit path writes the formatted active tree, not a one-line marker).
func archiveConfigText(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range ents {
		if e.IsDir() {
			continue
		}
		d, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, string(d))
	}
	return out
}

func hasMarker(texts []string, marker string) bool {
	for _, tx := range texts {
		if strings.Contains(tx, marker) {
			return true
		}
	}
	return false
}

// markerSet renders a compact view of which archive markers survived, for
// failure messages (avoids dumping full multi-line config text).
func markerSet(texts []string) []string {
	var out []string
	for _, tx := range texts {
		first := tx
		if i := strings.IndexByte(tx, '\n'); i >= 0 {
			first = tx[:i]
		}
		out = append(out, first)
	}
	return out
}
