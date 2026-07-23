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

// TestParseArchiveSeqRejectsLegacyNanoseconds is the #6396 C179-060 residual
// guard for parseArchiveSeq. A legacy pre-#3441 archive is named
// config-<ts>.conf where <ts> = "20060102-150405.000000000" — a subsecond ts
// whose single dot separates seconds from nanoseconds. The pre-fix parse took
// the LAST dot-delimited field as the seq, so it read a legacy name's
// nanoseconds ("123456789") as a huge sequence. In a MIXED legacy+current
// archive dir that mis-key corrupts the seq-ordered prune: legacy entries are
// ranked by their nanosecond fraction instead of ordering as the oldest.
//
// FAIL-ON-REVERT: dropping the "ts dot must be present" check restores the
// nanoseconds-as-seq parse — this test's ok=false assertion goes RED.
func TestParseArchiveSeqRejectsLegacyNanoseconds(t *testing.T) {
	// Legacy: config-<ts-with-nanos>.conf, no separate seq field.
	legacyTS := time.Date(2026, 6, 28, 12, 0, 0, 123456789, time.UTC)
	legacy := fmt.Sprintf("config-%s.conf", legacyTS.Format("20060102-150405.000000000"))
	if seq, ok := parseArchiveSeq(legacy); ok {
		t.Errorf("parseArchiveSeq(%q) = (%d, true); a legacy config-<ts>.conf must be "+
			"unparseable so its nanoseconds are not mis-read as a sequence (#6396)", legacy, seq)
	}

	// Current: config-<ts>.<seq>.conf — two dots, still parses to the real seq.
	cur := fmt.Sprintf("config-%s.%020d.conf", legacyTS.Format("20060102-150405.000000000"), uint64(7))
	if seq, ok := parseArchiveSeq(cur); !ok || seq != 7 {
		t.Errorf("parseArchiveSeq(%q) = (%d, %v), want (7, true)", cur, seq, ok)
	}
}

// TestRotateArchivesLegacyPrunedBeforeCurrent is the retention consequence of
// the parse fix: in a MIXED dir, every legacy config-<ts>.conf must rank as
// older than any current config-<ts>.<seq>.conf and be pruned first, so the
// newest current archives survive.
//
// FAIL-ON-REVERT: with the legacy nanoseconds parsed as a seq, a legacy file
// with a large nanosecond fraction outranks a small-seq current archive and is
// retained over it — the "current survives, legacy pruned" assertions go RED.
func TestRotateArchivesLegacyPrunedBeforeCurrent(t *testing.T) {
	dir := t.TempDir()
	base := time.Date(2026, 6, 28, 12, 0, 0, 0, time.UTC)

	// Two legacy files with LARGE nanosecond fractions (would parse as huge
	// bogus seqs under the old code) — these predate the current scheme and
	// must be the first evicted.
	for i, nanos := range []int{900000000, 800000000} {
		ts := base.Add(time.Duration(i) * time.Second).Add(time.Duration(nanos) * time.Nanosecond)
		name := fmt.Sprintf("config-%s.conf", ts.Format("20060102-150405.000000000"))
		if err := os.WriteFile(filepath.Join(dir, name), []byte(fmt.Sprintf("legacy-%d\n", i)), 0600); err != nil {
			t.Fatal(err)
		}
	}
	// Two current files with SMALL seqs (1, 2). These are the newest by the
	// true commit order and must be retained.
	for seq := 1; seq <= 2; seq++ {
		ts := base.Add(time.Duration(10+seq) * time.Second)
		if err := writeArchive(dir, 100, fmt.Sprintf("current-%d\n", seq), ts, uint64(seq)); err != nil {
			t.Fatal(err)
		}
	}

	// Keep only the 2 newest of the 4 files.
	rotateArchives(dir, 2)

	remain := map[string]bool{}
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 2 {
		t.Fatalf("want 2 archives after prune (max=2), got %d", len(ents))
	}
	for _, e := range ents {
		d, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		remain[strings.TrimSpace(string(d))] = true
	}
	for _, w := range []string{"current-1", "current-2"} {
		if !remain[w] {
			t.Errorf("current archive %q must be retained over any legacy file; remain=%v", w, remain)
		}
	}
	for _, w := range []string{"legacy-0", "legacy-1"} {
		if remain[w] {
			t.Errorf("legacy archive %q must be pruned before any current file; remain=%v", w, remain)
		}
	}
}

// TestSetArchiveConfigReseedsOnDirSwitch is the #6396 C179-060 residual guard
// for the runtime archive-dir switch. archiveSeq is seeded once from the
// original dir; a later switch to a DIFFERENT previously-used dir whose existing
// archives carry HIGHER seqs must re-seed the counter from that dir. Without the
// re-seed, this process keeps its lower counter and the archives it writes to
// the new dir carry seqs BELOW the pre-existing ones — so the seq-ordered prune
// evicts the fresh archives as if they were the oldest.
//
// FAIL-ON-REVERT: dropping the dir-change re-seed (leaving only the seq==0
// guard) leaves archiveSeq at the first dir's max after the switch — the
// "reseeded to dirB's max" assertion goes RED.
func TestSetArchiveConfigReseedsOnDirSwitch(t *testing.T) {
	dirA := t.TempDir()
	dirB := t.TempDir()
	base := time.Date(2026, 6, 28, 12, 0, 0, 0, time.UTC)

	// dirA holds seqs 1..5; dirB (a previously-used dir) holds seqs 100..102.
	for seq := 1; seq <= 5; seq++ {
		ts := base.Add(time.Duration(seq) * time.Second)
		if err := writeArchive(dirA, 100, fmt.Sprintf("a-%d\n", seq), ts, uint64(seq)); err != nil {
			t.Fatal(err)
		}
	}
	for seq := 100; seq <= 102; seq++ {
		ts := base.Add(time.Duration(seq) * time.Second)
		if err := writeArchive(dirB, 100, fmt.Sprintf("b-%d\n", seq), ts, uint64(seq)); err != nil {
			t.Fatal(err)
		}
	}

	s := &Store{}
	s.SetArchiveConfig(dirA, 3)
	if got := s.archiveSeq.Load(); got != 5 {
		t.Fatalf("after configuring dirA, archiveSeq = %d, want 5 (dirA max)", got)
	}

	// Runtime switch to dirB: the counter must jump to dirB's higher max so the
	// next archive written there outranks the pre-existing 100..102.
	s.SetArchiveConfig(dirB, 3)
	if got := s.archiveSeq.Load(); got != 102 {
		t.Fatalf("after switching to dirB, archiveSeq must re-seed to dirB's max (102) so a new "+
			"archive there is not outranked by the pre-existing ones (#6396); got %d", got)
	}

	// Prove the REAL rotation outcome, not just the private counter: an archive
	// written to dirB with the reseeded counter must SURVIVE rotation (its seq
	// now outranks the pre-existing 100..102) and the oldest pre-existing
	// archive must be pruned. Without the reseed the new file would carry a seq
	// below 100 and be pruned as stale instead.
	seq := s.archiveSeq.Add(1) // 103, from the reseeded 102
	ts := base.Add(time.Duration(seq) * time.Second)
	if err := writeArchive(dirB, 3, "b-new\n", ts, seq); err != nil {
		t.Fatal(err)
	}
	remain := archiveContents(t, dirB)
	if !remain["b-new"] {
		t.Errorf("the freshly-written archive must survive rotation (its reseeded seq outranks "+
			"the pre-existing ones); remain=%v", remain)
	}
	if remain["b-100"] {
		t.Errorf("the oldest pre-existing archive (b-100) must be pruned; remain=%v", remain)
	}
	if len(remain) != 3 {
		t.Errorf("want 3 archives after rotation (max=3), got %d: %v", len(remain), remain)
	}

	// Switching to an empty dir must NOT rewind the monotonic counter.
	dirEmpty := t.TempDir()
	s.SetArchiveConfig(dirEmpty, 3)
	if got := s.archiveSeq.Load(); got != 103 {
		t.Fatalf("switching to an empty dir rewound archiveSeq to %d, want it held at 103 "+
			"(seed is monotonic-up only)", got)
	}
}

// TestSetArchiveConfigReseedScanErrorDoesNotRegress is the #6396 Codex MINOR 4
// guard: a transient failure to READ the archive dir during the reseed scan
// must NOT pin the monotonic counter below the on-disk max. maxArchiveSeq now
// distinguishes a read error from an empty dir, and SetArchiveConfig leaves the
// counter unchanged AND the dir un-seeded on error, so the next call retries.
//
// FAIL-ON-REVERT: treating a scan error as an empty dir (seed 0 + mark the dir
// seeded) means the retry call skips the rescan and the counter stays stuck —
// the "retry catches up to 202" assertion goes RED.
func TestSetArchiveConfigReseedScanErrorDoesNotRegress(t *testing.T) {
	base := time.Date(2026, 6, 28, 12, 0, 0, 0, time.UTC)
	dirA := t.TempDir()
	for seq := 1; seq <= 5; seq++ {
		ts := base.Add(time.Duration(seq) * time.Second)
		if err := writeArchive(dirA, 100, fmt.Sprintf("a-%d\n", seq), ts, uint64(seq)); err != nil {
			t.Fatal(err)
		}
	}
	dirB := t.TempDir()
	for seq := 200; seq <= 202; seq++ {
		ts := base.Add(time.Duration(seq) * time.Second)
		if err := writeArchive(dirB, 100, fmt.Sprintf("b-%d\n", seq), ts, uint64(seq)); err != nil {
			t.Fatal(err)
		}
	}

	s := &Store{}
	s.SetArchiveConfig(dirA, 3)
	if got := s.archiveSeq.Load(); got != 5 {
		t.Fatalf("after dirA, archiveSeq = %d, want 5", got)
	}

	// Switch to dirB, but the scan fails (transient mount/permission error).
	injErr := errors.New("injected: ReadDir EIO")
	prev := archiveDirReader
	archiveDirReader = func(string) ([]os.DirEntry, error) { return nil, injErr }
	s.SetArchiveConfig(dirB, 3)
	archiveDirReader = prev

	// The counter must NOT have regressed (stays 5, not dropped to 0), and dirB
	// must NOT be recorded as seeded.
	if got := s.archiveSeq.Load(); got != 5 {
		t.Fatalf("a failed reseed scan regressed archiveSeq to %d, want it held at 5", got)
	}

	// Retry: the scan now succeeds and must RESCAN dirB (not skip it), catching
	// the counter up to dirB's on-disk max (202).
	s.SetArchiveConfig(dirB, 3)
	if got := s.archiveSeq.Load(); got != 202 {
		t.Fatalf("after a failed scan the next same-dir call must rescan and catch up to "+
			"dirB's max (202); got %d", got)
	}
}

// archiveContents reads dir and returns the set of trimmed archive-file
// contents present, for asserting rotation outcomes.
func archiveContents(t *testing.T, dir string) map[string]bool {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	for _, e := range ents {
		d, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		out[strings.TrimSpace(string(d))] = true
	}
	return out
}
