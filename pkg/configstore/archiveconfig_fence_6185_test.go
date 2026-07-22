package configstore

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// archiveSecret6185 stands in for any prior-tenant secret that lands in an
// archived config snapshot (IKE PSK, WireGuard private key, SNMP community).
// The synchronous ArchiveConfig path drops the same 0600 copies of the full
// committed config TEXT the async writer does, so a resurrected archive carries
// such leaves in cleartext.
const archiveSecret6185 = "PRIOR-TENANT-SECRET-6185"

// commitSecret6185 commits a config carrying a recognizable secret so a leaked
// archive is detectable, mirroring the #5869 residue shape.
func commitSecret6185(t *testing.T, s *Store, marker string) {
	t.Helper()
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := s.SetFromInput("system host-name " + marker); err != nil {
		t.Fatalf("SetFromInput: %v", err)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	// Release the configure lock so a later commit in the same test can
	// re-enter (the fence→resume cycle commits twice).
	s.ExitConfigure()
}

// TestArchiveConfigFencedDoesNotRecreateArchiveDir pins the #6185 fix: the
// SYNCHRONOUS archive path (Store.ArchiveConfig) must honor the #5869/#6182
// archive fence exactly like the async auto-archive launch guard. ArchiveConfig
// has ZERO production callers today, but if it is ever wired to an operator
// command (e.g. `request system configuration archive`) a call that ran AFTER a
// factory reset (zeroize) set the fence and erased the archive directory would
// MkdirAll it back and drop a config-<ts>.<seq>.conf snapshot of the PRIOR
// tenant's full config text — the exact re-tenant secret residue #5869 closed
// for the async path.
//
// RED on revert: neutralize the `if s.archiveFenced.Load() { ... return nil }`
// guard at the top of ArchiveConfig. The fenced call then falls through to
// writeArchive, whose os.MkdirAll recreates the archive directory the zeroize
// was erasing — the Stat assertion below trips (the directory reappears).
func TestArchiveConfigFencedDoesNotRecreateArchiveDir(t *testing.T) {
	// ArchiveConfig writes to the explicit archiveDir argument, so a throwaway
	// subdir that does not exist yet is enough — no DefaultArchiveDir repoint.
	dir := filepath.Join(t.TempDir(), "archive")

	s := newTestStore(t)
	commitSecret6185(t, s, archiveSecret6185)

	// Zeroize sequence: fence archival. With no async writer outstanding
	// (SetArchiveConfig was never called, so no commit launched one) the JOIN in
	// QuiesceArchival returns immediately; only the fence remains set.
	s.QuiesceArchival()

	// The synchronous archive path must now be a silent no-op and MUST NOT
	// recreate the archive directory the wipe is erasing.
	if err := s.ArchiveConfig(dir, 10); err != nil {
		t.Fatalf("fenced ArchiveConfig should be a silent no-op, got err: %v", err)
	}

	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		names := archiveDirEntries(dir)
		t.Fatalf("fenced ArchiveConfig recreated the archive directory (zeroize "+
			"secret residue): stat err=%v, entries=%v", err, names)
	}
}

// TestArchiveConfigUnfencedArchivesNormally is the CONTROL for the fence guard:
// with no fence set, the synchronous ArchiveConfig path still writes exactly one
// snapshot carrying the committed config text. It proves the #6185 guard
// defaults to ALLOWING archival (the fence starts false) and that the added
// archiveWG.Add/Done tracking did not break the ordinary synchronous path.
func TestArchiveConfigUnfencedArchivesNormally(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "archive")

	s := newTestStore(t)
	commitSecret6185(t, s, archiveSecret6185)

	if err := s.ArchiveConfig(dir, 10); err != nil {
		t.Fatalf("un-fenced ArchiveConfig: %v", err)
	}

	// Synchronous path: the write has completed by the time ArchiveConfig
	// returns, so no polling is needed.
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("archive directory not created by un-fenced ArchiveConfig: %v", err)
	}
	if len(ents) != 1 {
		t.Fatalf("un-fenced ArchiveConfig must write exactly one snapshot, got %d", len(ents))
	}
	body, err := os.ReadFile(filepath.Join(dir, ents[0].Name()))
	if err != nil {
		t.Fatalf("read archive file: %v", err)
	}
	if !strings.Contains(string(body), archiveSecret6185) {
		t.Fatalf("archive did not capture the committed config text; got:\n%s", body)
	}
}

// TestQuiesceArchivalJoinsInflightSyncArchiveConfig pins the JOIN half of the
// #6185 fix for the synchronous path: an ArchiveConfig call that has already
// passed the fence check (fence was false when it captured the config) and is
// MID-WRITE must be JOINED by a concurrent QuiesceArchival before the wipe, so
// the write cannot land AFTER the archive directory is erased. The fence alone
// cannot close this write-after-wipe window — only tracking the synchronous
// writer in archiveWG (Add before the write, Done after) lets QuiesceArchival
// wait it out.
//
// The writer is held mid-flight at archiveWriteBarrier — deliberately PAST the
// fence check — so the fence cannot mask a missing join.
//
// RED on revert: neutralize the `s.archiveWG.Add(1)` in ArchiveConfig.
// QuiesceArchival's Wait() then sees a zero counter and returns immediately
// (the wipe runs while the writer is still blocked), so `done` fires before the
// writer is released — tripping the "QuiesceArchival returned before joining"
// assertion below.
func TestQuiesceArchivalJoinsInflightSyncArchiveConfig(t *testing.T) {
	dir := useTempArchiveDefault(t) // archive dir == the ownership-guarded default so FactoryResetArchiveDir actually wipes

	s := newTestStore(t)
	commitSecret6185(t, s, archiveSecret6185)

	// Hold the synchronous archive writer MID-FLIGHT: past the fence check (so
	// the fence cannot mask a missing join) and before the actual write.
	release := make(chan struct{})
	started := make(chan struct{})
	var once sync.Once
	old := archiveWriteBarrier
	archiveWriteBarrier = func() {
		once.Do(func() { close(started) })
		<-release
	}
	t.Cleanup(func() { archiveWriteBarrier = old })

	// Launch the synchronous archive. It Add(1)s to archiveWG under the store
	// lock (fence is false), then blocks in the barrier past the fence check.
	archiveErr := make(chan error, 1)
	go func() { archiveErr <- s.ArchiveConfig(dir, 10) }()

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("synchronous archive writer never reached the barrier")
	}

	// Run the daemon's factory-reset sequence: QuiesceArchival (fence + JOIN)
	// then the archive-dir wipe. QuiesceArchival must block joining the in-flight
	// synchronous writer, so drive it from a goroutine.
	done := make(chan struct{})
	go func() {
		s.QuiesceArchival()             // JOIN: with the fix, blocks until the writer is done
		_ = FactoryResetArchiveDir(dir) // wipe: RemoveAll + parent fsync
		close(done)
	}()

	// QuiesceArchival must be BLOCKED joining the in-flight synchronous writer:
	// the wipe must not run yet. Without the archiveWG.Add(1) in ArchiveConfig,
	// QuiesceArchival returns immediately and `done` fires here — the exact race.
	select {
	case <-done:
		t.Fatal("QuiesceArchival returned before joining the in-flight synchronous " +
			"ArchiveConfig — the wipe raced the write (missing archiveWG tracking)")
	case <-time.After(100 * time.Millisecond):
		// Still blocked in Wait() — the join is holding, as intended.
	}

	// Release the writer; it writes then Done()s, QuiesceArchival's Wait returns,
	// and the wipe runs AFTER the write — so the write is erased, no residue.
	close(release)

	if err := <-archiveErr; err != nil {
		t.Fatalf("synchronous ArchiveConfig: %v", err)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("factory-reset sequence (QuiesceArchival + wipe) did not complete")
	}

	// The write landed BEFORE the wipe (QuiesceArchival joined it), so the wipe
	// erased it: no archive directory / prior-tenant snapshot survives.
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		names := archiveDirEntries(dir)
		t.Fatalf("archive directory survived zeroize after a joined synchronous "+
			"write: stat err=%v, entries=%v", err, names)
	}
}

// TestResumeArchivalReenablesCommitArchival covers the #6185 second note: the
// only prior fail-path test (pkg/daemon factory_reset_5281_test.go) drives a
// bare Daemon{} with a nil store, so it exercises the `d.store != nil` guard —
// NOT the real fence-clear in ResumeArchival. This drives the store directly:
// fence archival (as a factory reset would), prove the fence blocks a commit's
// auto-archive, then ResumeArchival (the fail-closed recoverable wipe path) and
// prove the fence is cleared AND a subsequent commit archives normally again —
// the WaitGroup is reusable and no state is corrupt.
func TestResumeArchivalReenablesCommitArchival(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "archive")

	s := newTestStore(t)
	s.SetArchiveConfig(dir, 10)

	// Fence archival, as daemon.factoryReset does before the wipe.
	s.QuiesceArchival()
	if !s.archiveFenced.Load() {
		t.Fatal("QuiesceArchival did not set the archive fence")
	}

	// While fenced, a commit must NOT launch/write an auto-archive: the launch
	// guard reads the fence under s.mu.
	commitSecret6185(t, s, archiveSecret6185+"-fenced")
	time.Sleep(200 * time.Millisecond) // give any (erroneously launched) writer time
	s.archiveWG.Wait()                 // join anything in flight (there should be none)
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		names := archiveDirEntries(dir)
		t.Fatalf("a fenced commit archived (zeroize residue window): entries=%v", names)
	}

	// Fail-closed recoverable wipe path: the daemon stays up and resumes normal
	// config work, so it clears the fence.
	s.ResumeArchival()
	if s.archiveFenced.Load() {
		t.Fatal("ResumeArchival did not clear the archive fence")
	}

	// A subsequent commit must archive normally again — the WaitGroup is reusable
	// (its counter returned to zero and Wait() completed), the fence is cleared,
	// and no state is corrupt.
	commitSecret6185(t, s, archiveSecret6185+"-resumed")

	deadline := time.Now().Add(2 * time.Second)
	var ents []os.DirEntry
	for time.Now().Before(deadline) {
		if e, err := os.ReadDir(dir); err == nil && len(e) >= 1 {
			ents = e
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if len(ents) != 1 {
		t.Fatalf("post-resume commit must archive exactly one snapshot, got %d", len(ents))
	}
	body, err := os.ReadFile(filepath.Join(dir, ents[0].Name()))
	if err != nil {
		t.Fatalf("read archive file: %v", err)
	}
	if !strings.Contains(string(body), archiveSecret6185+"-resumed") {
		t.Fatalf("post-resume archive did not capture the committed config text; got:\n%s", body)
	}
}

// archiveDirEntries lists an archive directory's file names for failure
// messages; it returns nil when the directory is absent.
func archiveDirEntries(dir string) []string {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	names := make([]string, 0, len(ents))
	for _, e := range ents {
		names = append(names, e.Name())
	}
	return names
}
