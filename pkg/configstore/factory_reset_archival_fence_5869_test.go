package configstore

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// archiveSecret5869 stands in for any prior-tenant secret that lands in an
// archived config snapshot. writeArchive drops 0600 copies of the full
// committed config TEXT, so a resurrected archive carries such leaves in
// cleartext (IKE PSK, WireGuard private key, SNMP community).
const archiveSecret5869 = "PRIOR-TENANT-SECRET-5869"

// TestQuiesceArchivalJoinsInflightWriterBeforeWipe pins the #5869 fix: a
// factory reset must JOIN an in-flight async archive writer before it erases the
// archive directory, so a writer that has already started cannot recreate a
// config-<ts>.<seq>.conf snapshot of the PRIOR tenant's config AFTER the wipe —
// zeroize secret residue on a re-tenanted device.
//
// Auto-archive launches a fire-and-forget writer goroutine per commit
// (commitWithDescriptionLocked). The #5281 terminal reset generation gates the
// daemon's config writers but NOT that configstore-owned goroutine, so before
// #5869 a writer scheduled just before a zeroize could resume after
// FactoryResetArchiveDir removed /var/lib/xpf/archive and MkdirAll + write the
// prior tenant's archive right back.
//
// This reproduces the exact race deterministically: a commit launches the
// writer, the writer blocks MID-FLIGHT at archiveWriteBarrier — deliberately
// PAST the goroutine fence check, so the fence cannot mask a missing join — and
// then the daemon's factory-reset sequence runs QuiesceArchival() (fence + JOIN)
// followed by the archive-dir wipe. The writer is released only after
// QuiesceArchival has begun joining it.
//
// RED on revert: neutralize the `s.archiveWG.Wait()` line in QuiesceArchival
// (the JOIN). QuiesceArchival then returns without waiting, the wipe runs while
// the writer is still blocked, and when the writer is released it MkdirAll's the
// archive dir and writes the prior-tenant snapshot AFTER the wipe — the file
// survives and the assertions below trip.
func TestQuiesceArchivalJoinsInflightWriterBeforeWipe(t *testing.T) {
	dir := useTempArchiveDefault(t) // archive dir == the ownership-guarded default

	s := newTestStore(t)
	s.SetArchiveConfig(dir, 10)

	// Hold the archive writer MID-FLIGHT: past the fence check (so the fence
	// cannot mask a missing join) and before the actual write.
	release := make(chan struct{})
	started := make(chan struct{})
	var once sync.Once
	old := archiveWriteBarrier
	archiveWriteBarrier = func() {
		once.Do(func() { close(started) })
		<-release
	}
	t.Cleanup(func() { archiveWriteBarrier = old })

	// A commit whose config text carries a recognizable secret launches the
	// writer (Commit -> CommitWithDescription("") archives).
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := s.SetFromInput("system host-name " + archiveSecret5869); err != nil {
		t.Fatalf("SetFromInput: %v", err)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}

	// Wait until the writer is blocked in the barrier (in-flight, past the fence).
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("archive writer never reached the barrier")
	}

	// Run the daemon's factory-reset sequence: QuiesceArchival (fence + JOIN)
	// then the archive-dir wipe. QuiesceArchival blocks joining the in-flight
	// writer, so drive it from a goroutine and release the writer once the join
	// is under way.
	done := make(chan struct{})
	go func() {
		s.QuiesceArchival()             // JOIN: with the fix, blocks until the writer is done
		_ = FactoryResetArchiveDir(dir) // wipe: RemoveAll + parent fsync
		close(done)
	}()

	// Give the factory-reset goroutine a moment to run, then release the writer.
	// With the fix QuiesceArchival is now blocked in Wait() joining this writer,
	// so the wipe runs only after the write. WITHOUT the join QuiesceArchival
	// returns immediately and the wipe has already run against the absent dir by
	// now — the exact race — so the writer, once released, recreates the archive
	// AFTER the wipe.
	time.Sleep(50 * time.Millisecond)
	close(release)

	// Wait for the writer goroutine itself to fully finish (in-package access to
	// the tracking WaitGroup) BEFORE asserting. This is what makes the revert
	// deterministically RED: without the JOIN in QuiesceArchival, `done` fires
	// early (before the writer is released), so the assertion must independently
	// wait out the writer's post-wipe recreation instead of racing it.
	s.archiveWG.Wait()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("factory-reset sequence (QuiesceArchival + wipe) did not complete")
	}

	// The archive directory — and any prior-tenant snapshot in it — must be gone.
	if ents, err := os.ReadDir(dir); err == nil {
		names := make([]string, 0, len(ents))
		for _, e := range ents {
			names = append(names, e.Name())
		}
		t.Fatalf("archive directory recreated after zeroize: a resumed writer resurrected the prior-tenant archive: %v", names)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("archive directory still present after zeroize (stat err=%v)", err)
	}
}

// TestAutoArchiveStillWritesWithoutQuiesce is the CONTROL: a normal commit (no
// factory reset) still archives. It proves the #5869 launch guard defaults to
// ALLOWING archival (the fence starts false) and that tracking the writer in the
// WaitGroup did not break the ordinary auto-archive path. It polls for the async
// writer's output (mirroring TestAutoArchiveCapturesCommittedTreeNoOverwrite)
// rather than draining via QuiesceArchival — the latter would fence a
// not-yet-started writer into a no-op and race this control.
func TestAutoArchiveStillWritesWithoutQuiesce(t *testing.T) {
	dir := useTempArchiveDefault(t)

	s := newTestStore(t)
	s.SetArchiveConfig(dir, 10)

	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := s.SetFromInput("system host-name " + archiveSecret5869); err != nil {
		t.Fatalf("SetFromInput: %v", err)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}

	// Let the async writer finish.
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
		t.Fatalf("normal commit must archive exactly one snapshot, got %d", len(ents))
	}
	body, err := os.ReadFile(filepath.Join(dir, ents[0].Name()))
	if err != nil {
		t.Fatalf("read archive file: %v", err)
	}
	if !strings.Contains(string(body), archiveSecret5869) {
		t.Fatalf("archive did not capture the committed config text; got:\n%s", body)
	}
}
