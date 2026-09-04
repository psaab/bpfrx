package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestTraceDirSymlinkIsRefused8482 is the #8482 gate.
//
// `openTraceFile` hardened the FILE against symlink redirection and left the
// PARENT unchecked. `MkdirAll` stats THROUGH a symlink, so a pre-existing
// symlink at traceLogDir pointing to a directory made it return nil — and the
// O_NOFOLLOW open then applied to <target>/<name>, a real file at the
// redirected location rather than a symlink, so it passed too. Root-written
// flow telemetry landed in the attacker-chosen directory with both guards
// reporting success.
//
// Six prior archived reviews marked this confinement "VERIFIED SAFE", and each
// of them checked the file. That is why the cell drives the DIRECTORY.
//
// Severity, pinned here so it is not re-filed higher: defence in depth, not a
// live escape. Planting the symlink needs write access to /var/log (0755,
// root-owned); the CLI user supplies only the trigger. Those are two
// capabilities held by two parties.
func TestTraceDirSymlinkIsRefused8482(t *testing.T) {
	orig := traceLogDir
	t.Cleanup(func() { traceLogDir = orig })

	t.Run("a symlink to an existing directory is refused", func(t *testing.T) {
		base := t.TempDir()
		// The redirect target must EXIST as a directory: a dangling symlink
		// already failed at MkdirAll with "file exists", so that is not the
		// case this closes and a fixture using one would pass vacuously.
		target := filepath.Join(base, "attacker-chosen")
		if err := os.MkdirAll(target, 0o700); err != nil {
			t.Fatalf("fixture: %v", err)
		}
		link := filepath.Join(base, "trace-link")
		if err := os.Symlink(target, link); err != nil {
			t.Skipf("symlinks unavailable here: %v", err)
		}
		traceLogDir = link

		f, path, err := openTraceFile("flow.log")
		if f != nil {
			f.Close()
		}
		if err == nil {
			t.Fatalf("a symlinked trace dir was accepted and %q was opened — "+
				"root-written flow telemetry would land under %s (#8482)", path, target)
		}
		// Assert on a phrase containing a SPACE, not on the bare word.
		// `t.TempDir()` embeds the SUBTEST NAME in its path, the path lands in
		// the error string, and this subtest's name contains "symlink" — so a
		// `Contains(err, "symlink")` check passed on the test's own name. A
		// mutation removing the symlink branch escaped, because the fallback
		// "not a directory" error still carried the word in its path.
		if !strings.Contains(err.Error(), "is a symlink;") {
			t.Errorf("refused for the wrong reason — the symlink branch did not "+
				"fire: %v", err)
		}
		// The sharp half: nothing may have been created at the redirect target.
		// An error return with the file already written would be a guard that
		// reports failure after doing the damage.
		if entries, rerr := os.ReadDir(target); rerr == nil && len(entries) != 0 {
			t.Errorf("the refusal still wrote %d entry/entries into the redirect "+
				"target: %v", len(entries), entries)
		}
	})

	t.Run("a non-directory at the trace path is refused", func(t *testing.T) {
		base := t.TempDir()
		file := filepath.Join(base, "not-a-dir")
		if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
			t.Fatalf("fixture: %v", err)
		}
		traceLogDir = file

		f, _, err := openTraceFile("flow.log")
		if f != nil {
			f.Close()
		}
		if err == nil {
			t.Fatal("a regular file standing in for the trace dir was accepted")
		}
		if !strings.Contains(err.Error(), "exists and is not a directory") {
			t.Errorf("refused for the wrong reason: %v", err)
		}
	})

	// CONTROLS. Without these the guard is satisfied by refusing everything,
	// which would disable flow tracing entirely — a strictly worse outcome than
	// the hardening gap it replaces.
	t.Run("a real directory still works", func(t *testing.T) {
		traceLogDir = filepath.Join(t.TempDir(), "traces")
		f, path, err := openTraceFile("flow.log")
		if err != nil {
			t.Fatalf("an ordinary trace dir must still open: %v", err)
		}
		f.Close()
		if filepath.Dir(path) != traceLogDir {
			t.Errorf("opened %q, want it under %q", path, traceLogDir)
		}
	})

	t.Run("an absent trace dir is still created", func(t *testing.T) {
		// The pre-existing behaviour: MkdirAll creates it. The Lstat guard must
		// not turn "not there yet" into a refusal, which is the first day of
		// every fresh install.
		traceLogDir = filepath.Join(t.TempDir(), "a", "b", "traces")
		f, _, err := openTraceFile("flow.log")
		if err != nil {
			t.Fatalf("an absent trace dir must still be created: %v", err)
		}
		f.Close()
		fi, err := os.Lstat(traceLogDir)
		if err != nil || !fi.IsDir() {
			t.Fatalf("trace dir was not created as a directory: %v", err)
		}
	})
}
