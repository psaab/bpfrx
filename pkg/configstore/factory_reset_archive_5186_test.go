package configstore

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/fsatomic"
)

// archiveSecret5186 stands in for any prior-tenant secret that lands in an
// archived config snapshot: an IKE PSK, a WireGuard private key, an SNMP
// community. The archive files are 0600 copies of the full committed config
// TEXT, so they carry these leaves in cleartext.
const archiveSecret5186 = "MARKER-SECRET-5186-ike-psk"

// useTempArchiveDefault repoints the ownership-guard default at a throwaway
// tree for the test's lifetime and returns that path. Production code never
// mutates DefaultArchiveDir; only the zeroize tests do.
func useTempArchiveDefault(t *testing.T) string {
	t.Helper()
	old := DefaultArchiveDir
	dir := filepath.Join(t.TempDir(), "archive")
	DefaultArchiveDir = dir
	t.Cleanup(func() { DefaultArchiveDir = old })
	return dir
}

// seedArchiveFile writes a 0600 archive snapshot carrying the marker secret,
// mirroring writeArchive's config-<ts>.<seq>.conf naming and mode.
func seedArchiveFile(t *testing.T, archiveDir string) string {
	t.Helper()
	if err := os.MkdirAll(archiveDir, 0o700); err != nil {
		t.Fatalf("mkdir archive dir: %v", err)
	}
	path := filepath.Join(archiveDir, "config-20260101-000000.000000000.00000000000000000001.conf")
	body := "system {\n  ike { psk \"" + archiveSecret5186 + "\"; }\n}\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("seed archive file: %v", err)
	}
	return path
}

// TestFactoryResetArchiveDirErasesSecrets pins the #5186 fix: a factory reset
// must erase the xpf-owned local config archive. A pre-#5186 zeroize wiped the
// .configdb SSOT / rollback / rendered configs / login accounts but LEFT
// /var/lib/xpf/archive, so a re-tenanted device kept the prior tenant's
// archived cleartext secrets — the omitted on-box generation of config secrets.
//
// RED on revert: neutralize the os.RemoveAll(archiveDir) line in
// FactoryResetArchiveDir and the secret file survives, tripping the assertion
// below (the pre-#5186 world, where no zeroize step touched the archive).
func TestFactoryResetArchiveDirErasesSecrets(t *testing.T) {
	dir := useTempArchiveDefault(t)
	secretFile := seedArchiveFile(t, dir)

	if err := FactoryResetArchiveDir(dir); err != nil {
		t.Fatalf("FactoryResetArchiveDir returned error: %v", err)
	}

	if _, err := os.Stat(secretFile); !os.IsNotExist(err) {
		t.Errorf("archive secret file still present after zeroize (stat err=%v)", err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("archive directory still present after zeroize (stat err=%v)", err)
	}
}

// TestFactoryResetArchiveDirSkipsCustomPath pins the OWNERSHIP GUARD: an
// operator-configured CUSTOM archive path (a remote mount, NFS export, or a
// compliance/audit retention store) is NOT xpf's to destroy. It must survive
// the zeroize untouched, and the skip must be SURFACED as a warning so the
// operator knows to erase it out-of-band — never a blind fail-closed delete.
func TestFactoryResetArchiveDirSkipsCustomPath(t *testing.T) {
	root := t.TempDir()
	// Default (the guard's allowlisted path) is distinct from the custom dir
	// the operator pointed archival at.
	old := DefaultArchiveDir
	DefaultArchiveDir = filepath.Join(root, "default-archive")
	t.Cleanup(func() { DefaultArchiveDir = old })

	customDir := filepath.Join(root, "compliance-archive")
	secretFile := seedArchiveFile(t, customDir)

	buf := captureWarnLogs(t)
	// #7173 CHANGED THIS CONTRACT DELIBERATELY. The skip used to return nil,
	// which let the caller report a clean zeroize while the prior tenant's
	// archived PSKs were still on disk. It now returns a typed
	// *ArchiveDirSkippedError so the incompleteness is a first-class result.
	//
	// What this test is ABOUT is unchanged and still asserted below: a custom
	// path is skipped rather than erased, and its contents survive. Only the
	// return value moved, so the assertion moved with it rather than the test
	// being deleted.
	err := FactoryResetArchiveDir(customDir)
	var skipped *ArchiveDirSkippedError
	if !errors.As(err, &skipped) {
		t.Fatalf("FactoryResetArchiveDir(custom) returned %v, want an "+
			"*ArchiveDirSkippedError naming the unerased directory (#7173)", err)
	}

	// The custom archive and its secret survive.
	if _, err := os.Stat(secretFile); err != nil {
		t.Errorf("custom archive secret must survive zeroize, stat err=%v", err)
	}

	// The skip is surfaced as a warning that names the skipped path.
	logged := buf.String()
	if !strings.Contains(logged, "unproven") || !strings.Contains(logged, customDir) {
		t.Errorf("expected an ownership-guard warning naming the skipped custom dir; got log:\n%s", logged)
	}
}

// TestFactoryResetArchiveDirPropagatesSyncError pins durability-error
// surfacing: a final directory-fsync FAILURE must be returned, not swallowed —
// a wipe whose unlink never reached stable storage must not be reported as a
// clean factory reset. Deterministic (seam-injected), so it holds regardless of
// the test uid.
//
// RED on revert: dropping the rbSyncDir(parent) barrier makes
// FactoryResetArchiveDir return nil here.
func TestFactoryResetArchiveDirPropagatesSyncError(t *testing.T) {
	restoreRollbackSeams(t)
	dir := useTempArchiveDefault(t)
	seedArchiveFile(t, dir)

	sentinel := errors.New("injected archive dir fsync failure")
	parent := filepath.Dir(dir)
	rbSyncDir = func(d string) error {
		if filepath.Clean(d) == filepath.Clean(parent) {
			return sentinel
		}
		return fsatomic.SyncDir(d)
	}

	err := FactoryResetArchiveDir(dir)
	if err == nil {
		t.Fatalf("FactoryResetArchiveDir must surface a dir-fsync failure, got nil")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("returned error = %v, want it to wrap the injected fsync failure", err)
	}
}

// TestFactoryResetArchiveDirPropagatesRemoveError pins that a DELETION failure
// is surfaced, not silently swallowed: with the archive directory made
// read-only, RemoveAll cannot unlink the snapshot inside it, and that error
// must be returned so the caller does not report a clean zeroize while a
// secret-bearing archive file remains.
func TestFactoryResetArchiveDirPropagatesRemoveError(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root: a read-only dir does not block unlinks")
	}
	dir := useTempArchiveDefault(t)
	seedArchiveFile(t, dir)

	// Drop write permission on the archive dir so the inner unlink fails EACCES.
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("chmod archive dir read-only: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) }) // let t.TempDir cleanup proceed

	err := FactoryResetArchiveDir(dir)
	if err == nil {
		t.Fatalf("FactoryResetArchiveDir must surface a deletion failure, got nil")
	}
}

// TestFactoryResetArchiveDirAbsentIsClean is the negative control: an absent
// archive dir (archival was never configured / never wrote a snapshot) is a
// clean no-op — os.ErrNotExist is the goal, not an error.
func TestFactoryResetArchiveDirAbsentIsClean(t *testing.T) {
	dir := useTempArchiveDefault(t) // never created
	if err := FactoryResetArchiveDir(dir); err != nil {
		t.Fatalf("FactoryResetArchiveDir on an absent archive returned error: %v", err)
	}
}
