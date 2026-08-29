package configstore

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// #7173: a zeroize that does not erase the config archive must not report
// success.
//
// FactoryResetArchiveDir refuses to erase a directory whose ownership it cannot
// prove — correct, because a custom/remote/compliance archive destination may
// hold records that are not xpf's to destroy. But it returned nil, so the
// caller could not tell that refusal apart from a completed erasure.
//
// The consequence was not theoretical. The archive holds config-<ts>.<seq>.conf
// snapshots: full committed config TEXT with cleartext secret leaves — IKE PSK,
// WireGuard keys, SNMP communities. An operator who ran zeroize on a box with a
// custom `system archival archive-dir` was told the reset completed while all of
// that was still on disk.
//
// Note the file's OWN contract, stated a few lines above the skip: a merely
// non-durable erasure "must not be reported as a clean zeroize". A skipped one
// did not happen at all, which is strictly worse, and it was the case that
// returned nil.

func TestCustomArchiveDirIsReportedNotSilentlySkipped7173(t *testing.T) {
	custom := t.TempDir()
	// Something that looks like an archived config carrying secrets.
	secret := filepath.Join(custom, "config-20260829.1.conf")
	if err := os.WriteFile(secret, []byte("ike { psk \"hunter2\"; }\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	err := FactoryResetArchiveDir(custom)

	var skipped *ArchiveDirSkippedError
	if !errors.As(err, &skipped) {
		t.Fatalf("erasing a custom archive dir returned %v, want an *ArchiveDirSkippedError. "+
			"Returning nil tells the caller the archive was erased when it was not, and the "+
			"caller reports a clean zeroize while the prior tenant's PSKs are still on disk "+
			"(#7173)", err)
	}
	if skipped.Dir != custom {
		t.Errorf("the error must name the directory the operator has to erase by hand; "+
			"got %q want %q", skipped.Dir, custom)
	}

	// The refusal must be a refusal: the guard exists so an unproven directory
	// is NOT destroyed. A "fix" that reported the skip and erased anyway would
	// pass the assertions above while doing the thing the guard forbids.
	if _, statErr := os.Stat(secret); statErr != nil {
		t.Errorf("the archive file was removed from a directory whose ownership could not "+
			"be proven: %v. The skip is deliberate — a custom/remote/compliance archive may "+
			"hold records xpf must not destroy", statErr)
	}
}

// Control: the xpf-owned default still erases cleanly and returns nil, so the
// change above cannot be satisfied by reporting a skip for everything.
func TestDefaultArchiveDirStillErasesCleanly7173(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "archive")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config-1.1.conf"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Point the default at our temp tree for the duration.
	orig := DefaultArchiveDir
	DefaultArchiveDir = dir
	defer func() { DefaultArchiveDir = orig }()

	if err := FactoryResetArchiveDir(dir); err != nil {
		t.Fatalf("the xpf-owned default must erase cleanly, got %v", err)
	}
	if _, statErr := os.Stat(dir); !os.IsNotExist(statErr) {
		t.Errorf("the default archive dir must be removed; stat gave %v", statErr)
	}
}
