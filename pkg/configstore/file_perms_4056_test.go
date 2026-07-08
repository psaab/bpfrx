package configstore

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// secretToken is an identifiable cleartext credential embedded in the
// committed config so the tests below can prove BOTH that the persisted
// copy really contains the secret (i.e. the exposure is real) AND that the
// file is not world-readable.
const secretToken = "SUPERSECRET-PSK-4056"

// commitSecretConfig enters configure, sets a secret-bearing leaf (an SNMP
// community — one of the credential leaves called out in #4056), and
// commits. It returns the store so the caller can inspect the persisted
// files.
func commitSecretConfig(t *testing.T, s *Store) {
	t.Helper()
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := s.SetFromInput("snmp community " + secretToken); err != nil {
		t.Fatalf("SetFromInput: %v", err)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
}

// assertOwnerOnlyFile fails the test unless path exists as a regular file
// with mode exactly 0600. This is the load-bearing #4056 assertion: it goes
// RED on revert (0644 world-readable).
func assertOwnerOnlyFile(t *testing.T, path string) {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if got := fi.Mode().Perm(); got != 0o600 {
		t.Errorf("%s mode = %#o, want 0600 (world-readable secrets defeat encryption, #4056)", path, got)
	}
}

// assertContainsSecret confirms the persisted copy actually holds the
// cleartext credential — so the 0600 assertion is guarding a real secret,
// not an empty file. (When master-password is unset the config text/JSON is
// cleartext; this is exactly the case the perms fix protects.)
func assertContainsSecret(t *testing.T, path string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if !strings.Contains(string(data), secretToken) {
		t.Fatalf("%s does not contain the committed secret %q; test is not exercising a secret-bearing file", path, secretToken)
	}
}

// TestRollbackSlotOwnerOnly_4056 pins that the text rollback slot
// (xpf.conf.1) — which always holds the full config text including cleartext
// secret leaves — is written 0600, and that the daemon can still read it
// back.
//
// RED on revert: saveRollbackFiles writes the slot 0644 (world-readable),
// so assertOwnerOnlyFile fails.
func TestRollbackSlotOwnerOnly_4056(t *testing.T) {
	s := newTestStore(t)
	// First commit lands the secret; a second commit pushes the
	// secret-bearing config into rollback slot 1 (history is prior states,
	// most-recent-first). Commit keeps the configure lock, so both commits
	// happen in one configure session.
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := s.SetFromInput("snmp community " + secretToken); err != nil {
		t.Fatalf("SetFromInput: %v", err)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("first Commit: %v", err)
	}
	if err := s.SetFromInput("system host-name post-secret"); err != nil {
		t.Fatalf("SetFromInput: %v", err)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("second Commit: %v", err)
	}

	slot1 := s.rollbackPath(1)
	assertContainsSecret(t, slot1)
	assertOwnerOnlyFile(t, slot1)

	// Read-back still works at 0600 (daemon owns the file). The text slots
	// are consumed by loadRollbackHistory; confirm the on-disk text is
	// readable by the owner.
	if _, rerr := os.ReadFile(slot1); rerr != nil {
		t.Fatalf("owner cannot read back 0600 rollback slot: %v", rerr)
	}
}

// TestActiveDBOwnerOnly_4056 pins that the active-config JSON DB
// (active.json) — full config, secrets cleartext when master-password is
// unset — is written 0600, and that the .configdb directory holding it (plus
// master.key) is 0700.
//
// RED on revert: writeTreeMarked writes 0644 and NewDB creates .configdb
// 0755.
func TestActiveDBOwnerOnly_4056(t *testing.T) {
	s := newTestStore(t)
	commitSecretConfig(t, s)

	dbDir := filepath.Join(filepath.Dir(s.filePath), ".configdb")
	active := filepath.Join(dbDir, "active.json")
	assertContainsSecret(t, active)
	assertOwnerOnlyFile(t, active)

	// Directory holding master.key + the config DB must be owner-only 0700.
	fi, err := os.Stat(dbDir)
	if err != nil {
		t.Fatalf("stat %s: %v", dbDir, err)
	}
	if got := fi.Mode().Perm(); got != 0o700 {
		t.Errorf(".configdb mode = %#o, want 0700 (#4056)", got)
	}

	// Read-back through the store must still work at 0600.
	if tree, err := s.db.ReadActive(); err != nil || tree == nil {
		t.Fatalf("owner cannot read back 0600 active DB: tree=%v err=%v", tree, err)
	}
}

// TestRescueConfigOwnerOnly_4056 pins that rescue.conf — the full active
// config text with cleartext secrets — is written 0600 and still loads back.
//
// RED on revert: SaveRescueConfig writes 0644.
func TestRescueConfigOwnerOnly_4056(t *testing.T) {
	s := newTestStore(t)
	commitSecretConfig(t, s)

	if err := s.SaveRescueConfig(); err != nil {
		t.Fatalf("SaveRescueConfig: %v", err)
	}
	rescue := s.rescuePath()
	assertContainsSecret(t, rescue)
	assertOwnerOnlyFile(t, rescue)

	txt, err := s.LoadRescueConfig()
	if err != nil {
		t.Fatalf("LoadRescueConfig: %v", err)
	}
	if !strings.Contains(txt, secretToken) {
		t.Fatalf("LoadRescueConfig could not read back the 0600 rescue config")
	}
}

// TestConfigJournalOwnerOnly_4579 pins that the commit audit journal
// (.config.journal) is written owner-only 0600 (#4579 A4-02, folding it into
// the #4056 secret-sweep). The journal records metadata (timestamps, actions,
// config hashes), but Detail carries the operator's free-text commit comment
// verbatim — which can inadvertently name a credential — so it matches the
// 0600 posture of the rest of the config surface rather than sitting
// world-readable.
//
// RED on revert: journal.Log opens the file 0644 (world-readable), so
// assertOwnerOnlyFile fails.
func TestConfigJournalOwnerOnly_4579(t *testing.T) {
	s := newTestStore(t)
	// A commit writes an audit record to .config.journal (journalLog on the
	// commit path). Use a commit comment so Detail is non-empty — the field
	// whose free-text content motivates the 0600 tightening.
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := s.SetFromInput("system host-name journal-perms-4579"); err != nil {
		t.Fatalf("SetFromInput: %v", err)
	}
	if _, err := s.CommitWithDescription("rotated the site psk"); err != nil {
		t.Fatalf("CommitWithDescription: %v", err)
	}

	journalPath := filepath.Join(filepath.Dir(s.filePath), ".config.journal")
	assertOwnerOnlyFile(t, journalPath)

	// Owner can still tail the journal at 0600 (the history view reads it).
	if _, err := os.ReadFile(journalPath); err != nil {
		t.Fatalf("owner cannot read back 0600 journal: %v", err)
	}
}

// TestArchiveOwnerOnly_4056 pins that a config archive file (config-*.conf,
// full config text with cleartext secrets) is written 0600 and its directory
// 0700.
//
// RED on revert: writeArchive writes the file 0644 and the dir 0755.
func TestArchiveOwnerOnly_4056(t *testing.T) {
	s := newTestStore(t)
	commitSecretConfig(t, s)

	archiveDir := filepath.Join(t.TempDir(), "archive")
	if err := s.ArchiveConfig(archiveDir, 10); err != nil {
		t.Fatalf("ArchiveConfig: %v", err)
	}

	fi, err := os.Stat(archiveDir)
	if err != nil {
		t.Fatalf("stat %s: %v", archiveDir, err)
	}
	if got := fi.Mode().Perm(); got != 0o700 {
		t.Errorf("archive dir mode = %#o, want 0700 (#4056)", got)
	}

	entries, err := os.ReadDir(archiveDir)
	if err != nil {
		t.Fatalf("read archive dir: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("no archive file was written")
	}
	for _, e := range entries {
		p := filepath.Join(archiveDir, e.Name())
		assertContainsSecret(t, p)
		assertOwnerOnlyFile(t, p)
	}
}
