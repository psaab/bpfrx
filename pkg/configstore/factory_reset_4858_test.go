package configstore

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// zeroizeSecret4858 is a distinctive cleartext SNMP community that must not
// survive a factory reset nor reappear when a fresh Store loads the wiped dir.
const zeroizeSecret4858 = "ZEROIZE-SECRET-4858-snmp-community"

// TestFactoryResetConfigDirWipesSSOTAndSecrets pins #4858: `request system
// zeroize` must delete the authoritative config DB (.configdb — active /
// candidate / rollback trees + master.key) and the audit journal, not just the
// legacy top-level *.conf / rollback* files. Before the fix the CLI wipe left
// .configdb + master.key + .config.journal behind, so a fresh Store.Load
// resurrected the prior tenant's committed config + secrets on the next boot.
//
// RED on revert: neutering FactoryResetConfigDir to the old .conf-only wipe
// leaves .configdb/master.key/active.json in place — the assertAbsent checks
// and the "reloaded store still empty" check both fail.
func TestFactoryResetConfigDirWipesSSOTAndSecrets(t *testing.T) {
	dir := t.TempDir()
	configBase := "xpf.conf"
	configPath := filepath.Join(dir, configBase)

	// Commit a secret through the REAL store path so .configdb/master.key,
	// active.json and the audit journal are materialized exactly as production.
	store, err := New(configPath)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if _, err := store.LoadSet("set snmp community " + zeroizeSecret4858 + " authorization read-only"); err != nil {
		t.Fatalf("LoadSet: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	dbDir := filepath.Join(dir, ".configdb")
	if _, err := os.Stat(dbDir); err != nil {
		t.Fatalf("precondition: .configdb should exist after commit: %v", err)
	}

	// Also stage a text rollback slot, a rescue.conf, a rotated journal segment
	// and a non-xpf bystander to exercise the enumerated-artifact rules.
	textRollback := configPath + ".1"
	rescue := filepath.Join(dir, "rescue.conf")
	journalSeg := filepath.Join(dir, ".config.journal.1")
	bystander := filepath.Join(dir, "node-id")
	for _, p := range []string{textRollback, rescue, journalSeg} {
		if err := os.WriteFile(p, []byte(zeroizeSecret4858), 0o600); err != nil {
			t.Fatalf("seed %s: %v", p, err)
		}
	}
	if err := os.WriteFile(bystander, []byte("0"), 0o600); err != nil {
		t.Fatalf("seed bystander: %v", err)
	}

	if err := FactoryResetConfigDir(dir, configBase); err != nil {
		t.Fatalf("FactoryResetConfigDir: %v", err)
	}

	// Every secret-bearing artifact is gone.
	for _, p := range []string{
		dbDir,
		filepath.Join(dbDir, "master.key"),
		filepath.Join(dbDir, "active.json"),
		filepath.Join(dir, ".config.journal"),
		journalSeg, configPath, textRollback, rescue,
	} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("expected %s absent after factory reset, stat err = %v", p, err)
		}
	}

	// Scope guard: the non-xpf file survives.
	if _, err := os.Stat(bystander); err != nil {
		t.Errorf("factory reset removed a non-xpf file %s: %v", bystander, err)
	}

	// A fresh Store on the wiped dir starts empty and never-committed — the
	// prior tenant's secret does not reappear.
	store2, err := New(configPath)
	if err != nil {
		t.Fatalf("New after factory reset: %v", err)
	}
	if err := store2.Load(); err != nil {
		t.Fatalf("Load after factory reset: %v", err)
	}
	if got := store2.ActiveTree().FormatSet(); strings.Contains(got, zeroizeSecret4858) {
		t.Errorf("post-zeroize active config still contains prior-tenant secret:\n%s", got)
	}
	if store2.EverCommitted() {
		t.Errorf("post-zeroize store reports EverCommitted=true; want fresh/never-committed")
	}
}

// TestIsTextRollbackSlot pins the numbered text-rollback recognizer.
func TestIsTextRollbackSlot(t *testing.T) {
	base := "xpf.conf"
	cases := []struct {
		name string
		want bool
	}{
		{"xpf.conf.1", true},
		{"xpf.conf.42", true},
		{"xpf.conf", false},
		{"xpf.conf.bak", false},
		{"xpf.conf.", false},
		{"xpf.conf.1a", false},
		{"rescue.conf.1", false},
		{"node-id", false},
	}
	for _, tc := range cases {
		if got := isTextRollbackSlot(tc.name, base); got != tc.want {
			t.Errorf("isTextRollbackSlot(%q, %q) = %v, want %v", tc.name, base, got, tc.want)
		}
	}
}
