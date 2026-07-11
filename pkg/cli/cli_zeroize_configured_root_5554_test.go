package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
)

// TestCLIZeroizeResolvesConfiguredRoot pins #5554: the interactive-CLI
// `request system zeroize` path must resolve the wipe target from the daemon's
// ACTUAL configured config root — the directory + base name of the store's
// `-config` path (configstore.Store.ConfigPath) — NOT a hardcoded /etc/xpf.
// This is the local-CLI twin of the gRPC fix (#5280): when xpfd runs with a
// non-default `-config` (e.g. /srv/xpf/site.conf), the .configdb SSOT +
// master.key, rollback slots and journal live under THAT root; resolving to a
// hardcoded /etc/xpf would leave the prior tenant's secrets on disk.
//
// RED on revert: restoring `configDir := "/etc/xpf"` (and the "xpf.conf" base)
// makes zeroizeConfigRoot return /etc/xpf + xpf.conf instead of the store's
// temp root — so the gotDir/gotBase assertions (and the explicit /etc/xpf
// guard) fail.
func TestCLIZeroizeResolvesConfiguredRoot(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "site.conf")
	store := newConfigStore(t, configPath)
	c := &CLI{store: store}

	gotDir, gotBase, err := c.zeroizeConfigRoot()
	if err != nil {
		t.Fatalf("zeroizeConfigRoot: unexpected error %v", err)
	}
	if gotDir != dir {
		t.Fatalf("zeroize resolved configDir %q, want the CONFIGURED root %q (not hardcoded /etc/xpf)", gotDir, dir)
	}
	if gotBase != "site.conf" {
		t.Fatalf("zeroize resolved configBase %q, want the CONFIGURED base %q", gotBase, "site.conf")
	}
	// Explicit revert-shape guard: a hardcoded wipe would resolve /etc/xpf.
	if gotDir == "/etc/xpf" {
		t.Fatalf("zeroize resolved the hardcoded default /etc/xpf instead of the configured root %q", dir)
	}
}

// TestCLIZeroizeFailsClosedWithoutConfigRoot pins the fail-CLOSED half of
// #5554: if the configured config root cannot be determined (no store, or a
// store with an empty config path), the CLI zeroize must NOT silently wipe the
// wrong path or nothing — it must surface an error so the operator knows the
// device is not safe to re-tenant.
func TestCLIZeroizeFailsClosedWithoutConfigRoot(t *testing.T) {
	// No store => config root undeterminable.
	c := &CLI{store: nil}
	if _, _, err := c.zeroizeConfigRoot(); err == nil {
		t.Fatal("zeroizeConfigRoot with no store must fail closed; got nil error")
	}

	// A store with an empty config path is equally undeterminable.
	c = &CLI{store: &configstore.Store{}}
	if _, _, err := c.zeroizeConfigRoot(); err == nil {
		t.Fatal("zeroizeConfigRoot with an empty config path must fail closed; got nil error")
	}
}

// TestCLIZeroizeWipesConfiguredRootNotHardcoded drives the full CLI
// config-state wipe (zeroizeConfigState) against a NON-default configured root
// seeded with the on-disk secret artifacts a factory reset must erase, and
// asserts they are gone. It is the end-to-end revert guard for #5554: with the
// hardcoded `configDir := "/etc/xpf"` restored, FactoryResetConfigDir wipes
// /etc/xpf (absent in the test => nil) while the temp root's .configdb +
// rollback slots SURVIVE — so the "removed" assertions below fail.
func TestCLIZeroizeWipesConfiguredRootNotHardcoded(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "site.conf")
	// newConfigStore -> configstore.New creates dir/.configdb (the SSOT the wipe
	// must erase) and sets the store's ConfigPath to configPath.
	store := newConfigStore(t, configPath)

	// Point the archive wipe at an xpf-owned-default that is safe in the test:
	// FactoryResetArchiveDir only touches DefaultArchiveDir, so aim it at an
	// absent temp path (parent exists) => it no-ops cleanly instead of trying to
	// erase the real /var/lib/xpf/archive.
	origArchive := configstore.DefaultArchiveDir
	configstore.DefaultArchiveDir = filepath.Join(t.TempDir(), "archive")
	t.Cleanup(func() { configstore.DefaultArchiveDir = origArchive })

	// Seed the secret-bearing artifacts under the CONFIGURED root: master.key,
	// the live config text, and a numbered text rollback slot.
	if err := os.WriteFile(filepath.Join(dir, ".configdb", "master.key"), []byte("KEY"), 0o600); err != nil {
		t.Fatalf("seed master.key: %v", err)
	}
	if err := os.WriteFile(configPath, []byte("system { host-name fw; }\n"), 0o600); err != nil {
		t.Fatalf("seed site.conf: %v", err)
	}
	rollbackSlot := configPath + ".1"
	if err := os.WriteFile(rollbackSlot, []byte("system { host-name old; }\n"), 0o600); err != nil {
		t.Fatalf("seed rollback slot: %v", err)
	}

	c := &CLI{store: store}
	if err := c.zeroizeConfigState(); err != nil {
		t.Fatalf("zeroizeConfigState: %v", err)
	}

	// The config-DB SSOT under the CONFIGURED root must be gone.
	if _, err := os.Stat(filepath.Join(dir, ".configdb")); !os.IsNotExist(err) {
		t.Fatalf(".configdb under the configured root %q survived zeroize (stat err=%v); "+
			"the wipe hit the wrong (hardcoded) directory", dir, err)
	}
	// The numbered text rollback slot (full config text w/ secret leaves) too.
	if _, err := os.Stat(rollbackSlot); !os.IsNotExist(err) {
		t.Fatalf("rollback slot %q survived zeroize (stat err=%v)", rollbackSlot, err)
	}
	// And the live config text.
	if _, err := os.Stat(configPath); !os.IsNotExist(err) {
		t.Fatalf("config file %q survived zeroize (stat err=%v)", configPath, err)
	}
}
