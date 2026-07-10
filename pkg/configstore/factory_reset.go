package configstore

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// FactoryResetConfigDir securely erases the on-disk configuration STATE under
// configDir as part of a factory reset (#4858). It is the single shared
// primitive behind `request system zeroize` so the on-box CLI and any RPC
// factory-reset path wipe exactly the same artifacts, and none of them can
// report success while the authoritative config DB + encryption key survive to
// re-activate on the next boot.
//
// configBase is the config file's base name (e.g. "xpf.conf"), used to
// recognize the numbered text rollback slots "<configBase>.<N>".
//
// The artifacts removed — every file that persists the prior tenant's committed
// policy, IKE PSKs, WireGuard private keys, and SNMP communities:
//
//   - .configdb/master.key  — the AES-GCM key that decrypts an encrypted DB.
//     Removed FIRST (key-first) and that removal is fsynced (.configdb) BEFORE
//     the ciphertext body is touched (#5197): an interrupted wipe (crash /
//     power loss mid-RemoveAll) can then never leave the ciphertext together
//     with the key that decrypts it. Without the barrier both unlinks sit in
//     the page cache and the filesystem is free to persist the ciphertext
//     removal while losing the key removal, breaking the guarantee.
//   - .configdb/            — the SSOT: active.json, candidate.json,
//     rollback.N.json. Store.Load reloads active.json on the next boot, so the
//     whole tree must go or the "erased" config is restored.
//   - .config.journal[.N]   — the JSONL audit journal + rotated segments
//     (prior-tenant commit history; legacy fat lines may carry full config).
//   - <configBase>.<N>      — the canonical text rollback slots (full config
//     text with cleartext secret leaves; loadRollbackHistory reads them at
//     boot, so leaving them behind allows a rollback to the prior config).
//   - *.conf                — the live config + rescue.conf (legacy set).
//   - rollback*             — legacy rollback naming (pre-DB set).
//
// Discipline: os.ErrNotExist is never an error (an already-absent artifact is
// the goal); removal is best-effort past a single stubborn file, but the FIRST
// real error is returned so a silently-incomplete wipe is never reported as a
// clean factory reset. The parent dir is fsynced at the end so the unlinks are
// durable across a power cut before the completing reboot, and that final
// directory-fsync error is now PROPAGATED (#5197) — a fsync failure means the
// erasure may not be on stable storage, so it must not be reported as a clean
// zeroize the way the discarded end-of-function d.Sync() previously was. The
// durability barriers route through the package fsync seam (rbSyncDir) so a
// dropped sync fails a test RED.
//
// Scope: this erases the config-DB SSOT + journal + rollback state under
// configDir. The RENDERED service configs xpfd writes OUTSIDE configDir
// (/etc/frr/frr.conf, /etc/swanctl/conf.d, /etc/kea) and provisioned OS login
// accounts are handled separately by the daemon's RPC factory-reset path.
func FactoryResetConfigDir(configDir, configBase string) error {
	var firstErr error
	fail := func(err error) {
		if err != nil && !errors.Is(err, os.ErrNotExist) && firstErr == nil {
			firstErr = err
		}
	}

	dbDir := filepath.Join(configDir, ".configdb")
	// KEY-FIRST: master.key before the encrypted DB body. Make the key unlink
	// DURABLE before the ciphertext is removed (#5197) — fsync .configdb so the
	// key removal is on stable storage before RemoveAll begins. Otherwise a
	// power cut could persist the ciphertext removal while losing the key
	// removal, defeating the key-first cryptographic-erasure guarantee.
	keyErr := rbRemove(filepath.Join(dbDir, "master.key"))
	fail(keyErr)
	if keyErr == nil {
		// The key existed and was unlinked: make that unlink durable before the
		// ciphertext body removal. An absent .configdb yields ErrNotExist, which
		// fail() excludes (nothing was removed, so nothing to make durable).
		fail(rbSyncDir(dbDir))
	}
	// The config SSOT (active.json, candidate.json, rollback.N.json + any
	// residual key). RemoveAll erases the whole tree and is nil on absent.
	fail(os.RemoveAll(dbDir))

	// Top-level artifacts in a single ReadDir pass: the live/rescue .conf, the
	// legacy rollback* files, the audit journal (+ rotated segments), and the
	// numbered text rollback slots.
	entries, err := os.ReadDir(configDir)
	fail(err)
	for _, f := range entries {
		name := f.Name()
		if strings.HasSuffix(name, ".conf") ||
			strings.HasPrefix(name, "rollback") ||
			name == ".config.journal" ||
			strings.HasPrefix(name, ".config.journal.") ||
			isTextRollbackSlot(name, configBase) {
			fail(os.Remove(filepath.Join(configDir, name)))
		}
	}

	// fsync the parent directory so ALL the unlinks above are durable before
	// the reboot that completes the factory reset. Unlike the discarded
	// end-of-function d.Sync() this replaced, a sync failure here is PROPAGATED
	// (#5197): a failed fsync means the erasure may not be on stable storage,
	// so it must not be reported as a clean zeroize. ErrNotExist (configDir
	// itself absent → nothing to wipe) is excluded by fail().
	fail(rbSyncDir(configDir))
	return firstErr
}

// isTextRollbackSlot reports whether name is a numbered text rollback slot for
// the config file configBase — "<configBase>.<N>" with N one-or-more decimal
// digits. These files carry the full prior config text including cleartext
// secret leaves, so a factory reset removes them. configBase itself ("xpf.conf")
// is caught by the .conf-suffix rule.
func isTextRollbackSlot(name, configBase string) bool {
	rest, ok := strings.CutPrefix(name, configBase+".")
	if !ok || rest == "" {
		return false
	}
	for _, r := range rest {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
