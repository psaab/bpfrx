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
//     Removed FIRST (key-first): an interrupted wipe (crash / power loss
//     mid-RemoveAll) can then never leave the ciphertext together with the key
//     that decrypts it.
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
// durable across a power cut before the completing reboot.
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
	// KEY-FIRST: master.key before the encrypted DB body.
	fail(os.Remove(filepath.Join(dbDir, "master.key")))
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

	// fsync the parent directory so the unlinks are durable before the reboot
	// that completes the factory reset (best-effort — a fsync failure here does
	// not un-erase anything and must not gate the wipe result).
	if d, derr := os.Open(configDir); derr == nil {
		_ = d.Sync()
		_ = d.Close()
	}
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
