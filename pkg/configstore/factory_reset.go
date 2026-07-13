package configstore

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

// DefaultArchiveDir is the xpf-owned DEFAULT local config-archive directory —
// the pkg/config archival compiler default (compiler_system.go) and the
// pkg/daemon runtime fallback (daemon_apply.go). writeArchive drops timestamped
// config-<ts>.<seq>.conf snapshots here, each a 0600 copy of the full committed
// config TEXT with cleartext secret leaves (IKE PSK, WireGuard private keys,
// SNMP communities, BGP MD5). It is the ONLY archive path a factory reset
// provably owns and is therefore allowed to erase (see FactoryResetArchiveDir's
// ownership guard).
//
// KEEP IN SYNC with the pkg/config archival compiler default: pkg/config cannot
// import pkg/configstore (configstore already imports config), so the literal
// is duplicated rather than shared. If the compiler default ever moves, this
// must move with it or a zeroize would skip the real archive.
//
// It is a var, not a const, so the zeroize tests can repoint the ownership
// guard at a throwaway tree (mirroring the grpcapi zeroize* path seams).
// Production code must never mutate it.
var DefaultArchiveDir = "/var/lib/xpf/archive"

// FactoryResetArchiveDir erases the LOCAL configuration archive as part of a
// factory reset (#5186) — but ONLY when archiveDir is the xpf-owned default.
//
// WHY the wipe must erase it: zeroize must remove EVERY on-box generation of
// config secrets (the .configdb SSOT + master.key, the numbered text rollback
// slots, the audit journal, the rendered service configs, and the login
// accounts are all wiped by the sibling FactoryResetConfigDir /
// zeroizeRenderedConfigs / zeroizeLoginAccounts). The local config archive was
// the OMITTED generation: a pre-#5186 zeroize left /var/lib/xpf/archive
// untouched, so a device handed to the next tenant after a factory reset still
// carried 0600 full-config-text copies with the prior tenant's cleartext PSKs,
// keys, and communities.
//
// OWNERSHIP GUARD (#5186): erase the archive ONLY when archiveDir is the
// xpf-owned default (DefaultArchiveDir). An operator-configured CUSTOM archive
// directory may be a remote mount, an NFS export, or a compliance/audit
// retention store that is NOT xpf's to destroy — blindly deleting it could wipe
// records the operator is legally required to keep. Ownership cannot be proven
// for such a path, so it is SKIPPED with a warning rather than deleted (never
// fail-closed-delete). This mirrors how the config-state wipe proves ownership
// by its fixed default appliance path, and how zeroizeLoginAccounts refuses to
// touch a non-xpf-owned account.
//
// Discipline mirrors FactoryResetConfigDir: os.ErrNotExist is never an error
// (an already-absent archive is the goal); the whole archive tree is
// RemoveAll'd; the PARENT directory is then fsynced so the removal of the
// archive directory entry itself is durable before the completing reboot, and
// that fsync error is PROPAGATED — a fsync failure means the erasure may not be
// on stable storage, so it must not be reported as a clean zeroize. The
// durability barrier routes through the rbSyncDir seam so a dropped sync fails
// a test RED.
func FactoryResetArchiveDir(archiveDir string) error {
	// Ownership guard: only the xpf-owned default is provably safe to erase. A
	// custom/remote/compliance archive destination is skipped with a warning,
	// never blindly deleted.
	if filepath.Clean(archiveDir) != DefaultArchiveDir {
		slog.Warn("zeroize: skipping config archive directory with unproven "+
			"ownership (not the xpf-owned default); a custom, remote, or "+
			"compliance archive destination is the operator's to erase, not "+
			"the factory reset's",
			"dir", archiveDir, "default", DefaultArchiveDir)
		return nil
	}

	var firstErr error
	fail := func(err error) {
		if err != nil && !errors.Is(err, os.ErrNotExist) && firstErr == nil {
			firstErr = err
		}
	}

	// Erase the whole archive tree — every config-<ts>.<seq>.conf snapshot of
	// the prior tenant's config text. RemoveAll is nil on an absent dir.
	fail(os.RemoveAll(archiveDir))

	// fsync the PARENT so the unlink of the archive directory entry itself is
	// durable before the reboot that completes the factory reset. A sync
	// failure is propagated — a silently non-durable erasure must never be
	// reported as a clean zeroize. ErrNotExist (parent absent → nothing was
	// removed) is excluded by fail().
	fail(rbSyncDir(filepath.Dir(archiveDir)))
	return firstErr
}

// FactoryResetForbiddenRoots are directories a factory-reset config-state wipe
// must NEVER treat as an xpf-owned config root (#5684). FactoryResetConfigDir
// scans configDir for *.conf / rollback* / journal / numbered-text-rollback /
// fsatomic-temp artifacts and RemoveAll's <configDir>/.configdb — every removal
// is bounded to configDir, but configDir itself is derived from
// filepath.Dir(store.ConfigPath()). A daemon started with a custom `-config`
// placed DIRECTLY in a shared directory (`-config /etc/xpf.conf` → configDir
// "/etc"; `-config /srv/site.conf` → "/srv") or pointed at a directory-shaped
// path (`-config /srv/firewall`, where filepath.Dir climbs to the PARENT
// "/srv") turns a factory reset into a broad deletion of files xpf does not own
// — the destructive-scope defect #5684 closes. ValidateFactoryResetRoot rejects
// these so the reset fails CLOSED (erases NOTHING, reports incomplete) instead
// of wiping the wrong tree. The default appliance root /etc/xpf and any
// dedicated subdirectory (/srv/xpf, /opt/xpf/data) are deliberately NOT on the
// list and pass. It is a var so a test can register a throwaway tree as a shared
// root (mirroring the DefaultArchiveDir seam); production code must never mutate
// it.
var FactoryResetForbiddenRoots = []string{
	"/",
	"/bin", "/boot", "/dev", "/etc", "/home", "/lib", "/lib32", "/lib64",
	"/libx32", "/media", "/mnt", "/opt", "/proc", "/root", "/run", "/sbin",
	"/srv", "/sys", "/tmp", "/usr", "/usr/local", "/var", "/var/lib",
	"/var/tmp",
}

// ValidateFactoryResetRoot reports whether configDir is a plausible xpf-owned
// config root that a factory reset may erase, returning a descriptive error if
// it is not (#5684). configDir is filepath.Dir(store.ConfigPath()), so a
// custom/adversarial `-config` can resolve it to a directory xpf does not own;
// this is the guard that keeps `zeroize` from broad-deleting an enclosing
// directory. It rejects:
//
//   - a NON-ABSOLUTE path — an empty or relative `-config` resolves
//     filepath.Dir to "." (the daemon's working directory), never a config root;
//   - the filesystem root and the well-known shared/system directories in
//     FactoryResetForbiddenRoots — a `-config` placed directly in a shared
//     directory (or a directory-shaped `-config`, where filepath.Dir climbs to
//     the PARENT) would otherwise wipe *.conf / .configdb / tls siblings xpf
//     does not own.
//
// The comparison is lexical on filepath.Clean(configDir), so a trailing slash
// and `..` traversal (`/etc/xpf/..` → /etc) are normalized before the check.
// Callers surface the error so the reset erases NOTHING and reports incomplete
// rather than deleting the wrong tree. The default appliance root /etc/xpf and
// any dedicated subdirectory pass. This is a purely lexical guard (it does not
// resolve symlinks); a defense against config-path misconfiguration, not against
// an operator who symlinks the config root at a shared directory.
func ValidateFactoryResetRoot(configDir string) error {
	clean := filepath.Clean(configDir)
	if !filepath.IsAbs(clean) {
		return fmt.Errorf("zeroize: refusing to factory-reset non-absolute config root %q: a relative or empty -config path resolves to the daemon working directory, not an xpf config directory", configDir)
	}
	for _, forbidden := range FactoryResetForbiddenRoots {
		if clean == forbidden {
			return fmt.Errorf("zeroize: refusing to factory-reset shared/system directory %q as a config root: the -config path must live in a directory xpf owns (e.g. /etc/xpf), not directly in a shared directory whose siblings are not xpf's to erase", clean)
		}
	}
	return nil
}

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
//   - .<base>.tmp-*         — fsatomic crash-leaked write temps (#5475): a
//     daemon killed between fsatomic's CreateTemp and its rename leaves a
//     ".<base>.tmp-<rand>" file (pkg/fsatomic createTemp) still holding the FULL
//     cleartext config text it was mid-writing (xpf.conf / rescue.conf / a
//     numbered rollback slot) — IKE PSKs, WireGuard keys, SNMP communities.
//     fsatomic self-heals a leaked temp on the NEXT write to that base
//     (configstore NewDB sweeps the identical ".*.tmp-*" glob inside .configdb),
//     but a factory reset + reboot means there is no next write, so the temp —
//     and its secrets — would otherwise survive. Temps INSIDE .configdb are
//     already erased by the RemoveAll above; only TOP-LEVEL configDir temps
//     needed this sweep.
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
// accounts are handled separately by the daemon's RPC factory-reset path; the
// local config archive (/var/lib/xpf/archive) — another OUTSIDE-configDir
// generation of config secrets — is erased by the sibling FactoryResetArchiveDir
// (#5186), which both the CLI and the gRPC wipe also call.
func FactoryResetConfigDir(configDir, configBase string) error {
	// #5684: refuse to wipe a shared/parent/system directory. configDir is
	// filepath.Dir(store.ConfigPath()); a custom -config placed in (or resolving
	// to) a shared directory would turn this into a broad deletion of *.conf /
	// .configdb / tls siblings xpf does not own. Fail CLOSED — surface the error
	// and remove NOTHING — rather than erase the wrong tree.
	if err := ValidateFactoryResetRoot(configDir); err != nil {
		return err
	}

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
			isTextRollbackSlot(name, configBase) ||
			isFsatomicTemp(name) {
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

// isFsatomicTemp reports whether name is a crash-leaked fsatomic write temp —
// the ".<base>.tmp-<random>" shape pkg/fsatomic gives every temp it creates
// before the atomic rename (fsatomic.go createTemp: `"."+base+".tmp-"`). A
// daemon killed between CreateTemp and the rename leaves one behind still
// holding the FULL cleartext config text it was mid-writing (xpf.conf /
// rescue.conf / a numbered rollback slot with IKE PSKs, WireGuard keys, SNMP
// communities), and after a factory reset + reboot there is no next write to
// that base to self-heal it (#5475). The glob is the exact one the configstore
// NewDB sweep uses inside .configdb (db.go) — KEEP IN SYNC with fsatomic's temp
// naming. It is intentionally narrow: only a dotfile that contains ".tmp-"
// matches, so legitimate dotfiles (.config.journal, .config.journal.N) are left
// for their own rules. The pattern is a constant, so Match never errors.
func isFsatomicTemp(name string) bool {
	ok, _ := filepath.Match(".*.tmp-*", name)
	return ok
}
