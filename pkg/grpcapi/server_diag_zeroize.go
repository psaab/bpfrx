package grpcapi

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/psaab/xpf/pkg/dhcpserver"
	"github.com/psaab/xpf/pkg/frr"
	"github.com/psaab/xpf/pkg/fsatomic"
	"github.com/psaab/xpf/pkg/ipsec"
)

// zeroizeSyncDir is the directory-fsync seam for the factory-reset wipe
// (#5197). Production uses fsatomic.SyncDir; a test overrides it to record the
// durability barrier (so a dropped fsync fails RED) and to inject a sync
// failure. Mirrors the configstore rbSyncDir seam. Production code must never
// mutate it.
var zeroizeSyncDir = fsatomic.SyncDir

// defaultConfigDir / defaultConfigBase mirror the daemon's config-path default
// (cmd/xpfd `-config /etc/xpf/xpf.conf`, pkg/daemon). performZeroizeWipe erases
// the fixed appliance paths; a non-default `-config` location is out of scope
// (the pre-#4576 wipe already assumed /etc/xpf).
const (
	defaultConfigDir  = "/etc/xpf"
	defaultConfigBase = "xpf.conf"
)

// zeroizeConfigDir erases the xpf configuration STATE under configDir as part
// of a factory reset (#4576): the .configdb SSOT + master.key, the numbered
// text rollback slots, the top-level .conf files, and the audit journal — the
// artifacts that persist the prior tenant's committed policy, IKE PSKs,
// WireGuard private keys, and SNMP communities and would otherwise be reloaded
// on the next boot.
//
// NOTE (scope): this erases the SSOT and rollback/journal state under
// configDir. The RENDERED service configs xpfd writes OUTSIDE configDir —
// /etc/frr/frr.conf (0644, BGP-MD5/OSPF/ISIS auth), /etc/swanctl/conf.d/xpf.conf
// (IKE PSKs), /etc/kea/kea-dhcp{4,6}.conf — are erased separately by
// zeroizeRenderedConfigs (#4585). Both run under performZeroizeWipe. Erasing
// the rendered configs in the wipe (rather than deferring to the reboot) is
// required because a post-zeroize boot has no committed config and SKIPS the
// reconcile that would otherwise clear them — see zeroizeRenderedConfigs.
//
// The artifacts removed (configBase is the config file's base name, e.g.
// "xpf.conf", used to recognize the numbered text rollback slots):
//   - .configdb/master.key      — the AES-GCM key that decrypts an encrypted DB
//   - .configdb/                — the SSOT: active.json, candidate.json,
//     rollback.N.json (Store.Load reloads active.json on next boot)
//   - <configBase>.<N>          — the CANONICAL text rollback slots
//     (saveRollbackFiles / loadRollbackHistory), full config TEXT with
//     cleartext secret leaves; loadRollbackHistory reloads them at boot, so
//     leaving them behind would let the prior tenant's config be rolled back
//     to — the exact leak #4576 closes
//   - *.conf                    — the live config + rescue.conf (pre-#4576 set)
//   - rollback*                 — legacy rollback naming (pre-#4576 set)
//   - .config.journal[.N]       — the JSONL audit journal + rotated segments
//     (0644, prior-tenant commit history/comments; legacy v1 fat lines may
//     carry full config incl. secrets). This SUPERSEDES the #4108 "journal
//     survives a zeroize" belt-and-braces: the system_action record is still
//     fsynced BEFORE the wipe (so an interrupted wipe leaves a trail, and a
//     remote syslog collector keeps the durable cross-wipe record), but a
//     completed factory reset must not hand its audit log to the next owner.
//   - tls/                      — the self-signed REST-API TLS pair (#4599):
//     tls/key.pem (the device-generated localhost HTTPS private key, 0600) +
//     tls/cert.pem. xpf-generated, not tenant config; generateSelfSignedCertAt
//     (pkg/api) regenerates a fresh pair on absence at the next boot, so
//     removing them is safe and hands no prior-tenant key to the next owner.
//
// Removal is KEY-FIRST and DURABLY ordered (#4576/#5197): master.key is deleted
// before the encrypted DB body AND the key unlink is fsynced (.configdb) before
// RemoveAll begins, so an interrupted wipe (crash / power loss mid-RemoveAll)
// can never leave the ciphertext behind together with the key that decrypts it
// — once the key is gone any surviving ciphertext is unrecoverable. Without the
// fsync barrier both unlinks sit in the page cache and the filesystem is free
// to persist the ciphertext removal while losing the key removal.
//
// The parent directory is fsynced at the end so every unlink is durable before
// the completing reboot, and that final dir-fsync error is PROPAGATED (#5197):
// a failed fsync means the erasure may not be on stable storage, so it must not
// be reported as a clean zeroize.
//
// It is best-effort past a failure (a single stubborn file does not abort the
// rest of the erasure) but returns the FIRST real error so a
// silently-incomplete zeroize is never reported as a successful factory reset.
// os.ErrNotExist is not an error here (an already-absent artifact is the goal).
func zeroizeConfigDir(configDir, configBase string) error {
	var firstErr error
	fail := func(err error) {
		if err != nil && !errors.Is(err, os.ErrNotExist) && firstErr == nil {
			firstErr = err
		}
	}

	dbDir := filepath.Join(configDir, ".configdb")
	// KEY-FIRST (#4576): master.key before the encrypted DB body. Make the key
	// unlink DURABLE before the ciphertext is removed (#5197) — fsync .configdb
	// so the key removal is on stable storage before RemoveAll begins.
	// Otherwise a power cut could persist the ciphertext removal while losing
	// the key removal, defeating the key-first cryptographic-erasure guarantee.
	keyErr := os.Remove(filepath.Join(dbDir, "master.key"))
	fail(keyErr)
	if keyErr == nil {
		// The key existed and was unlinked: make that unlink durable before the
		// ciphertext body removal. Absent .configdb → ErrNotExist, excluded by fail().
		fail(zeroizeSyncDir(dbDir))
	}
	// The config SSOT (active.json, candidate.json, rollback.N.json + any
	// residual key). RemoveAll erases the whole tree and is nil on absent.
	fail(os.RemoveAll(dbDir))

	// The self-signed REST-API TLS material (#4599): tls/key.pem (the
	// device-generated localhost HTTPS private key) + tls/cert.pem. These are
	// xpf-generated, not tenant config — generateSelfSignedCertAt (pkg/api)
	// regenerates a fresh pair on absence at the next boot, so removing them is
	// safe. A subdir, so the top-level ReadDir loop's os.Remove never catches it;
	// erase the whole tree explicitly.
	fail(os.RemoveAll(filepath.Join(configDir, "tls")))

	// Top-level artifacts in a single ReadDir pass.
	entries, err := os.ReadDir(configDir)
	fail(err)
	for _, f := range entries {
		name := f.Name()
		if strings.HasSuffix(name, ".conf") ||
			strings.HasPrefix(name, "rollback") ||
			name == ".config.journal" ||
			strings.HasPrefix(name, ".config.journal.") ||
			isTextRollbackFile(name, configBase) {
			fail(os.Remove(filepath.Join(configDir, name)))
		}
	}

	// fsync the parent directory so ALL the unlinks above (the .configdb tree,
	// tls/, and the enumerated top-level files) are durable before the reboot
	// that completes the factory reset (#5197). A sync failure means the
	// erasure may not be on stable storage, so it is PROPAGATED — never
	// reported as a clean zeroize. ErrNotExist (configDir absent) is excluded
	// by fail().
	fail(zeroizeSyncDir(configDir))
	return firstErr
}

// isTextRollbackFile reports whether name is a numbered text rollback slot for
// the config file configBase — "<configBase>.<N>" with N one-or-more decimal
// digits (store_commit.go rollbackPath). These files carry the full prior
// config text including cleartext secret leaves, so a factory reset removes
// them. configBase itself ("xpf.conf") is caught by the .conf suffix rule.
func isTextRollbackFile(name, configBase string) bool {
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

// zeroizeRenderedConfigs erases the RENDERED service configs xpfd writes
// OUTSIDE configDir — the artifacts that hold the prior tenant's secrets in
// cleartext but are not part of the .configdb SSOT wiped by zeroizeConfigDir
// (#4585, follow-up to #4576):
//
//   - frrConf (/etc/frr/frr.conf, mode 0644 WORLD-READABLE): the xpf-managed
//     section carries BGP MD5 / OSPF / IS-IS authentication keys. Only that
//     section is stripped (frr.StripManagedSectionFile) — operator content
//     outside the markers is preserved and a purely operator-managed frr.conf
//     is left untouched. No FRR reload: FRR restarts clean on the reboot.
//   - swanctlSnippet (/etc/swanctl/conf.d/xpf.conf): the IKE PSKs live in this
//     single xpf-owned snippet, so it is removed outright.
//   - kea4/kea6 (/etc/kea/kea-dhcp{4,6}.conf): xpf owns these whole files, so
//     they are removed outright.
//
// WHY the wipe must erase these DIRECTLY rather than lean on the completing
// reboot: a post-zeroize boot has NO committed config, so the daemon enters
// #1922 bootstrap mode (or, on an HA node, a normal boot with a nil active
// config) and SKIPS the boot-time applyConfig that would otherwise reconcile
// FRR/IPsec/Kea to empty (pkg/daemon/daemon_run.go: bootstrap suppresses the
// apply, and the normal-boot apply is gated on ActiveConfig() != nil). The
// rendered secrets are therefore a PERSISTENT residual across the reboot, not a
// transient one — a device handed to the next tenant would keep the prior
// tenant's routing-auth keys in a world-readable file. (See docs/system-login.md.)
//
// Discipline mirrors zeroizeConfigDir: os.ErrNotExist is not an error (an
// already-absent artifact is the goal), removal is best-effort past a single
// failure, but the FIRST real error is returned so a silently-incomplete wipe
// is never reported as a clean factory reset.
func zeroizeRenderedConfigs(frrConf, swanctlSnippet, kea4, kea6 string) error {
	var firstErr error
	fail := func(err error) {
		if err != nil && !errors.Is(err, os.ErrNotExist) && firstErr == nil {
			firstErr = err
		}
	}
	// FRR: strip only the xpf-managed section (the routing-auth secrets); the
	// file may carry operator content outside the markers. StripManagedSectionFile
	// already treats an absent file as a no-op (nil) and leaves an unmanaged
	// frr.conf untouched.
	fail(frr.StripManagedSectionFile(frrConf))
	// swanctl snippet + Kea configs: xpf owns these whole files, remove them.
	fail(os.Remove(swanctlSnippet))
	fail(os.Remove(kea4))
	fail(os.Remove(kea6))
	return firstErr
}

// zeroize login-account teardown paths (#4598). These mirror the production
// paths the daemon provisions OS login accounts under (pkg/daemon:
// provisionedUsersDir, sudoersDir/sudoersPrefix, passwdPath, /home/<user>).
// They cannot be imported — pkg/daemon imports pkg/grpcapi (daemon_run.go),
// so a shared symbol would create an import cycle, the same reason the exec
// timeout helper is duplicated here. They are package vars only so a test can
// point the teardown at a throwaway tree instead of the real /etc + /home +
// /var/lib.
var (
	// zeroizeProvisionedUsersDir is the per-account provenance-marker directory
	// (pkg/daemon.provisionedUsersDir). Each file is named for an xpf-created
	// login account and CONTAINS that account's UID at provision time — the
	// UID-keyed ownership marker of #1944. It is the authoritative registry of
	// "which OS users did xpf provision", so the wipe walks it to know exactly
	// which accounts are safe to remove.
	zeroizeProvisionedUsersDir = "/var/lib/xpf/provisioned-users"
	// zeroizeSudoersDir + zeroizeSudoersPrefix mirror pkg/daemon.sudoersDir /
	// sudoersPrefix — the exclusive namespace of xpf-managed NOPASSWD sudo
	// drop-ins. Only files with the prefix are ever removed; operator-authored
	// drop-ins in the same directory are left untouched.
	zeroizeSudoersDir    = "/etc/sudoers.d"
	zeroizeSudoersPrefix = "xpf-"
	// zeroizePasswdPath is /etc/passwd, read to resolve an account's CURRENT
	// UID so a userdel only ever fires when the live UID still matches the
	// marker (never on an out-of-band recreate). Mirrors pkg/daemon.passwdPath.
	zeroizePasswdPath = "/etc/passwd"
	// zeroizeHomeBase is the home-directory root; authorized_keys lives at
	// <base>/<user>/.ssh/authorized_keys.
	zeroizeHomeBase = "/home"
	// zeroizeUserdel removes an OS account, its /etc/shadow + /etc/passwd
	// entries, and its home tree (-r). It is a seam so tests can record the
	// removal without touching real accounts. context.Background(): a client
	// disconnect must not abort a confirmed factory reset (mirrors runTimeout's
	// power-action rationale).
	zeroizeUserdel = func(name string) ([]byte, error) {
		return combinedOutputTimeout(context.Background(), "userdel", "-r", name)
	}
)

// zeroizeLookupUID returns the current numeric UID for name by parsing
// zeroizePasswdPath directly (cgo-free, mirroring pkg/daemon.lookupUID). It
// returns (uid, true) on success and (0, false) if the file is unreadable, the
// account is absent, or the UID field does not parse — the "not our account"
// disposition that suppresses a userdel.
func zeroizeLookupUID(name string) (int, bool) {
	data, err := os.ReadFile(zeroizePasswdPath)
	if err != nil {
		return 0, false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) < 3 {
			continue
		}
		if fields[0] == name {
			uid, err := strconv.Atoi(fields[2])
			if err != nil {
				return 0, false
			}
			return uid, true
		}
	}
	return 0, false
}

// zeroizeLoginAccounts tears down the OS LOGIN accounts xpf provisioned as part
// of a factory reset (#4598, follow-up to #4576/#4585). These are the biggest
// re-tenant leak of the three because they grant INTERACTIVE LOGIN + SUDO, not
// just a config-secret read:
//
//   - /etc/shadow password hashes (pkg/daemon.reconcileUserPassword)
//   - SSH authorized_keys under /home/<user>/.ssh (pkg/daemon.applySystemLogin)
//   - /etc/sudoers.d/xpf-<user> NOPASSWD grants (pkg/daemon.reconcileSudoers)
//
// All three live OUTSIDE /etc/xpf and SURVIVE the config wipe: applySystemLogin
// runs only inside the boot-time applyConfig, which a post-zeroize boot SKIPS
// (bootstrap mode / nil active config — the same boot-skip #4585 documents), and
// even a full reconcile early-returns on an empty config and never userdel's. So
// without this teardown a re-tenanted / RMA'd / resold device still carries the
// prior tenant's login accounts, SSH keys, and passwordless sudo.
//
// Ownership discipline — NEVER touch a non-xpf account (the core safety
// invariant, #1944 §5.4):
//   - Sudoers: only the xpf-<user> namespace is swept. Operator-authored
//     drop-ins (no xpf- prefix) are left untouched. The whole namespace is
//     removed unconditionally — at factory reset nothing is desired — so no
//     passwordless-root grant survives even if a marker is missing.
//   - Users: a userdel fires ONLY for an account that has a provenance marker
//     AND whose CURRENT /etc/passwd UID still equals the marker's recorded UID.
//     An operator's own account (no marker) is never iterated; a system account
//     or root (no marker) is never touched; an out-of-band userdel+recreate with
//     a different UID (marker mismatch) is left alone — exactly the #1944
//     leave-then-rejoin vs recreate distinction, so the wipe can never nuke the
//     wrong account or strand access.
//
// authorized_keys is removed BEFORE userdel so the SSH-key login vector dies
// even if userdel later fails; the marker is retained on a userdel FAILURE so a
// retried zeroize re-attempts the removal (and the failure is surfaced, so the
// device is not reported safe to re-tenant while a live account remains).
//
// Discipline mirrors zeroizeConfigDir / zeroizeRenderedConfigs: os.ErrNotExist
// is never an error (an already-absent artifact is the goal), removal is
// best-effort past a single failure, but the FIRST real error is returned so a
// silently-incomplete teardown is never reported as a clean factory reset.
func zeroizeLoginAccounts() error {
	var firstErr error
	fail := func(err error) {
		if err != nil && !errors.Is(err, os.ErrNotExist) && firstErr == nil {
			firstErr = err
		}
	}

	// (A) Sweep the xpf sudoers namespace. Removing every xpf-<user> drop-in
	// guarantees no passwordless-root grant survives, independent of the marker
	// registry. Operator drop-ins without the prefix are never touched.
	if entries, err := os.ReadDir(zeroizeSudoersDir); err != nil {
		fail(err) // a real ReadDir error (absent dir is ErrNotExist → excluded)
	} else {
		for _, e := range entries {
			name := e.Name()
			if e.IsDir() || !strings.HasPrefix(name, zeroizeSudoersPrefix) {
				continue
			}
			fail(os.Remove(filepath.Join(zeroizeSudoersDir, name)))
		}
	}

	// (B) Tear down each xpf-provisioned OS user, gated on the UID-keyed marker.
	entries, err := os.ReadDir(zeroizeProvisionedUsersDir)
	if err != nil {
		// Absent dir = xpf never provisioned a login account: nothing to do.
		// Any other read error is surfaced (we cannot prove the accounts gone).
		fail(err)
		return firstErr
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name() // marker filename == account name (Base'd on write)
		markerFile := filepath.Join(zeroizeProvisionedUsersDir, name)

		recordedUID, uidErr := readProvisionedMarkerUID(markerFile)
		curUID, curOK := zeroizeLookupUID(name)
		keysFile := filepath.Join(zeroizeHomeBase, name, ".ssh", "authorized_keys")

		removeMarker := true
		switch {
		case !curOK:
			// Account already absent from /etc/passwd — it cannot authenticate.
			// Best-effort clean up any orphaned key residue; nothing to userdel.
			fail(os.Remove(keysFile))
		case uidErr != nil || curUID != recordedUID:
			// Corrupt marker OR out-of-band recreate (UID changed): NOT the
			// account xpf provisioned. Never userdel or touch its home — the
			// current owner is someone else. Drop our stale marker only.
		default:
			// curUID == recordedUID → the exact account xpf provisioned. Kill
			// the SSH-key vector first (survives a userdel failure), then remove
			// the account (userdel -r drops /etc/shadow + /etc/passwd + home).
			fail(os.Remove(keysFile))
			if out, derr := zeroizeUserdel(name); derr != nil {
				slog.Error("zeroize: failed to remove xpf-provisioned login account",
					"user", name, "err", derr, "output", strings.TrimSpace(string(out)))
				fail(derr)
				removeMarker = false // keep the marker so a retry re-attempts
			} else {
				slog.Info("zeroize: removed xpf-provisioned login account", "user", name)
			}
		}
		if removeMarker {
			fail(os.Remove(markerFile))
		}
	}
	// Drop the now-empty marker directory (best-effort; ENOTEMPTY after a
	// retained marker is fine and must not gate the factory reset).
	_ = os.Remove(zeroizeProvisionedUsersDir)
	return firstErr
}

// readProvisionedMarkerUID reads a provenance marker file and returns the UID
// it records (pkg/daemon.markProvisioned writes the account's UID as decimal
// text). A read or parse error yields the "not our account" disposition in
// zeroizeLoginAccounts (no userdel).
func readProvisionedMarkerUID(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(data)))
}

// performZeroizeWipe erases the on-disk config, rendered service-config
// secrets, provisioned login accounts, BPF pins, and managed networkd files
// (factory reset). It is a package var so a test can drive the `zeroize`
// SystemAction verb (to assert the #4108 F8 journal wiring) WITHOUT wiping a
// real /etc/xpf on the developer/appliance box. It returns a non-nil error when
// a security-critical erasure did not fully complete (#4576/#4585/#4598).
var performZeroizeWipe = func() error {
	// Config state FIRST — the security-critical erasure. A failure here can
	// leave prior-tenant config/secrets on disk, so it is surfaced to the
	// caller (#4576).
	err := zeroizeConfigDir(defaultConfigDir, defaultConfigBase)

	// Rendered service configs (#4585): also security-critical — routing-auth
	// keys in a world-readable frr.conf, IKE PSKs, Kea configs. A post-zeroize
	// boot enters bootstrap / nil-active-config normal boot and SKIPS the
	// reconcile that would clear them, so the wipe must erase them itself. Fold
	// its first error into the surfaced result (the .configdb error takes
	// priority) so a partial wipe is never reported as a clean factory reset.
	if e := zeroizeRenderedConfigs(
		frr.DefaultFRRConf,
		filepath.Join(ipsec.DefaultSwanctlDir, ipsec.BPFRXConfFile),
		dhcpserver.DefaultKea4ConfPath,
		dhcpserver.DefaultKea6ConfPath,
	); e != nil && err == nil {
		err = e
	}

	// Provisioned login accounts (#4598): the OS users xpf created — their
	// /etc/shadow hashes, SSH authorized_keys, and /etc/sudoers.d/xpf-* grants —
	// live OUTSIDE /etc/xpf and SURVIVE the config wipe (applySystemLogin runs
	// only inside the boot-time applyConfig, which a post-zeroize boot SKIPS), so
	// a re-tenanted device would otherwise grant the prior tenant interactive
	// login + passwordless sudo. Marker-aware teardown (UID-keyed provenance
	// marker, #1944) so a non-xpf admin/system/operator account is NEVER touched.
	// Also security-critical, so fold its first error into the surfaced result.
	if e := zeroizeLoginAccounts(); e != nil && err == nil {
		err = e
	}

	// BPF pins + managed networkd files carry no secret material, so their
	// removal stays best-effort (logged, never fatal — they do not gate the
	// success/failure of the factory reset).
	if e := os.RemoveAll("/sys/fs/bpf/xpf"); e != nil {
		slog.Warn("zeroize: remove BPF pins failed", "err", e)
	}
	if ndFiles, e := os.ReadDir("/etc/systemd/network"); e == nil {
		for _, f := range ndFiles {
			if strings.HasPrefix(f.Name(), "10-xpf-") {
				if re := os.Remove(filepath.Join("/etc/systemd/network", f.Name())); re != nil && !errors.Is(re, os.ErrNotExist) {
					slog.Warn("zeroize: remove networkd file failed", "file", f.Name(), "err", re)
				}
			}
		}
	}
	return err
}
