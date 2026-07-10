// Package daemon implements the xpf daemon lifecycle.
package daemon

import (
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/fsatomic"
)

// login_password.go implements the `system login user <name> authentication
// encrypted-password` apply + declarative-reconciliation lifecycle (#1944).
//
// The OS-account password for a configured non-root user must reach
// /etc/shadow so the operator can log in on the serial console (SSH has the
// authorized_keys path; the console has nothing without a password). This
// mirrors applyRootAuth's `chpasswd -e` idiom, adds idempotency by reading
// /etc/shadow directly, and — when the directive is REMOVED from config —
// locks the account (Path D2) instead of orphaning a live credential, but
// ONLY for accounts xpf actually provisioned, identified by a UID-keyed
// provenance marker.

// pwAction is the decision a pure helper makes about whether to (re)apply,
// lock, or leave a user's password alone on a config apply.
type pwAction int

const (
	pwNoop  pwAction = iota // leave /etc/shadow as-is
	pwApply                 // write `desired` via chpasswd -e
	pwLock                  // lock the account via chpasswd -e (<user>:!)
)

// provisionedUsersDir holds one marker file per xpf-provisioned account.
// The marker's CONTENT is the numeric UID of the account at the time xpf
// last wrote its password (or created it). Keying provenance by UID (not
// name alone) lets removing the encrypted-password directive lock the SAME
// account (leave-then-rejoin: UID unchanged → lock fires) while leaving an
// out-of-band userdel+recreate alone (new UID → marker mismatch → skip),
// with no separate garbage-collection pass. /var/lib/xpf is persistent (it
// holds the config DB + archive). #1944 §5.4.
var provisionedUsersDir = "/var/lib/xpf/provisioned-users"

// shadowPath and passwdPath are the OS account databases the password
// reconciler reads directly. They are package vars only so tests can
// inject sample files; production never overrides them.
var (
	shadowPath = "/etc/shadow"
	passwdPath = "/etc/passwd"
)

// passwordAction is PURE and table-tested. It is the central safety
// invariant of #1944:
//   - Fail-OPEN toward applying a real password: on any shadow read error /
//     missing entry / mismatch, (re)apply, so a first commit never silently
//     skips the password.
//   - Fail-CLOSED (noop) in the lock branch on a read error, so a transient
//     /etc/shadow read failure can NEVER lock out an operator.
//
// cur is the current shadow password field; ok is whether it was read
// successfully; desired is the configured encrypted-password ("" when the
// directive is absent).
func passwordAction(cur string, ok bool, desired string) pwAction {
	if desired != "" {
		if !ok || cur != desired {
			return pwApply // apply on read-fail / miss / mismatch (fail-open)
		}
		return pwNoop
	}
	// desired == "": Path D2 declarative lock.
	if !ok {
		return pwNoop // never lock on a read error
	}
	if isLockedShadow(cur) {
		return pwNoop // already locked
	}
	return pwLock // empty (passwordless) OR a usable hash → lock
}

// isLockedShadow reports whether a /etc/shadow password field is in a
// locked state. A bare "*" or any field beginning with "!" ("!", "!!",
// "!$6$...") is locked. An EMPTY field is passwordless (`passwd -d`) — the
// MOST permissive state, NOT locked — so D2 must lock it. #1944 §5.4.
func isLockedShadow(s string) bool {
	return s == "*" || strings.HasPrefix(s, "!")
}

// currentShadowHash reads /etc/shadow DIRECTLY (the daemon runs as root) and
// returns the password field (field 2) for name, plus ok. It returns
// ("", false) on any read/parse error or if the user is absent. A direct
// read is used in preference to `getent shadow`, which shells out and is
// subject to nscd/NSS caching → stale reads. #1944 §5.4.
func currentShadowHash(name string) (string, bool) {
	data, err := os.ReadFile(shadowPath)
	if err != nil {
		return "", false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" {
			continue
		}
		fields := strings.SplitN(line, ":", 3)
		if len(fields) < 2 {
			continue
		}
		if fields[0] == name {
			return fields[1], true
		}
	}
	return "", false
}

// lookupUIDGID returns the numeric UID and GID for name by parsing
// /etc/passwd directly (cgo-free, consistent with currentShadowHash —
// the codebase deliberately avoids os/user to stay free of cgo/nsswitch).
// /etc/passwd field 2 is the UID, field 3 is the primary GID. Returns
// (uid, gid, true) on success, (0, 0, false) if absent or unparseable.
//
// fsatomic.WithOwner uses this so a DurableState authorized_keys write
// installs the file already owned by the target user/group at rename
// time — no post-rename chown race that could leave root-owned keys.
func lookupUIDGID(name string) (uid, gid int, ok bool) {
	data, err := os.ReadFile(passwdPath)
	if err != nil {
		return 0, 0, false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) < 4 {
			continue
		}
		if fields[0] == name {
			u, uerr := strconv.Atoi(fields[2])
			g, gerr := strconv.Atoi(fields[3])
			if uerr != nil || gerr != nil {
				return 0, 0, false
			}
			return u, g, true
		}
	}
	return 0, 0, false
}

// lookupUID returns the numeric UID for name (the GID-less convenience
// wrapper over lookupUIDGID, kept for existing callers).
func lookupUID(name string) (int, bool) {
	uid, _, ok := lookupUIDGID(name)
	return uid, ok
}

// markerPath returns the provenance marker file path for name. names are
// validated OS usernames here (created via useradd), but Clean+Base the
// name defensively so a marker can never escape the directory.
func markerPath(name string) string {
	return filepath.Join(provisionedUsersDir, filepath.Base(filepath.Clean(name)))
}

// markProvisioned records that xpf manages this exact account's password by
// writing the account's current UID into the per-user marker file. Called
// on a successful useradd AND on a successful pwApply, so that once xpf has
// written a password (even to a pre-existing or marker-wiped account),
// removing the directive will lock it. Best-effort: a marker write failure
// is logged by the caller, not fatal. #1944 §5.4.
func markProvisioned(name string, uid int) error {
	// DurableState: the marker must survive a power cut so a post-reboot
	// declarative lock can still identify the account xpf provisioned
	// (#1944 §5.4). MkdirAllDurable persists the directory entry itself,
	// not just the file's entry within it.
	if err := fsatomic.MkdirAllDurable(provisionedUsersDir, 0o700); err != nil {
		return err
	}
	return fsatomic.WriteFileDurable(markerPath(name), []byte(strconv.Itoa(uid)), 0o600)
}

// xpfProvisioned reports whether xpf manages name's password for the
// account that currently has UID curUID. It returns true ONLY if the marker
// exists AND its recorded UID equals curUID. A marker whose UID no longer
// matches (account deleted/recreated out of band with a different UID) is
// opportunistically removed — no separate GC pass — and reports false, so a
// pwLock decision never touches an out-of-band account. #1944 §5.4.
func xpfProvisioned(name string, curUID int) bool {
	data, err := os.ReadFile(markerPath(name))
	if err != nil {
		return false
	}
	recorded, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		// Corrupt marker — treat as not-ours and clean it up.
		_ = os.Remove(markerPath(name))
		return false
	}
	if recorded != curUID {
		// Stale marker for a different (recreated) account: clean inline.
		_ = os.Remove(markerPath(name))
		return false
	}
	return true
}

// homeBaseDir is the parent directory of per-user home directories. It is a
// package var only so tests can point the authorized_keys reconcile at a
// throwaway tree; production never overrides it. #5128.
var homeBaseDir = "/home"

// rootSSHDir is the root account's .ssh directory. It is a package var only so
// tests can point the root authorized_keys reconcile at a throwaway tree;
// production never overrides it. It is the root-account analogue of homeBaseDir
// for the #5276 root-credential revocation lifecycle.
var rootSSHDir = "/root/.ssh"

// rootAuthorizedKeysPath returns the xpf-managed root authorized_keys file.
// applyRootAuth writes /root/.ssh/authorized_keys wholesale from the configured
// root-authentication SSHKeys, so the whole file is xpf-owned. Revocation
// removes it to disable key-based root login, gated on the UID-keyed provenance
// marker (name "root", UID 0) so an operator-installed key file xpf never wrote
// is left untouched — the same provenance scoping the non-root
// managedAuthorizedKeysPath removal uses. #5276.
func rootAuthorizedKeysPath() string {
	return filepath.Join(rootSSHDir, "authorized_keys")
}

// managedAuthorizedKeysPath returns the xpf-managed authorized_keys file for
// name. applySystemLogin writes /home/<name>/.ssh/authorized_keys wholesale
// from the configured SSHKeys, so the whole file is xpf-owned. Two reconciles
// remove it to revoke key-based login: the absent-user reconcile when the user
// is deleted from config (#5128), and applySystemLogin's own empty-key-list
// branch when a RETAINED user's last key is removed from config (#5106).
// filepath.Base(Clean(...)) keeps the join inside homeBaseDir defensively
// (names reaching here are validated OS usernames, but never trust a name for
// a root-privileged removal). #5128.
func managedAuthorizedKeysPath(name string) string {
	return filepath.Join(homeBaseDir, filepath.Base(filepath.Clean(name)), ".ssh", "authorized_keys")
}

// reconcileAbsentLoginUsers revokes the host credentials of every
// xpf-provisioned login account that is NO LONGER present in
// cfg.System.Login.Users (#5128). Declarative removal of a `system login user`
// must revoke that user's host access — Junos semantics — not merely drop the
// sudo grant (reconcileSudoers) while leaving the account, password, and
// authorized_keys live.
//
// It is the removal half of the #1944 UID-keyed provenance lifecycle and the
// mirror of reconcileSudoers: it MUST run unconditionally on every apply
// (independent of applySystemLogin's early return) so the "all users removed"
// case still revokes. It enumerates provisionedUsersDir — the set of accounts
// xpf actually provisioned — and deprovisions each marker whose username no
// longer appears in the config. An out-of-band account (no marker) is never
// enumerated and never touched.
func (d *Daemon) reconcileAbsentLoginUsers(cfg *config.Config) {
	entries, err := os.ReadDir(provisionedUsersDir)
	if err != nil {
		// No markers yet (fresh install) or unreadable — nothing xpf
		// provisioned, so nothing to revoke.
		return
	}

	// The set of usernames still declared in config; these are kept.
	desired := make(map[string]struct{})
	if cfg.System.Login != nil {
		for _, u := range cfg.System.Login.Users {
			if u.Name == "" {
				continue
			}
			desired[u.Name] = struct{}{}
		}
	}

	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if name == "root" {
			continue // root is never provisioned/deprovisioned via config
		}
		if _, keep := desired[name]; keep {
			continue // still configured — leave it alone
		}
		d.deprovisionLoginUser(name)
	}
}

// deprovisionLoginUser revokes one removed account's password and managed
// authorized_keys, but ONLY when the UID-keyed provenance marker still matches
// the account's current UID (never an out-of-band account), then drops the
// marker so xpf forgets the account. It is fail-closed toward retry: any step
// that cannot be completed safely leaves the marker in place so the next apply
// retries, and it never removes a credential it did not first verify as
// xpf-owned. #5128.
func (d *Daemon) deprovisionLoginUser(name string) {
	curUID, uidOK := lookupUID(name)
	if !uidOK {
		// The account is already gone from the host (out-of-band userdel).
		// There is nothing to revoke; drop the stale marker so we stop
		// revisiting it every apply.
		_ = os.Remove(markerPath(name))
		return
	}
	if !xpfProvisioned(name, curUID) {
		// Marker missing or its UID no longer matches (the account was
		// deleted+recreated out of band with a different UID). xpfProvisioned
		// already cleaned a stale marker inline. NEVER touch a non-xpf account.
		return
	}

	// Lock the password (idempotent). Fail-CLOSED on a shadow read error: we
	// must not forget the account (drop the marker) while a live credential may
	// still be active — retry next apply instead. Mirrors the #1944 pwLock
	// discipline (never lock on a read error, but here that also means never
	// prematurely stop managing the account).
	cur, ok := currentShadowHash(name)
	if !ok {
		slog.Warn("skipping removed-user deprovision: cannot read shadow",
			"user", name)
		return // keep marker; retry next apply
	}
	if !isLockedShadow(cur) {
		stdin := strings.NewReader(name + ":!\n")
		if out, err := runCommandStdinTimeout(stdin, "chpasswd", "-e"); err != nil {
			slog.Warn("failed to lock password for removed login user",
				"user", name, "err", err, "output", strings.TrimSpace(string(out)))
			return // keep marker; retry
		}
		slog.Info("locked password for removed login user", "user", name)
	}

	// Remove the xpf-managed authorized_keys so key-based login is revoked too
	// (the whole file is xpf-owned — applySystemLogin writes it wholesale).
	keysFile := managedAuthorizedKeysPath(name)
	if err := os.Remove(keysFile); err != nil && !os.IsNotExist(err) {
		slog.Warn("failed to remove authorized_keys for removed login user",
			"user", name, "file", keysFile, "err", err)
		return // keep marker; retry
	}

	// Fully revoked — drop the provenance marker so xpf no longer manages this
	// account. If the same user is later re-added to config, applySystemLogin
	// recreates it and re-records the marker.
	if err := os.Remove(markerPath(name)); err != nil && !os.IsNotExist(err) {
		slog.Warn("failed to remove provenance marker after deprovision",
			"user", name, "err", err)
	}
	slog.Info("deprovisioned removed login user (password locked, keys removed)",
		"user", name)
}
