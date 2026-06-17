// Package daemon implements the xpf daemon lifecycle.
package daemon

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
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

// lookupUID returns the numeric UID for name by parsing /etc/passwd
// directly (cgo-free, consistent with currentShadowHash). Returns
// (uid, true) on success, (0, false) if absent or unparseable.
func lookupUID(name string) (int, bool) {
	data, err := os.ReadFile(passwdPath)
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
	if err := os.MkdirAll(provisionedUsersDir, 0o700); err != nil {
		return err
	}
	return os.WriteFile(markerPath(name), []byte(strconv.Itoa(uid)), 0o600)
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
