// Package osident resolves the OS credential of the invoking process.
//
// It exists so no xpf CLI surface has to ask the ENVIRONMENT who the caller is
// (#6701). `$USER` is set by the caller's shell and can be anything the caller
// wants:
//
//	USER=nobody cli        # before #6701: matched no configured user ...
//	                       # ... and the `if !found` branch handed out super-user
//	env -u USER cli        # same, via the empty string
//
// Per #5278 the daemon provisions every `system login user` with a real shell
// account (`useradd -m -s /bin/bash`), so an operator restricted to
// `class read-only` had a login shell from which one environment variable
// defeated the entire login-class boundary. The kernel-supplied uid is not
// forgeable that way: it is set by the setuid()/execve() path, not by the
// process's own environment.
//
// This package is deliberately a leaf — stdlib only, no xpf imports — so both
// the daemon (pkg/daemon, pkg/cli) and the standalone remote client (cmd/cli)
// can depend on it.
package osident

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
)

// Identity is the resolved OS credential of the invoking process.
//
// Name is the account name from the passwd database for UID, or "" when the
// lookup fails (no passwd entry — a minimal container, an LDAP/NSS outage, a
// deleted account). An empty Name is a REAL and meaningful state: it means the
// process could not be identified, and callers making an authorization
// decision must fail closed on it rather than substitute a default.
type Identity struct {
	UID  int
	Name string
}

// Resolved reports whether the caller was identified — i.e. whether Name
// carries an account name from the passwd database.
func (id Identity) Resolved() bool { return id.Name != "" }

// IsRoot reports whether the caller is uid 0.
//
// uid 0 already owns the config database file, the daemon process, and the
// on-disk secrets, so it is not a boundary xpf can meaningfully enforce; it is
// the console lifeline instead. Callers use this for a Junos-parity default
// (root with no `system login user root` stanza is super-user), never to
// OVERRIDE an explicit configured class.
func (id Identity) IsRoot() bool { return id.UID == 0 }

// String renders the identity for a log line or a shell prompt: the account
// name when known, otherwise an explicit `uid-<n>` so an unidentified caller
// is never displayed as a plausible account name.
func (id Identity) String() string {
	if id.Name != "" {
		return id.Name
	}
	return fmt.Sprintf("uid-%d", id.UID)
}

// lookupID is the passwd-database lookup, indirected so tests can drive the
// failure branch (no passwd entry) without needing a broken NSS.
var lookupID = func(uid int) (string, error) {
	u, err := user.LookupId(strconv.Itoa(uid))
	if err != nil {
		return "", err
	}
	if u == nil {
		return "", fmt.Errorf("no passwd entry for uid %d", uid)
	}
	return u.Username, nil
}

// Current returns the identity of the invoking process, derived from the REAL
// uid (os.Getuid).
//
// It never reads $USER or $LOGNAME. The REAL uid — not the effective one — is
// the right question here: it is the identity of whoever invoked the process,
// which is what an RBAC decision is about. Under `sudo` both are 0 because sudo
// really does become root, and xpf's sudo grant is issued only to `super-user`
// class accounts (pkg/daemon reconcileSudoers), so a restricted user has no
// sudo path to uid 0 to begin with.
//
// A failed passwd lookup yields Name == "" (never a fabricated default), so a
// caller that fails closed on an unresolved identity does so on the real
// signal.
func Current() Identity {
	uid := os.Getuid()
	name, err := lookupID(uid)
	if err != nil {
		return Identity{UID: uid}
	}
	return Identity{UID: uid, Name: name}
}
