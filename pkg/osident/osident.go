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
//
// WHY THE PASSWD DATABASE IS READ DIRECTLY RATHER THAN VIA os/user.
// `os/user.LookupId` is NOT a safe identity source for this package, because
// under the build xpf actually ships it consults the ENVIRONMENT — the exact
// input #6701 exists to stop trusting. The chain, all in the standard library:
//
//	Makefile builds xpfd and cli with CGO_ENABLED=0, so os/user selects its
//	pure-Go implementation.
//	user.LookupId(uid) returns the cached user.Current() whenever its uid
//	matches — and it always matches here, since we ask about our own uid.
//	pure-Go current() first tries the real passwd row; if that lookup FAILS it
//	FABRICATES a User from $USER and $HOME and returns it with a nil error.
//	That fabricated identity is then cached process-wide.
//
// So on any box where the caller's uid has no passwd row — a minimal
// container, an NSS/LDAP outage, a deleted account, an unreadable
// /etc/passwd — `USER=admin HOME=/tmp cli` resolves to the account name
// `admin`, and every downstream RBAC decision believes it. That is the #6701
// hole reopened one layer below the call sites the fix audited.
//
// Reading /etc/passwd here is not a downgrade in reach: with CGO_ENABLED=0 the
// standard library's own lookup is a pure-Go /etc/passwd scan (os/user
// userFile) with no NSS either, so for every uid that HAS a local row the
// resolved name is identical. What changes is that a uid WITHOUT one now
// resolves to "unidentified" instead of to whatever the caller put in $USER —
// and pkg/cli fails closed on unidentified.
//
// A cgo-enabled dev build loses NSS name resolution — and that affects the RBAC
// CLASS DECISION, not merely the displayed prompt. An NSS-only account (LDAP,
// SSSD) resolves to "unidentified" and is therefore denied, where a cgo build
// would previously have named it. That is a narrowing and never a promotion, so
// it is safe in the direction that matters, but it is a functional narrowing
// rather than a cosmetic one and is worth stating as such. The shipped build is
// CGO_ENABLED=0 (see the Makefile), so production is unaffected either way.
// TestNoOsUserInIdentityResolution_6701 keeps os/user out.
package osident

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Identity is the resolved OS credential of the invoking process.
//
// Name is the account name from the passwd database for UID, or "" when the
// caller could not be identified UNAMBIGUOUSLY (no passwd entry, an unreadable
// database, or a uid shared by several accounts). An empty Name is a REAL and
// meaningful state: it means the process could not be identified, and callers
// making an authorization decision must fail closed on it rather than
// substitute a default. Reason records WHICH of those it was, so the operator
// gets a diagnosis that matches reality.
type Identity struct {
	UID    int
	Name   string
	Reason Reason
}

// Reason explains why Name is empty. It is a comparable enum rather than an
// error so two Identity values for the same credential compare equal (the
// #6701 environment-invariance test asserts exactly that), and because an RBAC
// caller has nothing to do with an errno beyond naming the category in its log
// line.
type Reason uint8

const (
	// ReasonNone is the zero value: no lookup failure was recorded. It is what
	// a successful lookup carries, and also what a hand-constructed Identity
	// carries — callers must key "is this caller identified?" on Resolved(),
	// never on Reason.
	ReasonNone Reason = iota
	// ReasonNoPasswdEntry: the passwd database was read and contains no row
	// for UID.
	ReasonNoPasswdEntry
	// ReasonAmbiguousUID: more than one distinct account name maps to UID, so
	// the kernel credential does not name a single account. See lookupPasswd
	// for why this fails closed rather than picking one.
	ReasonAmbiguousUID
	// ReasonLookupFailed: the passwd database could not be read at all (I/O
	// error, permissions). Distinct from ReasonNoPasswdEntry on purpose: "the
	// database says you do not exist" and "the database could not be
	// consulted" are different operator problems, and reporting the second as
	// the first sends the operator to look for a missing account that is
	// actually there.
	ReasonLookupFailed
)

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

// Sentinel lookup outcomes. lookupID returns one of these (or an I/O error) so
// Current can name the category without the caller parsing message text.
var (
	errNoPasswdEntry = errors.New("no passwd entry for uid")
	errAmbiguousUID  = errors.New("uid maps to more than one passwd account")
)

// passwdPath is the credential database. A variable so tests can point it at a
// fixture; production never changes it.
var passwdPath = "/etc/passwd"

// lookupID is the passwd-database lookup, indirected so tests can drive the
// failure branches without needing a broken NSS.
var lookupID = func(uid int) (string, error) { return lookupPasswd(passwdPath, uid) }

// lookupPasswd resolves uid to its account name by scanning the passwd
// database directly. It reads nothing but the file — no environment, no
// process-wide cache, no fallback.
//
// AMBIGUITY FAILS CLOSED. A uid shared by two names (`admin:x:2001:` and
// `bob:x:2001:` — `useradd -o`, a hand-edited passwd file, or a directory
// service that aliases) is not a rare curiosity to resolve arbitrarily: it is
// the whole authorization decision becoming undecidable. The kernel gives us
// 2001 and nothing else, so a process started by bob is INDISTINGUISHABLE from
// one started by admin. Returning "whichever row came first" — which is what
// os/user does — hands `system login user admin class super-user` to bob. That
// is privilege escalation BETWEEN TWO LEGITIMATE ACCOUNTS, not a symptom of an
// already-compromised host, so "a duplicate-uid passwd file is broken anyway"
// does not dispose of it.
//
// Refusing to name the caller is the only sound answer: pkg/cli then resolves
// the unidentified caller to the fail-closed class. uid 0 is unaffected in
// practice because pkg/cli's candidateNames still consults the literal "root"
// for uid 0 (an aliased root — the classic `toor` — keeps its console
// lifeline, and an explicit `system login user root class <c>` still wins).
func lookupPasswd(path string, uid int) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	var names []string
	sc := bufio.NewScanner(f)
	// A passwd line is short; the default 64KiB token cap is ample. Bound it
	// explicitly so a pathological file cannot be turned into an allocation.
	sc.Buffer(make([]byte, 0, 4096), 64*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// name:passwd:uid:gid:gecos:home:shell.
		//
		// These row filters MIRROR os/user's pure-Go matchUserIndexValue
		// exactly, and every one of them is load-bearing rather than defensive.
		// An earlier revision of this comment claimed NIS compat lines (`+`,
		// `-`) and truncated rows "carry no parsable uid and are skipped by the
		// Atoi below". That is false — `+alice::1000:...` yields "+alice" and
		// `alice:x:1000` yields "alice" — and because this lookup fails CLOSED
		// on ambiguity, a single stray row for a LIVE uid would have turned a
		// legitimate operator into ReasonAmbiguousUID and denied them, where
		// the standard library resolves the name fine (#6706 MINOR-4).
		// Diverging from stdlib here does not narrow safely; it narrows into an
		// availability failure, and it would falsify this package's own claim
		// that for every uid with a local row the resolved name is identical.
		//
		//   - >= 7 fields: stdlib requires `bytes.Count(line, ':') >= 6`, so a
		//     truncated row is not a passwd entry at all.
		//   - name non-empty and not `+`/`-`: NIS compat lines are directives,
		//     not accounts.
		//   - uid compared as a STRING: stdlib does `parts[idx] != value`, so
		//     `01000` does not match uid 1000. Atoi alone would accept it.
		//   - uid and gid must both parse.
		fields := strings.Split(line, ":")
		if len(fields) < 7 || fields[0] == "" || fields[0][0] == '+' || fields[0][0] == '-' {
			continue
		}
		if fields[2] != strconv.Itoa(uid) {
			continue
		}
		if _, convErr := strconv.Atoi(fields[2]); convErr != nil {
			continue
		}
		if _, convErr := strconv.Atoi(fields[3]); convErr != nil {
			continue
		}
		if !containsString(names, fields[0]) {
			names = append(names, fields[0])
		}
	}
	if err := sc.Err(); err != nil {
		return "", err
	}
	switch len(names) {
	case 0:
		return "", fmt.Errorf("%w %d", errNoPasswdEntry, uid)
	case 1:
		return names[0], nil
	default:
		return "", fmt.Errorf("%w: uid %d is shared by %s", errAmbiguousUID, uid,
			strings.Join(names, ", "))
	}
}

// containsString avoids pulling a generic slices dependency into this leaf for
// a list that is one element long in every real passwd file.
func containsString(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
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
// A failed or ambiguous passwd lookup yields Name == "" (never a fabricated
// default), so a caller that fails closed on an unresolved identity does so on
// the real signal. Reason carries which failure it was, for the log line.
func Current() Identity {
	uid := os.Getuid()
	name, err := lookupID(uid)
	switch {
	case err == nil && name != "":
		return Identity{UID: uid, Name: name}
	case errors.Is(err, errNoPasswdEntry):
		return Identity{UID: uid, Reason: ReasonNoPasswdEntry}
	case errors.Is(err, errAmbiguousUID):
		return Identity{UID: uid, Reason: ReasonAmbiguousUID}
	default:
		// Includes err == nil with an empty name, which no lookupPasswd path
		// produces but a future/test seam could: an unnamed success is not an
		// identification.
		return Identity{UID: uid, Reason: ReasonLookupFailed}
	}
}
