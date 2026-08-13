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
// userFile) with no NSS either, and this package applies os/user's row filters
// (matchPasswdRow) and its chunked long-row reader (readPasswdRow) unchanged.
// So for a READABLE database, every uid the file maps to exactly one account
// name resolves to that same name here.
//
// Two divergences are deliberate, and both narrow the IDENTITY:
//
//	a uid mapped to SEVERAL names resolves to "" here, where os/user returns
//	whichever row came first — see lookupPasswd for why that fails closed.
//	a uid with NO row also resolves to "" here (Reason ReasonNoPasswdEntry),
//	instead of to whatever the caller put in $USER.
//
// A NARROWER IDENTITY IS NOT A NARROWER CLASS, and at uid 0 it inverts
// (#6706 review r11). An earlier revision of this comment said the two
// divergences are "both NARROW" without that qualification, which reads as a
// statement about the authorization outcome. It is not one. This package
// decides only WHO the caller is; pkg/cli ResolveLoginClass decides what they
// may do, and for uid 0 an unresolved identity is MORE permissive than a
// resolved one. Measured, with `system login user toor class read-only;` and
// a uid-0 passwd alias `toor`:
//
//	resolved   uid 0 "toor"          -> class "read-only"
//	unresolved uid 0 (LookupFailed)  -> class "super-user"
//	unresolved uid 0 (NoPasswdEntry) -> class "super-user"
//	unresolved uid 0 (AmbiguousUID)  -> class "super-user"
//
// All three unresolved Reasons promote, because candidateNames offers only the
// literal "root" for an unnamed uid 0 and no `root` stanza matches, so
// ResolveLoginClass falls to ClassRootDefault. That promotion is DELIBERATE and
// is argued at pkg/cli/identity.go: uid 0 already owns the config database, the
// daemon process and the on-disk secrets, so it is not a boundary xpf can
// enforce, and denying would risk locking the console out over an unreadable
// passwd. It is stated here because the word "narrow" alone would let a reader
// conclude the opposite. For NON-root callers the divergences do narrow the
// class as well — an unresolved non-root identity matches no stanza and gets
// ClassUnidentified.
//
// Both divergences produce an empty Name — Resolved() == false — and nothing
// else; this package mints no placeholder account name. String() renders such
// an identity as `uid-<n>` for a log line or prompt. The word "unidentified" is
// a CATEGORY here, never a value: earlier revisions of this comment spelled it
// as though `Name` held the literal "unidentified", which is greppable text a
// reader would look for and not find. The class an unresolved caller lands in
// is pkg/cli's ClassUnidentified, whose value is "unauthorized" — a different
// thing again, one layer up (#6706 review r10 F4).
//
// pkg/cli fails closed on both FOR EVERY NON-ROOT CALLER. It does NOT for uid
// 0, and the difference is deliberate rather than an oversight — but an earlier
// revision of this sentence said "fails closed on both" flat, which is false
// for the one uid where the direction is a promotion (#6706 review r11).
// Measured by driving cli.ResolveLoginClass: uid 0 with ReasonAmbiguousUID,
// ReasonNoPasswdEntry or ReasonLookupFailed, against a config carrying
// `system login user toor class read-only`, resolves to `super-user` in all
// three cases — because candidateNames offers only the literal "root" for an
// unnamed uid 0, no `root` stanza matches, and ResolveLoginClass decision 2
// hands back the Junos root default. cli.ResolveLoginClass documents WHY that
// is left as-is (uid 0 owns the config database, the daemon process and the
// on-disk secrets, so a CLI-level denial is advisory and the alternative is
// locking the console out over a passwd alias) and its reason string says so to
// the operator. What must not happen is this package claiming otherwise.
//
// The sentence above is scoped to "exactly one name" and "readable" on purpose:
// an earlier revision claimed parity for every uid that HAS a row, which the
// ambiguity refusal falsifies outright (#6706 review r4/r5 F5).
//
// A cgo-enabled dev build loses NSS name resolution — and that affects the RBAC
// CLASS DECISION, not merely the displayed prompt. An NSS-only account (LDAP,
// SSSD) resolves to an empty Name — unidentified, the category — and is
// therefore denied, where a cgo build would previously have named it. That is a
// narrowing for every non-root uid. It is NOT a narrowing at uid 0, for the
// same reason as above: an unnamed uid 0 takes the root default, so a uid 0
// that a cgo build would have named through NSS as an aliased account carrying
// an explicit restrictive class is PROMOTED to super-user by losing the name.
// An earlier revision said "a narrowing and never a promotion", which is the
// claim this paragraph now scopes (#6706 review r11). uid 0 is essentially
// always a local passwd row, so this is a statement about the claim rather than
// a reachable production regression; the shipped build is CGO_ENABLED=0 (see
// the Makefile) and is unaffected either way.
// TestNoOsUserInIdentityResolution_6701 keeps os/user out.
package osident

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
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
// the console lifeline instead. Callers use this for a Junos-parity default:
// root with no MATCHING `system login user` stanza is super-user.
//
// "No matching stanza" is the honest phrasing, and an earlier revision's
// "never to OVERRIDE an explicit configured class" was not (#6706 review r11).
// The default does not override a class that MATCHED — an explicit
// `system login user root class read-only` still wins, and so does a stanza
// written for a resolved alias. But when the passwd lookup FAILS, uid 0 has no
// name to match with, so an explicit class the operator wrote for that account
// under its alias (`user toor class read-only`) is not applied and the caller
// lands on super-user. From the operator's side that is indistinguishable from
// an override, and it is reachable through all three unresolved Reasons.
// cli.ResolveLoginClass decision 1 documents the case, TestRootAliasClassMatrix_6706
// pins the matrix, and the reason string tells the operator that an explicit
// class was NOT applied rather than claiming root is unconfigured.
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

	want := strconv.Itoa(uid)
	var names []string
	rd := bufio.NewReader(f)
	for {
		row, whole, readErr := readPasswdRow(rd)
		if whole {
			// matchPasswdRow's second result, not `name != ""`, is what decides
			// whether the row is an entry for this uid. A redundant emptiness
			// filter here would MASK the empty-name term inside matchPasswdRow
			// and leave it unbindable by any test — which is how that term
			// survived a full mutation sweep at the previous head (#6706 review
			// r5 F4).
			if name, isEntry := matchPasswdRow(row, want); isEntry && !containsString(names, name) {
				names = append(names, name)
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				break
			}
			return "", readErr
		}
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

// passwdRowColons is the number of colons a passwd entry carries
// (name:passwd:uid:gid:gecos:home:shell). It is the same figure os/user passes
// to readColonFile as readCols, and it is the point at which a long row stops
// being accumulated.
const passwdRowColons = 6

var passwdColon = []byte{':'}

// readPasswdRow returns the next logical row from rd. whole reports whether
// row is a complete row that should be parsed; a row cut short by EOF or by an
// I/O error mid-line is dropped, which is what os/user's readColonFile does
// with the same input. A non-nil err (io.EOF included) means stop after
// handling row.
//
// WHY THIS IS NOT A bufio.Scanner. A Scanner has a fixed maximum token size and
// ABORTS THE WHOLE SCAN with bufio.ErrTooLong on the first line that exceeds
// it — the scan cannot be resumed past the offending row, so the error reaches
// Current(), which reports ReasonLookupFailed, which pkg/cli treats as
// unidentified. Under the previous 64KiB cap one pathological row for an
// UNRELATED account therefore denied EVERY non-root operator. Measured at the
// previous head with a 70KiB GECOS field on uid 4242: lookupPasswd(1000)
// returned "" / "bufio.Scanner: token too long" where os/user still returned
// "alice" (#6706 review r5 F6). Raising the cap only moves the cliff.
//
// os/user reads a row in CHUNKS instead: it accumulates only until the row has
// the six colons a passwd entry needs, then discards the remainder, so a
// pathological row costs at most that prefix and NO single row can fail the
// lookup — the scan always continues to the next one. This does the same, which
// is also what makes the package doc's parity claim true of the READER and not
// merely of the row filters.
//
// WHAT THE MEMORY BOUND IS, precisely, because an earlier revision of this
// comment (and the commit message that shipped it) said "bounded by the
// position of the sixth colon" and that is not what the loop guarantees.
// Accumulation stops at a bufio.Reader CHUNK boundary, and only once the
// accumulated prefix ALREADY holds six colons; a row with fewer than six colons
// never satisfies that test and is retained WHOLE. Measured directly against
// this function: an 8 MiB colon-free row retains all 8388608 bytes, the same
// row with five colons retains all of it, and a row whose sixth colon is at
// byte 12 followed by an 8 MiB shell field retains 4096. So the bound is
// min(row length, the first read-chunk boundary at or after the sixth colon).
// That is EXACTLY the standard library's bound — lookup_unix.go:63 breaks on
// the same `!isPrefix || bytes.Count(wholeLine, colon) >= readCols` — so the
// parity claim is unaffected, and /etc/passwd is root-owned, so an
// attacker-chosen row is not a reachable input. This is comment accuracy, not a
// defect (#6706 review r7 F5).
func readPasswdRow(rd *bufio.Reader) (row string, whole bool, err error) {
	var acc []byte
	isPrefix := true
	for isPrefix {
		chunk, more, rerr := rd.ReadLine()
		if rerr != nil {
			// ReadLine returns a line or an error, never both, so whatever was
			// accumulated is a partial row with no terminator. os/user drops it
			// the same way.
			return "", false, rerr
		}
		isPrefix = more
		// ReadLine's slice is only valid until the next read, so this copy is
		// load-bearing rather than idiomatic tidiness.
		acc = append(acc, chunk...)
		if bytes.Count(acc, passwdColon) >= passwdRowColons {
			break
		}
	}
	// Everything past the sixth colon is the shell field, which no filter in
	// matchPasswdRow reads. Drain it without accumulating.
	for isPrefix {
		_, more, rerr := rd.ReadLine()
		if rerr != nil {
			// The row itself is complete: hand it back AND report the error, so
			// the caller stops here rather than depending on the next read
			// repeating it.
			return string(acc), true, rerr
		}
		isPrefix = more
	}
	return string(acc), true, nil
}

// matchPasswdRow reports whether row is a passwd entry for wantUID (the uid as
// strconv.Itoa renders it) and, if so, returns its account name. A comment, a
// blank line, a row that is not an entry, or an entry for another uid all yield
// ("", false).
//
// The name it returns is guaranteed NON-EMPTY — that is the whole job of the
// `fields[0] == ""` term — and lookupPasswd relies on the boolean rather than on
// the name being non-empty, so that term stays observable.
//
// These filters MIRROR os/user's pure-Go matchUserIndexValue exactly, and every
// one of them is load-bearing rather than defensive. Each of the six terms
// below was mutated out on its own, with `go build ./...` and `go vet ./...`
// rc 0 in every case, and each produced a RED: five in TestLookupPasswdParsing
// and one — the `-` prefix — only in TestPasswdReaderMatchesOsUser_6706's
// "NIS minus directive" row, because the `-badnis` fixture line is caught by the
// field-count term first. At the previous head two terms were bound by nothing
// at all and a seventh was dead (#6706 review r5 F4).
//
// An earlier revision of this comment claimed NIS compat lines (`+`, `-`) and
// truncated rows "carry no parsable uid and are skipped by the Atoi below".
// That is false — `+alice::1000:...` yields "+alice" and `alice:x:1000` yields
// "alice" — and because this lookup fails CLOSED on ambiguity, a single stray
// row for a LIVE uid turned a legitimate operator into ReasonAmbiguousUID and
// DENIED them, where the standard library resolves the name fine. Diverging
// from stdlib here does not narrow safely; it narrows into an availability
// failure.
//
//   - >= 7 fields: stdlib requires `bytes.Count(line, ':') >= 6`, so a
//     truncated row is not a passwd entry at all.
//   - name non-empty: an unnamed row is not an account.
//   - name not `+`/`-`: NIS compat lines are directives, not accounts.
//   - uid compared as a STRING: stdlib does `parts[idx] != value`, so `01000`
//     does not match uid 1000. Atoi alone would accept it.
//   - gid must parse.
//
// The `+`/`-` test is written with strings.HasPrefix where stdlib indexes
// `parts[0][0]`. Same result on every non-empty name, but stdlib's form is
// panic-safe only because the emptiness test sits to its left in the same `||`
// chain — which would make removing the emptiness test show up as an index
// PANIC rather than as the parity failure it is. Splitting them keeps each term
// answerable by an assertion.
//
// stdlib also runs `strconv.Atoi(parts[2])` on the uid field. That branch is
// DEAD once the uid is compared against strconv.Itoa's output — Itoa emits a
// canonical decimal, which Atoi always accepts — so it is not reproduced here.
// Re-adding it as a panic() and running the suite never fires it. Its absence
// cannot change a result; keeping it would have been a term no mutation could
// bind.
func matchPasswdRow(row, wantUID string) (string, bool) {
	line := strings.TrimSpace(row)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", false
	}
	fields := strings.Split(line, ":")
	if len(fields) < 7 {
		return "", false
	}
	name := fields[0]
	if name == "" {
		return "", false
	}
	if strings.HasPrefix(name, "+") || strings.HasPrefix(name, "-") {
		return "", false
	}
	if fields[2] != wantUID {
		return "", false
	}
	if _, convErr := strconv.Atoi(fields[3]); convErr != nil {
		return "", false
	}
	return name, true
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
func Current() Identity { return ForUID(os.Getuid()) }

// ForUID resolves an ARBITRARY uid to an Identity, applying exactly the rules
// Current applies to the calling process — including the ambiguity refusal
// documented on lookupPasswd.
//
// It exists because a uid the process did not itself run as still has to be
// identified: the REST surface learns its caller's uid from SO_PEERCRED
// (pkg/authz), not from os.Getuid. Before #6645 that surface carried its OWN
// passwd scanner, which resolved a duplicate uid to the FIRST matching row —
// the precise behaviour the comment above calls privilege escalation between
// two legitimate accounts. The two implementations then disagreed on the same
// input: REST admitted uid N as the first row's class while the CLI refused to
// name it. Nothing compared them, so both packages stayed green.
//
// One rule, one implementation, one place to change it. A second resolver is
// how the divergence happened; a shared entry point is what prevents the next.
func ForUID(uid int) Identity {
	name, err := lookupID(uid)
	return classifyLookup(uid, name, err)
}

// SetPasswdPathForTest points the credential database at path and restores the
// previous value through the returned function.
//
// Exported (unlike the package's other seams) so a CROSS-PACKAGE test can drive
// the real resolution path against a fixture: pkg/api's REST authorization
// tests and pkg/authz's resolver tests both need identities that do not depend
// on whichever accounts exist on the machine running the suite. Dep-free — no
// test-only import reaches the production binary.
func SetPasswdPathForTest(path string) (restore func()) {
	prev := passwdPath
	passwdPath = path
	return func() { passwdPath = prev }
}

// classifyLookup maps one passwd-lookup outcome to an Identity.
//
// Split out of Current so the outcome classification is a PURE function of
// (uid, name, err) and can be driven directly. That is not a stylistic split:
// the `name != ""` term in the first case is unreachable through Current
// itself, because no lookupPasswd path returns ("", nil) — every zero-name
// return carries errNoPasswdEntry, errAmbiguousUID or an I/O error. Left inside
// Current the term was therefore unbindable, which is exactly the shape
// lookupPasswd's own comment (see matchPasswdRow's second result) refuses one
// screen earlier: mutating it to a bare `err == nil` left `./pkg/osident
// ./pkg/cli ./pkg/daemon ./cmd/cli` all ok. A seam that is a plain function
// argument, rather than a package-level function variable, keeps the term
// testable without putting a repointable hook on the identity path of a package
// whose whole purpose is failing closed (#6706 review r10 F3).
//
// The term is retained rather than deleted because an unnamed success is not an
// identification: should any future lookup path return ("", nil), the caller
// must get Resolved() == false and a stated Reason, not an Identity with an
// empty Name and ReasonNone — which reads as "resolved, no failure recorded"
// and is the one combination pkg/cli has no fail-closed arm for.
func classifyLookup(uid int, name string, err error) Identity {
	switch {
	case err == nil && name != "":
		return Identity{UID: uid, Name: name}
	case errors.Is(err, errNoPasswdEntry):
		return Identity{UID: uid, Reason: ReasonNoPasswdEntry}
	case errors.Is(err, errAmbiguousUID):
		return Identity{UID: uid, Reason: ReasonAmbiguousUID}
	default:
		// Includes err == nil with an empty name.
		return Identity{UID: uid, Reason: ReasonLookupFailed}
	}
}
