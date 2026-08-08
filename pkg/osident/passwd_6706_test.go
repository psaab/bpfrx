package osident

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// writePasswd writes a passwd fixture and points the package at it for the
// duration of the test.
func writePasswd(t *testing.T, rows ...string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "passwd")
	if err := os.WriteFile(path, []byte(strings.Join(rows, "\n")+"\n"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	restore := passwdPath
	t.Cleanup(func() { passwdPath = restore })
	passwdPath = path
}

// TestCurrentIgnoresUSERWhenPasswdHasNoRow_6701 is the #6706 blocker: the
// identity must stay unresolvable when the caller's uid has NO passwd row, even
// with $USER and $HOME naming a real configured account.
//
// This is the case the original #6701 tests could not reach. They asserted
// "Current() does not return $USER" while running as an account that HAS a
// passwd row, so the lookup always succeeded and the environment was never
// consulted by anything. With no row, the previous implementation went:
//
//	os/user.LookupId(uid)                     [production builds CGO_ENABLED=0]
//	  -> returns cached user.Current() when the uid matches — it always does,
//	     we ask about ourselves
//	  -> pure-Go current() tries the real passwd row, FAILS, and fabricates a
//	     User from $USER + $HOME, returning it with a NIL error
//
// so `USER=admin HOME=/tmp cli` on a box whose /etc/passwd lacks the caller's
// uid (a minimal container, an NSS outage, a deleted account) resolved to the
// account name `admin` — and `system login user admin class super-user` was
// then handed to whoever set the variable. That is the exact hole #6701 exists
// to close, one layer below the call sites it audited.
//
// FAIL-ON-REVERT: put os/user.LookupId back in lookupID and this goes RED in
// BOTH build modes — under CGO_ENABLED=0 on Name (it becomes `admin`), and
// under cgo on Reason (getpwuid_r resolves the real account, so the identity is
// not the fixture's).
func TestCurrentIgnoresUSERWhenPasswdHasNoRow_6701(t *testing.T) {
	uid := os.Getuid()
	// Rows for uids that are deliberately NOT the running one, so the fixture
	// is a passwd database in which this caller does not exist.
	writePasswd(t,
		fmt.Sprintf("admin:x:%d:%d::/home/admin:/bin/bash", uid+7001, uid+7001),
		fmt.Sprintf("decoy:x:%d:%d::/home/decoy:/bin/bash", uid+7002, uid+7002),
	)
	t.Setenv("USER", "admin")
	t.Setenv("LOGNAME", "admin")
	t.Setenv("HOME", "/home/admin")

	id := Current()

	if id.Name != "" {
		t.Fatalf("Current().Name = %q with no passwd row for uid %d — the identity came from "+
			"the environment, so $USER still decides who the caller is (#6701)", id.Name, uid)
	}
	if id.Resolved() {
		t.Fatalf("Resolved() = true with an empty Name")
	}
	if id.Reason != ReasonNoPasswdEntry {
		t.Fatalf("Reason = %v, want ReasonNoPasswdEntry — the caller is absent from the passwd "+
			"database, which is a different operator problem from an unreadable one", id.Reason)
	}
	if id.UID != uid {
		t.Fatalf("Current().UID = %d, want the real uid %d", id.UID, uid)
	}
}

// TestCurrentAmbiguousUIDFailsClosed_6701 covers the #6706 MAJOR: a uid shared
// by two accounts must not resolve to whichever passwd row comes first.
//
// `admin:x:2001:` + `bob:x:2001:` with `user admin class super-user` and `user
// bob class read-only` is a privilege escalation BETWEEN TWO LEGITIMATE
// ACCOUNTS — the kernel hands us 2001 and nothing else, so bob's process is
// indistinguishable from admin's. os/user resolves it by file order. Refusing
// to name the caller is the only sound answer; pkg/cli then denies.
func TestCurrentAmbiguousUIDFailsClosed_6701(t *testing.T) {
	uid := os.Getuid()
	writePasswd(t,
		fmt.Sprintf("admin:x:%d:%d::/home/admin:/bin/bash", uid, uid),
		fmt.Sprintf("bob:x:%d:%d::/home/bob:/bin/bash", uid, uid),
	)

	id := Current()

	if id.Name != "" {
		t.Fatalf("Current().Name = %q for a uid shared by two accounts — the caller was named "+
			"from passwd file order, so whichever row is first lends its login class to the "+
			"other account", id.Name)
	}
	if id.Reason != ReasonAmbiguousUID {
		t.Fatalf("Reason = %v, want ReasonAmbiguousUID", id.Reason)
	}
}

// TestCurrentUnreadablePasswdIsDistinctFromAbsent_6701 pins the third category.
// Both deny, but "the database says you do not exist" and "the database could
// not be read" send the operator to different places, and reporting the second
// as the first sends them hunting for an account that is in fact present.
func TestCurrentUnreadablePasswdIsDistinctFromAbsent_6701(t *testing.T) {
	restore := passwdPath
	t.Cleanup(func() { passwdPath = restore })
	passwdPath = filepath.Join(t.TempDir(), "does-not-exist")

	id := Current()

	if id.Name != "" {
		t.Fatalf("Current().Name = %q with an unreadable passwd database", id.Name)
	}
	if id.Reason != ReasonLookupFailed {
		t.Fatalf("Reason = %v, want ReasonLookupFailed", id.Reason)
	}
}

// TestLookupPasswdParsing covers the reader against the shapes a real
// /etc/passwd carries.
func TestLookupPasswdParsing(t *testing.T) {
	const file = `# a comment
root:x:0:0:root:/root:/bin/bash

daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
+::::::
-badnis
truncated:x
weird:x:notanumber:5::/:/bin/sh
alice:x:1000:1000:Alice:/home/alice:/bin/bash
alice:x:1000:1000:Alice again:/home/alice:/bin/bash
twin-a:x:2001:2001::/home/a:/bin/sh
twin-b:x:2001:2001::/home/b:/bin/sh
+alice::1000:1000:::
shortbob:x:1000
zeropad:x:01000:1000:Carol:/home/carol:/bin/sh
badgid:x:1000:NOTANUM::/home/badgid:/bin/sh
:x:1000:1000::/home/anon:/bin/sh
`
	path := filepath.Join(t.TempDir(), "passwd")
	if err := os.WriteFile(path, []byte(file), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	tests := []struct {
		name     string
		uid      int
		wantName string
		wantErr  error
	}{
		// Every case below with uid 1000 is load-bearing for the SAME assertion:
		// alice must still resolve. This lookup fails CLOSED on ambiguity, so a
		// row this parser accepts but os/user rejects does not merely add
		// noise — it turns a legitimate operator into ReasonAmbiguousUID and
		// DENIES them. The fixture therefore carries one row for EACH term of
		// matchPasswdRow, at alice's OWN uid, so removing any single term makes
		// "ordinary row" fail with errAmbiguousUID (#6706 MINOR-4, completed for
		// the two terms that were still unbound at r5 — see F4 there: dropping
		// `fields[0] == ""` or the gid Atoi left the whole suite green).
		{"ordinary row", 1000, "alice", nil},
		{"duplicate identical row is one account", 1000, "alice", nil},
		// `+alice::1000:1000:::` — a NIS compat directive, not an account.
		// stdlib rejects on parts[0][0] == '+'.
		{"NIS compat line at a live uid does not alias it", 1000, "alice", nil},
		// `shortbob:x:1000` — three fields. stdlib requires >= 6 colons.
		{"truncated row at a live uid does not alias it", 1000, "alice", nil},
		// `zeropad:x:01000:...` — Atoi("01000") == 1000, but stdlib compares the
		// uid field as a STRING, so it never matches uid 1000.
		{"zero-padded uid does not alias the same numeric uid", 1000, "alice", nil},
		// `badgid:x:1000:NOTANUM::/home/badgid:/bin/sh` — a real uid match with
		// an unparsable GID. stdlib rejects it on `Atoi(parts[3])`. Binds the
		// gid term: without it lookupPasswd(1000) returns
		// "uid 1000 is shared by alice, badgid" and denies alice.
		{"unparsable gid at a live uid does not alias it", 1000, "alice", nil},
		// `:x:1000:1000::/home/anon:/bin/sh` — seven fields, matching uid, no
		// NAME. stdlib rejects it on `parts[0] == ""`. Binds the empty-name
		// term: without it the empty string is collected as a second account
		// name for uid 1000 and alice is denied.
		{"empty account name at a live uid does not alias it", 1000, "alice", nil},
		{"uid 0", 0, "root", nil},
		{"absent uid", 4242, "", errNoPasswdEntry},
		{"two distinct names share a uid", 2001, "", errAmbiguousUID},
		// `+::::::` and `-badnis` must not be mistaken for uid 0.
		{"malformed rows do not alias uid 0", 5, "", errNoPasswdEntry},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := lookupPasswd(path, tt.uid)
			if got != tt.wantName {
				t.Errorf("name = %q, want %q", got, tt.wantName)
			}
			switch {
			case tt.wantErr == nil && err != nil:
				t.Errorf("unexpected error: %v", err)
			case tt.wantErr != nil && err == nil:
				t.Errorf("no error, want %v", tt.wantErr)
			case tt.wantErr != nil && !strings.Contains(err.Error(), tt.wantErr.Error()):
				t.Errorf("error = %v, want one wrapping %v", err, tt.wantErr)
			}
		})
	}
}

// osUserColon and the two functions below are a VERBATIM transcription of the
// standard library's pure-Go passwd reader — readColonFile plus the uid half of
// matchUserIndexValue — from $GOROOT/src/os/user/lookup_unix.go at go1.26.4.
//
// It has to be a copy: os/user offers no seam for pointing LookupId at a
// fixture, so the only way to compare this package against the implementation
// it claims parity with is to run that implementation over the same bytes. The
// copy is the ORACLE, so it must not be "improved" — if the toolchain's reader
// changes, this is what has to be re-transcribed, and
// TestPasswdReaderMatchesOsUser_6706 is what will disagree.
var osUserColon = []byte{':'}

func osUserReadColonFile(r io.Reader, fn func(line []byte) (any, error), readCols int) (v any, err error) {
	rd := bufio.NewReader(r)
	for {
		var isPrefix bool
		var wholeLine []byte
		for {
			var line []byte
			line, isPrefix, err = rd.ReadLine()
			if err != nil {
				if err == io.EOF {
					err = nil
				}
				return nil, err
			}
			if !isPrefix && len(wholeLine) == 0 {
				wholeLine = line
				break
			}
			wholeLine = append(wholeLine, line...)
			if !isPrefix || bytes.Count(wholeLine, osUserColon) >= readCols {
				break
			}
		}
		wholeLine = bytes.TrimSpace(wholeLine)
		if len(wholeLine) == 0 || wholeLine[0] == '#' {
			continue
		}
		v, err = fn(wholeLine)
		if v != nil || err != nil {
			return
		}
		for ; isPrefix; _, isPrefix, err = rd.ReadLine() {
			if err != nil {
				if err == io.EOF {
					err = nil
				}
				return nil, err
			}
		}
	}
}

func osUserMatchUID(value string) func(line []byte) (any, error) {
	substr := []byte(":" + value + ":")
	return func(line []byte) (v any, err error) {
		if !bytes.Contains(line, substr) || bytes.Count(line, osUserColon) < 6 {
			return
		}
		parts := strings.SplitN(string(line), ":", 7)
		if len(parts) < 6 || parts[2] != value || parts[0] == "" ||
			parts[0][0] == '+' || parts[0][0] == '-' {
			return
		}
		if _, err := strconv.Atoi(parts[2]); err != nil {
			return nil, nil
		}
		if _, err := strconv.Atoi(parts[3]); err != nil {
			return nil, nil
		}
		return parts[0], nil
	}
}

// osUserLookupUID resolves uid against path the way os/user would, returning ""
// when os/user would report the uid unknown.
func osUserLookupUID(t *testing.T, path string, uid int) string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer f.Close()
	v, err := osUserReadColonFile(f, osUserMatchUID(strconv.Itoa(uid)), 6)
	if err != nil || v == nil {
		return ""
	}
	return v.(string)
}

// writeRows writes rows to a fresh file and returns its path.
func writeRows(t *testing.T, rows ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "passwd")
	if err := os.WriteFile(path, []byte(strings.Join(rows, "\n")+"\n"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
}

// TestPasswdReaderMatchesOsUser_6706 BINDS the parity claim the package doc
// makes, instead of asserting it in prose.
//
// That claim — "for a readable database, every uid the file maps to exactly one
// account name resolves to that same name here" — has now been falsified three
// times by three different mechanisms (row filters that accepted rows stdlib
// rejects; the ambiguity refusal; a 64KiB token cap that failed the whole
// lookup on one long row). Each time it was found by a reader running the
// comparison by hand. This runs it in the suite: every case below is fed to
// lookupPasswd AND to the stdlib transcription above, and the two names must
// agree.
//
// The DELIBERATE divergences are asserted separately, by
// TestCurrentAmbiguousUIDFailsClosed_6701 and
// TestCurrentIgnoresUSERWhenPasswdHasNoRow_6701, and the last case here pins
// the ambiguity one directly so parity is never "fixed" by removing it.
func TestPasswdReaderMatchesOsUser_6706(t *testing.T) {
	const target = 1000
	longGecos := strings.Repeat("G", 200*1024)
	ordinary := "alice:x:1000:1000:Alice:/home/alice:/bin/bash"

	cases := []struct {
		name string
		rows []string
		uid  int
	}{
		{"canonical row", []string{ordinary}, target},
		{"extra trailing field", []string{"alice:x:1000:1000:Alice:/home/alice:/bin/bash:extra"}, target},
		{"trailing colon", []string{"alice:x:1000:1000:Alice:/home/alice:"}, target},
		{"truncated to three fields", []string{"alice:x:1000"}, target},
		{"truncated to six fields", []string{"alice:x:1000:1000:Alice:/home/alice"}, target},
		{"NIS plus directive", []string{"+alice::1000:1000:::", ordinary}, target},
		{"NIS minus directive", []string{"-alice::1000:1000:::", ordinary}, target},
		{"NIS empty directive", []string{"+::::::"}, 0},
		{"NIS netgroup directive", []string{"+@ops::1000:1000:::", ordinary}, target},
		{"zero-padded uid", []string{"zeropad:x:01000:1000::/home/z:/bin/sh"}, target},
		{"space-padded uid", []string{"spaced:x: 1000:1000::/home/s:/bin/sh"}, target},
		{"plus-signed uid", []string{"plus:x:+1000:1000::/home/p:/bin/sh"}, target},
		{"underscore-separated uid", []string{"under:x:1_000:1000::/home/u:/bin/sh"}, target},
		{"near-miss uid", []string{"near:x:11000:1000::/home/n:/bin/sh"}, target},
		{"trailing garbage on uid", []string{"garb:x:1000x:1000::/home/g:/bin/sh"}, target},
		{"unparsable gid", []string{"badgid:x:1000:NOTANUM::/home/b:/bin/sh"}, target},
		{"empty gid", []string{"nogid:x:1000:::/home/n:/bin/sh"}, target},
		{"empty account name", []string{":x:1000:1000::/home/anon:/bin/sh"}, target},
		{"leading whitespace", []string{"  " + ordinary}, target},
		{"leading tab", []string{"\t" + ordinary}, target},
		{"trailing whitespace", []string{ordinary + "   "}, target},
		{"CR terminated", []string{ordinary + "\r"}, target},
		{"comment", []string{"# alice:x:1000:1000::/h:/s"}, target},
		{"indented comment", []string{"   # alice:x:1000:1000::/h:/s"}, target},
		{"blank lines", []string{"", ordinary, "", ""}, target},
		{"colons inside gecos", []string{"alice:x:1000:1000:A:B:C:/home/alice:/bin/sh"}, target},
		{"uid 0", []string{"root:x:0:0:root:/root:/bin/bash", ordinary}, 0},
		{"absent uid", []string{ordinary}, 4242},
		{"identical duplicate rows", []string{ordinary, ordinary}, target},

		// The #6706 review r5 F6 cases: a row longer than the retired 64KiB
		// token cap must not fail the lookup. The first is the reported one —
		// the long row belongs to an UNRELATED account, and the target still has
		// to resolve.
		{"oversized row on another account", []string{
			ordinary,
			"bulk:x:4242:4242:" + longGecos + ":/home/bulk:/bin/sh",
		}, target},
		{"oversized row on another account, target last", []string{
			"bulk:x:4242:4242:" + longGecos + ":/home/bulk:/bin/sh",
			ordinary,
		}, target},
		{"oversized row on the target account", []string{
			"alice:x:1000:1000:" + longGecos + ":/home/alice:/bin/bash",
		}, target},
		{"oversized row with no colons at all", []string{longGecos, ordinary}, target},
		{"oversized row truncated before the sixth colon", []string{
			"trunc:x:1000:1000:" + longGecos,
			ordinary,
		}, target},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeRows(t, tc.rows...)
			got, err := lookupPasswd(path, tc.uid)
			want := osUserLookupUID(t, path, tc.uid)
			if got != want {
				t.Errorf("lookupPasswd(uid %d) = %q (err %v), os/user resolves %q — this package "+
					"claims parity with os/user for a readable database that maps a uid to one "+
					"name, and this row shape breaks it", tc.uid, got, err, want)
			}
		})
	}

	t.Run("ambiguity is the deliberate divergence", func(t *testing.T) {
		path := writeRows(t,
			"alice:x:1000:1000::/home/alice:/bin/sh",
			"toor:x:1000:1000::/home/toor:/bin/sh",
		)
		got, err := lookupPasswd(path, target)
		want := osUserLookupUID(t, path, target)
		if got != "" || !errors.Is(err, errAmbiguousUID) {
			t.Fatalf("lookupPasswd(uid %d) = %q / %v, want \"\" and errAmbiguousUID — the "+
				"fail-closed refusal is the whole point of not reusing os/user here", target, got, err)
		}
		if want == "" {
			t.Fatalf("os/user resolved a shared uid to %q — the transcription no longer models "+
				"the file-order behaviour this package deliberately refuses", want)
		}
	})
}

// TestOversizedRowDoesNotDenyEveryOperator_6706 is the whole-identity
// consequence of the reader change, at the level pkg/cli actually consumes.
//
// Before the chunked reader, lookupPasswd used a bufio.Scanner with a 64KiB
// token cap. bufio.Scanner surfaces ErrTooLong from Err() and cannot resume, so
// ONE over-long row anywhere in /etc/passwd — for an account with no relation to
// the caller — made Current() report ReasonLookupFailed, which pkg/cli resolves
// to ClassUnidentified. A stray service-account GECOS field denied every
// non-root operator on the box (#6706 review r5 F6).
//
// FAIL-ON-REVERT: put `sc := bufio.NewScanner(f); sc.Buffer(..., 64*1024)` back
// and this goes RED on Reason (ReasonLookupFailed instead of ReasonNone) with
// the caller's own row untouched and first in the file.
func TestOversizedRowDoesNotDenyEveryOperator_6706(t *testing.T) {
	uid := os.Getuid()
	writePasswd(t,
		fmt.Sprintf("me:x:%d:%d:Me:/home/me:/bin/sh", uid, uid),
		"bulk:x:424242:424242:"+strings.Repeat("G", 200*1024)+":/home/bulk:/bin/sh",
	)

	id := Current()

	if id.Name != "me" {
		t.Fatalf("Current().Name = %q (Reason %v) with a valid row for uid %d — one over-long "+
			"row for an UNRELATED account must not make the caller unidentifiable, because "+
			"pkg/cli denies an unidentified caller", id.Name, id.Reason, uid)
	}
	if id.Reason != ReasonNone {
		t.Fatalf("Reason = %v, want ReasonNone", id.Reason)
	}
}

// TestNoOsUserInIdentityResolution_6701 keeps os/user out of this package.
//
// It is a STRUCTURAL guard for the property TestCurrentIgnoresUSERWhenPasswdHasNoRow_6701
// asserts behaviourally, and it holds in every build mode. `os/user.LookupId`
// is not a safe identity source here for a reason that is invisible in a cgo
// dev build and decisive in the shipped one: with CGO_ENABLED=0 (Makefile) its
// pure-Go implementation falls back to $USER + $HOME and caches the result
// process-wide. A future edit that "simplifies" lookupPasswd back to the
// standard library would pass every cgo-built test while reopening #6701 on
// the appliance.
//
// FAIL-ON-REVERT: import os/user anywhere in this package and this names the
// file and goes RED.
func TestNoOsUserInIdentityResolution_6701(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	var scanned int
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, name, nil, parser.ImportsOnly)
		if perr != nil {
			t.Fatalf("parse %s: %v", name, perr)
		}
		scanned++
		for _, imp := range f.Imports {
			path := strings.Trim(imp.Path.Value, `"`)
			if path == "os/user" {
				t.Errorf("%s imports %q — under the shipped CGO_ENABLED=0 build os/user resolves "+
					"a uid with no passwd row from $USER, which is the #6701 hole; read the "+
					"passwd database directly instead (see lookupPasswd)",
					fset.Position(imp.Pos()), path)
			}
		}
	}
	if scanned == 0 {
		t.Fatal("scanned no production files — the guard is not reaching the source it checks")
	}
}

// TestOsUserCanaryDetectsTheImport_6701 proves the predicate above is not
// vacuous by running it over a synthetic file that does import os/user.
func TestOsUserCanaryDetectsTheImport_6701(t *testing.T) {
	const src = `package p

import (
	"os"
	"os/user"
	"strconv"
)

func who() string {
	u, _ := user.LookupId(strconv.Itoa(os.Getuid()))
	return u.Username
}
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "synthetic.go", src, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	var found bool
	for _, imp := range f.Imports {
		if strings.Trim(imp.Path.Value, `"`) == "os/user" {
			found = true
		}
	}
	if !found {
		t.Fatal("the import predicate did not detect os/user in a file that imports it — it " +
			"binds nothing")
	}
	// Keep ast imported in the same shape the sibling canaries use, so a future
	// edit that switches this file to a full parse does not have to re-add it.
	var _ ast.Node = f
}

// TestClassifyLookupUnnamedSuccessIsNotIdentified_6706 binds the `name != ""`
// term in classifyLookup's first case.
//
// It exists because the term was UNBINDABLE at the previous head. No
// lookupPasswd path returns ("", nil) — every empty-name return carries
// errNoPasswdEntry, errAmbiguousUID or an I/O error — so with the whole switch
// inlined in Current() there was no way to reach the combination, and mutating
// the case to a bare `err == nil` left `./pkg/osident ./pkg/cli ./pkg/daemon
// ./cmd/cli` all ok. That is precisely the shape lookupPasswd's own comment
// forbids one screen earlier ("A redundant emptiness filter here would MASK the
// empty-name term ... and leave it unbindable by any test"), so the file was
// asserting one rule and violating it (#6706 review r10 F3).
//
// Splitting the classification into a pure function makes the combination
// reachable by argument rather than by a repointable package-level hook, which
// on an identity path is a hook worth not having.
//
// FAIL-ON-REVERT: change the first case to `case err == nil:` and the unnamed
// -success sub-test reds on Reason (ReasonNone, not ReasonLookupFailed). The
// other sub-tests are the negative controls: they pin that the term did not
// swallow a NAMED success or re-route the two classified failures, so a
// mutation that deleted the whole first case cannot pass by making this one
// assertion true.
func TestClassifyLookupUnnamedSuccessIsNotIdentified_6706(t *testing.T) {
	t.Run("unnamed success is a lookup failure, not an identity", func(t *testing.T) {
		id := classifyLookup(1000, "", nil)
		if id.Resolved() {
			t.Fatalf("classifyLookup(1000, \"\", nil) reports Resolved() — an empty Name is "+
				"not an identification, and a caller that fails closed on Resolved() would "+
				"admit it: %+v", id)
		}
		if id.Reason != ReasonLookupFailed {
			t.Fatalf("classifyLookup(1000, \"\", nil).Reason = %v, want ReasonLookupFailed; "+
				"ReasonNone would read as `resolved, no failure recorded`, the one combination "+
				"pkg/cli has no fail-closed arm for", id.Reason)
		}
		if id.Name != "" {
			t.Fatalf("classifyLookup fabricated a name %q", id.Name)
		}
	})

	t.Run("a NAMED success is still an identity", func(t *testing.T) {
		// Negative control: the term must not have been widened into rejecting
		// every success.
		id := classifyLookup(1000, "alice", nil)
		if !id.Resolved() || id.Name != "alice" || id.Reason != ReasonNone {
			t.Fatalf("classifyLookup(1000, \"alice\", nil) = %+v, want a resolved alice with "+
				"ReasonNone", id)
		}
	})

	t.Run("the classified failures keep their own categories", func(t *testing.T) {
		// Negative control: the three failure arms are operator-facing (create
		// the account / fix the duplicate uid / repair the database), so
		// collapsing them into one would deny identically but misdirect.
		cases := []struct {
			err  error
			want Reason
		}{
			{fmt.Errorf("%w %d", errNoPasswdEntry, 1000), ReasonNoPasswdEntry},
			{fmt.Errorf("%w %d", errAmbiguousUID, 1000), ReasonAmbiguousUID},
			{errors.New("permission denied"), ReasonLookupFailed},
		}
		for _, tc := range cases {
			id := classifyLookup(1000, "", tc.err)
			if id.Reason != tc.want {
				t.Errorf("classifyLookup(1000, \"\", %v).Reason = %v, want %v",
					tc.err, id.Reason, tc.want)
			}
			if id.Resolved() {
				t.Errorf("classifyLookup(1000, \"\", %v) reports Resolved()", tc.err)
			}
		}
	})

	t.Run("a name arriving WITH an error is not trusted", func(t *testing.T) {
		// The first case requires err == nil as well; a name returned beside a
		// failure must not become an identity.
		id := classifyLookup(1000, "alice", fmt.Errorf("%w %d", errAmbiguousUID, 1000))
		if id.Resolved() || id.Reason != ReasonAmbiguousUID {
			t.Fatalf("classifyLookup(1000, \"alice\", errAmbiguousUID) = %+v, want unresolved "+
				"with ReasonAmbiguousUID", id)
		}
	})
}

// TestCurrentUsesClassifyLookup_6706 keeps the seam from drifting away from the
// path it stands in for: a classifyLookup that Current() no longer calls would
// leave the test above proving something about dead code.
func TestCurrentUsesClassifyLookup_6706(t *testing.T) {
	uid := os.Getuid()
	name, err := lookupID(uid)
	want := classifyLookup(uid, name, err)
	if got := Current(); got != want {
		t.Fatalf("Current() = %+v but classifyLookup(%d, %q, %v) gives %+v — Current no longer "+
			"routes through the classifier the unnamed-success test binds", got, uid, name, err, want)
	}
}
