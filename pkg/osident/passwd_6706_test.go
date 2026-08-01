package osident

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
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
		// DENIES them. The fixture therefore carries one of each stdlib-rejected
		// shape at alice's OWN uid; before the parity fix each of these alone
		// made "ordinary row" fail with errAmbiguousUID (#6706 MINOR-4).
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
