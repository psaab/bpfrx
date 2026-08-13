package osident

import (
	"errors"
	"fmt"
	"os"
	"testing"
)

// spoofedUSER is a sentinel no real passwd account can carry, so an assertion
// against it is never satisfied by coincidence on whatever uid runs the suite.
const spoofedUSER = "xpf-spoofed-6701"

// TestCurrentIgnoresUSEREnv_6701 is the core #6701 property: the resolved
// identity is a function of the KERNEL credential alone, so nothing the caller
// writes into its own environment can change it.
//
// The pre-fix call sites read os.Getenv("USER") verbatim, so with USER set to
// the sentinel they returned the sentinel. Both assertions below are written to
// stay mutation-sensitive no matter which account runs the suite:
//
//   - the name must not BE the sentinel (catches a straight $USER read);
//   - the identity with USER set must EQUAL the identity with USER unset
//     (catches a $USER read with any fallback — the old code fell back to
//     "root" in pkg/cli and "remote" in cmd/cli, and a plain equality against
//     one of those would be vacuous when the suite happens to run as root).
func TestCurrentIgnoresUSEREnv_6701(t *testing.T) {
	t.Setenv("USER", spoofedUSER)
	t.Setenv("LOGNAME", spoofedUSER)
	spoofed := Current()

	if spoofed.Name == spoofedUSER {
		t.Fatalf("Current().Name = %q: identity came from $USER, not the OS credential", spoofed.Name)
	}
	if spoofed.String() == spoofedUSER {
		t.Fatalf("Current().String() = %q: identity came from $USER, not the OS credential", spoofed.String())
	}
	if spoofed.UID != os.Getuid() {
		t.Fatalf("Current().UID = %d, want the real uid %d", spoofed.UID, os.Getuid())
	}

	os.Unsetenv("USER")
	os.Unsetenv("LOGNAME")
	unset := Current()
	if unset != spoofed {
		t.Fatalf("Current() varies with the environment: with $USER=%q got %+v, with $USER unset got %+v",
			spoofedUSER, spoofed, unset)
	}
}

// TestCurrentResolvesRealUIDThroughPasswd_6701 pins the SOURCE of the name: it
// must be the passwd entry for the real uid. The lookupID seam is driven with a
// recorder so the assertion holds on any account, including one whose passwd
// entry is missing.
func TestCurrentResolvesRealUIDThroughPasswd_6701(t *testing.T) {
	var gotUID int
	var calls int
	restore := lookupID
	t.Cleanup(func() { lookupID = restore })
	lookupID = func(uid int) (string, error) {
		gotUID = uid
		calls++
		return "resolved-by-passwd", nil
	}

	t.Setenv("USER", spoofedUSER)
	id := Current()

	if calls != 1 {
		t.Fatalf("passwd lookup ran %d times, want exactly 1", calls)
	}
	if gotUID != os.Getuid() {
		t.Fatalf("passwd lookup keyed on uid %d, want the real uid %d", gotUID, os.Getuid())
	}
	if id.Name != "resolved-by-passwd" {
		t.Fatalf("Current().Name = %q, want the passwd-resolved name %q", id.Name, "resolved-by-passwd")
	}
	if !id.Resolved() {
		t.Fatalf("Resolved() = false for a successful passwd lookup")
	}
}

// TestCurrentUnresolvedIsEmptyNameNotAFallback_6701 covers the failure branch:
// no passwd entry must leave Name EMPTY, never a fabricated plausible account
// name. Callers making an authorization decision key on exactly this — an
// invented default would be indistinguishable from a real account and would
// silently re-open the promote-on-no-match hole from the other side.
func TestCurrentUnresolvedIsEmptyNameNotAFallback_6701(t *testing.T) {
	restore := lookupID
	t.Cleanup(func() { lookupID = restore })
	lookupID = func(int) (string, error) { return "", errors.New("no passwd entry") }

	t.Setenv("USER", spoofedUSER)
	id := Current()

	if id.Name != "" {
		t.Fatalf("Current().Name = %q on a failed passwd lookup, want \"\" (no fabricated default)", id.Name)
	}
	if id.Resolved() {
		t.Fatalf("Resolved() = true with an empty Name")
	}
	want := fmt.Sprintf("uid-%d", os.Getuid())
	if got := id.String(); got != want {
		t.Fatalf("String() = %q for an unresolved identity, want %q", got, want)
	}
	if id.UID != os.Getuid() {
		t.Fatalf("Current().UID = %d on a failed lookup, want the real uid %d", id.UID, os.Getuid())
	}
}

// TestIdentityPredicates covers the small accessors the RBAC resolver branches
// on, including the uid-0 discriminator.
func TestIdentityPredicates(t *testing.T) {
	tests := []struct {
		name     string
		id       Identity
		resolved bool
		isRoot   bool
		str      string
	}{
		{"named root", Identity{UID: 0, Name: "root"}, true, true, "root"},
		{"unresolved root", Identity{UID: 0}, false, true, "uid-0"},
		{"named user", Identity{UID: 1000, Name: "bob"}, true, false, "bob"},
		{"unresolved user", Identity{UID: 1000}, false, false, "uid-1000"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.id.Resolved(); got != tt.resolved {
				t.Errorf("Resolved() = %v, want %v", got, tt.resolved)
			}
			if got := tt.id.IsRoot(); got != tt.isRoot {
				t.Errorf("IsRoot() = %v, want %v", got, tt.isRoot)
			}
			if got := tt.id.String(); got != tt.str {
				t.Errorf("String() = %q, want %q", got, tt.str)
			}
		})
	}
}
