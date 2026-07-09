package cli

import (
	"path/filepath"
	"testing"
)

// #4868 (local CLI): `commit confirmed <minutes>` must reject a malformed /
// zero / negative / int32-overflowing / over-max timeout instead of silently
// arming the 10-minute default (banana|0|-1) or a truncated value — the
// candidate must stay UNcommitted and no confirm window armed.
func TestLocalCommitConfirmedInvalidRejected_4868(t *testing.T) {
	for _, arg := range []string{"banana", "1x", "0", "-1", "4294967297", "99999"} {
		t.Run(arg, func(t *testing.T) {
			store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
			if err := store.EnterConfigure(); err != nil {
				t.Fatal(err)
			}
			c := &CLI{store: store}
			if _, err := store.LoadSet("set system host-name Edited"); err != nil {
				t.Fatal(err)
			}
			if err := c.handleCommit([]string{"confirmed", arg}); err == nil {
				t.Fatalf("commit confirmed %q: expected an error", arg)
			}
			if store.IsConfirmPending() {
				t.Fatalf("commit confirmed %q: armed a confirm window despite an invalid timeout", arg)
			}
			if !store.IsDirty() {
				t.Fatalf("commit confirmed %q: committed the candidate despite an invalid timeout", arg)
			}
		})
	}
}

// A valid timeout arms the confirm window.
func TestLocalCommitConfirmedValidArms_4868(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	c := &CLI{store: store}
	if _, err := store.LoadSet("set system host-name Edited"); err != nil {
		t.Fatal(err)
	}
	if err := c.handleCommit([]string{"confirmed", "5"}); err != nil {
		t.Fatalf("commit confirmed 5: %v", err)
	}
	if !store.IsConfirmPending() {
		t.Fatal("commit confirmed 5 should arm a pending confirm window")
	}
}

// An unrecognized modifier must ERROR before any mutation — never fall through
// to a permanent commit.
func TestLocalCommitUnknownModifierRejected_4868(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	c := &CLI{store: store}
	if _, err := store.LoadSet("set system host-name Edited"); err != nil {
		t.Fatal(err)
	}
	if err := c.handleCommit([]string{"confimed", "10"}); err == nil { // typo
		t.Fatal("commit confimed: expected an error for an unknown modifier")
	}
	if !store.IsDirty() {
		t.Fatal("an unknown commit modifier must NOT commit the candidate")
	}
}
