package daemon

import (
	"errors"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"
)

// renameSeam captures the ordered netlink call sequence renameInterface
// issues and lets each operation be made to fail. It installs itself over the
// package-global nlLink* seam vars and restores them via t.Cleanup. Tests
// using it MUST NOT call t.Parallel() — the seam vars are package-global
// mutable state.
type renameSeam struct {
	t *testing.T

	// link returned by nlLinkByName; carries a non-zero Index to mirror
	// production (netlink set ops act by ifindex, so the handle stays valid
	// across a rename — exercising the real recovery semantics).
	link *testLink

	// failures, keyed by the call-site. setUpFailFirstN fails the first N
	// LinkSetUp calls then succeeds (call-index-stateful so the "first
	// LinkSetUp fails, retry succeeds" case can be expressed).
	byNameErr       error
	setDownErr      error
	setNameErr      error
	setUpFailFirstN int
	setUpErr        error // error returned while still within setUpFailFirstN

	setUpCalls int
	// calls records the ordered (op, arg) sequence, e.g.
	// "down:enp5s0", "setname:ge-0-0-0", "up:ge-0-0-0".
	calls []string
}

func installRenameSeam(t *testing.T, oldName string) *renameSeam {
	t.Helper()
	s := &renameSeam{
		t:    t,
		link: &testLink{attrs: netlink.LinkAttrs{Name: oldName, Index: 7}},
	}

	oldByName := nlLinkByName
	oldSetDown := nlLinkSetDown
	oldSetName := nlLinkSetName
	oldSetUp := nlLinkSetUp
	t.Cleanup(func() {
		nlLinkByName = oldByName
		nlLinkSetDown = oldSetDown
		nlLinkSetName = oldSetName
		nlLinkSetUp = oldSetUp
	})

	nlLinkByName = func(name string) (netlink.Link, error) {
		s.calls = append(s.calls, "byname:"+name)
		if s.byNameErr != nil {
			return nil, s.byNameErr
		}
		// Resolve by the current link name regardless of the requested name;
		// renameInterface only ever resolves once (by oldName).
		return s.link, nil
	}
	nlLinkSetDown = func(l netlink.Link) error {
		s.calls = append(s.calls, "down:"+l.Attrs().Name)
		return s.setDownErr
	}
	nlLinkSetName = func(l netlink.Link, name string) error {
		s.calls = append(s.calls, "setname:"+name)
		if s.setNameErr != nil {
			return s.setNameErr
		}
		// Mirror the kernel: a successful rename updates the link name in
		// place. The cached handle keeps its (stable) Index.
		l.Attrs().Name = name
		return nil
	}
	nlLinkSetUp = func(l netlink.Link) error {
		s.setUpCalls++
		s.calls = append(s.calls, "up:"+l.Attrs().Name)
		if s.setUpCalls <= s.setUpFailFirstN {
			return s.setUpErr
		}
		return nil
	}
	return s
}

func (s *renameSeam) seq() string { return strings.Join(s.calls, ",") }

// assertNoRenameBack fails if any setname targeting oldName was issued (guards
// against the rejected rename-back design leaking back in).
func (s *renameSeam) assertNoRenameBack(oldName string) {
	s.t.Helper()
	for _, c := range s.calls {
		if c == "setname:"+oldName {
			s.t.Fatalf("rollback rename-back to %q was issued; sequence=%s",
				oldName, s.seq())
		}
	}
}

// TestRenameInterfaceBringsUpUnderNewNameAfterTransientUpFailure: the first
// post-rename LinkSetUp fails, the retry succeeds. The interface ends UP under
// the new name and the function returns nil. Deleting the retry makes this
// return the first error -> the assert-nil fails (non-tautological).
func TestRenameInterfaceBringsUpUnderNewNameAfterTransientUpFailure(t *testing.T) {
	const oldName, newName = "enp5s0", "ge-0-0-0"
	s := installRenameSeam(t, oldName)
	s.setUpFailFirstN = 1
	s.setUpErr = errors.New("transient ENETDOWN")

	if err := renameInterface(oldName, newName); err != nil {
		t.Fatalf("expected nil after successful retry, got %v", err)
	}
	want := "byname:enp5s0,down:enp5s0,setname:ge-0-0-0,up:ge-0-0-0,up:ge-0-0-0"
	if s.seq() != want {
		t.Fatalf("call sequence mismatch:\n got=%s\nwant=%s", s.seq(), want)
	}
	if s.setUpCalls != 2 {
		t.Fatalf("expected exactly 2 LinkSetUp calls (fail+retry), got %d", s.setUpCalls)
	}
	s.assertNoRenameBack(oldName)
	// Link is left correctly named.
	if got := s.link.Attrs().Name; got != newName {
		t.Fatalf("link left named %q, want %q", got, newName)
	}
}

// TestRenameInterfacePersistentUpFailureReturnsActionableError: both LinkSetUp
// calls fail. The function returns an actionable error that wraps the
// underlying LinkSetUp error and names both interfaces, the interface is left
// correctly named (NOT renamed back), and no rename-back was issued.
// Reintroducing a rename-back would add setname:oldName to the recorded
// sequence -> assertNoRenameBack fails (non-tautological).
func TestRenameInterfacePersistentUpFailureReturnsActionableError(t *testing.T) {
	const oldName, newName = "enp5s0", "ge-0-0-0"
	s := installRenameSeam(t, oldName)
	sentinel := errors.New("hardware fault: link up refused")
	s.setUpFailFirstN = 2 // fail the initial up AND the retry
	s.setUpErr = sentinel

	err := renameInterface(oldName, newName)
	if err == nil {
		t.Fatal("expected an error on persistent LinkSetUp failure, got nil")
	}
	if !errors.Is(err, sentinel) {
		t.Fatalf("error does not wrap the underlying LinkSetUp error via %%w: %v", err)
	}
	// The message must name both interfaces, state the DOWN condition, and be
	// actionable for BOTH recovery paths: the managed-interface reconcile and
	// the explicit operator command for the unmanaged case.
	for _, want := range []string{oldName, newName, "DOWN", "reconcile", "ip link set " + newName + " up"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error message missing %q (not actionable): %v", want, err)
		}
	}
	if s.setUpCalls != 2 {
		t.Fatalf("expected exactly 2 LinkSetUp calls (initial+retry, no loop), got %d", s.setUpCalls)
	}
	s.assertNoRenameBack(oldName)
	if got := s.link.Attrs().Name; got != newName {
		t.Fatalf("link should stay correctly named %q (never rolled back), got %q", newName, got)
	}
}

// TestRenameInterfaceSuccessPathUnchanged: all ops succeed on the first try.
// Exactly down -> setname(newName) -> up; no retry, no rename-back.
func TestRenameInterfaceSuccessPathUnchanged(t *testing.T) {
	const oldName, newName = "enp5s0", "ge-0-0-0"
	s := installRenameSeam(t, oldName)

	if err := renameInterface(oldName, newName); err != nil {
		t.Fatalf("expected nil on the happy path, got %v", err)
	}
	want := "byname:enp5s0,down:enp5s0,setname:ge-0-0-0,up:ge-0-0-0"
	if s.seq() != want {
		t.Fatalf("call sequence mismatch:\n got=%s\nwant=%s", s.seq(), want)
	}
	if s.setUpCalls != 1 {
		t.Fatalf("expected exactly 1 LinkSetUp on the happy path, got %d", s.setUpCalls)
	}
	s.assertNoRenameBack(oldName)
}

// TestRenameInterfaceLinkSetNameFailureStillRollsBackUp: regression guard on
// the pre-existing LinkSetName-failure path. The rename did not happen, so the
// link is brought back up under its original name and a rename error is
// returned. (This path intentionally DOES bring the link up, unlike the
// LinkSetUp-failure path.)
func TestRenameInterfaceLinkSetNameFailureStillRollsBackUp(t *testing.T) {
	const oldName, newName = "enp5s0", "ge-0-0-0"
	s := installRenameSeam(t, oldName)
	nameErr := errors.New("EEXIST: name in use")
	s.setNameErr = nameErr

	err := renameInterface(oldName, newName)
	if err == nil {
		t.Fatal("expected an error on LinkSetName failure, got nil")
	}
	if !errors.Is(err, nameErr) {
		t.Fatalf("error does not wrap the LinkSetName error: %v", err)
	}
	// down -> setname(fail) -> up (on the ORIGINAL name, rollback).
	want := "byname:enp5s0,down:enp5s0,setname:ge-0-0-0,up:enp5s0"
	if s.seq() != want {
		t.Fatalf("call sequence mismatch:\n got=%s\nwant=%s", s.seq(), want)
	}
	if got := s.link.Attrs().Name; got != oldName {
		t.Fatalf("link should remain on its original name %q after a failed rename, got %q", oldName, got)
	}
}

// TestRenameInterfaceLinkSetDownFailureReturnsEarly: LinkSetDown fails; no
// rename or bring-up is attempted and the error is returned.
func TestRenameInterfaceLinkSetDownFailureReturnsEarly(t *testing.T) {
	const oldName, newName = "enp5s0", "ge-0-0-0"
	s := installRenameSeam(t, oldName)
	downErr := errors.New("EBUSY: link down refused")
	s.setDownErr = downErr

	err := renameInterface(oldName, newName)
	if err == nil {
		t.Fatal("expected an error on LinkSetDown failure, got nil")
	}
	if !errors.Is(err, downErr) {
		t.Fatalf("error does not wrap the LinkSetDown error: %v", err)
	}
	want := "byname:enp5s0,down:enp5s0"
	if s.seq() != want {
		t.Fatalf("expected no rename/up after LinkSetDown failure:\n got=%s\nwant=%s", s.seq(), want)
	}
}

// TestRenameInterfaceLinkByNameFailureReturnsEarly: LinkByName fails; nothing
// else is attempted.
func TestRenameInterfaceLinkByNameFailureReturnsEarly(t *testing.T) {
	const oldName, newName = "enp5s0", "ge-0-0-0"
	s := installRenameSeam(t, oldName)
	s.byNameErr = errors.New("ENODEV")

	if err := renameInterface(oldName, newName); err == nil {
		t.Fatal("expected an error when LinkByName fails, got nil")
	}
	if s.seq() != "byname:enp5s0" {
		t.Fatalf("expected only the LinkByName call, got %s", s.seq())
	}
}
