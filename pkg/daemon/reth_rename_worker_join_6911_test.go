package daemon

import (
	"errors"
	"net"
	"testing"

	"github.com/vishvananda/netlink"
)

// #6911: renameRethMember performs a setDown -> setName -> setUp cycle on a RETH
// member. That is the same hazard #5103 fixed in programRethMAC — AF_XDP worker
// threads live across the link DOWN and touch UMEM pages the NIC unmaps as it
// tears down its queues — so this site needs the same beforeCycle join.
//
// The hazard is LATENT today (renameRethMember runs only when the target name
// does not resolve, so no binding can exist), which is exactly why these guards
// matter: the reachability argument rests on three properties of unrelated code
// and none of them is asserted. These tests assert the ORDERING and the ABORT,
// so a future change that makes the site reachable cannot silently reopen #5103.

// TestRenameRethMemberJoinsWorkersBeforeLinkDown pins the ordering: the join
// must run strictly BEFORE the first mutation of the link.
//
// RED-on-revert: moving the beforeCycle call below ops.setDown leaves
// opsAtJoin == ["down"], because the fake records every netlink op in order.
// A test that only asserted "the hook ran" would stay green under that move —
// which is the whole defect, since a join after the DOWN is no join at all.
func TestRenameRethMemberJoinsWorkersBeforeLinkDown(t *testing.T) {
	mac, err := net.ParseMAC("02:bf:72:01:01:00")
	if err != nil {
		t.Fatal(err)
	}
	link := &fakeRethLink{attrs: netlink.LinkAttrs{Index: 7, Name: "enp8s0", HardwareAddr: mac}}
	adminUp := true
	var ops []string
	installFakeRethLinkOps(t, link, &adminUp, &ops, false)

	joinRan := false
	var opsAtJoin []string
	join := func() error {
		joinRan = true
		opsAtJoin = append([]string(nil), ops...)
		return nil
	}

	if old := renameRethMember("ge-0-0-1", mac, join); old != "enp8s0" {
		t.Fatalf("renameRethMember returned %q, want enp8s0", old)
	}
	if !joinRan {
		t.Fatal("the beforeCycle worker join never ran on the rename path (#6911)")
	}
	if len(opsAtJoin) != 0 {
		t.Fatalf("worker join ran AFTER the link was already touched: ops at join = %v.\n"+
			"The join must precede setDown — workers live across the link DOWN and touch\n"+
			"UMEM pages the NIC unmaps during queue teardown (#5103, #6911).", opsAtJoin)
	}
	// The rename must still complete normally when the join succeeds.
	if link.attrs.Name != "ge-0-0-1" {
		t.Fatalf("link not renamed after a successful join: %q", link.attrs.Name)
	}
	if !adminUp {
		t.Fatal("link left administratively DOWN after a successful rename (#3920)")
	}
}

// TestRenameRethMemberAbortsWithoutTouchingLinkWhenJoinFails is the paired cell:
// on a join error the link must be left EXACTLY as found.
//
// RED-on-revert: dropping the `return ""` in the error arm lets the rename
// proceed, so ops becomes ["down", "name:ge-0-0-1", "up"] instead of empty.
// Asserting the empty-op sequence rather than just the "" return value is what
// makes this catch a fall-through — a fall-through that then failed for an
// unrelated reason would also return "".
func TestRenameRethMemberAbortsWithoutTouchingLinkWhenJoinFails(t *testing.T) {
	mac, err := net.ParseMAC("02:bf:72:01:01:00")
	if err != nil {
		t.Fatal(err)
	}
	link := &fakeRethLink{attrs: netlink.LinkAttrs{Index: 7, Name: "enp8s0", HardwareAddr: mac}}
	adminUp := true
	var ops []string
	installFakeRethLinkOps(t, link, &adminUp, &ops, false)

	join := func() error { return errors.New("worker join refused") }

	if old := renameRethMember("ge-0-0-1", mac, join); old != "" {
		t.Fatalf("renameRethMember returned %q on a failed join, want \"\"", old)
	}
	if len(ops) != 0 {
		t.Fatalf("link was mutated after the worker join failed: ops = %v.\n"+
			"A cycle with the workers in an unknown state is precisely the #5103\n"+
			"hazard this hook exists to avoid — the abort must touch nothing.", ops)
	}
	if link.attrs.Name != "enp8s0" {
		t.Fatalf("link renamed despite a failed join: %q", link.attrs.Name)
	}
	if !adminUp {
		t.Fatal("link left DOWN after an aborted rename — the abort must not touch admin state")
	}
}

// TestRenameRethMemberNilHookStillRenames keeps the nil-hook contract explicit,
// matching programRethMAC's: a nil beforeCycle means "no join needed" and must
// not change the rename behaviour. Without this, a fix that made the hook
// mandatory would break every caller with no live dataplane.
func TestRenameRethMemberNilHookStillRenames(t *testing.T) {
	mac, err := net.ParseMAC("02:bf:72:01:01:00")
	if err != nil {
		t.Fatal(err)
	}
	link := &fakeRethLink{attrs: netlink.LinkAttrs{Index: 7, Name: "enp8s0", HardwareAddr: mac}}
	adminUp := true
	var ops []string
	installFakeRethLinkOps(t, link, &adminUp, &ops, false)

	if old := renameRethMember("ge-0-0-1", mac, nil); old != "enp8s0" {
		t.Fatalf("renameRethMember with a nil hook returned %q, want enp8s0", old)
	}
	if link.attrs.Name != "ge-0-0-1" {
		t.Fatalf("link not renamed with a nil hook: %q", link.attrs.Name)
	}
}
