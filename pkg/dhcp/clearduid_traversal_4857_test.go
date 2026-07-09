package dhcp

import (
	"os"
	"path/filepath"
	"testing"
)

// TestClearDUIDRejectsPathTraversal pins #4857: ClearDUID derives the DUID
// state-file path from the caller-supplied interface name, which arrives
// verbatim from the REST/gRPC `interface` field. A traversal-y name
// ("../../victim") must be REFUSED — ClearDUID must return an error and must
// NOT unlink any file outside the DUID state directory.
//
// RED on revert: without the validInterfaceName / containment guard in
// duidPath, filepath.Join("<state>", "dhcpv6-duid-../../victim") normalizes to
// "<tmp>/victim" and os.Remove deletes the bystander file — the assertion that
// it still exists fails.
func TestClearDUIDRejectsPathTraversal(t *testing.T) {
	tmp := t.TempDir()
	stateDir := filepath.Join(tmp, "state")
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		t.Fatalf("mkdir state: %v", err)
	}

	// A root-owned bystander OUTSIDE the DUID state dir. The fixed
	// "dhcpv6-duid-" prefix absorbs the FIRST ".." (it pops the literal
	// "dhcpv6-duid-.." component), so "../../../victim" is the shortest
	// traversal that escapes stateDir and resolves to <tmp>/victim — the
	// arbitrary-root-file-unlink primitive #4857 is about.
	victim := filepath.Join(tmp, "victim")
	if err := os.WriteFile(victim, []byte("do-not-delete"), 0o600); err != nil {
		t.Fatalf("write victim: %v", err)
	}

	m, err := New(stateDir, func() {}, func() {})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if err := m.ClearDUID("../../../victim"); err == nil {
		t.Fatalf("ClearDUID accepted a traversal interface name; want an error")
	}
	if _, err := os.Stat(victim); err != nil {
		t.Fatalf("ClearDUID unlinked a file outside the DUID state dir: %v", err)
	}

	// A few more clearly-invalid names must all be refused.
	for _, bad := range []string{"..", ".", "eth0/../../x", "a b", "way-too-long-ifname-01234"} {
		if err := m.ClearDUID(bad); err == nil {
			t.Errorf("ClearDUID(%q) accepted; want an error", bad)
		}
	}
}

// TestClearDUIDNormalInterfaceStillClears asserts the validation does not
// regress the legitimate path: a real interface name's persisted DUID is
// removed, and a VLAN sub-interface name (contains '.') is accepted.
func TestClearDUIDNormalInterfaceStillClears(t *testing.T) {
	stateDir := t.TempDir()
	m, err := New(stateDir, func() {}, func() {})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	for _, ifname := range []string{"ge-0-0-0", "reth0.50"} {
		p, err := m.duidPath(ifname)
		if err != nil {
			t.Fatalf("duidPath(%q) rejected a valid interface name: %v", ifname, err)
		}
		if err := os.WriteFile(p, []byte("duid-bytes"), 0o644); err != nil {
			t.Fatalf("seed DUID file for %q: %v", ifname, err)
		}
		if err := m.ClearDUID(ifname); err != nil {
			t.Fatalf("ClearDUID(%q) returned error: %v", ifname, err)
		}
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("ClearDUID(%q) did not remove the DUID file (stat err=%v)", ifname, err)
		}
	}

	// Clearing a never-persisted interface is a no-op success (os.IsNotExist).
	if err := m.ClearDUID("ge-0-0-1"); err != nil {
		t.Fatalf("ClearDUID of an absent DUID should succeed, got: %v", err)
	}
}
