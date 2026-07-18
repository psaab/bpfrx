// #6041 (full-parity follow-up to #5819): a source-NAT pool that configures
// BOTH `persistent-nat` and `port no-translation` is now SUPPORTED. The
// userspace dataplane implements an address-only persistent lease
// (reserve_address_only_persistent, userspace-dp/src/nat/allocator.rs) that
// pins a public pool ADDRESS across the configured permit scope without
// consuming a translated pool port. The snapshot builder therefore keeps the
// pool USABLE and carries the persistent + no-translation fields — the #5819
// "persistent_nat_no_translation" fail-closed marker was removed.
//
// RED-on-revert (snapshot marker reinstated): the pool comes back PoolUnusable
// with reason "persistent_nat_no_translation" and the persistent binding never
// installs.
package userspace

import "testing"

func TestSourceNATSnapshotPersistentNoTranslationUsable_6041(t *testing.T) {
	cases := []struct {
		name string
		cmds []string
	}{
		{"permit-any-remote-host", []string{
			"set security nat source pool p1 address 203.0.113.5/32",
			"set security nat source pool p1 address 203.0.113.6/32",
			"set security nat source pool p1 port no-translation",
			"set security nat source pool p1 persistent-nat permit any-remote-host"}},
		{"ipv6", []string{
			"set security nat source pool p1 address 2001:db8::5/128",
			"set security nat source pool p1 address 2001:db8::6/128",
			"set security nat source pool p1 port no-translation",
			"set security nat source pool p1 persistent-nat inactivity-timeout 600"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := compileSNATPoolLenient(t, tc.cmds...)
			snaps := buildSourceNATSnapshots(cfg, nil)
			if len(snaps) != 1 {
				t.Fatalf("snapshots = %d, want 1", len(snaps))
			}
			s := snaps[0]
			if s.PoolUnusable {
				t.Fatalf("PoolUnusable = true, want false (persistent-nat + no-translation is now supported): reason=%q", s.PoolUnusableReason)
			}
			if s.PoolUnusableReason == "persistent_nat_no_translation" {
				t.Fatalf("PoolUnusableReason still carries the removed #5819 fail-closed marker")
			}
			if !s.PoolNoTranslation {
				t.Fatalf("PoolNoTranslation = false, want true")
			}
			if !s.PersistentNAT {
				t.Fatalf("PersistentNAT = false, want true (drives the address-only persistent lease)")
			}
		})
	}
}

// Control: a persistent-nat pool WITHOUT no-translation stays usable (the
// existing port-translating persistent-lease path is untouched).
func TestSourceNATSnapshotPersistentWithoutNoTranslationUsable_6041(t *testing.T) {
	cfg := compileSNATPoolLenient(t,
		"set security nat source pool p1 address 203.0.113.5/32",
		"set security nat source pool p1 address 203.0.113.6/32",
		"set security nat source pool p1 persistent-nat permit any-remote-host")
	snaps := buildSourceNATSnapshots(cfg, nil)
	if len(snaps) != 1 {
		t.Fatalf("snapshots = %d, want 1", len(snaps))
	}
	s := snaps[0]
	if s.PoolUnusable {
		t.Fatalf("PoolUnusable = true, want false (persistent-nat alone is supported): reason=%q", s.PoolUnusableReason)
	}
	if !s.PersistentNAT {
		t.Fatalf("PersistentNAT = false, want true")
	}
}
