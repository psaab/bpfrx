// #5819: a source-NAT pool that configures BOTH `persistent-nat` and `port
// no-translation` is unsupported — the no-translation (address-only) dataplane
// path bypasses the persistent-lease machinery, so a config that claims
// persistence silently degrades to ordinary per-flow address-only NAT. The
// strict commit gate (validateSourceNATPersistentNoTranslationStrict) hard-
// rejects it; on the tolerant load / peer-sync path that gate only warns, so the
// snapshot builder must independently FAIL CLOSED — marking the pool unusable so
// nothing installs rather than shipping the silent degradation.
//
// RED-on-revert (snapshot builder marker removed): the pool ships as a usable
// address-only pool (PoolUnusable comes back false) and silently no-op's the
// persistence contract.
package userspace

import "testing"

func TestSourceNATSnapshotPersistentNoTranslationUnusable_5819(t *testing.T) {
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
			if !s.PoolUnusable {
				t.Fatalf("PoolUnusable = false, want true (persistent-nat + no-translation must fail closed, not ship as address-only)")
			}
			if s.PoolUnusableReason != "persistent_nat_no_translation" {
				t.Fatalf("PoolUnusableReason = %q, want persistent_nat_no_translation", s.PoolUnusableReason)
			}
		})
	}
}

// Control: a persistent-nat pool WITHOUT no-translation stays usable (the
// existing persistent-lease path is untouched).
func TestSourceNATSnapshotPersistentWithoutNoTranslationUsable_5819(t *testing.T) {
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
