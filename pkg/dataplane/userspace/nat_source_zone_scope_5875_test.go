// #5875: a source-NAT pool address carrying an IPv6 zone/scope qualifier
// (`fe80::1%eth0`) is not representable by the Rust allocator (which parses each
// member as std::net::IpAddr, no zone model). Strict commit now rejects it, but
// a config persisted before the gate existed — or a peer-synced config on the
// LENIENT load path — still reaches the snapshot builder. The builder must fail
// CLOSED: mark the pool unusable ("zone_scoped_pool_address") so it installs
// nothing rather than shipping the unparseable string to Rust (where it would
// silently poison the whole pool at apply).
//
// RED-on-revert (nat_source.go zone-scope check removed): PoolUnusable comes
// back false and the raw scoped string ships in PoolAddresses.
package userspace

import "testing"

// This test reuses compileSNATPoolLenient (nat_source_pool_port_5457_test.go),
// which compiles via the tolerant path so a scoped pool address (which strict
// commit now rejects) survives into the compiled config, exactly as it would on
// a peer-sync / persisted-config load — the case the snapshot builder's
// fail-closed guard exists for.

// TestSourceNATSnapshotZoneScopedPoolUnusable_5875: a scoped pool address makes
// the snapshot builder mark the pool unusable with the zone_scoped reason and
// NOT translate. RED-on-revert: PoolUnusable stays false.
func TestSourceNATSnapshotZoneScopedPoolUnusable_5875(t *testing.T) {
	cfg := compileSNATPoolLenient(t,
		"set security nat source pool p1 address fe80::1%eth0")
	snaps := buildSourceNATSnapshots(cfg, nil)
	if len(snaps) != 1 {
		t.Fatalf("snapshots = %d, want 1", len(snaps))
	}
	s := snaps[0]
	if !s.PoolUnusable {
		t.Fatalf("PoolUnusable = false, want true (scoped pool address must fail closed; on revert the raw string %v ships)", s.PoolAddresses)
	}
	if s.PoolUnusableReason != "zone_scoped_pool_address" {
		t.Fatalf("PoolUnusableReason = %q, want %q", s.PoolUnusableReason, "zone_scoped_pool_address")
	}
}

// TestSourceNATSnapshotZoneScopedMixedPoolUnusable_5875: one scoped member among
// otherwise-valid members still poisons the pool at the dataplane, so the
// builder must fail the whole pool closed (matching the Rust "one bad member =
// InvalidPool" behavior).
func TestSourceNATSnapshotZoneScopedMixedPoolUnusable_5875(t *testing.T) {
	cfg := compileSNATPoolLenient(t,
		"set security nat source pool p1 address 203.0.113.5/32",
		"set security nat source pool p1 address fe80::1%eth0")
	snaps := buildSourceNATSnapshots(cfg, nil)
	if len(snaps) != 1 {
		t.Fatalf("snapshots = %d, want 1", len(snaps))
	}
	if !snaps[0].PoolUnusable || snaps[0].PoolUnusableReason != "zone_scoped_pool_address" {
		t.Fatalf("mixed pool with a scoped member must be unusable (zone_scoped_pool_address); got unusable=%v reason=%q",
			snaps[0].PoolUnusable, snaps[0].PoolUnusableReason)
	}
}

// TestSourceNATSnapshotUnscopedPoolUsable_5875: an UNSCOPED pool address (bare
// link-local, no `%`) is representable, so the builder must NOT mark the pool
// unusable. Regression guard against over-broad fail-closed.
func TestSourceNATSnapshotUnscopedPoolUsable_5875(t *testing.T) {
	cfg := compileSNATPoolLenient(t,
		"set security nat source pool p1 address 2001:db8::5/128")
	snaps := buildSourceNATSnapshots(cfg, nil)
	if len(snaps) != 1 {
		t.Fatalf("snapshots = %d, want 1", len(snaps))
	}
	if snaps[0].PoolUnusable {
		t.Fatalf("PoolUnusable = true, want false for an unscoped pool address: reason=%q", snaps[0].PoolUnusableReason)
	}
}
