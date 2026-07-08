// #4559: the source-NAT snapshot must carry the deterministic CGNAT (mode 1,
// IPv4 subscriber) block-allocation parameters to the userspace dataplane so
// the Rust allocator maps each subscriber to a fixed external IP + port block.
// An IPv6 (NAT64) subscriber host is mode 2 (still deferred) and must NOT set
// the mode-1 fields, so the pool round-robins and the commit-time advisory
// surfaces the gap. A plain pool carries no deterministic fields.
//
// RED-on-revert (builder wiring reverted): DeterministicMode comes back 0 for
// the IPv4 pool and the block/host params stay 0.
package userspace

import (
	"testing"
)

// TestSourceNATSnapshotDeterministicIPv4_4559: an IPv4-subscriber deterministic
// pool populates the mode-1 block-allocation wire fields. block-size 2016 over
// the default 1024-65535 range => 32 blocks/IP; /25 host => 128 subscribers;
// host base 100.64.0.0 => host-order 0x64400000.
func TestSourceNATSnapshotDeterministicIPv4_4559(t *testing.T) {
	cfg := compileSNATPool(t,
		"set security nat source pool p1 address 203.0.113.1/32 to 203.0.113.4/32",
		"set security nat source pool p1 port deterministic block-size 2016",
		"set security nat source pool p1 port deterministic host address 100.64.0.0/25")
	snaps := buildSourceNATSnapshots(cfg, nil)
	if len(snaps) != 1 {
		t.Fatalf("snapshots = %d, want 1", len(snaps))
	}
	s := snaps[0]
	if s.PoolUnusable {
		t.Fatalf("PoolUnusable = true, want false: %s", s.PoolUnusableReason)
	}
	if s.DeterministicMode != 1 {
		t.Fatalf("DeterministicMode = %d, want 1 (IPv4 subscriber; 0 on builder revert)", s.DeterministicMode)
	}
	if s.DeterministicBlockSize != 2016 {
		t.Fatalf("DeterministicBlockSize = %d, want 2016", s.DeterministicBlockSize)
	}
	if s.DeterministicBlocksPerIP != 32 {
		t.Fatalf("DeterministicBlocksPerIP = %d, want 32 (64512/2016)", s.DeterministicBlocksPerIP)
	}
	// 100.64.0.0 host-order = 100<<24 | 64<<16 = 0x64400000.
	const wantBase = uint32(0x64400000)
	if s.DeterministicHostBase != wantBase {
		t.Fatalf("DeterministicHostBase = %#x, want %#x (host-order 100.64.0.0)", s.DeterministicHostBase, wantBase)
	}
	if s.DeterministicHostCount != 128 {
		t.Fatalf("DeterministicHostCount = %d, want 128 (/25)", s.DeterministicHostCount)
	}
}

// TestSourceNATSnapshotDeterministicIPv6Deferred_4559: an IPv6 (NAT64)
// subscriber host is mode 2 and NOT yet enforced, so the builder leaves the
// mode-1 fields zero (the pool round-robins; the advisory covers it).
func TestSourceNATSnapshotDeterministicIPv6Deferred_4559(t *testing.T) {
	cfg := compileSNATPool(t,
		"set security nat source pool p1 address 203.0.113.1/32 to 203.0.113.4/32",
		"set security nat source pool p1 port deterministic block-size 2016",
		"set security nat source pool p1 port deterministic host address 2001:db8::/64")
	snaps := buildSourceNATSnapshots(cfg, nil)
	if len(snaps) != 1 {
		t.Fatalf("snapshots = %d, want 1", len(snaps))
	}
	s := snaps[0]
	if s.DeterministicMode != 0 {
		t.Fatalf("DeterministicMode = %d, want 0 (IPv6 subscriber is deferred mode 2)", s.DeterministicMode)
	}
	if s.DeterministicBlockSize != 0 || s.DeterministicBlocksPerIP != 0 ||
		s.DeterministicHostBase != 0 || s.DeterministicHostCount != 0 {
		t.Fatalf("IPv6 deterministic pool must leave mode-1 fields zero, got %+v", s)
	}
}

// TestSourceNATSnapshotDeterministicAbsent_4559: a plain source-NAT pool carries
// no deterministic wire fields.
func TestSourceNATSnapshotDeterministicAbsent_4559(t *testing.T) {
	cfg := compileSNATPool(t,
		"set security nat source pool p1 address 203.0.113.5/32")
	snaps := buildSourceNATSnapshots(cfg, nil)
	if len(snaps) != 1 {
		t.Fatalf("snapshots = %d, want 1", len(snaps))
	}
	if s := snaps[0]; s.DeterministicMode != 0 || s.DeterministicBlockSize != 0 {
		t.Fatalf("plain pool must carry no deterministic fields, got mode=%d block=%d",
			s.DeterministicMode, s.DeterministicBlockSize)
	}
}
