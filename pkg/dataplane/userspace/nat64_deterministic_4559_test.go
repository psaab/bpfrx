// #4559 mode 2 (NAPT64): a `security nat nat64` rule-set whose source pool
// carries `port deterministic` with an enforced IPv6 host must carry the
// block-allocation params onto the NAT64 snapshot so the Rust NAT64 allocator
// (allocate_deterministic_v6) maps each IPv6 subscriber to a fixed external
// IPv4 + port block. An unsupported prefix length, or no deterministic stanza,
// leaves the fields zero (the pool round-robins).
//
// RED-on-revert (builder wiring reverted): DeterministicBlockSize /
// BlocksPerIP / HostPrefixLen / HostBaseV6 come back zero/empty.
package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// compileNAT64DeterministicPool builds a config with a source pool (optionally
// carrying `port deterministic host address <hostPrefix>`) and a NAT64 rule-set
// referencing it as source-pool.
func compileNAT64DeterministicPool(t *testing.T, hostPrefix string) *config.Config {
	t.Helper()
	tree := &config.ConfigTree{}
	cmds := []string{
		"set security nat source pool p64 address 198.51.100.1/32 to 198.51.100.4/32",
		"set security nat nat64 rule-set rs1 prefix 64:ff9b::/96",
		"set security nat nat64 rule-set rs1 source-pool p64",
	}
	if hostPrefix != "" {
		cmds = append(cmds,
			"set security nat source pool p64 port deterministic block-size 512",
			"set security nat source pool p64 port deterministic host address "+hostPrefix,
		)
	}
	for _, cmd := range cmds {
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	return cfg
}

// TestNAT64SnapshotDeterministicV6_4559: a /64 IPv6-host deterministic pool
// referenced by a NAT64 rule-set carries the mode-2 wire fields. block-size 512
// over the FIXED NAT64 range 1024-65535 (64512 ports) => 126 blocks/IP.
func TestNAT64SnapshotDeterministicV6_4559(t *testing.T) {
	cfg := compileNAT64DeterministicPool(t, "2001:db8::/64")
	snaps := buildNAT64Snapshots(cfg)
	if len(snaps) != 1 {
		t.Fatalf("nat64 snapshots = %d, want 1", len(snaps))
	}
	s := snaps[0]
	if s.DeterministicBlockSize != 512 {
		t.Fatalf("DeterministicBlockSize = %d, want 512 (0 on builder revert)", s.DeterministicBlockSize)
	}
	if s.DeterministicBlocksPerIP != 126 {
		t.Fatalf("DeterministicBlocksPerIP = %d, want 126 (64512/512)", s.DeterministicBlocksPerIP)
	}
	if s.DeterministicHostPrefixLen != 64 {
		t.Fatalf("DeterministicHostPrefixLen = %d, want 64", s.DeterministicHostPrefixLen)
	}
	if s.DeterministicHostBaseV6 != "2001:db8::" {
		t.Fatalf("DeterministicHostBaseV6 = %q, want \"2001:db8::\"", s.DeterministicHostBaseV6)
	}
}

// TestNAT64SnapshotDeterministicV6Slash32_4559: a /32 host is also supported
// (subscriber word at octet offset 4).
func TestNAT64SnapshotDeterministicV6Slash32_4559(t *testing.T) {
	cfg := compileNAT64DeterministicPool(t, "2001:db8::/32")
	snaps := buildNAT64Snapshots(cfg)
	if len(snaps) != 1 {
		t.Fatalf("nat64 snapshots = %d, want 1", len(snaps))
	}
	if s := snaps[0]; s.DeterministicHostPrefixLen != 32 || s.DeterministicBlockSize != 512 {
		t.Fatalf("/32 host must set prefix-len 32 + block-size 512, got len=%d block=%d",
			s.DeterministicHostPrefixLen, s.DeterministicBlockSize)
	}
}

// TestDeterministicNAT64V6FieldsGuards unit-tests the builder helper's
// defense-in-depth guards directly (the strict commit validator already rejects
// a non-/32-or-/64 IPv6 deterministic host, so an unsupported prefix can only
// reach the builder via the lenient / HA-sync load path). An unsupported prefix
// length, an IPv4 host (mode 1, not mode 2), and no deterministic stanza all
// return ok=false; a supported /64 host returns the computed params.
func TestDeterministicNAT64V6FieldsGuards(t *testing.T) {
	mk := func(host string, block int) *config.NATPool {
		return &config.NATPool{
			Name:          "p64",
			Deterministic: &config.DeterministicNATConfig{BlockSize: block, HostAddress: host},
		}
	}
	// Supported /64.
	if bs, bpi, pl, base, ok := deterministicNAT64V6Fields(mk("2001:db8::/64", 512)); !ok ||
		bs != 512 || bpi != 126 || pl != 64 || base != "2001:db8::" {
		t.Fatalf("/64 host: got ok=%v bs=%d bpi=%d pl=%d base=%q", ok, bs, bpi, pl, base)
	}
	// Unsupported /48 (lenient path) -> not enforced.
	if _, _, _, _, ok := deterministicNAT64V6Fields(mk("2001:db8::/48", 512)); ok {
		t.Fatal("/48 host must not be enforced (unsupported subscriber-prefix length)")
	}
	// IPv4 host is mode 1, not mode 2.
	if _, _, _, _, ok := deterministicNAT64V6Fields(mk("100.64.0.0/25", 512)); ok {
		t.Fatal("an IPv4 host is mode 1 and must not be built as mode 2")
	}
	// No deterministic stanza.
	if _, _, _, _, ok := deterministicNAT64V6Fields(&config.NATPool{Name: "p"}); ok {
		t.Fatal("a pool with no deterministic stanza must not be built")
	}
}

// TestNAT64SnapshotDeterministicV6Absent_4559: a NAT64 pool with no `port
// deterministic` stanza carries no mode-2 fields (round-robin).
func TestNAT64SnapshotDeterministicV6Absent_4559(t *testing.T) {
	cfg := compileNAT64DeterministicPool(t, "")
	snaps := buildNAT64Snapshots(cfg)
	if len(snaps) != 1 {
		t.Fatalf("nat64 snapshots = %d, want 1", len(snaps))
	}
	if s := snaps[0]; s.DeterministicBlockSize != 0 || s.DeterministicHostBaseV6 != "" {
		t.Fatalf("a plain NAT64 pool must carry no mode-2 fields, got block=%d base=%q",
			s.DeterministicBlockSize, s.DeterministicHostBaseV6)
	}
}
