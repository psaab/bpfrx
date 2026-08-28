package api

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #4692: the natPoolDeterministicInfo host_count label for an IPv6 subscriber
// CIDR computed 1<<(128-ones), a shift >=64 that yields 0 in Go — so an IPv6
// deterministic pool reported a subscriber capacity of 0. Mirror the
// compiler_nat.go deterministic-capacity gate and report the pool's
// block/subscriber capacity (totalBlocks) instead.
//
// RED-on-revert: restoring the unconditional `1 << uint(bits-ones)` makes the
// IPv6 case return 0 and the >0 assertion below fires RED.
func TestDeterministicSubscriberCapacity_IPv6ReportsPoolCapacity(t *testing.T) {
	// IPv6 /64 subscriber CIDR: 1<<(128-64) is a >=64-bit shift (0 in Go).
	// PortLow/PortHigh default to 1024..65535 (64512 ports); blockSize 2016 =>
	// 32 blocks per address; 2 addresses => 64 total blocks.
	pool := &config.NATPool{
		Addresses: []string{"203.0.113.1", "203.0.113.2"},
		Deterministic: &config.DeterministicNATConfig{
			BlockSize:   2016,
			HostAddress: "2001:db8::/64",
		},
	}
	got := deterministicSubscriberCapacity(pool, "p", nil)
	if got == 0 {
		t.Fatal("IPv6 deterministic pool reported 0 capacity (1<<(128-ones) shift overflow) — #4692")
	}
	wantBlocks := 2 * ((65535 - 1024 + 1) / 2016) // 2 * 32 = 64
	if got != wantBlocks {
		t.Fatalf("IPv6 capacity = %d, want totalBlocks %d", got, wantBlocks)
	}
}

// IPv4 must keep reporting the host-address count so the fix does not regress
// the pre-existing behavior.
func TestDeterministicSubscriberCapacity_IPv4HostCount(t *testing.T) {
	pool := &config.NATPool{
		Addresses: []string{"203.0.113.1"},
		Deterministic: &config.DeterministicNATConfig{
			BlockSize:   64,
			HostAddress: "100.64.0.0/24", // /24 => 256 subscriber addresses
		},
	}
	if got := deterministicSubscriberCapacity(pool, "p", nil); got != 256 {
		t.Fatalf("IPv4 capacity = %d, want 256 (1<<(32-24))", got)
	}
}

// An unparseable / non-positive-block pool must not panic and reports 0.
func TestDeterministicSubscriberCapacity_Degenerate(t *testing.T) {
	if got := deterministicSubscriberCapacity(&config.NATPool{
		Deterministic: &config.DeterministicNATConfig{HostAddress: "not-a-cidr"},
	}, "p", nil); got != 0 {
		t.Fatalf("unparseable host CIDR must report 0, got %d", got)
	}
	if got := deterministicSubscriberCapacity(&config.NATPool{
		Addresses:     []string{"203.0.113.1"},
		Deterministic: &config.DeterministicNATConfig{BlockSize: 0, HostAddress: "2001:db8::/64"},
	}, "p", nil); got != 0 {
		t.Fatalf("non-positive block size must report 0, got %d", got)
	}
}
