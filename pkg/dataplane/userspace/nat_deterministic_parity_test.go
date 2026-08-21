package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/nat"
)

// TestDeterministicParamsMatchWireBuilders guards the single-canonical-
// implementation invariant (#5794 invariant 8): the pkg/nat lookup that
// backs the CLI/gRPC/REST deterministic-mapping surface MUST derive the
// exact same block-allocation parameters as the shipped wire-field builders
// that ship those parameters to the Rust dataplane. If either Go derivation
// drifts, the operator-facing reverse map would attribute a translated tuple
// to the wrong subscriber while the dataplane enforced a different mapping —
// the exact forensic-integrity failure this feature exists to prevent.
func TestDeterministicParamsMatchWireBuilders(t *testing.T) {
	// Mode 1 (IPv4 subscriber) pools spanning the servable/degenerate space.
	v4Pools := []*config.NATPool{
		{
			Addresses:     []string{"203.0.113.1", "203.0.113.2", "203.0.113.3", "203.0.113.4"},
			PortLow:       1024,
			PortHigh:      65535,
			Deterministic: &config.DeterministicNATConfig{BlockSize: 512, HostAddress: "100.64.0.0/22"},
		},
		{
			// Non-default narrower port window + prepended single Address.
			Address:       "198.51.100.10",
			Addresses:     []string{"198.51.100.11"},
			PortLow:       2000,
			PortHigh:      10000,
			Deterministic: &config.DeterministicNATConfig{BlockSize: 256, HostAddress: "10.0.0.0/28"},
		},
		{
			// CIDR pool entry that enumerates.
			Addresses:     []string{"192.0.2.0/30"},
			PortLow:       1024,
			PortHigh:      65535,
			Deterministic: &config.DeterministicNATConfig{BlockSize: 1024, HostAddress: "100.100.0.0/24"},
		},
	}
	for i, pool := range v4Pools {
		portLow, portHigh, ok := config.SourceNATPoolPortRange(pool)
		if !ok {
			t.Fatalf("v4 pool %d: unexpected invalid port range", i)
		}
		wMode, wBlk, wBpi, wBase, wCount := deterministicSourceNATFields(pool, portLow, portHigh)
		nMode, nBlk, nBpi, nBase, nCount := nat.DerivedV4Params(pool)
		if wMode != nMode || wBlk != nBlk || wBpi != nBpi || wBase != nBase || wCount != nCount {
			t.Fatalf("v4 pool %d param drift:\n wire=(mode=%d blk=%d bpi=%d base=%d count=%d)\n  nat=(mode=%d blk=%d bpi=%d base=%d count=%d)",
				i, wMode, wBlk, wBpi, wBase, wCount, nMode, nBlk, nBpi, nBase, nCount)
		}
	}

	// Mode 2 (IPv6 subscriber / NAPT64) pools for /32 and /64 prefixes.
	v6Pools := []*config.NATPool{
		{
			Addresses:     []string{"198.51.100.1", "198.51.100.2", "198.51.100.3", "198.51.100.4"},
			Deterministic: &config.DeterministicNATConfig{BlockSize: 512, HostAddress: "2001:db8::/32"},
		},
		{
			Addresses:     []string{"203.0.113.20", "203.0.113.21"},
			Deterministic: &config.DeterministicNATConfig{BlockSize: 2016, HostAddress: "2001:db8:abcd::/64"},
		},
	}
	for i, pool := range v6Pools {
		wBlk, wBpi, wLen, wBase, wOK := deterministicNAT64V6Fields(pool)
		nBlk, nBpi, nLen, nBase, nOK := nat.DerivedV6Params(pool)
		if wOK != nOK || wBlk != nBlk || wBpi != nBpi || wLen != nLen || wBase != nBase {
			t.Fatalf("v6 pool %d param drift:\n wire=(blk=%d bpi=%d prefix=%d base=%q ok=%v)\n  nat=(blk=%d bpi=%d prefix=%d base=%q ok=%v)",
				i, wBlk, wBpi, wLen, wBase, wOK, nBlk, nBpi, nLen, nBase, nOK)
		}
	}
}
