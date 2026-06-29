// #3450: DNAT POOL port/address builder fail-closed. A pool whose configured
// `port` is out of range / non-numeric (PortRaw set but Port not in 1..65535)
// or whose `address` is a non-host CIDR / non-IP token must make the rule emit
// NO snapshot — it must never wrap the port on the uint16 cast (70000→4464),
// collapse to preserve-destination-port, or coerce a non-host CIDR to its
// network base. RED-on-revert: restore the bare `uint16(pool.Port)` cast and
// the `poolAddr = pool.Address; strip /` block and these emit a (wrong)
// snapshot instead of matching nothing.
package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func dnatPoolConfig(pool *config.NATPool) *config.Config {
	cfg := &config.Config{}
	cfg.Security.NAT.Destination = &config.DestinationNATConfig{
		Pools: map[string]*config.NATPool{pool.Name: pool},
		RuleSets: []*config.NATRuleSet{
			{
				Name:     "rs",
				FromZone: "untrust",
				Rules: []*config.NATRule{{
					Name:  "r1",
					Match: config.NATMatch{DestinationAddress: "203.0.113.10"},
					Then:  config.NATThen{Type: config.NATDestination, PoolName: pool.Name},
				}},
			},
		},
	}
	return cfg
}

func TestBuildDNATSnapshotPoolOverRangePortFailsClosed_3450(t *testing.T) {
	cfg := dnatPoolConfig(&config.NATPool{Name: "p1", Address: "192.168.1.10", Port: 70000, PortRaw: "70000"})
	if snaps := buildDestinationNATSnapshots(cfg, nil); len(snaps) != 0 {
		t.Fatalf("pool port 70000 must match nothing (not wrap to 4464), got %d snapshot(s): %+v", len(snaps), snaps)
	}
}

func TestBuildDNATSnapshotPoolZeroConfiguredPortFailsClosed_3450(t *testing.T) {
	// `port 0` was explicitly configured (PortRaw set) → fail closed, not the
	// preserve-dest-port default.
	cfg := dnatPoolConfig(&config.NATPool{Name: "p1", Address: "192.168.1.10", Port: 0, PortRaw: "0"})
	if snaps := buildDestinationNATSnapshots(cfg, nil); len(snaps) != 0 {
		t.Fatalf("pool port 0 (configured) must match nothing, got %d snapshot(s): %+v", len(snaps), snaps)
	}
}

func TestBuildDNATSnapshotPoolNonNumericPortFailsClosed_3450(t *testing.T) {
	// `port httpp` → Atoi failed, Port stays 0, but PortRaw records it → reject.
	cfg := dnatPoolConfig(&config.NATPool{Name: "p1", Address: "192.168.1.10", Port: 0, PortRaw: "httpp"})
	if snaps := buildDestinationNATSnapshots(cfg, nil); len(snaps) != 0 {
		t.Fatalf("pool non-numeric port must match nothing, got %d snapshot(s): %+v", len(snaps), snaps)
	}
}

func TestBuildDNATSnapshotPoolNonHostCIDRFailsClosed_3450(t *testing.T) {
	// 10.0.0.0/24 would coerce to the network base 10.0.0.0 — fail closed.
	cfg := dnatPoolConfig(&config.NATPool{Name: "p1", Address: "10.0.0.0/24"})
	if snaps := buildDestinationNATSnapshots(cfg, nil); len(snaps) != 0 {
		t.Fatalf("pool non-host CIDR must match nothing (not coerce to network base), got %d snapshot(s): %+v", len(snaps), snaps)
	}
}

func TestBuildDNATSnapshotPoolNameAddressFailsClosed_3450(t *testing.T) {
	// An address-book name the Rust parser drops — fail closed at the builder.
	cfg := dnatPoolConfig(&config.NATPool{Name: "p1", Address: "web-server"})
	if snaps := buildDestinationNATSnapshots(cfg, nil); len(snaps) != 0 {
		t.Fatalf("pool name address must match nothing, got %d snapshot(s): %+v", len(snaps), snaps)
	}
}

func TestBuildDNATSnapshotPoolValidStillEmits_3450(t *testing.T) {
	// The fail-closed must not over-reject a good pool. A bare host, a /32, a
	// valid port, and a preserve-port (no PortRaw) pool all emit one snapshot.
	cases := []struct {
		name     string
		pool     *config.NATPool
		wantPort uint16
	}{
		{"bare-host-no-port", &config.NATPool{Name: "p1", Address: "192.168.1.10"}, 0},
		{"host-32-no-port", &config.NATPool{Name: "p1", Address: "192.168.1.10/32"}, 0},
		{"valid-port", &config.NATPool{Name: "p1", Address: "192.168.1.10", Port: 8080, PortRaw: "8080"}, 8080},
		{"port-1", &config.NATPool{Name: "p1", Address: "192.168.1.10", Port: 1, PortRaw: "1"}, 1},
		{"port-65535", &config.NATPool{Name: "p1", Address: "192.168.1.10", Port: 65535, PortRaw: "65535"}, 65535},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := dnatPoolConfig(tc.pool)
			snaps := buildDestinationNATSnapshots(cfg, nil)
			if len(snaps) != 1 {
				t.Fatalf("len(snaps) = %d, want 1 (valid pool)", len(snaps))
			}
			if snaps[0].PoolAddress != "192.168.1.10" {
				t.Fatalf("PoolAddress = %q, want 192.168.1.10", snaps[0].PoolAddress)
			}
			if tc.wantPort != 0 && snaps[0].PoolPort != tc.wantPort {
				t.Fatalf("PoolPort = %d, want %d", snaps[0].PoolPort, tc.wantPort)
			}
		})
	}
}
