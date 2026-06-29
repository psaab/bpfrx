// #3446: DNAT `match destination-port` builder fail-closed. A port that was
// CONFIGURED but resolves to no valid 1..65535 value (0, out-of-range, or an
// all-non-numeric list) must make the rule match NOTHING — it must never widen
// to the wildcard port (DestinationPort=0 = translate every port). Out-of-range
// numerics used to wrap on the bare uint16 cast (70000→4464); a non-numeric
// list collapsed to the wildcard port (H14). RED-on-revert: restore the
// `dstPorts = []uint16{0}` wildcard fallback and these emit a wildcard snapshot
// instead of matching nothing.
package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func dnatPortConfig(match config.NATMatch) *config.Config {
	cfg := &config.Config{}
	if match.DestinationAddress == "" {
		match.DestinationAddress = "203.0.113.10"
	}
	cfg.Security.NAT.Destination = &config.DestinationNATConfig{
		Pools: map[string]*config.NATPool{
			"p1": {Name: "p1", Address: "192.168.1.10"},
		},
		RuleSets: []*config.NATRuleSet{
			{
				Name:     "rs",
				FromZone: "untrust",
				Rules: []*config.NATRule{{
					Name:  "r1",
					Match: match,
					Then:  config.NATThen{Type: config.NATDestination, PoolName: "p1"},
				}},
			},
		},
	}
	return cfg
}

func TestBuildDNATSnapshotZeroPortFailsClosed_3446(t *testing.T) {
	cfg := dnatPortConfig(config.NATMatch{
		DestinationPorts: []int{0},
		DestinationPort:  0,
	})
	if snaps := buildDestinationNATSnapshots(cfg, nil); len(snaps) != 0 {
		t.Fatalf("port 0 must match nothing, got %d snapshot(s): %+v", len(snaps), snaps)
	}
}

func TestBuildDNATSnapshotOutOfRangePortFailsClosed_3446(t *testing.T) {
	cfg := dnatPortConfig(config.NATMatch{
		DestinationPorts: []int{70000},
		DestinationPort:  70000,
	})
	if snaps := buildDestinationNATSnapshots(cfg, nil); len(snaps) != 0 {
		t.Fatalf("port 70000 must match nothing (not wrap to 4464), got %d snapshot(s): %+v", len(snaps), snaps)
	}
}

func TestBuildDNATSnapshotNonNumericPortFailsClosed_3446(t *testing.T) {
	// All tokens non-numeric → DestinationPorts empty, but a port WAS configured
	// (InvalidDestinationPorts non-empty). Must NOT widen to the wildcard port.
	cfg := dnatPortConfig(config.NATMatch{
		InvalidDestinationPorts: []string{"http"},
	})
	if snaps := buildDestinationNATSnapshots(cfg, nil); len(snaps) != 0 {
		t.Fatalf("non-numeric port must match nothing, got %d snapshot(s): %+v", len(snaps), snaps)
	}
}

func TestBuildDNATSnapshotPartialValidPortKeepsGood_3446(t *testing.T) {
	// A mixed [80, 70000] list keeps the valid port and drops the bad one (the
	// strict commit gate rejects the whole rule; this is the lenient backstop).
	cfg := dnatPortConfig(config.NATMatch{
		DestinationPorts: []int{80, 70000},
		DestinationPort:  80,
	})
	snaps := buildDestinationNATSnapshots(cfg, nil)
	if len(snaps) != 1 {
		t.Fatalf("len(snaps) = %d, want 1 (valid port 80 kept)", len(snaps))
	}
	if snaps[0].DestinationPort != 80 {
		t.Fatalf("DestinationPort = %d, want 80", snaps[0].DestinationPort)
	}
}

func TestBuildDNATSnapshotNoPortIsWildcard_3446(t *testing.T) {
	// No destination-port configured at all → genuine wildcard (DestinationPort
	// 0), unchanged behavior. The fail-closed must not over-reject this.
	cfg := dnatPortConfig(config.NATMatch{})
	snaps := buildDestinationNATSnapshots(cfg, nil)
	if len(snaps) != 1 {
		t.Fatalf("len(snaps) = %d, want 1 (wildcard rule)", len(snaps))
	}
	if snaps[0].DestinationPort != 0 {
		t.Fatalf("DestinationPort = %d, want 0 (wildcard)", snaps[0].DestinationPort)
	}
}

func TestBuildDNATSnapshotValidPortInstalled_3446(t *testing.T) {
	cfg := dnatPortConfig(config.NATMatch{
		DestinationPorts: []int{8080},
		DestinationPort:  8080,
	})
	snaps := buildDestinationNATSnapshots(cfg, nil)
	if len(snaps) != 1 {
		t.Fatalf("len(snaps) = %d, want 1", len(snaps))
	}
	if snaps[0].DestinationPort != 8080 {
		t.Fatalf("DestinationPort = %d, want 8080", snaps[0].DestinationPort)
	}
}
