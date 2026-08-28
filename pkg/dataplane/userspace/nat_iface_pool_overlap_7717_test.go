package userspace

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// The egress address every fixture shares. It is what a DHCP lease or a netlink
// event would put on the WAN unit — knowable only at snapshot build.
const overlapEgress = "172.16.80.8"

func overlapSnapshot(ifaceRule, poolRule *SourceNATRuleSnapshot, ifc InterfaceSnapshot) *ConfigSnapshot {
	snap := &ConfigSnapshot{Interfaces: []InterfaceSnapshot{ifc}}
	if ifaceRule != nil {
		snap.SourceNAT = append(snap.SourceNAT, *ifaceRule)
	}
	if poolRule != nil {
		snap.SourceNAT = append(snap.SourceNAT, *poolRule)
	}
	return snap
}

func wanUnit() InterfaceSnapshot {
	return InterfaceSnapshot{
		Name:            "ge-0/0/2.0",
		Zone:            "wan",
		RoutingInstance: "vr-blue",
		Addresses: []InterfaceAddressSnapshot{
			{Family: "inet", Address: overlapEgress + "/24"},
		},
	}
}

func ifaceModeRule() *SourceNATRuleSnapshot {
	return &SourceNATRuleSnapshot{Name: "iface-snat", InterfaceMode: true}
}

func poolRuleOn(addrs ...string) *SourceNATRuleSnapshot {
	return &SourceNATRuleSnapshot{Name: "pool-snat", PoolName: "P", PoolAddresses: addrs}
}

// TestInterfaceSNATPoolOverlapDetection is the three-row table.
//
// The MIDDLE row is the one a happy-path fixture omits and the one that matters:
// a detector that reports an overlap on every config is worse than none, because
// an operator learns to ignore it. The THIRD row separates "the addresses do not
// coincide" from "there is no interface-mode rule at all" — two different reasons
// to stay silent, and a detector that only handled the first would still warn on
// a pure-pool config that cannot collide with anything.
func TestInterfaceSNATPoolOverlapDetection(t *testing.T) {
	for _, tc := range []struct {
		name      string
		ifaceRule *SourceNATRuleSnapshot
		poolRule  *SourceNATRuleSnapshot
		want      int
	}{
		{
			name:      "pool address IS the interface egress address",
			ifaceRule: ifaceModeRule(),
			poolRule:  poolRuleOn(overlapEgress),
			want:      1,
		},
		{
			name:      "pool address does NOT coincide with the egress address",
			ifaceRule: ifaceModeRule(),
			poolRule:  poolRuleOn("198.51.100.7"),
			want:      0,
		},
		{
			name:     "no interface-mode rule at all — nothing can collide",
			poolRule: poolRuleOn(overlapEgress),
			want:     0,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := detectInterfaceSNATPoolOverlaps(overlapSnapshot(tc.ifaceRule, tc.poolRule, wanUnit()))
			if len(got) != tc.want {
				t.Fatalf("detectInterfaceSNATPoolOverlaps = %d findings %v, want %d", len(got), got, tc.want)
			}
			if tc.want > 0 && got[0].Address != overlapEgress {
				t.Errorf("finding names address %q, want %q", got[0].Address, overlapEgress)
			}
		})
	}
}

// TestInterfaceSNATEgressScopeMatrix covers all FOUR shapes of the derivation
// matrix, including the wildcard row the old maps_sync.go precedent got wrong by
// returning nothing — which understates the candidate set exactly where it is
// widest, so an overlap goes unreported.
//
// Each scope is exercised BOTH matching and non-matching. A row that only tests
// the matching value cannot tell a working constraint from one that is ignored.
func TestInterfaceSNATEgressScopeMatrix(t *testing.T) {
	for _, tc := range []struct {
		name string
		rule SourceNATRuleSnapshot
		want bool
	}{
		{"unscoped is a WILDCARD", SourceNATRuleSnapshot{InterfaceMode: true}, true},

		{"to-zone matches", SourceNATRuleSnapshot{InterfaceMode: true, ToZone: "wan"}, true},
		{"to-zone does not match", SourceNATRuleSnapshot{InterfaceMode: true, ToZone: "dmz"}, false},

		{"to-interface matches the logical unit", SourceNATRuleSnapshot{InterfaceMode: true, ToInterface: "ge-0/0/2.0"}, true},
		{"to-interface matches the bare physical", SourceNATRuleSnapshot{InterfaceMode: true, ToInterface: "ge-0/0/2"}, true},
		{"to-interface does not match", SourceNATRuleSnapshot{InterfaceMode: true, ToInterface: "ge-0/0/1.0"}, false},

		{"to-routing-instance matches", SourceNATRuleSnapshot{InterfaceMode: true, ToRoutingInstance: "vr-blue"}, true},
		{"to-routing-instance does not match", SourceNATRuleSnapshot{InterfaceMode: true, ToRoutingInstance: "vr-red"}, false},

		// AND-of-non-empty-constraints: one disagreeing scope excludes the
		// interface even when another agrees.
		{"two scopes, one disagrees", SourceNATRuleSnapshot{InterfaceMode: true, ToZone: "wan", ToRoutingInstance: "vr-red"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.rule.Name = "iface-snat"
			snap := overlapSnapshot(&tc.rule, poolRuleOn(overlapEgress), wanUnit())
			got := len(detectInterfaceSNATPoolOverlaps(snap)) > 0
			if got != tc.want {
				t.Fatalf("interface in egress scope = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestInterfaceSNATPoolOverlapStatsDistinguishUnknownFromHealthy pins the reason
// there are TWO values instead of one gauge.
//
// A single "overlaps" number reads 0 both when nothing overlaps and when the
// detector never ran. Zero is the healthy reading AND the not-wired reading, so
// a gauge alone cannot tell an operator which one they are looking at — the same
// ambiguity as an unguarded headroom read reporting "enormous room" at the moment
// headroom is unknown. `scans` is what disambiguates them.
func TestInterfaceSNATPoolOverlapStatsDistinguishUnknownFromHealthy(t *testing.T) {
	before, _ := InterfaceSNATPoolOverlapStats()

	// A CLEAN snapshot: the detector ran and found nothing.
	reportInterfaceSNATPoolOverlaps(overlapSnapshot(ifaceModeRule(), poolRuleOn("198.51.100.7"), wanUnit()))
	afterClean, addrsClean := InterfaceSNATPoolOverlapStats()
	if afterClean != before+1 {
		t.Fatalf("scans = %d, want %d — a clean scan must still count, or 'no overlap' is "+
			"indistinguishable from 'never ran'", afterClean, before+1)
	}
	if addrsClean != 0 {
		t.Fatalf("addresses = %d on a non-overlapping snapshot, want 0", addrsClean)
	}

	// An OVERLAPPING snapshot: scan count advances again and the address count
	// becomes non-zero.
	reportInterfaceSNATPoolOverlaps(overlapSnapshot(ifaceModeRule(), poolRuleOn(overlapEgress), wanUnit()))
	afterDirty, addrsDirty := InterfaceSNATPoolOverlapStats()
	if afterDirty != afterClean+1 {
		t.Fatalf("scans = %d, want %d", afterDirty, afterClean+1)
	}
	if addrsDirty != 1 {
		t.Fatalf("addresses = %d on an overlapping snapshot, want 1", addrsDirty)
	}
}

// TestInterfaceSNATPoolOverlapSkipsNonHostPoolMembers pins the stated limitation.
//
// A pool member expressed as a range or prefix is NOT compared. Reporting a
// maybe-overlap as an overlap would make the warning unactionable, and this half
// exists to give operators a signal they can act on. The limitation is in the
// warning's own text; this is what keeps the code honest about it.
func TestInterfaceSNATPoolOverlapSkipsNonHostPoolMembers(t *testing.T) {
	snap := overlapSnapshot(ifaceModeRule(), poolRuleOn("172.16.80.0/24"), wanUnit())
	if got := detectInterfaceSNATPoolOverlaps(snap); len(got) != 0 {
		t.Fatalf("prefix pool member produced %d findings %v; ranges/prefixes are out of "+
			"scope for this detector and must be skipped, not approximated", len(got), got)
	}
	// CONTROL: the same address as a HOST member is detected, so the skip above
	// is about the member's SHAPE and not about the address being wrong.
	snap = overlapSnapshot(ifaceModeRule(), poolRuleOn(overlapEgress), wanUnit())
	if got := detectInterfaceSNATPoolOverlaps(snap); len(got) != 1 {
		t.Fatalf("control: host pool member produced %d findings, want 1", len(got))
	}
}

// TestBuilderRunsTheOverlapDetector binds the WIRING, not the detector.
//
// Added because a mutation cell found the wiring unbound: deleting the
// `reportInterfaceSNATPoolOverlaps(snap)` call from buildSnapshot red NOTHING,
// because every other test in this file calls the detector or the reporter
// directly. A detector that is perfect and never runs in production is the
// defect this whole PR is about, one layer up — code that exists and does
// nothing, with no test able to tell working from inert.
//
// Asserting the SCAN counter advances is the minimal statement of "the builder
// called it", and it holds regardless of whether the config overlaps.
func TestBuilderRunsTheOverlapDetector(t *testing.T) {
	before, _ := InterfaceSNATPoolOverlapStats()
	_ = mustBuildSnapshot(t, &config.Config{}, config.UserspaceConfig{}, 1, 0)
	after, _ := InterfaceSNATPoolOverlapStats()
	if after == before {
		t.Fatalf("buildSnapshot did not run the overlap detector (scans stayed %d). The "+
			"detector can be entirely correct and never execute; this is the assertion that "+
			"notices", before)
	}
}

// TestBuilderDetectsOverlapEndToEnd drives the REAL builder with a config whose
// interface address is also a pool address, and asserts the detector saw it.
//
// The counter test above proves the builder CALLS the detector; this proves the
// snapshot the builder produces actually carries the shape the detector reads —
// interface addresses and pool addresses in the fields it looks at. A wiring
// bind that only counted calls would pass even if the builder handed the
// detector a snapshot with no interfaces in it.
func TestBuilderDetectsOverlapEndToEnd(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/2": {Name: "ge-0/0/2", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{overlapEgress + "/24"}},
		}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"wan": {Name: "wan", Interfaces: []string{"ge-0/0/2.0"}},
	}
	cfg.Security.NAT.SourcePools = map[string]*config.NATPool{
		"P": {Name: "P", Addresses: []string{overlapEgress}},
	}
	cfg.Security.NAT.Source = []*config.NATRuleSet{
		{
			Name: "rs-iface", FromZone: "lan", ToZone: "wan",
			Rules: []*config.NATRule{{
				Name: "iface-snat",
				Then: config.NATThen{Type: config.NATSource, Interface: true},
			}},
		},
		{
			Name: "rs-pool", FromZone: "lan", ToZone: "wan",
			Rules: []*config.NATRule{{
				Name: "pool-snat",
				Then: config.NATThen{Type: config.NATSource, PoolName: "P"},
			}},
		},
	}

	snap := mustBuildSnapshot(t, cfg, config.UserspaceConfig{}, 1, 0)

	// Read through the detector rather than the counter: the counter is global
	// and other tests in this package build snapshots too, so a value read here
	// could have come from anywhere.
	got := detectInterfaceSNATPoolOverlaps(snap)
	if len(got) == 0 {
		t.Fatalf("the builder's own snapshot shows no overlap, but %s is both the interface "+
			"address and the pool's only member. The detector reads snapshot fields; if the "+
			"builder does not populate them the detection never fires in production, however "+
			"green the unit tests are", overlapEgress)
	}
	if got[0].Address != overlapEgress {
		t.Errorf("overlap names %q, want %q", got[0].Address, overlapEgress)
	}
}

// TestBuilderQuarantinesTheOverlappingPool is the Go half of the acceptance
// control, and it drives the SNAPSHOT BUILDER — not the unit-level pin, which
// cannot invert because it constructs a healthy pool directly (#7730).
//
// Paired: the same builder, the same shapes, differing only in whether the pool
// address coincides with the interface egress address. Without the second row a
// builder that quarantined every pool would pass.
func TestBuilderQuarantinesTheOverlappingPool(t *testing.T) {
	for _, tc := range []struct {
		name     string
		poolAddr string
		wantQuar bool
	}{
		{"pool address IS the interface egress", overlapEgress, true},
		{"pool address does NOT coincide", "198.51.100.7", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{}
			cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
				"ge-0/0/2": {Name: "ge-0/0/2", Units: map[int]*config.InterfaceUnit{
					0: {Number: 0, Addresses: []string{overlapEgress + "/24"}},
				}},
			}
			cfg.Security.Zones = map[string]*config.ZoneConfig{
				"wan": {Name: "wan", Interfaces: []string{"ge-0/0/2.0"}},
			}
			cfg.Security.NAT.SourcePools = map[string]*config.NATPool{
				"P": {Name: "P", Addresses: []string{tc.poolAddr}},
			}
			cfg.Security.NAT.Source = []*config.NATRuleSet{
				{Name: "rs-iface", FromZone: "lan", ToZone: "wan", Rules: []*config.NATRule{{
					Name: "iface-snat",
					Then: config.NATThen{Type: config.NATSource, Interface: true},
				}}},
				{Name: "rs-pool", FromZone: "lan", ToZone: "wan", Rules: []*config.NATRule{{
					Name: "pool-snat",
					Then: config.NATThen{Type: config.NATSource, PoolName: "P"},
				}}},
			}

			snap := mustBuildSnapshot(t, cfg, config.UserspaceConfig{}, 1, 0)

			var poolRule *SourceNATRuleSnapshot
			for i := range snap.SourceNAT {
				if !snap.SourceNAT[i].InterfaceMode && snap.SourceNAT[i].PoolName == "P" {
					poolRule = &snap.SourceNAT[i]
				}
			}
			if poolRule == nil {
				t.Fatal("the builder emitted no pool rule — fixture is not exercising the path")
			}
			if poolRule.PoolUnusable != tc.wantQuar {
				t.Fatalf("PoolUnusable = %v, want %v. The builder is where the runtime overlap "+
					"becomes a quarantine; the dataplane only honours what it is told",
					poolRule.PoolUnusable, tc.wantQuar)
			}
			if tc.wantQuar && poolRule.PoolUnusableReason != poolUnusableReasonIfaceOverlap {
				t.Fatalf("PoolUnusableReason = %q, want %q — the reason is what selects the "+
					"DRAIN-retaining failure variant in the dataplane; any other string maps to "+
					"the catch-all and the pool's allocator is dropped instead of drained",
					poolRule.PoolUnusableReason, poolUnusableReasonIfaceOverlap)
			}
		})
	}
}

// TestPoolUnusableReasonLockstepWithRust pins the reason STRING to the dataplane
// arm that consumes it.
//
// Neither side is pinned to a literal by hand: the Go constant is read from the
// package, and the Rust arm is read out of the source. A mismatch does not fail
// anything loudly — `source_nat_failure_reason_from_snapshot` has a catch-all
// that maps an unknown string to `InvalidPool`, which is still fail-closed but
// does NOT retain the allocator. So the pool would be quarantined and its live
// flows stranded: the exact outcome the drain exists to prevent, reached by a
// typo, with every test green.
func TestPoolUnusableReasonLockstepWithRust(t *testing.T) {
	path := filepath.Join("..", "..", "..", "userspace-dp", "src", "nat", "source.rs")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	// Strip comments first: this file's own prose names the reason string, and
	// so does the Rust doc comment on the variant.
	var code []string
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "//") {
			continue
		}
		code = append(code, line)
	}
	want := `"` + poolUnusableReasonIfaceOverlap + `" => SourceNatFailureReason::PoolIfaceEgressOverlap`
	if !strings.Contains(strings.Join(code, "\n"), want) {
		t.Fatalf("userspace-dp/src/nat/source.rs has no arm mapping %q to "+
			"PoolIfaceEgressOverlap. Without it the reason falls to the catch-all "+
			"(InvalidPool), which does NOT retain the allocator — the pool is quarantined and "+
			"its live flows are stranded, which is what the drain exists to prevent",
			poolUnusableReasonIfaceOverlap)
	}
}
