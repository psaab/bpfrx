package dataplane

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #8597 K75.
//
// The finding is "nat_port_counters has 32 slots against a 256-wide PoolID
// space; the boot seed covers 0..31", with the fix direction "size the seed
// loop and the shim spec from one constant tied to the pool-ID space". Measured
// at this head, the shape is different in both halves:
//
//  1. The 32 is not arbitrary. MAX_NAT_POOLS in bpf/headers/xpf_common.h is the
//     shared C/Go ABI for that map, so "size it from the pool-ID space" would
//     desync Go from the header rather than resolve an incoherence. What the
//     seed loop owed was to stop repeating the number as a literal.
//  2. The pool-ID space is not 256-wide-but-bounded, it is UNBOUNDED: nothing
//     limited the uint8 numbering at all, so it wrapped and aliased.
//
// Both halves are pinned below.

// The seed loop must cover the whole map, whatever size the map is.
func TestSeedNATPortCountersCoversTheWholeMap_8597(t *testing.T) {
	src, err := os.ReadFile("maps_nat.go")
	if err != nil {
		t.Fatalf("read maps_nat.go: %v", err)
	}
	re := regexp.MustCompile(`for poolID := uint32\(0\); poolID < ([A-Za-z0-9_]+); poolID\+\+`)
	m := re.FindStringSubmatch(string(src))
	if len(m) < 2 {
		t.Fatal("the seed loop's bound could not be located — this cell has gone " +
			"blind rather than the code having gone right")
	}
	if m[1] != "userspaceShimMaxNATPools" {
		t.Errorf("the seed loop is bounded by %q, not by the map's own size "+
			"constant. A literal here is the same number written twice, and the "+
			"copy that does not move is the one that seeds the wrong range "+
			"(#8597 K75)", m[1])
	}
}

// ...and the map's size constant is the C ABI's, not a Go invention. This is
// what makes "size it from the pool-ID space" the wrong fix: the two numbers
// are not free to converge.
func TestShimNATPoolCapMatchesTheCHeader_8597(t *testing.T) {
	data, err := os.ReadFile("../../bpf/headers/xpf_common.h")
	if err != nil {
		t.Skipf("cannot read bpf/headers/xpf_common.h: %v", err)
	}
	re := regexp.MustCompile(`(?m)^#define\s+MAX_NAT_POOLS\s+(\d+)`)
	m := re.FindStringSubmatch(string(data))
	if len(m) < 2 {
		t.Fatal("MAX_NAT_POOLS define not found in bpf/headers/xpf_common.h")
	}
	got, err := strconv.ParseUint(m[1], 10, 32)
	if err != nil {
		t.Fatalf("parse MAX_NAT_POOLS %q: %v", m[1], err)
	}
	if uint32(got) != userspaceShimMaxNATPools {
		t.Fatalf("C MAX_NAT_POOLS=%d drifted from Go userspaceShimMaxNATPools=%d. "+
			"nat_port_counters is declared with the C one in xpf_maps.h and created "+
			"with the Go one in loader_userspace_shim.go; they are one number "+
			"(#8597 K75)", got, userspaceShimMaxNATPools)
	}
}

// manyPoolCfg builds n named source-NAT pools, each referenced by its own SNAT
// rule so each takes an id.
func manyPoolCfg(n int) *config.Config {
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust":   {Interfaces: []string{"ge-0-0-1"}},
		"untrust": {Interfaces: []string{"ge-0-0-2"}},
	}
	cfg.Security.NAT.SourcePools = map[string]*config.NATPool{}
	rs := &config.NATRuleSet{Name: "rs1", FromZone: "trust", ToZone: "untrust"}
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("pool%03d", i)
		cfg.Security.NAT.SourcePools[name] = &config.NATPool{
			Name: name, Addresses: []string{fmt.Sprintf("192.0.2.%d/32", i%250+1)},
		}
		rs.Rules = append(rs.Rules, &config.NATRule{
			Name: fmt.Sprintf("r%03d", i),
			Then: config.NATThen{PoolName: name},
		})
	}
	cfg.Security.NAT.Source = []*config.NATRuleSet{rs}
	return cfg
}

func compilePoolIDs(t *testing.T, cfg *config.Config) *CompileResult {
	t.Helper()
	result := newValidationResult()
	assignZoneIDs(result, cfg)
	if err := compileNAT(idProbeDP{}, cfg, result); err != nil {
		t.Fatalf("compileNAT: %v", err)
	}
	return result
}

// collidingIDs reports pool ids held by more than one pool.
func collidingIDs(result *CompileResult) map[uint8][]string {
	byID := map[uint8][]string{}
	for name, id := range result.PoolIDs {
		byID[id] = append(byID[id], name)
	}
	out := map[uint8][]string{}
	for id, names := range byID {
		if len(names) > 1 {
			out[id] = names
		}
	}
	return out
}

// The positive control: at a normal size every pool gets a distinct id, so a
// "no collisions" result below means the guard worked rather than the fixture
// never having produced a contested id.
func TestPoolIDsAreDistinctAtNormalScale_8597(t *testing.T) {
	result := compilePoolIDs(t, manyPoolCfg(40))
	if len(result.PoolIDs) != 40 {
		t.Fatalf("PoolIDs has %d entries, want 40 — the fixture did not assign", len(result.PoolIDs))
	}
	if c := collidingIDs(result); len(c) != 0 {
		t.Fatalf("40 pools already collide: %v", c)
	}
	// 40 > MAX_NAT_POOLS deliberately: the legacy map's 32-slot ABI is NOT a
	// limit on the numbering, and a fix that capped the allocator there would
	// break this config, which forwards correctly today.
	if uint32(len(result.PoolIDs)) <= userspaceShimMaxNATPools {
		t.Fatalf("this cell is meant to exceed the legacy map cap (%d) and does not",
			userspaceShimMaxNATPools)
	}
}

// The row itself. Past the uint8 range the numbering used to WRAP: measured,
// 260 pools produced 256 distinct ids with 4 collisions, pool000 sharing id 0
// with pool256, and NextPoolID back at 4 so compileNAT64's auto-assign would
// hand out ids already in use.
func TestPoolIDsSaturateRatherThanWrap_8597(t *testing.T) {
	result := compilePoolIDs(t, manyPoolCfg(260))
	if len(result.PoolIDs) != 260 {
		t.Fatalf("PoolIDs has %d entries, want 260", len(result.PoolIDs))
	}

	// Saturation aliases the LAST id and nothing else: the 256 pools that fit
	// keep distinct numbers, and the overflow shares 255.
	collisions := collidingIDs(result)
	if _, ok := collisions[0]; ok {
		t.Errorf("pool id 0 is shared by %v — the numbering wrapped, so a pool at "+
			"the start of the config and one 256 later are the same id (#8597 K75)",
			collisions[0])
	}
	for id := range collisions {
		if id != maxSourceNATPoolID {
			t.Errorf("pool id %d collides (%v); only the saturated id %d may",
				id, collisions[id], maxSourceNATPoolID)
		}
	}
	if len(collisions[maxSourceNATPoolID]) != 260-int(maxSourceNATPoolID) {
		t.Errorf("id %d is shared by %d pools, want %d — saturation must absorb "+
			"exactly the overflow", maxSourceNATPoolID,
			len(collisions[maxSourceNATPoolID]), 260-int(maxSourceNATPoolID))
	}

	// And the cursor compileNAT64 continues from must not have wrapped behind
	// the ids already handed out.
	if result.NextPoolID != maxSourceNATPoolID {
		t.Errorf("NextPoolID=%d, want %d: a wrapped cursor gives compileNAT64's "+
			"auto-assign branch an id another pool already holds (#8597 K75)",
			result.NextPoolID, maxSourceNATPoolID)
	}
}

// THE SECOND ALLOCATION SITE. compileNAT64 auto-assigns an id to a pool that is
// defined but referenced by no SNAT rule, from the SAME cursor — and a guard on
// only the SNAT site leaves this one wrapping. That escape was found by
// mutation: guarding the SNAT site alone passed every cell above.
func TestNAT64AutoAssignAlsoSaturates_8597(t *testing.T) {
	cfg := manyPoolCfg(260)
	// A pool defined but referenced by no SNAT rule, so compileNAT64's
	// auto-assign branch is the site that numbers it.
	cfg.Security.NAT.SourcePools["nat64pool"] = &config.NATPool{
		Name: "nat64pool", Addresses: []string{"198.51.100.7/32"},
	}
	cfg.Security.NAT.NAT64 = []*config.NAT64RuleSet{{
		Name: "n64", Prefix: "64:ff9b::/96", SourcePool: "nat64pool",
	}}

	result := newValidationResult()
	assignZoneIDs(result, cfg)
	if err := compileNAT(idProbeDP{}, cfg, result); err != nil {
		t.Fatalf("compileNAT: %v", err)
	}
	before := result.NextPoolID
	if before != maxSourceNATPoolID {
		t.Fatalf("the SNAT phase left NextPoolID at %d, want the saturated %d — "+
			"this cell needs the cursor AT the boundary or it measures nothing",
			before, maxSourceNATPoolID)
	}
	if err := compileNAT64(idProbeDP{}, cfg, result); err != nil {
		t.Fatalf("compileNAT64: %v", err)
	}

	if _, ok := result.PoolIDs["nat64pool"]; !ok {
		t.Fatal("the auto-assign branch did not run — non-vacuity check")
	}
	if result.NextPoolID != maxSourceNATPoolID {
		t.Errorf("NextPoolID=%d after the NAT64 auto-assign, want %d. The cursor "+
			"wrapped at the second allocation site, so the next pool numbered "+
			"anywhere starts back at 0 over ids already handed out (#8597 K75)",
			result.NextPoolID, maxSourceNATPoolID)
	}
}
