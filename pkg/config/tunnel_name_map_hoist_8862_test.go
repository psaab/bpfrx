package config

import (
	"fmt"
	"testing"
)

// #8862: the tolerant compile stayed quadratic after #8854 because
// (*Config).TunnelNameMap was rebuilt per interface and per unit at two sites
// that dominated the profile taken afterwards:
//
//	TunnelNameMap                                    73.2% cum
//	  <- junosHostLinuxName                          49.4%   (junos-host deny projection)
//	  <- ResolveKernelIfName                         25.9%   (ifname collision gate)
//
// TunnelNameMap walks every interface and every unit, and it is a method on
// *Config taking no arguments — loop-invariant by construction, the same shape
// as #8854 one layer down.
//
// WHY THIS CELL ASSERTS A CURVE AND NOT A COUNT. #8854 landed a call-count
// guard that was GREEN while the compile stayed quadratic, because the property
// it asserted ("called once") was true and the property that mattered ("cost
// does not grow with the square of the input") was not. So this cell asserts
// that the number of map builds is INDEPENDENT OF INPUT SIZE: measured at five
// zone counts spanning 1..128, the count must be identical at all of them. A
// per-item rebuild makes it grow with Z, which is exactly the defect.
//
// Counted rather than timed: a wall-clock threshold on a shared machine is
// either flaky or so loose it stops failing, while the build count is
// deterministic and fails for the right reason.
func TestTunnelNameMapBuildsAreInputSizeIndependent8862(t *testing.T) {
	orig := tunnelNameMapFn
	defer func() { tunnelNameMapFn = orig }()

	sizes := []int{1, 2, 8, 32, 128}
	counts := make(map[int]int, len(sizes))
	for _, z := range sizes {
		n := 0
		tunnelNameMapFn = func(c *Config) map[string]string {
			n++
			return orig(c)
		}
		tree, perrs := NewParser(hostInboundZonesFixture8854(z)).Parse()
		if len(perrs) > 0 {
			t.Fatalf("fixture must parse at z=%d: %v", z, perrs)
		}
		cfg, err := CompileConfigLenient(tree)
		if err != nil {
			t.Fatalf("tolerant compile must succeed at z=%d: %v", z, err)
		}
		if got := len(cfg.Security.Zones); got != z {
			t.Fatalf("z=%d compiled %d zones — the pass may not have been exercised", z, got)
		}
		// Non-vacuity: a count of zero would satisfy "identical at every size"
		// while measuring nothing at all.
		if n == 0 {
			t.Fatalf("z=%d built the tunnel-name map zero times, so this cell "+
				"measured nothing", z)
		}
		counts[z] = n
	}

	base := counts[sizes[0]]
	for _, z := range sizes[1:] {
		if counts[z] != base {
			t.Errorf("tunnel-name map was built %d times at %d zones but %d times "+
				"at %d zones. The build count must NOT depend on input size: "+
				"TunnelNameMap walks every interface and every unit, so a count "+
				"that grows with Z means it is being rebuilt per item and the "+
				"tolerant compile — boot and HA peer-sync — is quadratic again "+
				"(#8862). Counts: %s", counts[z], z, base, sizes[0], fmtCounts8862(counts, sizes))
		}
	}
}

func fmtCounts8862(counts map[int]int, sizes []int) string {
	out := ""
	for _, z := range sizes {
		out += fmt.Sprintf("z=%d:%d ", z, counts[z])
	}
	return out
}
