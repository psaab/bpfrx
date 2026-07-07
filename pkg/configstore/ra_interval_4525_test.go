package configstore

import (
	"strings"
	"testing"
)

// #4525 — cross-field RFC 4861 §6.2.1 relation for router-advertisement
// intervals: MinRtrAdvInterval MUST be <= 0.75 * MaxRtrAdvInterval. The
// per-leaf schema validators bound each leaf on its own (max in [4,1800],
// min in [3,1350]) but cannot see both siblings; crossCheckRAIntervals
// (compileTreeStrict) enforces the ratio strictly at commit, warns on the
// tolerant Load/SyncApply path.

func raIntervalText(maxI, minI string) string {
	return `protocols {
    router-advertisement {
        interface ge-0-0-0 {
            max-advertisement-interval ` + maxI + `;
            min-advertisement-interval ` + minI + `;
        }
    }
}`
}

// TestCheckText_RAIntervals_RejectsMinOver75Max is the strict-path RED guard.
// Both values are individually in range, so ONLY the cross-field check can
// reject them — proving the ratio guard is load-bearing. On revert
// (no crossCheckRAIntervals) these compile cleanly and CheckText returns nil.
func TestCheckText_RAIntervals_RejectsMinOver75Max(t *testing.T) {
	cases := [][2]string{
		{"4", "4"},   // 4*4=16 > 4*3=12 (min == max, jitter window collapsed)
		{"10", "9"},  // 9*4=36 > 10*3=30
		{"12", "10"}, // 10*4=40 > 12*3=36
	}
	for _, c := range cases {
		_, err := CheckText(raIntervalText(c[0], c[1]), -1)
		if err == nil {
			t.Fatalf("expected reject for max=%s min=%s (min > 0.75*max, RFC 4861 §6.2.1), got nil", c[0], c[1])
		}
		if !strings.Contains(err.Error(), "min-advertisement-interval") ||
			!strings.Contains(err.Error(), "0.75") {
			t.Fatalf("error should explain the 0.75*max relation: %v", err)
		}
	}
}

// TestCheckText_RAIntervals_AcceptsValidRatio confirms in-ratio pairs pass,
// including the exact-0.75 boundary and the canonical max=30/min=10 shipped
// in docs/ha-cluster-userspace.conf.
func TestCheckText_RAIntervals_AcceptsValidRatio(t *testing.T) {
	for _, c := range [][2]string{
		{"600", "200"}, // default-ish
		{"30", "10"},   // canonical HA config
		{"8", "6"},     // exact 0.75 boundary: 6*4=24 == 8*3=24
		{"1800", "3"},  // widest window
	} {
		if _, err := CheckText(raIntervalText(c[0], c[1]), -1); err != nil {
			t.Fatalf("max=%s min=%s should validate (min <= 0.75*max): %v", c[0], c[1], err)
		}
	}
}

// TestCheckText_RAIntervals_LoneLeafSkipsCrossCheck confirms a lone max or
// lone min (the sibling absent → 0 = "use default") never cross-checks: the
// sender derives the missing bound.
func TestCheckText_RAIntervals_LoneLeafSkipsCrossCheck(t *testing.T) {
	loneMax := `protocols {
    router-advertisement {
        interface ge-0-0-0 {
            max-advertisement-interval 4;
        }
    }
}`
	if _, err := CheckText(loneMax, -1); err != nil {
		t.Fatalf("lone max-advertisement-interval should validate (min derived): %v", err)
	}
}
