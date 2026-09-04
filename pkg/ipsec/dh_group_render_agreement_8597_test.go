package ipsec

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #8597 (muse-004 K88), the renderer half.
//
// formatDHGroup carried its own switch with a `default: modp<dhGroupBits(n)>`
// fall-through. That fall-through is what let an unspellable group reach
// swanctl: 99 -> "modp99", 33 -> "modp33", 17 -> "modp17" (17 being a REAL
// group whose correct keyword is modp6144, so the render was wrong rather than
// merely unspelled). It now delegates to config.DHGroupKeyword — the same map
// ValidateDHGroup accepts against — so the gate and the renderer cannot
// disagree about the accepted set, which was the defect.

// TestFormatDHGroupMatchesTheValidatedSet_8597 is the agreement assertion. It
// deliberately asserts the RELATIONSHIP rather than a table of literals: a
// pinned table here would be a second copy of the map, which is the shape that
// caused this.
func TestFormatDHGroupMatchesTheValidatedSet_8597(t *testing.T) {
	for _, g := range config.SupportedDHGroups() {
		want, ok := config.DHGroupKeyword(g)
		if !ok {
			t.Fatalf("group %d is supported but has no keyword", g)
		}
		if got := formatDHGroup(g); got != want {
			t.Errorf("formatDHGroup(%d) = %q, want %q", g, got, want)
		}
	}
}

// TestFormatDHGroupHasNoFallThrough_8597 is the RED-on-revert core. Restoring
// `default: modp<dhGroupBits(n)>` makes each of these a plausible-looking
// keyword that charon refuses; with the fall-through gone they render EMPTY,
// which fails loudly at proposal-build.
func TestFormatDHGroupHasNoFallThrough_8597(t *testing.T) {
	for _, g := range []int{0, 3, 17, 18, 33, 99, 1000000, -5} {
		got := formatDHGroup(g)
		if got == "" {
			continue
		}
		t.Errorf("formatDHGroup(%d) = %q for a group the validator refuses; a "+
			"fall-through renders a plausible keyword strongSwan does not accept, so "+
			"IPsec fails to establish with the diagnostics pointing at charon", g, got)
	}
}

// TestFormatDHGroupNeverSpellsACurveAsBits_8597 pins the #2392/#2604 property
// the old fall-through kept breaking: `modp256` for group 19 is a bit count
// where a curve name belongs.
func TestFormatDHGroupNeverSpellsACurveAsBits_8597(t *testing.T) {
	for _, g := range []int{19, 20, 21, 25, 26, 27, 28, 29, 30, 31, 32} {
		got := formatDHGroup(g)
		if strings.HasPrefix(got, "modp") {
			t.Errorf("formatDHGroup(%d) = %q — an elliptic-curve group must never "+
				"render a modp spelling (#2392)", g, got)
		}
		if got == "" {
			t.Errorf("formatDHGroup(%d) = \"\"; the curve groups are in the accepted set "+
				"and must still spell", g)
		}
	}
}
