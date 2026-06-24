package config

import (
	"fmt"
	"strings"
	"testing"
)

// zoneSetLines returns `set security zones security-zone z<NNNN>` lines for n
// distinct zones. Names are zero-padded so the deterministic 1..N id assignment
// (sorted by name in pkg/dataplane/compiler.go) is independent of n.
func zoneSetLines(n int) []string {
	lines := make([]string, 0, n)
	for i := 0; i < n; i++ {
		lines = append(lines, fmt.Sprintf("set security zones security-zone z%04d", i))
	}
	return lines
}

// TestZoneCountOverCapFailsCommit asserts that a configuration defining more
// than MaxUsableZoneID (255) security zones is HARD-REJECTED at commit (#2391).
//
// This is the fail-on-revert guard for the silent-remap bug: zone ids are
// assigned 1..N sequentially and the dataplane carries them in a u8 wire field,
// so the 256th+ zone ids overflow and were silently dropped — collapsing the
// referencing interfaces to zone 0 ("unknown") rather than failing the commit.
// Remove validateZoneCountStrict (or its dispatch in compiler.go) and this
// subtest goes green on the over-cap config, which is the regression it guards.
func TestZoneCountOverCapFailsCommit(t *testing.T) {
	tree := buildTree(t, zoneSetLines(MaxUsableZoneID+1))
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatalf("expected commit to reject a config with %d zones (cap is %d), got nil error", MaxUsableZoneID+1, MaxUsableZoneID)
	}
	// The error must name both the offending count and the limit so the
	// operator can act on it.
	for _, want := range []string{
		fmt.Sprintf("%d security zones", MaxUsableZoneID+1),
		fmt.Sprintf("at most %d", MaxUsableZoneID),
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q does not contain %q", err.Error(), want)
		}
	}
}

// TestZoneCountAtCapCommits asserts the boundary is inclusive: a config with
// EXACTLY MaxUsableZoneID zones still compiles (#2391 anti-over-reject). The
// 255th id is the largest the u8 wire field can carry.
func TestZoneCountAtCapCommits(t *testing.T) {
	tree := buildTree(t, zoneSetLines(MaxUsableZoneID))
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("strict commit rejected a config at exactly the %d-zone cap: %v", MaxUsableZoneID, err)
	}
}

// TestZoneCountNormalConfigUnaffected asserts a small, ordinary zone count
// commits cleanly — the cap does not perturb the common case (#2391).
func TestZoneCountNormalConfigUnaffected(t *testing.T) {
	tree := buildTree(t, []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security zones security-zone dmz",
	})
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("strict commit rejected an ordinary 3-zone config: %v", err)
	}
}

// TestZoneCountOverCapLenientDowngradesToWarning asserts the tolerant load /
// peer-sync path downgrades the over-cap rejection to a warning instead of
// failing the compile, so an already-persisted or peer-synced config an older
// binary accepted still boots (#2391 / #1960 no-brick). The dataplane fails
// closed on every overflowing zone, so the leniently-loaded over-cap config is
// inert (the overflow zones do not forward) rather than mis-attributed.
func TestZoneCountOverCapLenientDowngradesToWarning(t *testing.T) {
	tree := buildTree(t, zoneSetLines(MaxUsableZoneID+1))
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile must not fail on an over-cap zone config: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "zone count (downgraded to warning on tolerant path)") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected a downgraded zone-count warning, got warnings: %v", cfg.Warnings)
	}
}
