package config

import (
	"strings"
	"testing"
)

// Hash-freeze pins (#1873): StableTunnelEndpointID is wire-adjacent —
// both HA nodes must compute identical ids from identical config, so
// the fold may NEVER change. If this test fails, you changed the fold;
// revert. (The literal values were computed once and frozen.)
func TestStableTunnelEndpointIDHashFreeze(t *testing.T) {
	pins := map[string]uint16{
		// Ordinary names.
		"wg0.0":      16091,
		"gr-0/0/0.0": 44687,
		// The verified colliding pair (Codex plan-review r1): both
		// fold to 824. Pinned so the collision-handling tests below
		// stay grounded in a REAL collision under the frozen fold.
		"wg1408.0": 824,
		"wg78.0":   824,
	}
	for name, want := range pins {
		if got := StableTunnelEndpointID(name); got != want {
			t.Fatalf("StableTunnelEndpointID(%q) = %d, want %d — the fold is frozen (#1873)", name, got, want)
		}
	}
}

// id 0 means "not a tunnel" everywhere; the mapping must never emit it.
func TestStableTunnelEndpointIDNeverZero(t *testing.T) {
	names := []string{"", "wg0", "wg0.0", "gr-0/0/0.0", "a", "zz.4094"}
	for _, name := range names {
		if got := StableTunnelEndpointID(name); got == 0 {
			t.Fatalf("StableTunnelEndpointID(%q) = 0", name)
		}
	}
}

// R-B: a config whose tunnel names fold to the same id must fail
// commit compilation (strict path) with a two-name remediation error.
func TestTunnelEndpointIDCollisionFailsCommit(t *testing.T) {
	tree := buildTree(t, []string{
		"set interfaces wg1408 unit 0 tunnel mode wireguard",
		"set interfaces wg78 unit 0 tunnel mode wireguard",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatalf("CompileConfig accepted a colliding tunnel pair")
	}
	for _, want := range []string{"wg1408.0", "wg78.0", "collision", "rename"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("collision error %q does not mention %q", err.Error(), want)
		}
	}
}

// R-B lenient: an already-active config with a collision must still
// compile on the tolerant load/peer-sync paths (warn, not reject) so
// an upgraded node boots.
func TestTunnelEndpointIDCollisionLenientWarns(t *testing.T) {
	tree := buildTree(t, []string{
		"set interfaces wg1408 unit 0 tunnel mode wireguard",
		"set interfaces wg78 unit 0 tunnel mode wireguard",
	})
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient rejected a colliding pair: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "collision") && strings.Contains(w, "wg1408.0") {
			found = true
		}
	}
	if !found {
		t.Fatalf("lenient compile carried no collision warning: %v", cfg.Warnings)
	}
}

// R-B union-of-groups symmetry (Claude SMR plan r2): a collision
// involving a `groups nodeN`-scoped tunnel must fail commit on BOTH
// nodes — including the node whose effective config never applies the
// group — or config-sync would split (originator accepts, peer
// rejects).
func TestTunnelEndpointIDCollisionAcrossGroupsIsSymmetric(t *testing.T) {
	tree := buildTree(t, []string{
		"set groups node1 interfaces wg1408 unit 0 tunnel mode wireguard",
		"set interfaces wg78 unit 0 tunnel mode wireguard",
		// No apply-groups: node0's EFFECTIVE config never contains
		// wg1408 — the union check must still reject.
	})
	if _, err := CompileConfigForNode(tree, 0); err == nil {
		t.Fatalf("node0 compile accepted a collision hidden in groups node1")
	}
	if _, err := CompileConfigForNode(tree, 1); err == nil {
		t.Fatalf("node1 compile accepted a collision hidden in groups node1")
	}
}

// Non-colliding multi-tunnel configs must compile clean (no false
// positives from the gate).
func TestTunnelEndpointIDNoFalsePositive(t *testing.T) {
	tree := buildTree(t, []string{
		"set interfaces wg0 unit 0 tunnel mode wireguard",
		"set groups node0 interfaces gr-0/0/0 unit 0 tunnel mode gre",
		"set groups node0 interfaces gr-0/0/0 unit 0 tunnel source 10.0.0.1",
		"set groups node0 interfaces gr-0/0/0 unit 0 tunnel destination 10.0.0.2",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig rejected a non-colliding config: %v", err)
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "tunnel endpoint id collision") {
			t.Fatalf("unexpected collision warning: %q", w)
		}
	}
}
