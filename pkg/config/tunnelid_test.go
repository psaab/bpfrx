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
		"set interfaces wg1408 unit 0 tunnel wireguard peer aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa allowed-ips 10.0.0.0/24",
		"set interfaces wg78 unit 0 tunnel mode wireguard",
		"set interfaces wg78 unit 0 tunnel wireguard peer aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa allowed-ips 10.0.0.0/24",
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
		"set interfaces wg1408 unit 0 tunnel wireguard peer aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa allowed-ips 10.0.0.0/24",
		"set interfaces wg78 unit 0 tunnel mode wireguard",
		"set interfaces wg78 unit 0 tunnel wireguard peer aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa allowed-ips 10.0.0.0/24",
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
		"set groups node1 interfaces wg1408 unit 0 tunnel wireguard peer aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa allowed-ips 10.0.0.0/24",
		"set interfaces wg78 unit 0 tunnel mode wireguard",
		"set interfaces wg78 unit 0 tunnel wireguard peer aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa allowed-ips 10.0.0.0/24",
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

// #1910 r3 Codex: the collision gate must not model endpoint ids the
// snapshot builder never publishes. An interface-level WireGuard
// tunnel with units emits exactly ONE endpoint (lowest unit ref), so
// a collision involving a higher, never-emitted unit ref must not
// reject the commit. Real collision under the frozen fold:
// StableTunnelEndpointID("wg0.1") == StableTunnelEndpointID("wg341")
// == 14730, but only "wg0.0" (16091) and "wg341" are published.
func TestTunnelEndpointIDNoFalsePositiveOnNonEmittedWGUnit(t *testing.T) {
	if a, b := StableTunnelEndpointID("wg0.1"), StableTunnelEndpointID("wg341"); a != b || a != 14730 {
		t.Fatalf("precondition: wg0.1=%d wg341=%d, want both 14730 (frozen fold)", a, b)
	}
	tree := buildTree(t, []string{
		"set interfaces wg0 tunnel mode wireguard",
		"set interfaces wg0 tunnel wireguard peer aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa allowed-ips 10.0.0.0/24",
		"set interfaces wg0 unit 0 family inet address 10.70.0.1/30",
		"set interfaces wg0 unit 1 family inet address 10.70.0.5/30",
		"set interfaces wg341 tunnel mode wireguard",
		"set interfaces wg341 tunnel wireguard peer aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa allowed-ips 10.0.0.0/24",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig rejected a config whose only id collision is on a never-emitted WG unit ref: %v", err)
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "collision") {
			t.Fatalf("unexpected collision warning: %q", w)
		}
	}
}

// #1910 r4 Codex: a non-canonical numeric unit spelling (`unit 01`)
// compiles to unit 1 and the builder emits/hashes the canonical
// "wg0.1" — the gate must hash the SAME canonical ref, or it misses
// the frozen wg0.1/wg341 collision (14730) and the runtime usedIDs
// belt silently drops an endpoint instead of failing the commit.
func TestTunnelEndpointIDLeadingZeroUnitStillCollides(t *testing.T) {
	tree := buildTree(t, []string{
		"set interfaces wg0 tunnel mode wireguard",
		"set interfaces wg0 tunnel wireguard peer aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa allowed-ips 10.0.0.0/24",
		"set interfaces wg0 unit 01 family inet address 10.70.0.1/30",
		"set interfaces wg341 tunnel mode wireguard",
		"set interfaces wg341 tunnel wireguard peer aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa allowed-ips 10.0.0.0/24",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatalf("CompileConfig accepted a builder-emitted collision hidden behind a leading-zero unit spelling (wg0.01 -> emits wg0.1, collides with wg341)")
	}
	for _, want := range []string{"wg0.1", "wg341", "collision"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("collision error %q does not mention %q", err.Error(), want)
		}
	}
}

// #1910 r5 Codex: an interface-level WG tunnel whose ONLY unit
// spelling overflows strconv.Atoi compiles with iface.Units empty, so
// the builder emits the BARE interface ref — the gate must hash that
// bare ref, not the raw overflow spelling (which hashes elsewhere and
// would let a real builder-emitted collision pass strict compile,
// landing on the runtime usedIDs drop instead of failing commit).
// Frozen collision: StableTunnelEndpointID("wg0") ==
// StableTunnelEndpointID("wg34524.0") == 17799.
func TestTunnelEndpointIDOverflowOnlyUnitHashesBareRef(t *testing.T) {
	if a, b := StableTunnelEndpointID("wg0"), StableTunnelEndpointID("wg34524.0"); a != b || a != 17799 {
		t.Fatalf("precondition: wg0=%d wg34524.0=%d, want both 17799 (frozen fold)", a, b)
	}
	tree := buildTree(t, []string{
		"set interfaces wg0 tunnel mode wireguard",
		"set interfaces wg0 tunnel wireguard peer aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa allowed-ips 10.0.0.0/24",
		"set interfaces wg0 unit 99999999999999999999999999999999999999 family inet address 10.70.2.1/30",
		"set interfaces wg34524 unit 0 tunnel mode wireguard",
		"set interfaces wg34524 unit 0 tunnel wireguard peer aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa allowed-ips 10.0.0.0/24",
	})
	if _, err := CompileConfig(tree); err == nil {
		t.Fatalf("CompileConfig accepted a builder-emitted collision hidden behind an overflow-only unit spelling (wg0 emits bare ref, collides with wg34524.0)")
	}
}

// The same canonicalization must hold on the per-unit branches: a
// UNIT-LEVEL tunnel declared as `unit 01` compiles to unit 1 and the
// builder emits "wg0.1" — the gate must hash the canonical ref there
// too, or it misses the frozen wg0.1/wg341 collision (14730).
func TestTunnelEndpointIDUnitLevelLeadingZeroStillCollides(t *testing.T) {
	tree := buildTree(t, []string{
		"set interfaces wg0 unit 01 tunnel mode wireguard",
		"set interfaces wg0 unit 01 tunnel wireguard peer aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa allowed-ips 10.0.0.0/24",
		"set interfaces wg341 tunnel mode wireguard",
		"set interfaces wg341 tunnel wireguard peer aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa allowed-ips 10.0.0.0/24",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatalf("CompileConfig accepted a builder-emitted collision hidden behind a unit-level leading-zero spelling (wg0.01 -> emits wg0.1, collides with wg341)")
	}
	for _, want := range []string{"wg0.1", "wg341", "collision"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("collision error %q does not mention %q", err.Error(), want)
		}
	}
}

// #1910 r6 Codex: duplicate spellings of the same unit number must
// follow the typed compiler's LAST-WINS overwrite
// (ifc.Units[unitNum] = unit per instance). When `unit 00` carries
// the tunnel but a later `unit 0` re-declares the unit without one,
// the compiled unit has no tunnel and the builder emits nothing — the
// gate must not register the ref (false reject). When the order is
// reversed the tunnel-carrying instance wins and the collision is
// real.
func TestTunnelEndpointIDDuplicateUnitSpellingLastWins(t *testing.T) {
	// Tunnel on the OVERWRITTEN earlier instance: no endpoint emitted,
	// so the wg1408.0/wg78.0 collision (both refs would collide if
	// emitted) must NOT reject the commit.
	tree := buildTree(t, []string{
		"set interfaces wg1408 unit 00 tunnel mode wireguard",
		"set interfaces wg1408 unit 00 tunnel wireguard peer aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa allowed-ips 10.0.0.0/24",
		"set interfaces wg1408 unit 0 family inet address 10.70.3.1/30",
		"set interfaces wg78 unit 0 tunnel mode wireguard",
		"set interfaces wg78 unit 0 tunnel wireguard peer aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa allowed-ips 10.0.0.0/24",
	})
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("CompileConfig rejected a collision on a ref whose tunnel lives only on an overwritten duplicate unit instance: %v", err)
	}
	// Tunnel on the LAST instance: the unit compiles with the tunnel,
	// the builder emits wg1408.0, and the collision must reject.
	tree = buildTree(t, []string{
		"set interfaces wg1408 unit 00 family inet address 10.70.3.1/30",
		"set interfaces wg1408 unit 0 tunnel mode wireguard",
		"set interfaces wg1408 unit 0 tunnel wireguard peer aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa allowed-ips 10.0.0.0/24",
		"set interfaces wg78 unit 0 tunnel mode wireguard",
		"set interfaces wg78 unit 0 tunnel wireguard peer aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa allowed-ips 10.0.0.0/24",
	})
	if _, err := CompileConfig(tree); err == nil {
		t.Fatalf("CompileConfig accepted a real collision whose tunnel lives on the last duplicate unit instance (wg1408.0 vs wg78.0)")
	}
}

// And the inverse: a collision on the EMITTED lowest unit ref of an
// interface-level WG tunnel must still be rejected.
func TestTunnelEndpointIDCollisionOnEmittedWGUnitStillRejected(t *testing.T) {
	tree := buildTree(t, []string{
		"set interfaces wg1408 tunnel mode wireguard",
		"set interfaces wg1408 tunnel wireguard peer aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa allowed-ips 10.0.0.0/24",
		"set interfaces wg1408 unit 0 family inet address 10.70.1.1/30",
		"set interfaces wg1408 unit 1 family inet address 10.70.1.5/30",
		"set interfaces wg78 unit 0 tunnel mode wireguard",
		"set interfaces wg78 unit 0 tunnel wireguard peer aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa allowed-ips 10.0.0.0/24",
	})
	if _, err := CompileConfig(tree); err == nil {
		t.Fatalf("CompileConfig accepted a collision on the emitted lowest unit ref (wg1408.0 vs wg78.0)")
	}
}

// Non-colliding multi-tunnel configs must compile clean (no false
// positives from the gate).
func TestTunnelEndpointIDNoFalsePositive(t *testing.T) {
	tree := buildTree(t, []string{
		"set interfaces wg0 unit 0 tunnel mode wireguard",
		"set interfaces wg0 unit 0 tunnel wireguard peer aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa allowed-ips 10.0.0.0/24",
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

// #1914 Defect A: a WILDCARD apply-group splices `unit 0 tunnel mode
// wireguard` onto the interfaces that reference it. The pre-expansion
// View-1 collector hashes only the LITERAL group ref `<*>.0` (50477) — it
// never sees the concrete post-expansion `wg78.0`/`wg1408.0`, both folding
// to 824 — so View 1 alone FALSELY ACCEPTS a builder-emitted collision the
// runtime usedIDs belt then drops with a loud slog.Error. The post-expansion
// Views 2/3 expand the wildcard onto wg78 + wg1408, see both concrete refs,
// and must REJECT the commit (strict path).
func TestTunnelEndpointIDWildcardApplyGroupsCollisionRejected(t *testing.T) {
	// Frozen-fold preconditions: the literal wildcard ref does NOT collide
	// with the concrete refs, but the two concrete refs collide with each
	// other (so only the post-expansion views can catch it).
	if got := StableTunnelEndpointID("<*>.0"); got != 50477 {
		t.Fatalf("precondition: <*>.0=%d, want 50477 (frozen fold)", got)
	}
	if a, b := StableTunnelEndpointID("wg78.0"), StableTunnelEndpointID("wg1408.0"); a != b || a != 824 {
		t.Fatalf("precondition: wg78.0=%d wg1408.0=%d, want both 824 (frozen fold)", a, b)
	}
	tree := buildTree(t, []string{
		"set groups wgtun interfaces <*> unit 0 tunnel mode wireguard",
		"set groups wgtun interfaces <*> unit 0 tunnel wireguard peer aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa allowed-ips 10.0.0.0/24",
		"set interfaces wg78 apply-groups wgtun",
		"set interfaces wg1408 unit 0 tunnel mode wireguard",
		"set interfaces wg1408 unit 0 tunnel wireguard peer aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa allowed-ips 10.0.0.0/24",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatalf("CompileConfig accepted a wildcard-apply-groups builder-emitted collision (wg78.0 vs wg1408.0)")
	}
	for _, want := range []string{"wg78.0", "wg1408.0", "collision", "rename"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("collision error %q does not mention %q", err.Error(), want)
		}
	}
}

// #1914 Defect A lenient: the same wildcard-apply-groups collision must
// WARN (not error) on the tolerant load/peer-sync path.
func TestTunnelEndpointIDWildcardApplyGroupsCollisionLenientWarns(t *testing.T) {
	tree := buildTree(t, []string{
		"set groups wgtun interfaces <*> unit 0 tunnel mode wireguard",
		"set groups wgtun interfaces <*> unit 0 tunnel wireguard peer aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa allowed-ips 10.0.0.0/24",
		"set interfaces wg78 apply-groups wgtun",
		"set interfaces wg1408 unit 0 tunnel mode wireguard",
		"set interfaces wg1408 unit 0 tunnel wireguard peer aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa allowed-ips 10.0.0.0/24",
	})
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient rejected a wildcard-apply-groups collision: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "collision") && strings.Contains(w, "wg78.0") && strings.Contains(w, "wg1408.0") {
			found = true
		}
	}
	if !found {
		t.Fatalf("lenient compile carried no wildcard-collision warning: %v", cfg.Warnings)
	}
}

// #1914 Defect A symmetry: the wildcard-apply-groups collision must reject
// IDENTICALLY under both per-node compiles, or config-sync would split.
func TestTunnelEndpointIDWildcardApplyGroupsCollisionSymmetric(t *testing.T) {
	tree := buildTree(t, []string{
		"set groups wgtun interfaces <*> unit 0 tunnel mode wireguard",
		"set groups wgtun interfaces <*> unit 0 tunnel wireguard peer aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa allowed-ips 10.0.0.0/24",
		"set interfaces wg78 apply-groups wgtun",
		"set interfaces wg1408 unit 0 tunnel mode wireguard",
		"set interfaces wg1408 unit 0 tunnel wireguard peer aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa allowed-ips 10.0.0.0/24",
	})
	if _, err := CompileConfigForNode(tree, 0); err == nil {
		t.Fatalf("node0 compile accepted a wildcard-apply-groups collision")
	}
	if _, err := CompileConfigForNode(tree, 1); err == nil {
		t.Fatalf("node1 compile accepted a wildcard-apply-groups collision")
	}
}

// #1914 View-1 byte-identity / cross-node symmetry: the #1873 guarantee
// that a collision hidden in a `groups node1` block (never applied on
// node0's effective config) still rejects on BOTH nodes must survive the
// addition of Views 2/3 — Views 2/3 never expand the un-applied group, so
// only the UNCHANGED presence union (View 1) catches it. This is the
// regression guard for "don't narrow View 1".
func TestTunnelEndpointIDView1PresenceUnionPreserved(t *testing.T) {
	tree := buildTree(t, []string{
		// Collision hidden in an UN-APPLIED groups node1 block; node0
		// never applies it (no apply-groups "${node}"). Views 2/3 expand
		// to empty for this group, so only View 1's presence union can
		// reject — proving View 1 was not narrowed.
		"set groups node1 interfaces wg1408 unit 0 tunnel mode wireguard",
		"set groups node1 interfaces wg1408 unit 0 tunnel wireguard peer aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa allowed-ips 10.0.0.0/24",
		"set interfaces wg78 unit 0 tunnel mode wireguard",
		"set interfaces wg78 unit 0 tunnel wireguard peer aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa allowed-ips 10.0.0.0/24",
	})
	if _, err := CompileConfigForNode(tree, 0); err == nil {
		t.Fatalf("node0 compile accepted a collision hidden in un-applied groups node1 (View 1 was narrowed?)")
	}
	if _, err := CompileConfigForNode(tree, 1); err == nil {
		t.Fatalf("node1 compile accepted a collision hidden in groups node1")
	}
}

// #1914 Defect B (DOCUMENTED LIMITATION — pin CURRENT behavior): View 1
// registers a non-WG tunnel ref from presence alone, with no src/dest
// check, while the builder drops an incomplete non-WG tunnel. A
// half-configured GRE whose unit ref folds onto a real emitted ref still
// REJECTS — the accepted residual. This test pins the limitation so a
// future reader knows it is intentional (Defect B is mutually exclusive
// with the Defect-A fix), not a new bug. Frozen collision:
// gr-0/0/0.0 == wg29715.0 == 44687.
func TestTunnelEndpointIDDefectBIncompleteGREStillRejects(t *testing.T) {
	if a, b := StableTunnelEndpointID("gr-0/0/0.0"), StableTunnelEndpointID("wg29715.0"); a != b || a != 44687 {
		t.Fatalf("precondition: gr-0/0/0.0=%d wg29715.0=%d, want both 44687 (frozen fold)", a, b)
	}
	tree := buildTree(t, []string{
		// Incomplete GRE: no source/dest. The builder drops it, but View 1
		// registers it (presence-only). It folds onto the real wg29715.0.
		"set interfaces gr-0/0/0 unit 0 tunnel mode gre",
		"set interfaces wg29715 unit 0 tunnel mode wireguard",
		"set interfaces wg29715 unit 0 tunnel wireguard peer aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa allowed-ips 10.0.0.0/24",
	})
	if _, err := CompileConfig(tree); err == nil {
		t.Fatalf("Defect B residual changed: incomplete-GRE phantom no longer rejects (View 1 was narrowed?)")
	}
}

// #1914 no false positive: a WG wildcard apply-group applied to a SINGLE
// interface (no second colliding ref) must compile clean — Views 2/3 add
// exactly one concrete ref, no collision.
func TestTunnelEndpointIDWildcardApplyGroupsSingleInterfaceClean(t *testing.T) {
	tree := buildTree(t, []string{
		"set groups wgtun interfaces <*> unit 0 tunnel mode wireguard",
		"set groups wgtun interfaces <*> unit 0 tunnel wireguard peer aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa allowed-ips 10.0.0.0/24",
		"set interfaces wg78 apply-groups wgtun",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig rejected a single-interface wildcard WG group: %v", err)
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "tunnel endpoint id collision") {
			t.Fatalf("unexpected collision warning: %q", w)
		}
	}
}

// #1914 non-fatal peer-group expansion: a config that defines only
// `groups node0` and applies "${node}" has NO `groups node1`, so View 3
// (node1 expansion) hits `undefined group "node1"`. That MUST be non-fatal
// (View 3 contributes the empty set) and the config must COMMIT cleanly —
// the gate must not turn a valid-on-the-local-node config into a spurious
// failure.
func TestTunnelEndpointIDNonFatalUndefinedPeerGroup(t *testing.T) {
	tree := buildTree(t, []string{
		"set groups node0 interfaces wg0 unit 0 tunnel mode wireguard",
		"set groups node0 interfaces wg0 unit 0 tunnel wireguard peer aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa allowed-ips 10.0.0.0/24",
		`set apply-groups "${node}"`,
	})
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("CompileConfig (generic, node0 fallback) failed on undefined peer group: %v", err)
	}
	if _, err := CompileConfigForNode(tree, 0); err != nil {
		t.Fatalf("node0 compile failed on a config with only groups node0: %v", err)
	}
}

// #1914 no-recursion regression: the gate on a wildcard / multi-node config
// must return in bounded time. If a future edit reintroduces a
// CompileConfig* call from the gate it recurses to stack overflow; this
// test guards the recursion-free invariant by simply requiring the gate to
// terminate (a recursion would panic/hang well before this returns).
func TestTunnelEndpointIDGateTerminatesNoRecursion(t *testing.T) {
	tree := buildTree(t, []string{
		"set groups wgtun interfaces <*> unit 0 tunnel mode wireguard",
		"set groups wgtun interfaces <*> unit 0 tunnel wireguard peer aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa allowed-ips 10.0.0.0/24",
		"set interfaces wg78 apply-groups wgtun",
		"set interfaces wg1408 unit 0 tunnel mode wireguard",
		"set interfaces wg1408 unit 0 tunnel wireguard peer aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa allowed-ips 10.0.0.0/24",
		"set groups node0 interfaces gr-0/0/0 unit 0 tunnel mode gre",
		`set apply-groups "${node}"`,
	})
	// Direct gate call: must terminate (and reject the real wg collision).
	if _, err := validateTunnelEndpointIDCollisionAST(tree, false); err == nil {
		t.Fatalf("gate accepted a wildcard collision (or recursed before returning)")
	}
}
