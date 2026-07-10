package config

import (
	"strings"
	"testing"
)

// #5116: the FRR renderer derives a per-use-site fail-closed redistribute
// route-map alias `name + ReservedRedistSuffix` ("-xpf-redist") into FRR's
// GLOBAL name-keyed route-map namespace (redistFailClosedRouteMap, pkg/frr).
// An operator policy-statement literally named `<X>-xpf-redist` collides with
// that generated alias and can silently undo the #4481 fail-closed BGP/IGP
// separation, reintroducing route redistribution leakage under a config that
// otherwise passes validation. validatePolicyReservedRedistNameStrict reserves
// the suffix: hard-reject at commit / commit-check (strict), lenient-warn on
// load / peer-sync (#1960). This makes the generated-alias namespace injective
// by construction.
//
// These tests drive the real CompileConfig (strict) / CompileConfigLenient
// (tolerant) paths via buildTreeFromSet (the shared flat-set helper). They FAIL
// if the reserve gate is reverted (the reserved-suffix name is then silently
// accepted at commit).

// TestPolicyReservedRedistSuffixRejected is the core: an operator
// policy-statement whose name ends in the reserved suffix is hard-rejected at
// commit, naming the policy, the suffix, and that it is reserved.
func TestPolicyReservedRedistSuffixRejected(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set policy-options policy-statement SHARED-xpf-redist term t1 from protocol direct",
		"set policy-options policy-statement SHARED-xpf-redist term t1 then accept",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig accepted a policy-statement ending in the reserved " +
			"\"-xpf-redist\" suffix; expected rejection (#5116)")
	}
	for _, want := range []string{"SHARED-xpf-redist", "-xpf-redist", "reserved"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q missing %q", err.Error(), want)
		}
	}
}

// TestPolicyNormalNameAccepted is the negative control: a normal
// policy-statement name (no reserved suffix) still compiles, so the gate is
// SURGICAL and does not reject the common case. It also proves the collision
// trigger requires the exact suffix — `SHARED` alone is fine.
func TestPolicyNormalNameAccepted(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set policy-options policy-statement SHARED term t1 from protocol direct",
		"set policy-options policy-statement SHARED term t1 then accept",
		"set protocols ospf area 0.0.0.0 interface ge-0-0-0",
		"set protocols ospf export SHARED",
	})
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("CompileConfig rejected a normal (non-reserved) policy-statement name: %v", err)
	}
}

// TestPolicyReservedRedistSuffixLenientWarns pins the #1960 fail-closed-on-load
// doctrine: an already-persisted or peer-synced config an older binary accepted
// (before this gate) must still BOOT through CompileConfigLenient — the reserved
// name is downgraded to a warning, not a hard failure. The render-side
// redistAliasCollision guard (pkg/frr) fails the actual apply closed, so the
// leniently-loaded name still cannot leak.
func TestPolicyReservedRedistSuffixLenientWarns(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set policy-options policy-statement SHARED-xpf-redist term t1 from protocol direct",
		"set policy-options policy-statement SHARED-xpf-redist term t1 then accept",
	})
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient must not hard-fail on a reserved-suffix name; must downgrade to warning: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "SHARED-xpf-redist") && strings.Contains(w, "reserved") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected a downgraded reserved-suffix warning naming the policy; warnings=%v", cfg.Warnings)
	}
}
