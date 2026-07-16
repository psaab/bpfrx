package appid

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #5296: app_id is a STABLE, name-derived id, so a RETAINED session's frozen
// app_id keeps resolving to the application it was stamped under even after an
// ordinary catalog edit inserts an earlier-sorting application. These tests pin
// that end-to-end through BuildCatalog + ResolveSessionName, and pin the
// resolveTupleFallback tie-break re-key that keeps the AppID-on/off label paths
// in agreement (#3612) under the new ids.

func mkAppIDCfg(names []string, ports map[string]string) *config.Config {
	apps := map[string]*config.Application{}
	for _, n := range names {
		apps[n] = &config.Application{Name: n, Protocol: "tcp", DestinationPort: ports[n]}
	}
	cfg := &config.Config{Applications: config.ApplicationsConfig{Applications: apps}}
	// AppID disabled keeps CatalogNames on the policy-referenced set (exactly
	// these apps) rather than pulling in all 89 predefined names, so the ids
	// under test are just these user apps. ResolveSessionName still resolves a
	// nonzero stamped app_id through the AppNames map regardless of the knob.
	cfg.Services.ApplicationIdentification = false
	cfg.Security.GlobalPolicies = []*config.Policy{
		{Name: "ref", Match: config.PolicyMatch{Applications: names}},
	}
	return cfg
}

func idOfName(cat Catalog, name string) uint16 {
	for id, n := range cat.AppNames {
		if n == name {
			return id
		}
	}
	return 0
}

// TestStableIDResolvesRetainedSessionAfterCatalogEdit is the core #5296
// end-to-end fail-on-revert: a session is stamped app_id=k under config C1; C2
// inserts an application that sorts BEFORE the stamped app; the retained
// session's frozen k MUST still resolve to the original name under C2.
//
// RED-on-revert: restore the sorted 1..N positional assignment and C2 shifts the
// stamped app to k+1, so the frozen k resolves to the newly-inserted app's name
// (the exact #5296 mis-label).
func TestStableIDResolvesRetainedSessionAfterCatalogEdit(t *testing.T) {
	ports := map[string]string{
		"svc-alpha":   "7070",
		"svc-bravo":   "8080",
		"svc-charlie": "9090",
		"aaa-early":   "70",
	}
	c1 := mkAppIDCfg([]string{"svc-alpha", "svc-bravo", "svc-charlie"}, ports)
	cat1, err := BuildCatalog(c1)
	if err != nil {
		t.Fatal(err)
	}
	frozen := idOfName(cat1, "svc-bravo") // stamped on a live session under C1
	if frozen == 0 {
		t.Fatal("svc-bravo was not assigned an app_id under C1")
	}
	if frozen != config.StableAppID("svc-bravo") {
		t.Fatalf("svc-bravo id = %d, want its StableAppID %d", frozen, config.StableAppID("svc-bravo"))
	}

	// C2 adds aaa-early, which sorts before every svc-* name.
	c2 := mkAppIDCfg([]string{"aaa-early", "svc-alpha", "svc-bravo", "svc-charlie"}, ports)
	cat2, err := BuildCatalog(c2)
	if err != nil {
		t.Fatal(err)
	}

	// The retained session (frozen app_id from C1, tcp/8080) must still resolve
	// to svc-bravo under C2's catalog.
	got := ResolveSessionName(cat2.AppNames, c2, 6, 0, 8080, frozen)
	if got != "svc-bravo" {
		t.Fatalf("retained session frozen app_id %d resolves to %q under C2, want svc-bravo (the #5296 mis-label — ids must be stable across the edit)", frozen, got)
	}

	// And the stamped id itself is unchanged across the edit (nothing renumbered).
	if idOfName(cat2, "svc-bravo") != frozen {
		t.Fatalf("svc-bravo id changed across the catalog edit: C1=%d C2=%d", frozen, idOfName(cat2, "svc-bravo"))
	}
}

// TestResolveTupleFallbackTieBreakByStableID pins the #5296 tie-break re-key:
// resolveTupleFallback breaks a same-tier overlap by LOWEST StableAppID, not by
// alphabetically-first name, so it agrees with the AppID-enabled Rust catalog
// (AppCatalog::lookup_directional, lowest app_id) under the stable ids — the
// #3612 cross-language precedence-parity contract.
//
// aaa-svc sorts before ccc-svc but StableAppID(aaa-svc) > StableAppID(ccc-svc),
// so the stable-id tiebreak picks ccc-svc. RED-on-revert: restore the `name <
// best` alphabetical tiebreak and the winner flips to aaa-svc.
func TestResolveTupleFallbackTieBreakByStableID(t *testing.T) {
	if !(config.StableAppID("aaa-svc") > config.StableAppID("ccc-svc")) {
		t.Skipf("fixture stale: StableAppID no longer orders aaa-svc after ccc-svc")
	}
	// Both apps match tcp/8080 in the same (port-constrained) specificity tier.
	cfg := mkAppIDCfg([]string{"aaa-svc", "ccc-svc"}, map[string]string{
		"aaa-svc": "8080",
		"ccc-svc": "8080",
	})
	// AppID-disabled fallback path (resolveTupleFallback is the label source).
	name := resolveTupleFallback(6, 0, 8080, cfg)
	if name != "ccc-svc" {
		t.Fatalf("same-tier tie-break resolved to %q, want ccc-svc (lowest StableAppID); the fallback must key on StableAppID to match the dataplane, not alphabetical order", name)
	}
}
