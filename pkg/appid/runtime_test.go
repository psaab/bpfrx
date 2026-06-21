package appid

import (
	"reflect"
	"sort"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestCatalogNamesReferencedOnly(t *testing.T) {
	cfg := &config.Config{
		Applications: config.ApplicationsConfig{
			Applications: map[string]*config.Application{
				"custom-web": {Name: "custom-web", Protocol: "tcp", DestinationPort: "8443"},
			},
			ApplicationSets: map[string]*config.ApplicationSet{
				"web-set": {Name: "web-set", Applications: []string{"junos-http", "custom-web"}},
			},
		},
		Security: config.SecurityConfig{
			Policies: []*config.ZonePairPolicies{
				{
					Policies: []*config.Policy{
						{Match: config.PolicyMatch{Applications: []string{"web-set"}}},
					},
				},
			},
		},
	}

	got, err := CatalogNames(cfg, false)
	if err != nil {
		t.Fatalf("CatalogNames() error = %v", err)
	}
	want := []string{"custom-web", "junos-http"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("CatalogNames() = %v, want %v", got, want)
	}
}

// TestStrictValidationSetMatchesCatalogNames is the #2185 drift guard
// (independent review check #4). The compiler's commit-time strict-validation
// walk (config.applicationsToValidateStrict, exposed as
// config.ApplicationsToValidateStrict) INLINE-duplicates the policy-reference
// resolution in CatalogNames, because pkg/appid imports pkg/config and the
// compiler cannot call back into appid without an import cycle. This test pins
// the two walks together: for a fixture whose application-sets all resolve, the
// USER-APP subset of CatalogNames(cfg, false) must equal the strict set exactly.
// If a future change to CatalogNames's resolution silently diverges from the
// compiler copy, this fails — turning a silent commit-gate drift into a test
// failure. It is a cross-check TEST, not a runtime coupling.
func TestStrictValidationSetMatchesCatalogNames(t *testing.T) {
	cfg := &config.Config{
		Applications: config.ApplicationsConfig{
			Applications: map[string]*config.Application{
				// referenced directly by a policy
				"direct-app": {Name: "direct-app", Protocol: "tcp", DestinationPort: "8443"},
				// referenced only via an application-set
				"set-app": {Name: "set-app", Protocol: "udp", DestinationPort: "1234"},
				// not referenced anywhere — must appear in NEITHER walk
				"unref-app": {Name: "unref-app", Protocol: "tcp", DestinationPort: "9000"},
			},
			ApplicationSets: map[string]*config.ApplicationSet{
				// resolvable set: a predefined junos app + a user app. CatalogNames
				// includes junos-http; the strict walk drops it (predefined specs are
				// not operator-owned), so the user-app subset is what must match.
				"web-set": {Name: "web-set", Applications: []string{"junos-http", "set-app"}},
			},
		},
		Security: config.SecurityConfig{
			Policies: []*config.ZonePairPolicies{
				{
					Policies: []*config.Policy{
						{Match: config.PolicyMatch{Applications: []string{"direct-app"}}},
						{Match: config.PolicyMatch{Applications: []string{"web-set"}}},
					},
				},
			},
		},
	}

	catalog, err := CatalogNames(cfg, false)
	if err != nil {
		t.Fatalf("CatalogNames() error = %v", err)
	}
	// User-app subset of CatalogNames: drop predefined junos-* names, which the
	// strict walk never returns (their specs are owned by the predefined table).
	catalogUserSubset := map[string]struct{}{}
	for _, name := range catalog {
		if _, isUser := cfg.Applications.Applications[name]; isUser {
			catalogUserSubset[name] = struct{}{}
		}
	}

	strict := config.ApplicationsToValidateStrict(cfg)

	if !reflect.DeepEqual(strict, catalogUserSubset) {
		t.Fatalf("strict-validation walk and CatalogNames user-app subset have "+
			"drifted:\n  strict        = %v\n  catalog(user) = %v",
			sortedKeys(strict), sortedKeys(catalogUserSubset))
	}
	// Guard against the fixture degenerating to the trivial empty/equal case.
	if _, ok := strict["unref-app"]; ok {
		t.Fatal("unreferenced app must not be in the strict-validation set")
	}
	if len(strict) != 2 {
		t.Fatalf("expected exactly {direct-app, set-app} in strict set, got %v", sortedKeys(strict))
	}
}

func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func TestResolveSessionNameUsesAppIDWhenEnabled(t *testing.T) {
	cfg := &config.Config{}
	cfg.Services.ApplicationIdentification = true

	got := ResolveSessionName(map[uint16]string{7: "junos-http"}, cfg, 6, 80, 7)
	if got != "junos-http" {
		t.Fatalf("ResolveSessionName() = %q, want junos-http", got)
	}
}

func TestResolveSessionNameUnknownWhenEnabled(t *testing.T) {
	cfg := &config.Config{}
	cfg.Services.ApplicationIdentification = true

	got := ResolveSessionName(nil, cfg, 6, 80, 0)
	if got != Unknown {
		t.Fatalf("ResolveSessionName() = %q, want %q", got, Unknown)
	}
}

func TestResolveSessionNameFallbackWhenDisabled(t *testing.T) {
	cfg := &config.Config{
		Applications: config.ApplicationsConfig{
			Applications: map[string]*config.Application{
				"custom-web": {Name: "custom-web", Protocol: "tcp", DestinationPort: "8443-8445"},
			},
		},
	}

	got := ResolveSessionName(nil, cfg, 6, 8444, 0)
	if got != "custom-web" {
		t.Fatalf("ResolveSessionName() = %q, want custom-web", got)
	}
}

func TestSessionMatchesUnknown(t *testing.T) {
	cfg := &config.Config{}
	cfg.Services.ApplicationIdentification = true
	if !SessionMatches("unknown", nil, cfg, 6, 80, 0) {
		t.Fatal("SessionMatches() should match UNKNOWN when AppID is enabled")
	}
}
