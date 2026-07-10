package appid

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestCatalogNamesNilApplicationSetNoPanic is the #5179 end-to-end proof at the
// reported crash site. A policy `match application <set>` whose application-set
// value is present-but-nil (tolerant-load / peer-sync admits the null slot,
// #1960) must fail closed with an expansion error — not panic CatalogNames and
// take down the control-plane catalog build. addAppRef gates on map membership
// (true for a nil value) and calls ExpandApplicationSet; before the fix that
// dereferenced a nil *ApplicationSet. Reverting the pkg/config guard turns this
// RED: CatalogNames panics (recovered here) instead of returning an error.
func TestCatalogNamesNilApplicationSetNoPanic(t *testing.T) {
	cfg := &config.Config{
		Applications: config.ApplicationsConfig{
			Applications: map[string]*config.Application{},
			ApplicationSets: map[string]*config.ApplicationSet{
				"nilset": nil,
			},
		},
		Security: config.SecurityConfig{
			Policies: []*config.ZonePairPolicies{
				{
					Policies: []*config.Policy{
						{Match: config.PolicyMatch{Applications: []string{"nilset"}}},
					},
				},
			},
		},
	}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("CatalogNames panicked on a nil application-set value (must fail closed, not panic): %v", r)
		}
	}()

	got, err := CatalogNames(cfg, false)
	if err == nil {
		t.Fatalf("CatalogNames() = %v, want a deterministic expansion error for a nil application-set", got)
	}
}
