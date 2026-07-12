// #5629: with AppID DISABLED, appid.CatalogNames must expand a strict
// PREDEFINED application-set bundle (junos-ms-rpc, junos-sun-rpc, junos-cifs,
// junos-routing-inbound) to its member applications — the SAME members the
// shared resolver (config.ResolveApplicationSet + config.ExpandApplicationSet,
// #4102) yields, and the SAME members the AppID-enabled full catalog carries.
//
// Before this fix the per-reference resolver (addAppRef) gated set expansion on
// a bare cfg.Applications.ApplicationSets map membership test, which only sees
// USER-defined sets. A predefined bundle name therefore fell through and was
// recorded as if the bundle NAME were itself an application, so the dataplane
// catalog carried a set name with no resolvable port/proto — diverging from the
// resolver's member expansion.
//
// RED-on-revert: restore the `cfg.Applications.ApplicationSets[appName]` guard
// (drop the config.ResolveApplication/ResolveApplicationSet reorder) and
// CatalogNames records the bare "junos-ms-rpc" token instead of its members,
// failing the containment and resolver-parity asserts below.
package appid

import (
	"reflect"
	"sort"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func hasName(names []string, want string) bool {
	for _, n := range names {
		if n == want {
			return true
		}
	}
	return false
}

// A predefined bundle referenced by a security policy must expand in the
// AppID-disabled catalog to exactly the resolver's members.
func TestCatalogNamesPredefinedSetPolicyReference_5629(t *testing.T) {
	cfg := &config.Config{}
	cfg.Services.ApplicationIdentification = false // AppID DISABLED
	cfg.Security.GlobalPolicies = []*config.Policy{
		{Name: "p1", Match: config.PolicyMatch{Applications: []string{"junos-ms-rpc"}}},
	}

	names, err := CatalogNames(cfg, false)
	if err != nil {
		t.Fatalf("CatalogNames() error = %v", err)
	}

	// (1) The bundle NAME must NOT be recorded as an application.
	if hasName(names, "junos-ms-rpc") {
		t.Fatalf("catalog recorded the bare bundle name %q as an application "+
			"(the #5629 bypass): %v", "junos-ms-rpc", names)
	}
	// (2) The members must be present.
	for _, member := range []string{"junos-ms-rpc-tcp", "junos-ms-rpc-udp"} {
		if !hasName(names, member) {
			t.Fatalf("catalog missing predefined-bundle member %q: %v", member, names)
		}
	}
	// (3) Resolver parity: the disabled-path catalog must equal the shared
	// resolver's expansion (config.ExpandApplicationSet), sorted.
	expanded, err := config.ExpandApplicationSet("junos-ms-rpc", &cfg.Applications)
	if err != nil {
		t.Fatalf("ExpandApplicationSet: %v", err)
	}
	sort.Strings(expanded)
	sortedNames := append([]string(nil), names...)
	sort.Strings(sortedNames)
	if !reflect.DeepEqual(sortedNames, expanded) {
		t.Fatalf("AppID-disabled catalog %v != resolver expansion %v", sortedNames, expanded)
	}
	// (4) AppID-enabled-path parity: every member is present in the full
	// (includeAll) catalog, which compiles every predefined application.
	full, err := CatalogNames(cfg, true)
	if err != nil {
		t.Fatalf("CatalogNames(includeAll) error = %v", err)
	}
	for _, member := range expanded {
		if !hasName(full, member) {
			t.Fatalf("member %q missing from the AppID-enabled full catalog", member)
		}
	}
}

// The same expansion must hold when the predefined bundle is referenced ONLY by
// a NAT rule (the #3626 NAT-reference walk shares addAppRef).
func TestCatalogNamesPredefinedSetNATReference_5629(t *testing.T) {
	cfg := &config.Config{}
	cfg.Services.ApplicationIdentification = false
	cfg.Security.NAT.Source = []*config.NATRuleSet{{
		Name: "rs", FromZone: "trust", ToZone: "untrust",
		Rules: []*config.NATRule{{
			Name:  "r1",
			Match: config.NATMatch{SourceAddress: "10.0.0.0/24", Application: "junos-sun-rpc"},
		}},
	}}

	names, err := CatalogNames(cfg, false)
	if err != nil {
		t.Fatalf("CatalogNames() error = %v", err)
	}
	if hasName(names, "junos-sun-rpc") {
		t.Fatalf("catalog recorded the bare NAT-referenced bundle name: %v", names)
	}
	for _, member := range []string{"junos-sun-rpc-tcp", "junos-sun-rpc-udp"} {
		if !hasName(names, member) {
			t.Fatalf("catalog missing NAT-referenced bundle member %q: %v", member, names)
		}
	}
}

// A user application whose name collides with a predefined-set name must keep
// application semantics (user definitions win, matching resolveUserspace
// ApplicationNames). This guards the app-first precedence of the fix.
func TestCatalogNamesUserAppShadowsPredefinedSet_5629(t *testing.T) {
	cfg := &config.Config{}
	cfg.Services.ApplicationIdentification = false
	cfg.Applications.Applications = map[string]*config.Application{
		"junos-ms-rpc": {Name: "junos-ms-rpc", Protocol: "tcp", DestinationPort: "9999"},
	}
	cfg.Security.GlobalPolicies = []*config.Policy{
		{Name: "p1", Match: config.PolicyMatch{Applications: []string{"junos-ms-rpc"}}},
	}

	names, err := CatalogNames(cfg, false)
	if err != nil {
		t.Fatalf("CatalogNames() error = %v", err)
	}
	// The user application wins: the token stays recorded as the application,
	// NOT expanded to the predefined bundle's members.
	if !hasName(names, "junos-ms-rpc") {
		t.Fatalf("user application shadowing a predefined-set name was dropped: %v", names)
	}
	if hasName(names, "junos-ms-rpc-tcp") || hasName(names, "junos-ms-rpc-udp") {
		t.Fatalf("predefined bundle wrongly shadowed the user application: %v", names)
	}
}
