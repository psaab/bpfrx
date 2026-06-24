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
//
// Scope note (#2187): the strict walk also collects source/destination-NAT
// `match application` references, which CatalogNames does not. This fixture
// carries NO NAT rules, so the two walks still coincide here. Adding a NAT
// reference to this fixture would (correctly) break the equality — the
// NAT-reference path is exercised by the compiler-package tests instead.
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

// TestMatchTupleProtocolOnly is the #2548 fail-on-revert guard. A custom app
// configured with a protocol but NO destination-port (e.g. user-defined
// GRE/ESP/AH) must tuple-match on protocol alone. Before the fix, matchTuple
// returned false on appPort=="", so the protocol-only app never matched and
// its sessions reported UNKNOWN. Reverting the empty-appPort short-circuit to
// `return false` fails the protocol-only-matches assertion below.
func TestMatchTupleProtocolOnly(t *testing.T) {
	const greProto = 47

	// Protocol-only app matches a session of its protocol regardless of port.
	if !matchTuple(greProto, 0, "gre", "") {
		t.Error("protocol-only GRE app must match a GRE session (proto match alone) — got no match")
	}
	if !matchTuple(greProto, 1234, "gre", "") {
		t.Error("protocol-only GRE app must match regardless of dstPort — got no match")
	}
	// Protocol-only app does NOT match a different protocol.
	if matchTuple(6 /*tcp*/, 0, "gre", "") {
		t.Error("protocol-only GRE app must NOT match a TCP session")
	}
	// Numeric protocol token, protocol-only.
	if !matchTuple(greProto, 0, "47", "") {
		t.Error("protocol-only numeric-protocol app must match its protocol")
	}
	// Port-based app still requires BOTH protocol AND port — no regression.
	if !matchTuple(6, 8443, "tcp", "8443") {
		t.Error("port-based app must match on protocol+port")
	}
	if matchTuple(6, 9999, "tcp", "8443") {
		t.Error("port-based app must NOT match on protocol-match/port-mismatch")
	}
	if matchTuple(17 /*udp*/, 8443, "tcp", "8443") {
		t.Error("port-based app must NOT match on port-match/protocol-mismatch")
	}
	// Port-range app unchanged.
	if !matchTuple(6, 8444, "tcp", "8443-8445") {
		t.Error("port-range app must match a dstPort inside the range")
	}
	if matchTuple(6, 8500, "tcp", "8443-8445") {
		t.Error("port-range app must NOT match a dstPort outside the range")
	}
	// Empty appProto must NOT match-all.
	if matchTuple(47, 0, "", "") {
		t.Error("app with empty protocol must NOT match-all")
	}
}

// TestResolveSessionNameProtocolOnlyApp proves the protocol-only fix flows
// through resolveTupleFallback so the session reports the configured app name
// rather than UNKNOWN. (#2548)
func TestResolveSessionNameProtocolOnlyApp(t *testing.T) {
	cfg := &config.Config{
		Applications: config.ApplicationsConfig{
			Applications: map[string]*config.Application{
				"custom-gre": {Name: "custom-gre", Protocol: "gre"},
			},
		},
	}

	// AppID disabled → tuple fallback. A GRE session (proto 47) names the app.
	got := ResolveSessionName(nil, cfg, 47, 0, 0)
	if got != "custom-gre" {
		t.Fatalf("ResolveSessionName(GRE) = %q, want custom-gre (protocol-only app)", got)
	}
	// A non-GRE session must not pick up the protocol-only GRE app.
	if got := ResolveSessionName(nil, cfg, 6, 80, 0); got == "custom-gre" {
		t.Fatalf("ResolveSessionName(TCP/80) = %q, must not match protocol-only GRE app", got)
	}
}

func TestSessionMatchesUnknown(t *testing.T) {
	cfg := &config.Config{}
	cfg.Services.ApplicationIdentification = true
	if !SessionMatches("unknown", nil, cfg, 6, 80, 0) {
		t.Fatal("SessionMatches() should match UNKNOWN when AppID is enabled")
	}
}
