package config

import (
	"strings"
	"testing"
)

// #3827 (Low, #3771/#3826 follow-up): the qualified-next-hop `preference`
// leaf is a typed integer bounded to [0, 2147483647] at the Go commit
// boundary, mirroring the route-level `preference` leaf (#3771). The
// compiler folds a qualified-next-hop preference into the same route.Preference
// i32 wire field (compiler_routing.go), so an untyped qnh preference let a
// negative / i32-overflow value slip past the primary Go gate and land on the
// Rust snapshot backstop (RoutePreferenceOutOfRange) — an opaque
// snapshot-rejection with retained-prior-state instead of a clean commit error
// naming the leaf.
//
// FAIL-ON-REVERT: dropping the `valueType: ValueInteger, validator:
// ValidateInteger(0, maxWireI32)` on the qualified-next-hop `preference` leaf
// makes the untyped leaf accept any token again, so the negative/overflow
// reject assertions below fire RED.
func TestStaticRouteQualifiedNextHopPreference_SchemaGate(t *testing.T) {
	reject := func(val string) {
		t.Helper()
		tree := flatTreeFromSets(t,
			"set routing-options static route 0.0.0.0/0 qualified-next-hop 192.168.1.1 preference "+val)
		if err := SchemaValidate(tree, nil); err == nil {
			t.Fatalf("qualified-next-hop preference %q: expected SchemaValidate to reject, got nil", val)
		}
	}
	accept := func(val string) {
		t.Helper()
		tree := flatTreeFromSets(t,
			"set routing-options static route 0.0.0.0/0 qualified-next-hop 192.168.1.1 preference "+val)
		if err := SchemaValidate(tree, nil); err != nil {
			t.Fatalf("qualified-next-hop preference %q: expected SchemaValidate to accept, got %v", val, err)
		}
	}
	// Negative (the primary-gate gap), non-numeric, and i32-overflow reject.
	for _, val := range []string{"-1", "-2147483648", "notanumber", "2147483648", "4294967295"} {
		reject(val)
	}
	// 0 (most-preferred) and normal values through the i32 ceiling accept.
	for _, val := range []string{"0", "1", "5", "100", "2147483647"} {
		accept(val)
	}
}

// #3827: the reject error names the offending value so the operator sees which
// qualified-next-hop preference was out of range (commit-time diagnostic, not
// the opaque Rust snapshot rejection).
func TestStaticRouteQualifiedNextHopPreference_NegativeErrorMentionsValue(t *testing.T) {
	tree := flatTreeFromSets(t,
		"set routing-options static route ::/0 qualified-next-hop 2001:db8::1 preference -7")
	err := SchemaValidate(tree, nil)
	if err == nil {
		t.Fatal("expected a negative qualified-next-hop preference to be rejected at commit")
	}
	if !strings.Contains(err.Error(), "-7") {
		t.Fatalf("error %q must name the out-of-range value -7", err.Error())
	}
}

// #3827: a valid qualified-next-hop preference (with interface + metric
// siblings) still commits — the typing tightens the value slot without
// breaking the surrounding qualified-next-hop grammar.
func TestStaticRouteQualifiedNextHopPreference_ValidCommits(t *testing.T) {
	tree := flatTreeFromSets(t,
		"set routing-options static route 10.0.0.0/24 qualified-next-hop 192.168.1.1 preference 10",
		"set routing-options static route 10.0.0.0/24 qualified-next-hop 192.168.1.1 metric 20",
		"set routing-options static route 10.0.0.0/24 qualified-next-hop 192.168.1.1 interface ge-0-0-0")
	if err := SchemaValidate(tree, nil); err != nil {
		t.Fatalf("valid qualified-next-hop preference/metric/interface: SchemaValidate rejected: %v", err)
	}
}
