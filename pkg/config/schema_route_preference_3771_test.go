package config

import (
	"strings"
	"testing"
)

// #3771 (L1): the route `preference` leaf is a typed integer bounded to
// [0, 2147483647] at the Go commit boundary. Junos route preference is a
// non-negative admin distance, and the snapshot serializes it as a Rust i32,
// so a negative value (the documented defect — it would sort ahead of every
// route in the Rust FIB tie-break) or an i32-overflowing value is rejected at
// commit. The Rust helper backstops the lower bound too
// (RoutePreferenceOutOfRange).
//
// FAIL-ON-REVERT: dropping the `valueType: ValueInteger, validator:
// ValidateInteger(0, maxWireI32)` on the schema `preference` leaf makes the
// untyped leaf accept any token again, so the negative/overflow reject
// assertions below fire RED.
func TestStaticRoutePreference_SchemaGate(t *testing.T) {
	reject := func(val string) {
		t.Helper()
		tree := flatTreeFromSets(t,
			"set routing-options static route 0.0.0.0/0 preference "+val)
		if err := SchemaValidate(tree, nil); err == nil {
			t.Fatalf("preference %q: expected SchemaValidate to reject, got nil", val)
		}
	}
	accept := func(val string) {
		t.Helper()
		tree := flatTreeFromSets(t,
			"set routing-options static route 0.0.0.0/0 preference "+val)
		if err := SchemaValidate(tree, nil); err != nil {
			t.Fatalf("preference %q: expected SchemaValidate to accept, got %v", val, err)
		}
	}
	// Negative (the #3771 defect), non-numeric, and i32-overflow reject.
	for _, val := range []string{"-1", "-2147483648", "notanumber", "2147483648", "4294967295"} {
		reject(val)
	}
	// 0 (most-preferred) and normal values through the i32 ceiling accept.
	for _, val := range []string{"0", "1", "5", "100", "2147483647"} {
		accept(val)
	}
}

// #3771 (L1): the reject error names the offending value so the operator sees
// which preference was out of range.
func TestStaticRoutePreference_NegativeErrorMentionsRange(t *testing.T) {
	tree := flatTreeFromSets(t,
		"set routing-options static route ::/0 preference -5")
	err := SchemaValidate(tree, nil)
	if err == nil {
		t.Fatal("expected a negative route preference to be rejected at commit")
	}
	if !strings.Contains(err.Error(), "-5") {
		t.Fatalf("error %q must name the out-of-range value -5", err.Error())
	}
}
