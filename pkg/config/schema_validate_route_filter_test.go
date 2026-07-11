package config_test

// #2105 / #5576 — commit-time POSITION-AWARE validation for the
// policy-options route-filter slots. The `from route-filter <prefix>
// <match-type>` schema node is args:2 and uses a position-aware key
// validator (ValidateRouteFilterArgPositional): arg 0 (the prefix slot)
// must be a CIDR and arg 1 (the match-type slot) must be a supported
// match-type keyword. A match-type keyword in the CIDR slot, a CIDR in
// the match-type slot, or a malformed prefix is REJECTED at commit — the
// pre-#5576 position-agnostic validator accepted the union in either
// slot, so `route-filter longer exact` committed as a match-none policy
// (silent false-deny).
//
// Tests exercise both AST shapes: the flat-set path (ParseSetCommand +
// SetPath, via flatSchemaCheck) — the project-mandated route for flat
// set syntax — and the hierarchical brace path (schemaCheck).

import (
	"strings"
	"testing"
)

const rfSetPrefix = "set policy-options policy-statement P term T from route-filter "

// TestSchemaValidate_RouteFilter_AcceptsValid confirms every match-type
// with a well-formed v4/v6 prefix is accepted at commit. This is the
// control that proves the validator does not falsely reject the
// match-type keyword (which shares the keyValidator with the prefix
// slot) or a legitimate prefix.
func TestSchemaValidate_RouteFilter_AcceptsValid(t *testing.T) {
	accept := []string{
		rfSetPrefix + "10.0.0.0/24 exact",
		rfSetPrefix + "10.0.0.0/24 longer",
		rfSetPrefix + "10.0.0.0/24 orlonger",
		rfSetPrefix + "10.0.0.0/32 longer",
		rfSetPrefix + "0.0.0.0/0 orlonger",
		rfSetPrefix + "2001:db8::/32 exact",
		rfSetPrefix + "2001:db8::/32 orlonger",
		rfSetPrefix + "2001:db8::1/128 longer",
		// upto carries a trailing /N length token (a CHILD of the
		// route-filter node, so it does not reach the keyValidator).
		rfSetPrefix + "10.0.0.0/8 upto /24",
		rfSetPrefix + "2001:db8::/32 upto /48",
		// prefix-length-range and through are admitted as keywords
		// (#2105 Q4): they commit fine today and rejecting them would be
		// a grammar regression.
		rfSetPrefix + "10.0.0.0/24 prefix-length-range",
		rfSetPrefix + "10.0.0.0/24 through",
	}
	for _, cmd := range accept {
		if err := flatSchemaCheck(t, cmd); err != nil {
			t.Errorf("flat accept %q: unexpected error: %v", cmd, err)
		}
	}
}

// TestSchemaValidate_RouteFilter_RejectsMalformed confirms a malformed
// prefix is rejected at commit (commit-check). This is the #2105 hole:
// before the validator, these committed silently and reached the FRR
// renderer as garbage prefix-list lines that could fail the whole
// frr-reload.
func TestSchemaValidate_RouteFilter_RejectsMalformed(t *testing.T) {
	reject := []string{
		rfSetPrefix + "10.0.0.0 exact",      // no /prefix-length
		rfSetPrefix + "10.0.0.0/99 exact",   // mask out of range
		rfSetPrefix + "10.0.0.0/ab exact",   // non-numeric mask
		rfSetPrefix + "notanip exact",       // not an address
		rfSetPrefix + "10.0.0.0/24/8 exact", // double mask
		rfSetPrefix + "2001:db8:: orlonger", // v6 without /prefix-length
	}
	for _, cmd := range reject {
		err := flatSchemaCheck(t, cmd)
		if err == nil {
			t.Errorf("flat reject %q: expected commit-check error, got nil", cmd)
			continue
		}
		// The error must reference the route-filter leaf path so the
		// operator sees where the bad value is.
		if !strings.Contains(err.Error(), "route-filter") {
			t.Errorf("flat reject %q: error should reference route-filter: %v", cmd, err)
		}
	}
}

// TestSchemaValidate_RouteFilter_HierarchicalShape exercises the brace
// (hierarchical) AST path: a valid prefix accepts, a malformed prefix
// rejects. The compiler handles both shapes, so the validator must too.
func TestSchemaValidate_RouteFilter_HierarchicalShape(t *testing.T) {
	if err := schemaCheck(t, `policy-options {
    policy-statement P {
        term T {
            from {
                route-filter 10.0.0.0/24 orlonger;
                route-filter 2001:db8::/32 exact;
            }
            then accept;
        }
    }
}`); err != nil {
		t.Fatalf("hierarchical valid route-filters rejected: %v", err)
	}

	err := schemaCheck(t, `policy-options {
    policy-statement P {
        term T {
            from {
                route-filter 10.0.0.0 exact;
            }
            then accept;
        }
    }
}`)
	if err == nil {
		t.Fatal("hierarchical malformed prefix (no mask) must be rejected, got nil")
	}
	if !strings.Contains(err.Error(), "route-filter") {
		t.Errorf("hierarchical reject error should reference route-filter: %v", err)
	}
}

// TestSchemaValidate_RouteFilter_UptoLengthNotRejected locks the #2105
// Q5 edge: the upto /N length token lands as a CHILD of the
// route-filter node, NOT in the args:2 identity span, so it is never
// passed to the keyValidator and must not be falsely rejected. A bare
// length token in the PREFIX slot, however, is correctly rejected
// (it is neither a CIDR nor a match-type keyword).
func TestSchemaValidate_RouteFilter_UptoLengthNotRejected(t *testing.T) {
	if err := flatSchemaCheck(t, rfSetPrefix+"10.0.0.0/8 upto /24"); err != nil {
		t.Errorf("upto /24 length token must not be rejected: %v", err)
	}
	// A bare length-looking token in the prefix slot is NOT a valid CIDR
	// and NOT a match-type keyword → rejected.
	if err := flatSchemaCheck(t, rfSetPrefix+"24 exact"); err == nil {
		t.Error("a bare length token in the prefix slot must be rejected, got nil")
	}
}

// TestSchemaValidate_RouteFilter_PositionAware is the #5576 fail-on-revert
// guard. The validator is POSITION-AWARE, so a match-type keyword in the
// PREFIX (CIDR) slot — or a CIDR in the match-type slot — is REJECTED at
// commit rather than committed as a match-none policy (a silent
// false-deny). Before #5576 the validator accepted the union of CIDRs and
// match-type keywords in EITHER slot, so `route-filter longer exact`
// committed with `longer` in the CIDR slot; the FRR renderer then emitted
// no prefix-list entry but kept the route-map match, turning an authored
// accept into an operational match-none. Reverting the positional split
// makes the swapped/keyword-in-CIDR-slot forms commit clean again → this
// test fails RED.
func TestSchemaValidate_RouteFilter_PositionAware(t *testing.T) {
	// Each of these committed cleanly before #5576 (position-agnostic) and
	// rendered a match-none policy; they must now be rejected at commit.
	reject := []string{
		rfSetPrefix + "longer exact",            // match keyword in the CIDR slot (the #5576 bug)
		rfSetPrefix + "exact longer",            // two keywords, none a CIDR
		rfSetPrefix + "orlonger orlonger",       // keyword in both slots
		rfSetPrefix + "10.0.0.0/24 10.0.0.0/24", // CIDR in the match-type slot
		rfSetPrefix + "10.0.0.0/24 bogus",       // valid CIDR, but slot 2 is not a match-type
	}
	for _, cmd := range reject {
		err := flatSchemaCheck(t, cmd)
		if err == nil {
			t.Errorf("flat reject %q: expected commit-check error, got nil", cmd)
			continue
		}
		if !strings.Contains(err.Error(), "route-filter") {
			t.Errorf("flat reject %q: error should reference route-filter: %v", cmd, err)
		}
	}

	// The keyword-in-CIDR-slot form must reject in the hierarchical shape too.
	err := schemaCheck(t, `policy-options {
    policy-statement P {
        term T {
            from {
                route-filter longer exact;
            }
            then accept;
        }
    }
}`)
	if err == nil {
		t.Fatal("#5576: hierarchical `route-filter longer exact` (keyword in CIDR slot) must be rejected, got nil")
	}
	if !strings.Contains(err.Error(), "route-filter") {
		t.Errorf("hierarchical reject error should reference route-filter: %v", err)
	}

	// Every LEGITIMATE positional form still commits: bare CIDR + each
	// match-type, and the arg-carrying upto / prefix-length-range / through.
	accept := []string{
		rfSetPrefix + "10.0.0.0/24 exact",
		rfSetPrefix + "10.0.0.0/24 longer",
		rfSetPrefix + "10.0.0.0/24 orlonger",
		rfSetPrefix + "10.0.0.0/8 upto /24",
		rfSetPrefix + "10.0.0.0/8 prefix-length-range /16-/24",
		rfSetPrefix + "10.0.0.0/8 through 10.1.0.0/16",
		rfSetPrefix + "2001:db8::/32 orlonger",
		rfSetPrefix + "2001:db8::/32 upto /48",
	}
	for _, cmd := range accept {
		if err := flatSchemaCheck(t, cmd); err != nil {
			t.Errorf("flat accept %q: unexpected error: %v", cmd, err)
		}
	}
}
