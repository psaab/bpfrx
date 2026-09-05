package config

import (
	"strings"
	"testing"
)

// Issue 8867: SchemaValidate walked the UN-NORMALIZED tree, so a typed leaf
// authored in the packed spelling reached commit with no validation at all.
// The compiler normalizes the same pairs and therefore COMPILES their values,
// so the value took effect while its validator never ran.
//
// Measured before the fix, over the validator-bearing typed leaves reachable at
// a pair admitted to compactNormalizeInScope:
//
//	161 leaves: 146 rejected braced and ACCEPTED packed, 15 validated on both
//
// The 15 are why this is a claim about the packed path and not about
// validation in general.

// packedValidation8867 pairs a braced spelling with the packed spelling of the
// same statement. Both must reach the same verdict.
type packedValidation8867 struct {
	name      string
	braced    string
	packed    string
	badValue  string
	goodValue string
}

func packedValidationCases8867() []packedValidation8867 {
	return []packedValidation8867{
		{
			name:      "cos scheduler transmit-rate",
			braced:    "class-of-service { schedulers { be { transmit-rate %s; } } }",
			packed:    "class-of-service { schedulers be transmit-rate %s; }",
			badValue:  "asd",
			goodValue: "1g",
		},
		{
			name:      "cos scheduler priority",
			braced:    "class-of-service { schedulers { be { priority %s; } } }",
			packed:    "class-of-service { schedulers be priority %s; }",
			badValue:  "foo",
			goodValue: "high",
		},
		{
			name:      "applications inactivity-timeout",
			braced:    "applications { application a1 { inactivity-timeout %s; } }",
			packed:    "applications { application a1 inactivity-timeout %s; }",
			badValue:  "notanumber",
			goodValue: "300",
		},
	}
}

func TestPackedSpellingIsValidated8867(t *testing.T) {
	check := func(t *testing.T, text string) error {
		t.Helper()
		tree, perrs := NewParser(text).Parse()
		if len(perrs) > 0 {
			t.Fatalf("fixture does not parse (%q): %v", text, perrs[0])
		}
		cfg, _ := CompileConfigLenient(tree)
		tree2, _ := NewParser(text).Parse()
		return SchemaValidate(tree2, cfg)
	}

	for _, c := range packedValidationCases8867() {
		t.Run(c.name, func(t *testing.T) {
			// The braced arm is the reference. If it ever stopped rejecting,
			// the packed assertion below would be measuring nothing.
			if err := check(t, strings.Replace(c.braced, "%s", c.badValue, 1)); err == nil {
				t.Fatalf("braced reference ACCEPTS %q — the packed comparison is vacuous", c.badValue)
			}
			if err := check(t, strings.Replace(c.packed, "%s", c.badValue, 1)); err == nil {
				t.Errorf("packed spelling accepts %q that the braced spelling rejects — the commit gate is bypassable by spelling", c.badValue)
			}
			// NON-VACUITY: the gate must still accept a VALID value in the
			// packed spelling. A fix that rejected everything packed would
			// satisfy the assertion above and break the product.
			if err := check(t, strings.Replace(c.packed, "%s", c.goodValue, 1)); err != nil {
				t.Errorf("packed spelling REJECTS the valid value %q: %v", c.goodValue, err)
			}
		})
	}
}

// SchemaValidate runs on the operator's candidate tree, which the caller
// persists. Folding compact stanzas to validate them must therefore happen on a
// copy: normalizing in place would rewrite the stored configuration as a side
// effect of checking it, silently changing what `show configuration` renders.
func TestValidationDoesNotMutateCallerTree8867(t *testing.T) {
	const text = "class-of-service { schedulers be transmit-rate 1g; }"
	tree, perrs := NewParser(text).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs[0])
	}
	before := tree.Format()
	if !strings.Contains(before, "schedulers be transmit-rate") {
		t.Fatalf("fixture is not packed as intended: %q", before)
	}
	if err := SchemaValidate(tree, nil); err != nil {
		t.Fatalf("valid packed statement rejected: %v", err)
	}
	if after := tree.Format(); after != before {
		t.Errorf("SchemaValidate MUTATED the caller's tree.\n before: %q\n after:  %q", before, after)
	}
}
