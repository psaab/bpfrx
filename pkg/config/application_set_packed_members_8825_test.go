package config

import (
	"strings"
	"testing"
)

// #8825: `applications application-set <n> application <m>;` -- the brace-elided
// spelling -- compiled to a set with ZERO members while the braced form carried
// them, and the member was not even recorded in UnknownMembers.
//
// Same shape and same two-part remedy as #8800: `application-set` was declared
// args:1 children:nil, so its members were not schema children, the pass was
// never ASKED about the pairs, and no scope entry could have named them.
// Declaring alone is not sufficient -- the pairs must also be admitted.
//
// Found by the #8807 positional predicate, which is the class a keyword-anywhere
// check passes silently: `application` and `description` are declared under many
// other containers.
func TestApplicationSetPackedMembers8825(t *testing.T) {
	mk := func(body string) string {
		return "applications { application a1 { protocol tcp; destination-port 80; } " +
			"application a2 { protocol udp; destination-port 53; } " +
			"application-set inner { application a2; } " +
			"application-set " + body + " }"
	}
	members := func(t *testing.T, txt string) []string {
		t.Helper()
		tr, perrs := NewParser(txt).Parse()
		if len(perrs) > 0 {
			t.Fatalf("parse: %v", perrs)
		}
		cfg, err := CompileConfigLenient(tr)
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		s := cfg.Applications.ApplicationSets["as1"]
		if s == nil {
			return nil
		}
		return s.Applications
	}

	for _, tc := range []struct{ name, packed, braced string }{
		{"application", "as1 application a1;", "as1 { application a1; }"},
		{"nested-set", "as1 application-set inner;", "as1 { application-set inner; }"},
		{"bracket-list", "as1 application [ a1 a2 ];", "as1 { application [ a1 a2 ]; }"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, b := members(t, mk(tc.packed)), members(t, mk(tc.braced))
			if strings.Join(p, ",") != strings.Join(b, ",") {
				t.Errorf("packed and braced DIFFER for an application-set member (#8825)\n"+
					"  packed %q -> %v\n  braced %q -> %v\n"+
					"MEASURED, NOT DIAGNOSED. The #8825 cause was a MISSING SCHEMA "+
					"DECLARATION -- the members were not children of `application-set`, "+
					"so the brace-elision pass was never asked about the pair. A scope "+
					"entry alone cannot fix an undeclared head, and declaring alone was "+
					"measured insufficient on #8800.", tc.packed, p, tc.braced, b)
			}
			if len(p) == 0 {
				t.Errorf("packed %q compiled to a ZERO-member set -- the #8825 defect", tc.packed)
			}
		})
	}

	// `description` is NOT part of this fix and must stay inert. It is accepted
	// deliberately and ApplicationSet has no Description field, so the value
	// lands nowhere by design and both spellings must agree on EMPTY.
	t.Run("description-stays-inert", func(t *testing.T) {
		p, b := members(t, mk(`as1 description "x";`)), members(t, mk(`as1 { description "x"; }`))
		if len(p) != 0 || len(b) != 0 {
			t.Errorf("`description` produced members (packed=%v braced=%v); it is metadata "+
				"the compiler accepts without recording, and ApplicationSet has no "+
				"Description field. If that changed, this fix's scope changed with it.", p, b)
		}
	})

	// A TYPO'd member is unchanged by this fix and must stay that way: the
	// packed spelling does not reach the #3890 UnknownMembers arm (the fold only
	// fires for admitted pairs, and a typo is not one), so the set stays empty
	// and the #3146 gate rejects it LOUDLY when referenced. Measured against a
	// masked baseline: [] both before and after, so this is pre-existing and not
	// a regression introduced here.
	t.Run("typo-unchanged-and-still-empty", func(t *testing.T) {
		if got := members(t, mk("as1 applicaton a1;")); len(got) != 0 {
			t.Errorf("a typo'd packed member produced %v; it must leave the set EMPTY so "+
				"the #3146 empty-application-set gate still rejects it when referenced", got)
		}
	})
}
