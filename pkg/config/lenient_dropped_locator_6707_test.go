package config

import (
	"strings"
	"testing"
)

// #6707: LenientDroppedPolicyLocator is the local proof that a config cannot
// become the running dataplane snapshot. Its consumers gate operator actions on
// it, so a shape it fails to walk is a shape that slips the gate.
//
// The fixtures are compiled by the REAL tolerant compiler rather than hand-set
// struct literals. LenientContentDropped is set by compilePolicy from three
// AST predicates; a literal `&Policy{LenientContentDropped: true}` would prove
// only that the field can be read, not that the production path that sets it is
// the one this locator sees.
//
// FAIL-ON-REVERT: delete the GlobalPolicies loop and the global cell reds;
// delete the zone-pair loop and the zone-pair cell reds.

func lenientCfg6707(t *testing.T, text string) *Config {
	t.Helper()
	tree, perrs := NewParser(text).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs)
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}
	return cfg
}

const zonePairPoisoned6707 = `security {
  policies {
    from-zone trust to-zone untrust {
      policy zp-bad {
        then { permit; }
      }
    }
  }
}`

const globalPoisoned6707 = `security {
  policies {
    global {
      policy g-bad {
        then { permit; }
      }
    }
  }
}`

const zonePairClean6707 = `security {
  policies {
    from-zone trust to-zone untrust {
      policy zp-ok {
        match { source-address any; destination-address any; application any; }
        then { permit; }
      }
    }
  }
}`

func TestLenientDroppedPolicyLocatorWalksBothPolicyShapes6707(t *testing.T) {
	for _, tc := range []struct {
		name     string
		text     string
		wantHit  bool
		wantName string
	}{
		{"zone-pair-poisoned", zonePairPoisoned6707, true, "zp-bad"},
		{"global-poisoned", globalPoisoned6707, true, "g-bad"},
		{"zone-pair-clean", zonePairClean6707, false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := lenientCfg6707(t, tc.text)

			// Premise: the REAL compiler set (or did not set) the poison. Without
			// this a locator that always returns "" would pass the clean cell and
			// the poisoned cells would be failing for the wrong reason.
			poisoned := false
			for _, zpp := range cfg.Security.Policies {
				for _, p := range zpp.Policies {
					poisoned = poisoned || p.LenientContentDropped
				}
			}
			for _, p := range cfg.Security.GlobalPolicies {
				poisoned = poisoned || p.LenientContentDropped
			}
			if poisoned != tc.wantHit {
				t.Fatalf("premise broken: compiled LenientContentDropped = %v, want %v — "+
					"the fixture does not exercise what this cell claims to measure",
					poisoned, tc.wantHit)
			}

			got := LenientDroppedPolicyLocator(cfg)
			if !tc.wantHit {
				if got != "" {
					t.Fatalf("locator = %q for a clean config, want \"\" — a false positive "+
						"here refuses a `commit confirmed` the operator is entitled to", got)
				}
				return
			}
			if got == "" {
				t.Fatalf("locator = \"\" for a poisoned %s config; the gate built on it "+
					"would arm a rollback timer whose target the dataplane refuses", tc.name)
			}
			if !strings.Contains(got, tc.wantName) {
				t.Errorf("locator = %q, want it to name policy %q so the operator can find "+
					"the offending rule", got, tc.wantName)
			}
		})
	}
}

func TestLenientDroppedPolicyLocatorNilConfig6707(t *testing.T) {
	if got := LenientDroppedPolicyLocator(nil); got != "" {
		t.Fatalf("locator(nil) = %q, want \"\"", got)
	}
}
