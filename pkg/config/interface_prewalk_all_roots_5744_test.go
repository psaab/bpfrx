package config

import (
	"strings"
	"testing"
)

// Tests for #5744: two interface AST pre-walks — the unit-alias collision gate
// (validateInterfaceUnitAliasCollisionsAST, #5631) and the unsupported-stanza
// gate (validateUnsupportedInterfaceStanzasAST, #2008/#2354) — were still
// FIRST-ROOT-ONLY after PR #5741 routed the interface-range expansion and the
// stable-ID collision gates through all top-level roots. A hierarchical config
// can split its `interfaces { }` across TWO sibling roots (compileSections
// dispatches every one), so a collision or an unsupported stanza placed in the
// SECOND root bypassed these validators entirely.
//
// A split config with two top-level roots of the same stanza is a
// hierarchical-only shape: the flat-set path (ParseSetCommand + tree.SetPath)
// always MERGES `set interfaces …` onto ONE root, so these tests are authored
// through NewParser (the only shape that can express sibling roots) and each
// asserts the two-root precondition, mirroring the #5741
// compiler_multi_root_5675_5691_test.go pattern.
//
// FAIL-ON-REVERT: restoring either validator's first-root-only selection (a
// `for … break` on the first `interfaces` root) turns the second-root case
// GREEN and so RED here.

// TestUnitAliasCollisionSecondRootRejected_5744 — a numeric unit-alias collision
// (`unit 0` + `unit 00` collapsing to the same logical unit) living in the
// SECOND `interfaces` root is rejected at strict commit.
func TestUnitAliasCollisionSecondRootRejected_5744(t *testing.T) {
	input := `
interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet {
                address 10.0.0.1/24;
            }
        }
    }
}
interfaces {
    ge-0/0/1 {
        unit 0 {
            family inet {
                address 10.0.1.1/24;
            }
        }
        unit 00 {
            family inet {
                address 10.0.2.1/24;
            }
        }
    }
}
`
	tree, errs := NewParser(input).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	// Precondition: the split-root shape this guards actually exists.
	if got := len(tree.FindChildren("interfaces")); got != 2 {
		t.Fatalf("expected 2 top-level interfaces roots, got %d", got)
	}

	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatalf("expected strict commit to reject a unit-alias collision in the SECOND interfaces root")
	}
	if !strings.Contains(err.Error(), "same logical unit") || !strings.Contains(err.Error(), "ge-0/0/1") {
		t.Fatalf("error %q does not name the second-root unit-alias collision", err.Error())
	}
}

// TestUnsupportedStanzaSecondRootRejected_5744 — an unsupported interface stanza
// (a static `mac` override, H10) living in the SECOND `interfaces` root is
// flagged (strict: rejected) instead of being silently dropped at compile.
func TestUnsupportedStanzaSecondRootRejected_5744(t *testing.T) {
	input := `
interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet {
                address 10.0.0.1/24;
            }
        }
    }
}
interfaces {
    ge-0/0/1 {
        mac 00:11:22:33:44:55;
        unit 0 {
            family inet {
                address 10.0.1.1/24;
            }
        }
    }
}
`
	tree, errs := NewParser(input).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	if got := len(tree.FindChildren("interfaces")); got != 2 {
		t.Fatalf("expected 2 top-level interfaces roots, got %d", got)
	}

	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatalf("expected strict commit to reject an unsupported `mac` stanza in the SECOND interfaces root")
	}
	if !strings.Contains(err.Error(), "mac` override is not supported") || !strings.Contains(err.Error(), "ge-0/0/1") {
		t.Fatalf("error %q does not name the second-root unsupported stanza", err.Error())
	}
}

// TestUnsupportedStanzaSecondRootLenientWarns_5744 — the tolerant load /
// peer-sync path (#1960) downgrades the second-root unsupported stanza to a
// warning and still loads (no-brick), proving the all-roots walk feeds the
// lenient path too.
func TestUnsupportedStanzaSecondRootLenientWarns_5744(t *testing.T) {
	input := `
interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet {
                address 10.0.0.1/24;
            }
        }
    }
}
interfaces {
    ge-0/0/1 {
        unit 0 {
            inner-vlan-id 100;
            family inet {
                address 10.0.1.1/24;
            }
        }
    }
}
`
	tree, errs := NewParser(input).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	if got := len(tree.FindChildren("interfaces")); got != 2 {
		t.Fatalf("expected 2 top-level interfaces roots, got %d", got)
	}

	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile must not brick on a second-root unsupported stanza: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "inner-vlan-id") && strings.Contains(w, "ge-0/0/1") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("lenient compile must warn about the second-root unsupported stanza; warnings = %v", cfg.Warnings)
	}
}

// TestInterfacePrewalkSingleRootUnchanged_5744 pins no regression: a
// single-root config behaves identically — a collision / unsupported stanza in
// the ONLY root is still rejected, and a clean single/split config still
// compiles.
func TestInterfacePrewalkSingleRootUnchanged_5744(t *testing.T) {
	// Single-root collision still rejected.
	collide := `
interfaces {
    ge-0/0/1 {
        unit 0 {
            family inet { address 10.0.1.1/24; }
        }
        unit 00 {
            family inet { address 10.0.2.1/24; }
        }
    }
}
`
	tree, errs := NewParser(collide).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	if _, err := CompileConfig(tree); err == nil || !strings.Contains(err.Error(), "same logical unit") {
		t.Fatalf("single-root unit-alias collision must still be rejected, got err=%v", err)
	}

	// Clean split-root config compiles with no interface pre-walk error.
	clean := `
interfaces {
    ge-0/0/0 {
        unit 0 { family inet { address 10.0.0.1/24; } }
    }
}
interfaces {
    ge-0/0/1 {
        unit 0 { family inet { address 10.0.1.1/24; } }
    }
}
`
	tree2, errs2 := NewParser(clean).Parse()
	if len(errs2) > 0 {
		t.Fatalf("parse: %v", errs2)
	}
	if got := len(tree2.FindChildren("interfaces")); got != 2 {
		t.Fatalf("expected 2 top-level interfaces roots, got %d", got)
	}
	if _, err := CompileConfig(tree2); err != nil {
		t.Fatalf("clean split-root interfaces config must compile: %v", err)
	}
}
