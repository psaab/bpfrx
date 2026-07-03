package config

import (
	"strings"
	"testing"
)

// #3843: a firewall-filter term with a HIERARCHICAL single-name
// `source-prefix-list <name>;` / `destination-prefix-list <name>;` leaf (the
// shape produced by `load merge` / a config file, where the name rides on
// child.Keys[1] with ZERO children) had its scoping constraint SILENTLY DROPPED
// — compileFilterFrom iterated only child.Children and never read child.Keys[1].
// The term then compiled UNSCOPED (implicit match-all) and passed strict commit
// cleanly, a HIGH fail-open. This is the #2419 dual-AST-shape class on the
// prefix-list-ref leaf (distinct from the #2506 dataplane-snapshot resolver).
//
// Fail-on-revert: firewallPrefixListRefs now reads BOTH child.Keys[1:] (the
// single-name leaf) AND child.Children (block / flat-set). Reverting that helper
// to a child.Children-only iteration makes every assertion below go RED — the
// scoped refs vanish and the undefined-reference reject disappears (the term
// silently becomes match-all).

// compileParsedHier parses a HIERARCHICAL config text (the load-merge /
// config-file shape, NOT flat-set) and compiles it. The #3843 bug-triggering
// AST — a single-name `source-prefix-list plX;` leaf carrying the name on
// child.Keys[1] with no children — is ONLY produced by NewParser, so the test
// MUST use the parser, never ParseSetCommand/SetPath (which yields a child node).
func compileParsedHier(t *testing.T, text string) (*Config, error) {
	t.Helper()
	parser := NewParser(text)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	return CompileConfig(tree)
}

func TestPrefixListHierSingleNameSourceScoped3843(t *testing.T) {
	cfg, err := compileParsedHier(t, `policy-options {
    prefix-list plX {
        10.1.0.0/16;
    }
}
firewall {
    family inet {
        filter f {
            term t {
                from {
                    source-prefix-list plX;
                }
                then discard;
            }
        }
    }
}`)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	term := cfg.Firewall.FiltersInet["f"].Terms[0]
	if len(term.SourcePrefixLists) != 1 || term.SourcePrefixLists[0].Name != "plX" {
		t.Fatalf("hierarchical single-name source-prefix-list scope DROPPED "+
			"(fail-open — term became match-all): got %#v, want one ref to plX",
			term.SourcePrefixLists)
	}
	if term.SourcePrefixLists[0].Except {
		t.Error("except must be false for a clean single-name leaf")
	}
}

func TestPrefixListHierSingleNameSourceExcept3843(t *testing.T) {
	cfg, err := compileParsedHier(t, `policy-options {
    prefix-list plX {
        10.1.0.0/16;
    }
}
firewall {
    family inet {
        filter f {
            term t {
                from {
                    source-prefix-list plX except;
                }
                then accept;
            }
        }
    }
}`)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	term := cfg.Firewall.FiltersInet["f"].Terms[0]
	if len(term.SourcePrefixLists) != 1 || term.SourcePrefixLists[0].Name != "plX" {
		t.Fatalf("single-name source-prefix-list except scope DROPPED: got %#v, want one ref to plX",
			term.SourcePrefixLists)
	}
	if !term.SourcePrefixLists[0].Except {
		t.Error("except modifier lost on the single-name leaf")
	}
}

func TestPrefixListHierSingleNameDestScoped3843(t *testing.T) {
	cfg, err := compileParsedHier(t, `policy-options {
    prefix-list plY {
        2001:db8::/32;
    }
}
firewall {
    family inet6 {
        filter f6 {
            term t {
                from {
                    destination-prefix-list plY;
                }
                then discard;
            }
        }
    }
}`)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	term := cfg.Firewall.FiltersInet6["f6"].Terms[0]
	if len(term.DestPrefixLists) != 1 || term.DestPrefixLists[0].Name != "plY" {
		t.Fatalf("hierarchical single-name destination-prefix-list scope DROPPED "+
			"(fail-open): got %#v, want one ref to plY", term.DestPrefixLists)
	}
	if term.DestPrefixLists[0].Except {
		t.Error("except must be false for a clean single-name leaf")
	}
}

// TestPrefixListHierSingleNameUndefinedRejected3843 is the strongest fail-open
// witness: before #3843 the single-name leaf's name was dropped entirely, so a
// term referencing an UNDEFINED prefix-list carried no ref, the strict gate had
// nothing to check, and the term committed cleanly as match-all. With the fix
// the ref survives and validateFirewallPrefixListReferencesStrict rejects it.
func TestPrefixListHierSingleNameUndefinedRejected3843(t *testing.T) {
	_, err := compileParsedHier(t, `firewall {
    family inet {
        filter f {
            term t {
                from {
                    source-prefix-list ghost;
                }
                then accept;
            }
        }
    }
}`)
	if err == nil {
		t.Fatal("undefined single-name source-prefix-list must be REJECTED at commit; " +
			"pre-#3843 the scope was silently dropped so the term became match-all and " +
			"committed cleanly (fail-open)")
	}
	if !strings.Contains(err.Error(), "undefined source-prefix-list") ||
		!strings.Contains(err.Error(), "ghost") {
		t.Fatalf("error = %v, want it to name the undefined source-prefix-list ghost", err)
	}
}

// TestPrefixListShapesStillWork3843 locks in that the flat-set and hierarchical
// block shapes (which already worked via child.Children) keep scoping correctly
// after the helper rewrite.
func TestPrefixListShapesStillWork3843(t *testing.T) {
	// Flat-set shape (child node per name).
	flat := buildTree(t, []string{
		"set policy-options prefix-list mgmt 10.0.0.0/8",
		"set firewall family inet filter ff term t from source-prefix-list mgmt except",
		"set firewall family inet filter ff term t then discard",
	})
	cfg, err := CompileConfig(flat)
	if err != nil {
		t.Fatalf("flat-set compile: %v", err)
	}
	term := cfg.Firewall.FiltersInet["ff"].Terms[0]
	if len(term.SourcePrefixLists) != 1 || term.SourcePrefixLists[0].Name != "mgmt" ||
		!term.SourcePrefixLists[0].Except {
		t.Fatalf("flat-set source-prefix-list ref = %#v, want one except ref to mgmt", term.SourcePrefixLists)
	}

	// Hierarchical block shape (two positive names; mixing a positive and an
	// `except` prefix-list in one direction is the #3359 mutex, rejected).
	cfg, err = compileParsedHier(t, `policy-options {
    prefix-list pl1 { 10.0.0.0/8; }
    prefix-list pl2 { 172.16.0.0/12; }
}
firewall {
    family inet {
        filter fb {
            term t {
                from {
                    source-prefix-list {
                        pl1;
                        pl2;
                    }
                }
                then discard;
            }
        }
    }
}`)
	if err != nil {
		t.Fatalf("block-form compile: %v", err)
	}
	term = cfg.Firewall.FiltersInet["fb"].Terms[0]
	if len(term.SourcePrefixLists) != 2 {
		t.Fatalf("block-form refs = %#v, want two", term.SourcePrefixLists)
	}
	if term.SourcePrefixLists[0].Name != "pl1" || term.SourcePrefixLists[0].Except {
		t.Errorf("block-form ref[0] = %#v, want pl1 no-except", term.SourcePrefixLists[0])
	}
	if term.SourcePrefixLists[1].Name != "pl2" || term.SourcePrefixLists[1].Except {
		t.Errorf("block-form ref[1] = %#v, want pl2 no-except", term.SourcePrefixLists[1])
	}
}
