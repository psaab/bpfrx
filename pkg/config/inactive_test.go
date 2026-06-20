package config

// Regression tests for #2008 H1 — Junos `inactive:` statement marker
// (deactivate without delete).
//
// Before this change `:` was an identifier character, so `inactive:` lexed
// as a single identifier token and became the node's first key
// (Keys[0] == "inactive:"). No compiler walk or schema gate matched that
// mangled key, so the node was SILENTLY dropped from compilation AND from
// every display path — the operator's reversible-deactivate intent was lost
// with no error.
//
// The tests below prove: the parser lifts `inactive:` into Node.Inactive
// (so the node's real Keys are intact), the node round-trips through every
// serializer, the compiler and the typed-leaf schema gate exclude it, the
// HA node-aware compile excludes it identically on both nodes, the on-disk
// JSON stays byte-identical for all-active trees, and `show | compare`
// surfaces a pure activate/deactivate.

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func mustParse(t *testing.T, src string) *ConfigTree {
	t.Helper()
	tree, errs := NewParser(src).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors for %q: %v", src, errs)
	}
	return tree
}

// --- Parser: marker lift + lone-marker error ---------------------------

func TestInactive_ParserLeafMarkerLifted(t *testing.T) {
	tree := mustParse(t, `interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet {
                inactive: address 192.168.50.210/24;
            }
        }
    }
}`)
	fam := tree.FindChild("interfaces").
		FindChild("ge-0/0/0").
		FindChild("unit").
		FindChild("family")
	addr := fam.FindChild("address")
	if addr == nil {
		t.Fatalf("address node not found; family children=%v", fam.Children)
	}
	if !addr.Inactive {
		t.Fatal("address node should be marked Inactive")
	}
	if got := addr.KeyPath(); got != "address 192.168.50.210/24" {
		t.Fatalf("inactive: marker leaked into Keys: %q", got)
	}
}

func TestInactive_ParserBlockMarkerLifted(t *testing.T) {
	tree := mustParse(t, `security {
    policies {
        from-zone trust to-zone untrust {
            inactive: policy long-ssh {
                match {
                    source-address any;
                    destination-address any;
                    application any;
                }
                then {
                    permit;
                }
            }
        }
    }
}`)
	pair := tree.FindChild("security").
		FindChild("policies").
		FindChild("from-zone")
	pol := pair.FindChild("policy")
	if pol == nil {
		t.Fatalf("policy node not found; pair children=%v", pair.Children)
	}
	if !pol.Inactive {
		t.Fatal("policy node should be marked Inactive")
	}
	if got := pol.KeyPath(); got != "policy long-ssh" {
		t.Fatalf("inactive: marker leaked into Keys: %q", got)
	}
	// Children must still parse normally.
	if pol.FindChild("then") == nil {
		t.Fatal("inactive block lost its children")
	}
}

func TestInactive_LoneMarkerIsParseError(t *testing.T) {
	for _, src := range []string{
		"system {\n inactive: ;\n}",
		"inactive:",
		"inactive: {\n host-name h;\n}",
	} {
		_, errs := NewParser(src).Parse()
		if len(errs) == 0 {
			t.Fatalf("expected parse error for lone marker %q, got none", src)
		}
		found := false
		for _, e := range errs {
			if strings.Contains(e.Message, "inactive") {
				found = true
			}
		}
		if !found {
			t.Fatalf("expected an inactive-marker error for %q, got %v", src, errs)
		}
	}
}

// TestInactive_LoneMarkerErrorPointsAtMarker verifies the lone-marker parse
// error is reported at the `inactive:` token itself, not at the following
// terminator (`;`/`{`/EOF). Regression for the position bug where
// markerLine/markerCol were captured from p.lexer.Peek() AFTER parseKeys()
// had already consumed the marker (PR #2042 Copilot review). The buggy parser
// reported columns 5/1/1 -> 12/1.../11; this pins the correct marker columns.
func TestInactive_LoneMarkerErrorPointsAtMarker(t *testing.T) {
	cases := []struct {
		src      string
		wantLine int
		wantCol  int
	}{
		// Marker followed by a `;` terminator (4-space indent -> column 5).
		{"system {\n    inactive: ;\n}", 2, 5},
		// Lone marker at EOF.
		{"inactive:", 1, 1},
		// Marker followed by a `{` block.
		{"inactive: {\n host-name h;\n}", 1, 1},
	}
	for _, tc := range cases {
		_, errs := NewParser(tc.src).Parse()
		var markerErr *ParseError
		for i := range errs {
			if strings.Contains(errs[i].Message, "inactive") {
				markerErr = &errs[i]
				break
			}
		}
		if markerErr == nil {
			t.Fatalf("expected an inactive-marker error for %q, got %v", tc.src, errs)
		}
		if markerErr.Line != tc.wantLine || markerErr.Column != tc.wantCol {
			t.Errorf("marker error position for %q = line %d col %d, want line %d col %d",
				tc.src, markerErr.Line, markerErr.Column, tc.wantLine, tc.wantCol)
		}
	}
}

// --- Round-trip through every serializer -------------------------------

func TestInactive_TextRoundTrip(t *testing.T) {
	src := `security {
    policies {
        from-zone trust to-zone untrust {
            inactive: policy p1 {
                then {
                    permit;
                }
            }
        }
    }
}`
	tree := mustParse(t, src)
	out := tree.Format()
	if !strings.Contains(out, "inactive: policy p1 {") {
		t.Fatalf("Format dropped inactive: prefix:\n%s", out)
	}
	// Re-parse the formatted output: the flag must survive a full round trip.
	reparsed := mustParse(t, out)
	pol := reparsed.FindChild("security").FindChild("policies").
		FindChild("from-zone").FindChild("policy")
	if pol == nil || !pol.Inactive {
		t.Fatalf("inactive flag lost on Format->parse round trip:\n%s", out)
	}
}

func TestInactive_LeafTextRoundTrip(t *testing.T) {
	src := "system {\n    inactive: host-name parked;\n}"
	tree := mustParse(t, src)
	out := tree.Format()
	if !strings.Contains(out, "inactive: host-name parked;") {
		t.Fatalf("Format dropped inactive: leaf prefix:\n%s", out)
	}
	reparsed := mustParse(t, out)
	hn := reparsed.FindChild("system").FindChild("host-name")
	if hn == nil || !hn.Inactive {
		t.Fatalf("inactive leaf flag lost on round trip:\n%s", out)
	}
}

func TestInactive_SetFormEmitsDeactivate(t *testing.T) {
	src := `security {
    policies {
        from-zone trust to-zone untrust {
            inactive: policy p1 {
                then {
                    permit;
                }
            }
        }
    }
}`
	tree := mustParse(t, src)
	out := tree.FormatSet()
	if !strings.Contains(out, "set security policies from-zone trust to-zone untrust policy p1 then permit") {
		t.Fatalf("FormatSet missing the set line:\n%s", out)
	}
	if !strings.Contains(out, "deactivate security policies from-zone trust to-zone untrust policy p1") {
		t.Fatalf("FormatSet missing the deactivate line:\n%s", out)
	}
}

func TestInactive_XMLAttribute(t *testing.T) {
	tree := mustParse(t, "system {\n    inactive: host-name h;\n}")
	out := tree.FormatXML()
	if !strings.Contains(out, `<host-name inactive="inactive">h</host-name>`) {
		t.Fatalf("FormatXML missing inactive attribute:\n%s", out)
	}
}

func TestInactive_JSONMarker(t *testing.T) {
	tree := mustParse(t, "system {\n    inactive: host-name h;\n}")
	out := tree.FormatJSON()
	if !strings.Contains(out, `"host-name h @inactive": "inactive"`) {
		t.Fatalf("FormatJSON missing inactive marker:\n%s", out)
	}
	// And it must be valid JSON.
	var obj map[string]interface{}
	if err := json.Unmarshal([]byte(out), &obj); err != nil {
		t.Fatalf("FormatJSON produced invalid JSON: %v\n%s", err, out)
	}
}

// --- Compile strip: inactive node is excluded --------------------------

func TestInactive_CompileExcludesPolicy(t *testing.T) {
	withInactive := mustParse(t, `security {
    policies {
        from-zone trust to-zone untrust {
            inactive: policy parked {
                match { source-address any; destination-address any; application any; }
                then { deny; }
            }
            policy live {
                match { source-address any; destination-address any; application any; }
                then { permit; }
            }
        }
    }
}`)
	cfg, err := CompileConfig(withInactive)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	names := policyNames(cfg)
	if contains(names, "parked") {
		t.Fatalf("inactive policy 'parked' must be excluded from compile; got %v", names)
	}
	if !contains(names, "live") {
		t.Fatalf("active sibling 'live' must compile; got %v", names)
	}

	// The compiled output must equal the active-only equivalent config.
	activeOnly := mustParse(t, `security {
    policies {
        from-zone trust to-zone untrust {
            policy live {
                match { source-address any; destination-address any; application any; }
                then { permit; }
            }
        }
    }
}`)
	cfgActive, err := CompileConfig(activeOnly)
	if err != nil {
		t.Fatalf("compile active-only: %v", err)
	}
	if !reflect.DeepEqual(cfg.Security.Policies, cfgActive.Security.Policies) {
		t.Fatalf("inactive-pruned config != active-only config:\n  with=%+v\n  active=%+v",
			cfg.Security.Policies, cfgActive.Security.Policies)
	}
}

// TestInactive_CompileDoesNotMutateInput proves the strip works on a clone
// — the caller's tree must retain the inactive node for display/persistence.
func TestInactive_CompileDoesNotMutateInput(t *testing.T) {
	tree := mustParse(t, `security {
    policies {
        from-zone trust to-zone untrust {
            inactive: policy parked {
                then { deny; }
            }
        }
    }
}`)
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("compile: %v", err)
	}
	pol := tree.FindChild("security").FindChild("policies").
		FindChild("from-zone").FindChild("policy")
	if pol == nil || !pol.Inactive {
		t.Fatal("compile mutated the caller's tree: inactive policy was removed")
	}
}

// --- Group interaction: inactive apply-groups suppresses inheritance ----

func TestInactive_ApplyGroupsSuppressed(t *testing.T) {
	// `inactive: apply-groups g` must NOT inherit g's content.
	withInactiveAG := mustParse(t, `groups {
    g {
        system { host-name from-group; }
    }
}
inactive: apply-groups g;
system { domain-name example.com; }`)
	cfg, err := CompileConfig(withInactiveAG)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if cfg.System.HostName == "from-group" {
		t.Fatal("inactive apply-groups must not inherit the group's host-name")
	}

	// Sanity: an ACTIVE apply-groups DOES inherit.
	withActiveAG := mustParse(t, `groups {
    g {
        system { host-name from-group; }
    }
}
apply-groups g;
system { domain-name example.com; }`)
	cfgActive, err := CompileConfig(withActiveAG)
	if err != nil {
		t.Fatalf("compile active apply-groups: %v", err)
	}
	if cfgActive.System.HostName != "from-group" {
		t.Fatalf("active apply-groups should inherit host-name, got %q", cfgActive.System.HostName)
	}
}

// --- Schema-validate: deactivated invalid leaf commits clean -----------

func TestInactive_SchemaValidateSkipsInactiveLeaf(t *testing.T) {
	// An ACTIVE bad transmit-rate must be rejected by the typed-leaf gate.
	active := mustParse(t, `class-of-service {
    schedulers { s { transmit-rate garbage; } }
}`)
	if err := SchemaValidate(active, nil); err == nil {
		t.Fatal("expected schema rejection for active bad transmit-rate")
	}

	// The SAME bad value, deactivated, must pass (Junos parks WIP).
	inactive := mustParse(t, `class-of-service {
    schedulers { s { inactive: transmit-rate garbage; } }
}`)
	if err := SchemaValidate(inactive, nil); err != nil {
		t.Fatalf("deactivated bad transmit-rate should commit clean, got: %v", err)
	}
}

// --- On-disk compatibility: omitempty keeps active trees byte-identical -

func TestInactive_JSONStructOmitemptyForActive(t *testing.T) {
	// A node with Inactive=false must NOT emit an "Inactive" key — the
	// persisted DB format (json.Marshal of *Node) stays byte-identical to
	// pre-#2008 for all-active configs.
	n := &Node{Keys: []string{"host-name", "h"}, IsLeaf: true}
	data, err := json.Marshal(n)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(data), "Inactive") {
		t.Fatalf("active node leaked Inactive key: %s", data)
	}

	// An inactive node DOES carry the flag, and it survives a marshal round
	// trip (the persistence path is json.Marshal/Unmarshal of the tree).
	ni := &Node{Keys: []string{"host-name", "h"}, IsLeaf: true, Inactive: true}
	data, err = json.Marshal(ni)
	if err != nil {
		t.Fatalf("marshal inactive: %v", err)
	}
	var back Node
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !back.Inactive {
		t.Fatalf("Inactive flag lost on JSON round trip: %s", data)
	}
}

// --- Upgrade equivalence: old mangled form vs new flag form ------------

func TestInactive_UpgradeEquivalence(t *testing.T) {
	// New behavior: parsed `inactive:` -> Inactive flag -> stripped.
	newForm := mustParse(t, `security {
    policies {
        from-zone trust to-zone untrust {
            inactive: policy parked { then { deny; } }
        }
    }
}`)
	cfgNew, err := CompileConfig(newForm)
	if err != nil {
		t.Fatalf("compile new form: %v", err)
	}

	// Old behavior simulated: the mangled node with Keys[0]=="inactive:"
	// that no compiler walk matched -> excluded all the same.
	oldForm := &ConfigTree{Children: []*Node{{
		Keys: []string{"security"}, Children: []*Node{{
			Keys: []string{"policies"}, Children: []*Node{{
				Keys: []string{"from-zone", "trust", "to-zone", "untrust"},
				Children: []*Node{{
					Keys: []string{"inactive:", "policy", "parked"},
					Children: []*Node{{
						Keys: []string{"then"}, Children: []*Node{{
							Keys: []string{"deny"}, IsLeaf: true,
						}},
					}},
				}},
			}},
		}},
	}}}
	cfgOld, err := CompileConfig(oldForm)
	if err != nil {
		t.Fatalf("compile old form: %v", err)
	}
	if !reflect.DeepEqual(cfgNew.Security.Policies, cfgOld.Security.Policies) {
		t.Fatalf("upgrade changed compiled output:\n new=%+v\n old=%+v",
			cfgNew.Security.Policies, cfgOld.Security.Policies)
	}
}

// --- Dual-AST: flat-set path round-trips the deactivate -----------------

func TestInactive_DualASTFlatSet(t *testing.T) {
	// Build the active tree via the flat-set authoring path (CLAUDE.md:
	// ALWAYS ParseSetCommand+SetPath for flat-set, never NewParser).
	tree := &ConfigTree{}
	for _, cmd := range []string{
		"set security policies from-zone trust to-zone untrust policy p1 then permit",
	} {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	// Deactivate the policy node (the deactivate verb flips the flag on the
	// node the set path created). Locate and mark it.
	pol := tree.FindChild("security").FindChild("policies").
		FindChild("from-zone").FindChild("policy")
	if pol == nil {
		t.Fatalf("flat-set did not create the policy node: %+v", tree.Children)
	}
	pol.Inactive = true

	// Compile excludes it.
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if contains(policyNames(cfg), "p1") {
		t.Fatal("deactivated flat-set policy must be excluded from compile")
	}

	// FormatSet round trips through a deactivate line.
	out := tree.FormatSet()
	if !strings.Contains(out, "deactivate security policies from-zone trust to-zone untrust policy p1") {
		t.Fatalf("flat-set deactivate line missing:\n%s", out)
	}
}

// --- HA: both nodes compile the same active set ------------------------

func TestInactive_HABothNodesExcludeSame(t *testing.T) {
	tree := mustParse(t, `security {
    policies {
        from-zone trust to-zone untrust {
            inactive: policy parked { then { deny; } }
            policy live { match { source-address any; destination-address any; application any; } then { permit; } }
        }
    }
}`)
	cfg0, err := CompileConfigForNode(tree, 0)
	if err != nil {
		t.Fatalf("compile node 0: %v", err)
	}
	cfg1, err := CompileConfigForNode(tree, 1)
	if err != nil {
		t.Fatalf("compile node 1: %v", err)
	}
	for _, c := range []*Config{cfg0, cfg1} {
		names := policyNames(c)
		if contains(names, "parked") {
			t.Fatalf("inactive policy live on a node: %v", names)
		}
		if !contains(names, "live") {
			t.Fatalf("active policy missing on a node: %v", names)
		}
	}
}

// --- Compare: pure activate/deactivate shows as a diff -----------------

func TestInactive_CompareShowsDeactivate(t *testing.T) {
	active := mustParse(t, `system {
    host-name h;
}`)
	deactivated := mustParse(t, `system {
    inactive: host-name h;
}`)
	out := FormatCompare(active, deactivated)
	if out == "" {
		t.Fatal("a pure deactivate must show as a diff, got empty compare")
	}
	if !strings.Contains(out, "inactive: host-name h") {
		t.Fatalf("compare did not surface the deactivate:\n%s", out)
	}
	// And nodesEqual must report them as different.
	a := active.FindChild("system").FindChild("host-name")
	d := deactivated.FindChild("system").FindChild("host-name")
	if nodesEqual(a, d) {
		t.Fatal("nodesEqual treated active vs inactive as equal")
	}
}

// --- helpers -----------------------------------------------------------

func policyNames(cfg *Config) []string {
	var names []string
	for _, zp := range cfg.Security.Policies {
		for _, p := range zp.Policies {
			names = append(names, p.Name)
		}
	}
	return names
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}
