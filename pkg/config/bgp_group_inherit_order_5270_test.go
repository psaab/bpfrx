package config

import "testing"

// #5270: BGP group inheritance must be sibling-ORDER-INDEPENDENT. A group's
// `neighbor` children and its group-level default attributes (export/import/
// peer-as/local-address/hold-time/…) are semantically-unordered Junos
// siblings. The compiler used to walk the group children ONCE and stamp each
// neighbor with whatever group defaults had been *seen so far*; a `neighbor`
// authored before the group's `export` therefore captured an empty Export →
// FRR emitted no outbound route-map → routes leaked (fail-open, not
// vSRX-equivalent). compiler_protocols.go now collects every group default in
// a first pass and stamps neighbors in a second pass, so encounter order no
// longer matters. Per-neighbor explicit values still override the inherited
// group default (unchanged precedence).
//
// These tests drive the flat-set path (ParseSetCommand + SetPath via
// buildTreeFromSet) per the CLAUDE.md set-syntax rule, plus one hierarchical
// (NewParser) variant. A policy-statement `OUT` is defined so the #2144 export
// reference validator accepts the `export OUT` used below.

func findBGPNeighbor5270(t *testing.T, c *Config, addr string) *BGPNeighbor {
	t.Helper()
	if c.Protocols.BGP == nil {
		t.Fatalf("Protocols.BGP is nil; expected a compiled BGP block")
	}
	for _, n := range c.Protocols.BGP.Neighbors {
		if n.Address == addr {
			return n
		}
	}
	t.Fatalf("neighbor %s not found among compiled neighbors", addr)
	return nil
}

func exportedPolicy5270() []string {
	return []string{
		"set policy-options policy-statement OUT term t1 from protocol direct",
		"set policy-options policy-statement OUT term t1 then accept",
	}
}

// PRIMARY RED-ON-REVERT ANCHOR (the bug case): a `neighbor` authored BEFORE
// the group's `export` must still inherit that export. The neighbor carries
// its own peer-as so the config compiles cleanly on BOTH the fixed and the
// (reverted) single-pass compiler — isolating Export as the tested attribute.
// Reverting to stamp-as-you-go leaves neighbor.Export empty here → RED.
func TestBGPGroupNeighborBeforeExportInherits_5270(t *testing.T) {
	cmds := append(exportedPolicy5270(),
		"set protocols bgp local-as 65001",
		"set protocols bgp group G neighbor 192.0.2.1 peer-as 65002",
		"set protocols bgp group G export OUT", // export AFTER the neighbor
	)
	c := compileSets3870(t, cmds)
	n := findBGPNeighbor5270(t, c, "192.0.2.1")
	if len(n.Export) != 1 || n.Export[0] != "OUT" {
		t.Fatalf("neighbor authored before group export did not inherit it: Export=%v, want [OUT] "+
			"(RED here means the order-dependent single-pass stamp is back)", n.Export)
	}
}

// Regression guard: the correctly-ordered config (export BEFORE neighbor) must
// keep working identically. This passed before #5270 and must still pass.
func TestBGPGroupExportBeforeNeighborInherits_5270(t *testing.T) {
	cmds := append(exportedPolicy5270(),
		"set protocols bgp local-as 65001",
		"set protocols bgp group G export OUT", // export BEFORE the neighbor
		"set protocols bgp group G neighbor 192.0.2.1 peer-as 65002",
	)
	c := compileSets3870(t, cmds)
	n := findBGPNeighbor5270(t, c, "192.0.2.1")
	if len(n.Export) != 1 || n.Export[0] != "OUT" {
		t.Fatalf("correctly-ordered group export not inherited: Export=%v, want [OUT]", n.Export)
	}
}

// Both encounter orders must compile to IDENTICAL neighbor state across
// several inherited attributes (export, peer-as, local-address, hold-time).
func TestBGPGroupInheritIdenticalBothOrders_5270(t *testing.T) {
	attrsFirst := append(exportedPolicy5270(),
		"set protocols bgp local-as 65001",
		"set protocols bgp group G peer-as 65002",
		"set protocols bgp group G local-address 10.0.0.9",
		"set protocols bgp group G hold-time 90",
		"set protocols bgp group G export OUT",
		"set protocols bgp group G neighbor 192.0.2.1",
	)
	neighborFirst := append(exportedPolicy5270(),
		"set protocols bgp local-as 65001",
		"set protocols bgp group G neighbor 192.0.2.1",
		"set protocols bgp group G peer-as 65002",
		"set protocols bgp group G local-address 10.0.0.9",
		"set protocols bgp group G hold-time 90",
		"set protocols bgp group G export OUT",
	)

	a := findBGPNeighbor5270(t, compileSets3870(t, attrsFirst), "192.0.2.1")
	b := findBGPNeighbor5270(t, compileSets3870(t, neighborFirst), "192.0.2.1")

	if len(a.Export) != 1 || a.Export[0] != "OUT" || len(b.Export) != 1 || b.Export[0] != "OUT" {
		t.Fatalf("Export differs by order: attrs-first=%v neighbor-first=%v, want both [OUT]", a.Export, b.Export)
	}
	if a.PeerAS != 65002 || b.PeerAS != 65002 {
		t.Fatalf("PeerAS differs by order: attrs-first=%d neighbor-first=%d, want both 65002", a.PeerAS, b.PeerAS)
	}
	if a.LocalAddress != "10.0.0.9" || b.LocalAddress != "10.0.0.9" {
		t.Fatalf("LocalAddress differs by order: attrs-first=%q neighbor-first=%q, want both 10.0.0.9", a.LocalAddress, b.LocalAddress)
	}
	if a.HoldTime != 90 || b.HoldTime != 90 {
		t.Fatalf("HoldTime differs by order: attrs-first=%d neighbor-first=%d, want both 90", a.HoldTime, b.HoldTime)
	}
}

// A per-neighbor explicit value must still beat the inherited group default,
// regardless of sibling order (unchanged override precedence). Uses hold-time
// (a scalar) as the overridden attribute; the neighbor also carries its own
// peer-as so both orders compile on a reverted single-pass compiler too.
func TestBGPNeighborOverrideBeatsGroupBothOrders_5270(t *testing.T) {
	groupFirst := []string{
		"set protocols bgp local-as 65001",
		"set protocols bgp group G hold-time 90",
		"set protocols bgp group G neighbor 192.0.2.1 peer-as 65002",
		"set protocols bgp group G neighbor 192.0.2.1 hold-time 30", // neighbor override
	}
	neighborFirst := []string{
		"set protocols bgp local-as 65001",
		"set protocols bgp group G neighbor 192.0.2.1 peer-as 65002",
		"set protocols bgp group G neighbor 192.0.2.1 hold-time 30", // neighbor override
		"set protocols bgp group G hold-time 90",                    // group default AFTER
	}
	for _, tc := range []struct {
		name string
		cmds []string
	}{
		{"group-first", groupFirst},
		{"neighbor-first", neighborFirst},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n := findBGPNeighbor5270(t, compileSets3870(t, tc.cmds), "192.0.2.1")
			if n.HoldTime != 30 {
				t.Fatalf("per-neighbor hold-time override lost: HoldTime=%d, want 30 (group default was 90)", n.HoldTime)
			}
		})
	}
}

// A neighbor authored BEFORE the group's peer-as must inherit it. On the
// reverted single-pass compiler the neighbor captures peer-as 0, which the
// #2963 strict gate rejects (remote-as 0) — so CompileConfig errors and
// compileSets3870 t.Fatalf's → RED. With the two-pass fix the neighbor
// inherits 65002 and the config compiles.
func TestBGPGroupNeighborBeforePeerASInherits_5270(t *testing.T) {
	cmds := []string{
		"set protocols bgp local-as 65001",
		"set protocols bgp group G neighbor 192.0.2.1", // neighbor FIRST, no own peer-as
		"set protocols bgp group G peer-as 65002",      // group peer-as AFTER
	}
	n := findBGPNeighbor5270(t, compileSets3870(t, cmds), "192.0.2.1")
	if n.PeerAS != 65002 {
		t.Fatalf("neighbor authored before group peer-as did not inherit it: PeerAS=%d, want 65002", n.PeerAS)
	}
}

// Hierarchical (block) AST shape: `neighbor` appears before `export` inside the
// group block; the neighbor must still inherit the export. Uses NewParser on a
// single well-formed hierarchical string (the flat-set-merge gotcha does not
// apply to a single hierarchical document).
func TestBGPGroupInheritOrderIndependentHierarchical_5270(t *testing.T) {
	input := `
policy-options {
    policy-statement OUT {
        term t1 {
            from protocol direct;
            then accept;
        }
    }
}
protocols {
    bgp {
        local-as 65001;
        group G {
            neighbor 192.0.2.1 {
                peer-as 65002;
            }
            export OUT;
        }
    }
}
`
	p := NewParser(input)
	tree, errs := p.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	c, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	n := findBGPNeighbor5270(t, c, "192.0.2.1")
	if len(n.Export) != 1 || n.Export[0] != "OUT" {
		t.Fatalf("hierarchical neighbor-before-export did not inherit export: Export=%v, want [OUT]", n.Export)
	}
	if n.PeerAS != 65002 {
		t.Fatalf("hierarchical neighbor peer-as = %d, want 65002", n.PeerAS)
	}
}
