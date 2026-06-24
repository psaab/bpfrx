package config

import (
	"strings"
	"testing"
)

// #2144: routing export references (protocols ospf/bgp/ospf3/isis export,
// rip redistribute, bgp group/neighbor export, routing-options
// forwarding-table export) must be validated at commit against the defined
// policy-statement set and the known redistribution protocol tokens. A typo
// otherwise passes commit and fails OPEN at FRR render time (rejected
// reload, silent no-op, permit-all route-map, or silently-disabled ECMP).
//
// These tests drive the real CompileConfig (strict) / CompileConfigLenient
// (tolerant) paths via buildTreeFromSet (the flat-set helper shared with
// ipsec_proposal_ref_test.go).

// --- redistribute-backed exports: OSPF / OSPFv3 / BGP / IS-IS export,
// RIP redistribute. Accept a known protocol token OR a defined
// policy-statement; reject anything else. ---

func TestOSPFExportTypoRejected(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set protocols ospf area 0.0.0.0 interface ge-0-0-0",
		"set protocols ospf export EXPORT-POLCIY", // typo
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig accepted protocols ospf export with a dangling/typo reference; expected rejection")
	}
	for _, want := range []string{"ospf", "EXPORT-POLCIY", "policy-statement"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q missing %q", err.Error(), want)
		}
	}
}

func TestOSPFExportKnownProtocolAccepted(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set protocols ospf area 0.0.0.0 interface ge-0-0-0",
		"set protocols ospf export static",
		"set protocols ospf export connected",
		"set protocols ospf export direct",
	})
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("CompileConfig rejected bare protocol-token OSPF exports: %v", err)
	}
}

func TestOSPFExportDefinedPolicyAccepted(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set policy-options policy-statement EXPORT-DIRECT term t1 from protocol direct",
		"set policy-options policy-statement EXPORT-DIRECT term t1 then accept",
		"set protocols ospf area 0.0.0.0 interface ge-0-0-0",
		"set protocols ospf export EXPORT-DIRECT",
	})
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("CompileConfig rejected a defined policy-statement OSPF export: %v", err)
	}
}

func TestBGPExportTypoRejected(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set protocols bgp local-as 65001",
		"set protocols bgp export NO-SUCH-POLICY",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig accepted protocols bgp export with a dangling reference; expected rejection")
	}
	if !strings.Contains(err.Error(), "NO-SUCH-POLICY") {
		t.Errorf("error %q missing dangling export name", err.Error())
	}
}

func TestRIPRedistributeTypoRejected(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set protocols rip group g1 neighbor ge-0-0-0",
		"set protocols rip group g1 export RIP-TYPO",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig accepted a RIP redistribute typo; expected rejection")
	}
	if !strings.Contains(err.Error(), "RIP-TYPO") {
		t.Errorf("error %q missing dangling RIP export name", err.Error())
	}
}

func TestISISExportTypoRejected(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set protocols isis interface ge-0-0-0",
		"set protocols isis export ISIS-TYPO",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig accepted an IS-IS export typo; expected rejection")
	}
	if !strings.Contains(err.Error(), "ISIS-TYPO") {
		t.Errorf("error %q missing dangling IS-IS export name", err.Error())
	}
}

func TestOSPFv3ExportTypoRejected(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set protocols ospf3 area 0.0.0.0 interface ge-0-0-0",
		"set protocols ospf3 export V3-TYPO",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig accepted an OSPFv3 export typo; expected rejection")
	}
	if !strings.Contains(err.Error(), "V3-TYPO") {
		t.Errorf("error %q missing dangling OSPFv3 export name", err.Error())
	}
}

// --- BGP group/neighbor export: renders `route-map <name> out`. A protocol
// token is NOT a valid route-map name here — only a defined policy-statement
// is accepted (a dangling route-map name fails open to permit-all in FRR). ---

func TestBGPNeighborExportTypoRejected(t *testing.T) {
	// export precedes neighbor: the group-export value is collected as the
	// group's children are walked in order, then stamped onto each neighbor
	// created afterward (mirrors TestBGPGroupExportFamily).
	tree := buildTreeFromSet(t, []string{
		"set protocols bgp local-as 65001",
		"set protocols bgp group ebgp peer-as 65002",
		"set protocols bgp group ebgp export OUT-TYPO",
		"set protocols bgp group ebgp neighbor 10.0.2.1",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig accepted a BGP group/neighbor export with a dangling route-map; expected rejection")
	}
	for _, want := range []string{"OUT-TYPO", "policy-statement", "10.0.2.1"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q missing %q", err.Error(), want)
		}
	}
}

func TestBGPNeighborExportProtocolTokenRejected(t *testing.T) {
	// A bare protocol token ("static") is a legitimate redistribute-backed
	// export at the BGP top level but NOT at a neighbor, where it renders as
	// a route-map name. It must be rejected as an undefined policy-statement.
	tree := buildTreeFromSet(t, []string{
		"set protocols bgp local-as 65001",
		"set protocols bgp group ebgp peer-as 65002",
		"set protocols bgp group ebgp export static",
		"set protocols bgp group ebgp neighbor 10.0.2.1",
	})
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("CompileConfig accepted a protocol token as a BGP neighbor route-map name; expected rejection")
	}
}

func TestBGPNeighborExportDefinedPolicyAccepted(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set policy-options policy-statement OUT-POL term t1 then accept",
		"set protocols bgp local-as 65001",
		"set protocols bgp group ebgp peer-as 65002",
		"set protocols bgp group ebgp export OUT-POL",
		"set protocols bgp group ebgp neighbor 10.0.2.1",
	})
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("CompileConfig rejected a defined BGP neighbor export policy: %v", err)
	}
}

// --- BGP group/neighbor import (#2490): renders `route-map <name> in`.
// Inbound filtering is route-map-only — there is NO redistribute equivalent —
// so an import ref MUST be a defined policy-statement. An undefined/bare-token
// ref would render a dangling `route-map in` that FRR resolves to permit-all,
// accepting every inbound advertisement (the #2473 lesson, inbound side). ---

func TestBGPNeighborImportParsed(t *testing.T) {
	// Prove the Junos `import` clause is parsed onto the neighbor struct
	// (before #2490 it parsed to nothing — a silent no-op).
	tree := buildTreeFromSet(t, []string{
		"set policy-options policy-statement IN-POL term t1 then accept",
		"set protocols bgp local-as 65001",
		"set protocols bgp group ebgp peer-as 65002",
		"set protocols bgp group ebgp import IN-POL",
		"set protocols bgp group ebgp neighbor 10.0.2.1",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig rejected a defined BGP import policy: %v", err)
	}
	if cfg.Protocols.BGP == nil || len(cfg.Protocols.BGP.Neighbors) != 1 {
		t.Fatalf("expected one BGP neighbor, got %+v", cfg.Protocols.BGP)
	}
	n := cfg.Protocols.BGP.Neighbors[0]
	found := false
	for _, im := range n.Import {
		if im == "IN-POL" {
			found = true
		}
	}
	if !found {
		t.Errorf("import clause not parsed onto neighbor; got Import=%v", n.Import)
	}
}

func TestBGPNeighborImportTypoRejected(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set protocols bgp local-as 65001",
		"set protocols bgp group ebgp peer-as 65002",
		"set protocols bgp group ebgp import IN-TYPO",
		"set protocols bgp group ebgp neighbor 10.0.2.1",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig accepted a BGP import with a dangling route-map; expected rejection")
	}
	for _, want := range []string{"IN-TYPO", "policy-statement", "import", "10.0.2.1"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q missing %q", err.Error(), want)
		}
	}
}

func TestBGPNeighborImportProtocolTokenRejected(t *testing.T) {
	// A bare protocol token has NO redistribute equivalent on inbound — it
	// renders as a route-map name and must be rejected as undefined.
	tree := buildTreeFromSet(t, []string{
		"set protocols bgp local-as 65001",
		"set protocols bgp group ebgp peer-as 65002",
		"set protocols bgp group ebgp import static",
		"set protocols bgp group ebgp neighbor 10.0.2.1",
	})
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("CompileConfig accepted a protocol token as a BGP import route-map name; expected rejection")
	}
}

func TestBGPNeighborImportDefinedPolicyAccepted(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set policy-options policy-statement IN-POL term t1 then accept",
		"set protocols bgp local-as 65001",
		"set protocols bgp group ebgp peer-as 65002",
		"set protocols bgp group ebgp import IN-POL",
		"set protocols bgp group ebgp neighbor 10.0.2.1",
	})
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("CompileConfig rejected a defined BGP import policy: %v", err)
	}
}

func TestBGPImportTypoLenientDowngrade(t *testing.T) {
	// On the lenient (load / HA peer-sync, #1960) path an undefined import ref
	// must downgrade to a warning, NOT hard-fail — an already-persisted or
	// peer-pushed config must still load. The render path then drops the
	// dangling route-map in (no permit-all leak).
	cmds := []string{
		"set protocols bgp local-as 65001",
		"set protocols bgp group ebgp peer-as 65002",
		"set protocols bgp group ebgp import IN-TYPO",
		"set protocols bgp group ebgp neighbor 10.0.2.1",
	}
	if _, err := CompileConfigLenient(buildTreeFromSet(t, cmds)); err != nil {
		t.Fatalf("CompileConfigLenient hard-failed a dangling import ref; must downgrade to warning: %v", err)
	}
	if _, err := CompileConfigForNodeLenient(buildTreeFromSet(t, cmds), 0); err != nil {
		t.Fatalf("CompileConfigForNodeLenient hard-failed a dangling import ref; must downgrade (HA peer-sync): %v", err)
	}
}

// --- forwarding-table export: read by resolveECMP. A missing policy
// silently returns 0 max-paths (ECMP disabled). Only a defined
// policy-statement is valid. ---

func TestForwardingTableExportMissingRejected(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set routing-options forwarding-table export MISSING-POLICY",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig accepted a forwarding-table export naming a missing policy; expected rejection")
	}
	for _, want := range []string{"MISSING-POLICY", "forwarding-table", "ECMP"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q missing %q", err.Error(), want)
		}
	}
}

func TestForwardingTableExportDefinedPolicyAccepted(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set policy-options policy-statement LB term t1 then load-balance per-packet",
		"set policy-options policy-statement LB term t1 then accept",
		"set routing-options forwarding-table export LB",
	})
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("CompileConfig rejected a defined forwarding-table export policy: %v", err)
	}
}

// --- per routing-instance protocols are validated identically. ---

func TestRoutingInstanceOSPFExportTypoRejected(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set routing-instances VR1 instance-type virtual-router",
		"set routing-instances VR1 protocols ospf area 0.0.0.0 interface ge-0-0-0",
		"set routing-instances VR1 protocols ospf export VR-TYPO",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig accepted a per-instance OSPF export typo; expected rejection")
	}
	for _, want := range []string{"VR1", "VR-TYPO"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q missing %q", err.Error(), want)
		}
	}
}

func TestRoutingInstanceOSPFExportDefinedPolicyAccepted(t *testing.T) {
	// policy-options is global; a per-instance export resolves against it.
	tree := buildTreeFromSet(t, []string{
		"set policy-options policy-statement VR-POL term t1 then accept",
		"set routing-instances VR1 instance-type virtual-router",
		"set routing-instances VR1 protocols ospf area 0.0.0.0 interface ge-0-0-0",
		"set routing-instances VR1 protocols ospf export VR-POL",
	})
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("CompileConfig rejected a per-instance OSPF export naming a global policy: %v", err)
	}
}

// --- tolerant load / peer-sync: a typo must downgrade to a warning so an
// already-persisted or peer-synced config still boots (#1960). ---

func TestRoutingExportTypoLenientDowngrade(t *testing.T) {
	cmds := []string{
		"set protocols ospf area 0.0.0.0 interface ge-0-0-0",
		"set protocols ospf export EXPORT-POLCIY", // typo
	}
	hasWarning := func(cfg *Config) bool {
		for _, w := range cfg.Warnings {
			if strings.Contains(w, "routing export reference") {
				return true
			}
		}
		return false
	}

	t.Run("standalone", func(t *testing.T) {
		cfg, err := CompileConfigLenient(buildTreeFromSet(t, cmds))
		if err != nil {
			t.Fatalf("CompileConfigLenient hard-failed a dangling export ref; must downgrade to warning: %v", err)
		}
		if !hasWarning(cfg) {
			t.Errorf("expected a routing export reference warning, got %v", cfg.Warnings)
		}
	})

	t.Run("node-aware", func(t *testing.T) {
		cfg, err := CompileConfigForNodeLenient(buildTreeFromSet(t, cmds), 0)
		if err != nil {
			t.Fatalf("CompileConfigForNodeLenient hard-failed a dangling export ref; must downgrade to warning (HA peer-sync): %v", err)
		}
		if !hasWarning(cfg) {
			t.Errorf("expected a routing export reference warning, got %v", cfg.Warnings)
		}
	})
}
