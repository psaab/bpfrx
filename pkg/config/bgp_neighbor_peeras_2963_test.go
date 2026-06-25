package config

import (
	"strings"
	"testing"
)

// #2963: a BGP neighbor whose peer-as (remote-as) is missing/0 must be
// rejected at commit / commit-check. peer-as is optional in the
// parser/compiler, so a neighbor authored without one keeps a zero PeerAS and
// the FRR renderer (pkg/frr/policy_render.go) previously emitted
// `neighbor <addr> remote-as 0`. AS 0 is reserved (RFC 7607) and FRR/vtysh
// rejects it, failing the whole frr-reload — a commit-accepted config the
// routing daemon cannot load.
//
// These tests drive the real CompileConfig (strict) / CompileConfigLenient
// (tolerant) paths via buildTreeFromSet (the flat-set helper shared with
// routing_export_ref_test.go).

// FAIL-ON-REVERT anchor: strict commit rejects a neighbor with no peer-as.
// Without validateBGPNeighborPeerASStrict (or its call site) this config
// compiles clean and renders `remote-as 0`, so removing the fix turns this
// test RED.
func TestBGPNeighborMissingPeerASRejected(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set protocols bgp local-as 65001",
		"set protocols bgp group EXT neighbor 10.0.2.1",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig accepted a BGP neighbor with no peer-as; expected rejection (would render remote-as 0)")
	}
	for _, want := range []string{"bgp", "neighbor", "10.0.2.1", "peer-as"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q missing %q", err.Error(), want)
		}
	}
}

// The error names the offending group + neighbor so the operator can locate it.
func TestBGPNeighborMissingPeerASErrorNamesGroup(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set protocols bgp local-as 65001",
		"set protocols bgp group UPSTREAM neighbor 192.0.2.5",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig accepted a BGP neighbor with no peer-as; expected rejection")
	}
	for _, want := range []string{"group UPSTREAM", "192.0.2.5"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q missing %q", err.Error(), want)
		}
	}
}

// A neighbor inheriting a group-level peer-as is accepted (peer-as is resolved
// before this gate runs on the fully-compiled *Config).
func TestBGPNeighborGroupPeerASInherited(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set protocols bgp local-as 65001",
		"set protocols bgp group EXT peer-as 65002",
		"set protocols bgp group EXT neighbor 10.0.2.1",
	})
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("CompileConfig rejected a neighbor inheriting a group peer-as: %v", err)
	}
}

// A per-neighbor peer-as is accepted.
func TestBGPNeighborPerNeighborPeerASAccepted(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set protocols bgp local-as 65001",
		"set protocols bgp group EXT neighbor 10.0.2.1 peer-as 65002",
	})
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("CompileConfig rejected a neighbor with a per-neighbor peer-as: %v", err)
	}
}

// The same gate fires for a per-routing-instance BGP neighbor.
func TestBGPNeighborMissingPeerASRoutingInstanceRejected(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set routing-instances VR1 instance-type virtual-router",
		"set routing-instances VR1 protocols bgp local-as 65010",
		"set routing-instances VR1 protocols bgp group GEXT neighbor 10.1.1.1",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig accepted a routing-instance BGP neighbor with no peer-as; expected rejection")
	}
	for _, want := range []string{"routing-instance", "VR1", "10.1.1.1", "peer-as"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q missing %q", err.Error(), want)
		}
	}
}

// Tolerant load / peer-sync path: an already-persisted config carrying a
// peer-as-less neighbor must still BOOT (warn, not hard-fail) — #1960
// fail-closed-on-load doctrine. The render-path guard keeps AS 0 out of
// frr.conf.
func TestBGPNeighborMissingPeerASLenientWarns(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set protocols bgp local-as 65001",
		"set protocols bgp group EXT neighbor 10.0.2.1",
	})
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient hard-failed on a peer-as-less neighbor; expected warn-and-boot: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "peer-as") && strings.Contains(w, "10.0.2.1") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("lenient compile did not record a peer-as warning naming the neighbor; warnings=%v", cfg.Warnings)
	}
}
