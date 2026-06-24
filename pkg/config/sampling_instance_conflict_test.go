package config

import (
	"strings"
	"testing"
)

// #2462 — multi-sampling-instance conflict gate.
//
// Multiple `forwarding-options sampling instance` blocks that each export the
// SAME (export-version, address-family) pair are genuinely ambiguous: there is
// no per-interface sampling-instance selector, so the runtime cannot attribute
// a flow of that family to one instance. The compiler previously flattened
// them silently. The strict commit / commit-check path now hard-rejects;
// the tolerant load / peer-sync path downgrades to a warning (#1960).

// TestTwoInstancesSameFamilyVersionRejected: two instances both exporting
// inet flows under the (single) configured version are rejected at commit.
func TestTwoInstancesSameFamilyVersionRejected(t *testing.T) {
	cmds := []string{
		"set services flow-monitoring version9 template t flow-active-timeout 60",
		"set forwarding-options sampling instance alpha input rate 100",
		"set forwarding-options sampling instance alpha family inet output flow-server 10.0.0.1 version9 template t",
		"set forwarding-options sampling instance bravo input rate 200",
		"set forwarding-options sampling instance bravo family inet output flow-server 10.0.0.2 version9 template t",
	}
	tree := buildTreeFromSet(t, cmds)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig accepted two sampling instances both exporting inet/version9; expected rejection")
	}
	for _, want := range []string{"alpha", "bravo", "inet"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q missing %q", err.Error(), want)
		}
	}
}

// TestTwoInstancesDifferentFamilyAccepted: instances disambiguated by family
// (alpha inet, bravo inet6) compile cleanly — the supported multi-instance
// case (family is the per-flow attribution selector).
func TestTwoInstancesDifferentFamilyAccepted(t *testing.T) {
	cmds := []string{
		"set services flow-monitoring version9 template t flow-active-timeout 60",
		"set forwarding-options sampling instance alpha family inet output flow-server 10.0.0.1 port 2055",
		"set forwarding-options sampling instance bravo family inet6 output flow-server 2001:db8::2 port 2055",
	}
	tree := buildTreeFromSet(t, cmds)
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("CompileConfig rejected two family-disjoint sampling instances: %v", err)
	}
}

// TestTwoInstancesDifferentVersionAccepted: instances disambiguated by export
// version (alpha inet/version9, bravo inet/version-ipfix) compile cleanly —
// distinct datagram streams, not a merge.
func TestTwoInstancesDifferentVersionAccepted(t *testing.T) {
	cmds := []string{
		"set services flow-monitoring version9 template t9 flow-active-timeout 60",
		"set services flow-monitoring version-ipfix template ti flow-active-timeout 60",
		"set forwarding-options sampling instance alpha family inet output flow-server 10.0.0.1 version9 template t9",
		"set forwarding-options sampling instance bravo family inet output flow-server 10.0.0.2 version-ipfix template ti",
	}
	tree := buildTreeFromSet(t, cmds)
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("CompileConfig rejected two version-disjoint sampling instances: %v", err)
	}
}

// TestSingleInstanceMultiFamilyAccepted: ONE instance serving both families is
// fine (the common single-instance case is never gated — anti-over-gate).
func TestSingleInstanceMultiFamilyAccepted(t *testing.T) {
	cmds := []string{
		"set services flow-monitoring version9 template t flow-active-timeout 60",
		"set forwarding-options sampling instance s family inet output flow-server 10.0.0.1 port 2055",
		"set forwarding-options sampling instance s family inet6 output flow-server 2001:db8::1 port 2055",
	}
	tree := buildTreeFromSet(t, cmds)
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("CompileConfig rejected a single multi-family instance: %v", err)
	}
}

// TestConflictingInstancesLenientWarns: on the tolerant load / peer-sync path
// the conflict is downgraded to a warning so an already-persisted or
// peer-synced config still boots (#1960).
func TestConflictingInstancesLenientWarns(t *testing.T) {
	cmds := []string{
		"set services flow-monitoring version9 template t flow-active-timeout 60",
		"set forwarding-options sampling instance alpha family inet output flow-server 10.0.0.1 port 2055",
		"set forwarding-options sampling instance bravo family inet output flow-server 10.0.0.2 port 2055",
	}
	tree := buildTreeFromSet(t, cmds)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient must NOT hard-reject conflicting sampling instances: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "sampling instance conflict") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("lenient compile must emit a downgraded warning for the conflict; warnings=%v", cfg.Warnings)
	}
}
