package config

import (
	"strings"
	"testing"
)

// #2506: a firewall-filter term referencing an undefined source/destination
// prefix-list must be hard-rejected at commit
// (validateFirewallPrefixListReferencesStrict). A dangling reference otherwise
// compiles cleanly and the userspace snapshot builder contributes no prefixes
// for it, silently losing the term's address scope (fail-open or fail-closed
// depending on the action). Mirrors the #2217 policer / routing-instance gates.
//
// Each direction asserts the reject (fail-on-revert: delete the validator and
// the reject disappears) and a defined reference asserts no false reject.

func TestPrefixListRefUndefinedSourceRejected(t *testing.T) {
	tree := buildTree(t, []string{
		"set firewall family inet filter f1 term t1 from source-prefix-list no-such-list",
		"set firewall family inet filter f1 term t1 then discard",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("expected commit rejection for undefined source-prefix-list, got nil")
	}
	if !strings.Contains(err.Error(), "undefined source-prefix-list") ||
		!strings.Contains(err.Error(), "no-such-list") {
		t.Fatalf("error = %v, want it to name the undefined source-prefix-list", err)
	}
}

func TestPrefixListRefUndefinedDestRejected(t *testing.T) {
	tree := buildTree(t, []string{
		"set firewall family inet6 filter f1 term t1 from destination-prefix-list ghost except",
		"set firewall family inet6 filter f1 term t1 then accept",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("expected commit rejection for undefined destination-prefix-list, got nil")
	}
	if !strings.Contains(err.Error(), "undefined destination-prefix-list") ||
		!strings.Contains(err.Error(), "ghost") {
		t.Fatalf("error = %v, want it to name the undefined destination-prefix-list", err)
	}
}

func TestPrefixListRefDefinedCommitsCleanly(t *testing.T) {
	tree := buildTree(t, []string{
		"set policy-options prefix-list mgmt 10.0.0.0/8",
		"set firewall family inet filter f1 term t1 from source-prefix-list mgmt except",
		"set firewall family inet filter f1 term t1 then discard",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("defined prefix-list must commit cleanly, got: %v", err)
	}
	term := cfg.Firewall.FiltersInet["f1"].Terms[0]
	if len(term.SourcePrefixLists) != 1 || term.SourcePrefixLists[0].Name != "mgmt" {
		t.Fatalf("source-prefix-list ref = %#v, want one ref to mgmt", term.SourcePrefixLists)
	}
	if !term.SourcePrefixLists[0].Except {
		t.Error("except modifier lost on the defined reference")
	}
}
