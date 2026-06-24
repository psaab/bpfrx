package config

import "testing"

// #2605: in Junos/vSRX the flow-export `source-address` lives directly
// under `forwarding-options sampling family <af> output` (a sibling of
// flow-server) — the standard hierarchy. compileSamplingFamily
// previously only read `source-address` NESTED inside an individual
// flow-server (and inside inline-jflow), so an output-level
// source-address was silently dropped (no compile error). These tests
// drive the production flat-set path (ParseSetCommand + SetPath via
// buildTree, never NewParser per CLAUDE.md) and assert the precedence:
// a flow-server-nested source-address (more specific) wins over the
// output-level default; the output-level value is the fallback.

// sampleFamilyInet compiles the given set lines and returns the inet
// SamplingFamily for instance "i1", failing the test if any layer is
// missing.
func sampleFamilyInet(t *testing.T, lines []string) *SamplingFamily {
	t.Helper()
	tree := buildTree(t, lines)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if cfg.ForwardingOptions.Sampling == nil {
		t.Fatal("expected ForwardingOptions.Sampling to be non-nil")
	}
	inst := cfg.ForwardingOptions.Sampling.Instances["i1"]
	if inst == nil {
		t.Fatal("expected sampling instance i1")
	}
	if inst.FamilyInet == nil {
		t.Fatal("expected FamilyInet")
	}
	return inst.FamilyInet
}

// TestSamplingOutputLevelSourceAddress is the #2605 fix-confirming test:
// a `source-address` at the standard Junos hierarchy (directly under
// `output`, sibling of flow-server) is applied to the family exporter.
// fail-on-revert: deleting the `case "source-address":` (output-level)
// arm in compileSamplingFamily makes SourceAddress empty here.
func TestSamplingOutputLevelSourceAddress(t *testing.T) {
	fam := sampleFamilyInet(t, []string{
		"set forwarding-options sampling instance i1 input rate 100",
		"set forwarding-options sampling instance i1 family inet output source-address 10.0.0.1",
		"set forwarding-options sampling instance i1 family inet output flow-server 192.168.1.100 port 2055",
	})
	if fam.SourceAddress != "10.0.0.1" {
		t.Errorf("output-level source-address: got %q, want 10.0.0.1 (was silently dropped before #2605)", fam.SourceAddress)
	}
	if len(fam.FlowServers) != 1 || fam.FlowServers[0].Address != "192.168.1.100" {
		t.Fatalf("expected one flow-server 192.168.1.100, got %+v", fam.FlowServers)
	}
}

// TestSamplingFlowServerSourceAddressStillWorks confirms the legacy
// flow-server-nested source-address path is unchanged.
func TestSamplingFlowServerSourceAddressStillWorks(t *testing.T) {
	fam := sampleFamilyInet(t, []string{
		"set forwarding-options sampling instance i1 input rate 100",
		"set forwarding-options sampling instance i1 family inet output flow-server 192.168.1.100 port 2055",
		"set forwarding-options sampling instance i1 family inet output flow-server 192.168.1.100 source-address 10.0.0.2",
	})
	if fam.SourceAddress != "10.0.0.2" {
		t.Errorf("flow-server-nested source-address: got %q, want 10.0.0.2", fam.SourceAddress)
	}
}

// TestSamplingNestedSourceAddressWinsOverOutputDefault asserts the
// precedence decision: when BOTH an output-level default and a
// flow-server-nested source-address are present, the more-specific
// flow-server-nested value wins. The assertion is order-independent —
// the output-level line is intentionally placed AFTER the nested line.
func TestSamplingNestedSourceAddressWinsOverOutputDefault(t *testing.T) {
	fam := sampleFamilyInet(t, []string{
		"set forwarding-options sampling instance i1 input rate 100",
		"set forwarding-options sampling instance i1 family inet output flow-server 192.168.1.100 source-address 10.0.0.2",
		"set forwarding-options sampling instance i1 family inet output source-address 10.0.0.1",
	})
	if fam.SourceAddress != "10.0.0.2" {
		t.Errorf("nested-wins-over-output-default: got %q, want 10.0.0.2", fam.SourceAddress)
	}
}

// TestSamplingOutputLevelSourceAddressInet6 mirrors the fix for the
// inet6 family.
func TestSamplingOutputLevelSourceAddressInet6(t *testing.T) {
	tree := buildTree(t, []string{
		"set forwarding-options sampling instance i1 input rate 100",
		"set forwarding-options sampling instance i1 family inet6 output source-address 2001:db8::1",
		"set forwarding-options sampling instance i1 family inet6 output flow-server 2001:db8::100 port 2055",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	inst := cfg.ForwardingOptions.Sampling.Instances["i1"]
	if inst == nil || inst.FamilyInet6 == nil {
		t.Fatal("expected FamilyInet6")
	}
	if inst.FamilyInet6.SourceAddress != "2001:db8::1" {
		t.Errorf("inet6 output-level source-address: got %q, want 2001:db8::1", inst.FamilyInet6.SourceAddress)
	}
}

// TestSamplingOutputLevelSourceAddressFeedsInlineJflow confirms the
// output-level default also seeds inline-jflow's distinct source field
// when inline-jflow itself sets none, and that an explicit inline-jflow
// source-address still wins.
func TestSamplingOutputLevelSourceAddressFeedsInlineJflow(t *testing.T) {
	fam := sampleFamilyInet(t, []string{
		"set forwarding-options sampling instance i1 input rate 100",
		"set forwarding-options sampling instance i1 family inet output source-address 10.0.0.1",
		"set forwarding-options sampling instance i1 family inet output inline-jflow",
	})
	if !fam.InlineJflow {
		t.Fatal("expected InlineJflow")
	}
	if fam.InlineJflowSourceAddress != "10.0.0.1" {
		t.Errorf("inline-jflow inherits output-level default: got %q, want 10.0.0.1", fam.InlineJflowSourceAddress)
	}

	fam2 := sampleFamilyInet(t, []string{
		"set forwarding-options sampling instance i1 input rate 100",
		"set forwarding-options sampling instance i1 family inet output source-address 10.0.0.1",
		"set forwarding-options sampling instance i1 family inet output inline-jflow source-address 10.0.0.9",
	})
	if fam2.InlineJflowSourceAddress != "10.0.0.9" {
		t.Errorf("explicit inline-jflow source-address must win: got %q, want 10.0.0.9", fam2.InlineJflowSourceAddress)
	}
}
