package config

import "testing"

// #2605 + #3745: in Junos/vSRX the flow-export `source-address` lives at
// TWO hierarchies under `forwarding-options sampling family <af> output`:
// directly under `output` (a sibling of flow-server — the per-output
// default, #2605) and nested inside an individual flow-server (the
// per-collector override, #3745). These tests drive the production
// flat-set path (ParseSetCommand + SetPath via buildTree, never
// NewParser per CLAUDE.md) and assert that the output-level default is
// recorded on SamplingFamily.SourceAddress while each nested override is
// recorded PER COLLECTOR on FlowServer.SourceAddress — NOT collapsed into
// one family-wide value (the pre-#3745 last-writer-wins bug). The
// effective per-collector bind (nested override else family default) is
// resolved in the flowexport manager (collectInstanceVersionCollectors).

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

// TestSamplingFlowServerSourceAddressStillWorks confirms the
// flow-server-nested source-address is tracked PER COLLECTOR on the
// FlowServer (#3745), not collapsed into the family-wide default. With
// only a nested source configured, the family default stays empty and
// the per-collector FlowServer.SourceAddress carries the value.
func TestSamplingFlowServerSourceAddressStillWorks(t *testing.T) {
	fam := sampleFamilyInet(t, []string{
		"set forwarding-options sampling instance i1 input rate 100",
		"set forwarding-options sampling instance i1 family inet output flow-server 192.168.1.100 port 2055",
		"set forwarding-options sampling instance i1 family inet output flow-server 192.168.1.100 source-address 10.0.0.2",
	})
	if len(fam.FlowServers) != 1 {
		t.Fatalf("expected one flow-server, got %+v", fam.FlowServers)
	}
	if fam.FlowServers[0].SourceAddress != "10.0.0.2" {
		t.Errorf("per-collector flow-server source-address: got %q, want 10.0.0.2", fam.FlowServers[0].SourceAddress)
	}
	// The output-level family default is untouched by a nested source.
	if fam.SourceAddress != "" {
		t.Errorf("family default source-address: got %q, want empty (nested source must not collapse into it)", fam.SourceAddress)
	}
}

// TestSamplingNestedSourceAddressWinsOverOutputDefault asserts the
// precedence decision: when BOTH an output-level default and a
// flow-server-nested source-address are present, the family default is
// recorded on SamplingFamily.SourceAddress and the more-specific nested
// override is recorded on FlowServer.SourceAddress (#3745). The effective
// per-collector bind (nested-wins) is resolved in the flowexport manager.
// The assertion is order-independent — the output-level line is placed
// AFTER the nested line on purpose.
func TestSamplingNestedSourceAddressWinsOverOutputDefault(t *testing.T) {
	fam := sampleFamilyInet(t, []string{
		"set forwarding-options sampling instance i1 input rate 100",
		"set forwarding-options sampling instance i1 family inet output flow-server 192.168.1.100 source-address 10.0.0.2",
		"set forwarding-options sampling instance i1 family inet output source-address 10.0.0.1",
	})
	if fam.SourceAddress != "10.0.0.1" {
		t.Errorf("output-level family default: got %q, want 10.0.0.1", fam.SourceAddress)
	}
	if len(fam.FlowServers) != 1 || fam.FlowServers[0].SourceAddress != "10.0.0.2" {
		t.Errorf("per-collector nested override: got %+v, want SourceAddress 10.0.0.2", fam.FlowServers)
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

// TestSamplingPerCollectorSourceAddressNotCollapsed is the #3745
// fix-confirming RED-on-revert test: two flow-servers of the SAME family,
// each carrying its OWN nested source-address, must each retain its own
// source on FlowServer.SourceAddress. Before #3745 the compiler collapsed
// both nested sources into a single family-wide SamplingFamily.SourceAddress
// (last-writer-wins by AST order), so both collectors bound the last source.
//
// RED-on-revert: reverting compiler_services.go to write flowServerSrc
// (one string) instead of per-collector fs.SourceAddress makes the two
// FlowServer.SourceAddress values identical (empty, with the family value
// holding the last source) and this test fails.
func TestSamplingPerCollectorSourceAddressNotCollapsed(t *testing.T) {
	fam := sampleFamilyInet(t, []string{
		"set forwarding-options sampling instance i1 input rate 100",
		"set forwarding-options sampling instance i1 family inet output flow-server 192.168.1.100 port 2055",
		"set forwarding-options sampling instance i1 family inet output flow-server 192.168.1.100 source-address 10.0.0.2",
		"set forwarding-options sampling instance i1 family inet output flow-server 192.168.1.200 port 2055",
		"set forwarding-options sampling instance i1 family inet output flow-server 192.168.1.200 source-address 10.0.0.3",
	})
	if len(fam.FlowServers) != 2 {
		t.Fatalf("expected two flow-servers, got %d: %+v", len(fam.FlowServers), fam.FlowServers)
	}
	// Index by collector address so the assertion is AST-order-independent.
	got := map[string]string{}
	for _, fs := range fam.FlowServers {
		got[fs.Address] = fs.SourceAddress
	}
	if got["192.168.1.100"] != "10.0.0.2" {
		t.Errorf("collector 192.168.1.100 source: got %q, want 10.0.0.2 (collapsed to family LWW before #3745)", got["192.168.1.100"])
	}
	if got["192.168.1.200"] != "10.0.0.3" {
		t.Errorf("collector 192.168.1.200 source: got %q, want 10.0.0.3 (collapsed to family LWW before #3745)", got["192.168.1.200"])
	}
	// The family-wide default must stay empty — neither nested source
	// leaked into it.
	if fam.SourceAddress != "" {
		t.Errorf("family default source-address: got %q, want empty (per-collector sources must not collapse into it)", fam.SourceAddress)
	}
}
