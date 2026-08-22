package dataplane

import (
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #7426: bind the PRODUCTION CALL SITE, not the helper.
//
// `getOriginalKernelName` produces the `.link` `OriginalName=` for a RETH
// member. That name is the only stable match for such a member — its MAC
// alternates between physical at boot and virtual once the daemon programs the
// RETH virtual MAC — so a wrong or missing one is not self-correcting at the
// next boot.
//
// The helper is reachable from `buildInterfaceNetworkdModels` →
// `compiler_iface.go`, which is the live networkd `.link`/`.network`
// generation path.
//
// NOTE FOR THE NEXT READER: `pkg/dataplane/compiler.go` is flagged in the
// project notes as retired eBPF. THAT FLAG DOES NOT COVER THIS PATH. Another
// lane nearly dismissed this issue on that basis and had to re-check. The
// interface/networkd generation in this file is live on every commit.
//
// REQUIRED MUTATION: delete the CALL in compiler_iface.go, not the callee. A
// test that binds the helper while production bypasses it proves nothing —
// that shape has been found repeatedly in this campaign, including in
// already-merged code. #7420's own merge gate used exactly this.

// rethMemberConfig builds the minimum config that reaches the RETH-member
// OriginalName branch: a cluster (so clusterNodeID >= 0), a reth parent in a
// redundancy group, and a physical member naming it.
func rethMemberConfig() *config.Config {
	cfg := &config.Config{}
	cfg.Chassis.Cluster = &config.ClusterConfig{NodeID: 0, RethCount: 1}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"reth0": {Name: "reth0", RedundancyGroup: 1},
		"ge-0/0/1": {
			Name:            "ge-0/0/1",
			RedundantParent: "reth0",
		},
	}
	return cfg
}

// virtualRethMACIface returns a *net.Interface carrying a RETH VIRTUAL MAC
// (02:bf:72:...), which is the condition that makes OriginalName= load-bearing.
func virtualRethMACIface(name string) *net.Interface {
	return &net.Interface{
		Index:        7,
		Name:         name,
		HardwareAddr: net.HardwareAddr{0x02, 0xbf, 0x72, 0x01, 0x00, 0x01},
	}
}

func TestOriginalKernelNameIsCalledFromNetworkdGeneration(t *testing.T) {
	linuxName := config.LinuxIfName("ge-0/0/1")

	var calledWith []string
	saved := originalKernelNameFn
	originalKernelNameFn = func(ifName string, result *CompileResult) string {
		calledWith = append(calledWith, ifName)
		return "enp183s0f0np0"
	}
	t.Cleanup(func() { originalKernelNameFn = saved })

	result := &CompileResult{ifCache: map[string]*net.Interface{
		linuxName: virtualRethMACIface(linuxName),
	}}
	buildInterfaceNetworkdModels(rethMemberConfig(), result, map[string]bool{})

	if len(calledWith) == 0 {
		t.Fatal("the networkd generation path never called the original-kernel-name " +
			"resolver for a RETH member carrying a virtual MAC — the .link file " +
			"loses OriginalName=, and a RETH member cannot be matched by MAC " +
			"because its MAC alternates between physical and virtual")
	}

	// ...and the resolved name must actually REACH the emitted model. Asserting
	// only that the resolver was called would pass if its return value were
	// dropped on the floor.
	var got string
	for _, mi := range result.ManagedInterfaces {
		if mi.Name == linuxName {
			got = mi.OriginalName
		}
	}
	if got != "enp183s0f0np0" {
		t.Fatalf("OriginalName= on the emitted %s model = %q, want the resolved "+
			"name enp183s0f0np0 — the resolver ran but its answer did not reach "+
			"the .link file", linuxName, got)
	}
}

// TestOriginalKernelNameNotCalledForNonRethMember is the negative control: a
// plain interface with no RETH parent must not take the branch at all, so a
// resolver that fired unconditionally would be caught rather than looking
// correct.
func TestOriginalKernelNameNotCalledForNonRethMember(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/2": {Name: "ge-0/0/2"},
	}
	linuxName := config.LinuxIfName("ge-0/0/2")

	called := 0
	saved := originalKernelNameFn
	originalKernelNameFn = func(string, *CompileResult) string { called++; return "enpX" }
	t.Cleanup(func() { originalKernelNameFn = saved })

	result := &CompileResult{ifCache: map[string]*net.Interface{
		linuxName: {Index: 8, Name: linuxName,
			HardwareAddr: net.HardwareAddr{0x3c, 0xec, 0xef, 0x6a, 0xa8, 0xbc}},
	}}
	buildInterfaceNetworkdModels(cfg, result, map[string]bool{})

	if called != 0 {
		t.Errorf("the resolver ran %d time(s) for a non-RETH interface with a "+
			"factory MAC — OriginalName= is only load-bearing for a RETH member", called)
	}
}
