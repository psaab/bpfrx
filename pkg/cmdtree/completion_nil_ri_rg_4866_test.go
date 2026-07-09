package cmdtree

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #4866: the operational-tree DynamicFns for routing-instance and
// redundancy-group names dereferenced every slice element (ri.Name / rg.ID)
// with only a `cfg == nil` guard. A nil *RoutingInstanceConfig /
// *RedundancyGroup element is a tolerated shape on the tolerant-load / HA-sync
// config path (#3494 injects exactly these), which the daemon's own validators
// and route builder already skip. cmdtree is the completion SSOT for the local
// CLI, remote CLI, and gRPC, so a read-only completion / `?` help request that
// hit that shape crashed the control plane. These drive the real completers;
// reverting the `ri == nil` / `rg == nil` guards in the shared helpers makes
// them panic (RED on revert).

func nilTolerantRIRGConfig() *config.Config {
	cfg := &config.Config{}
	// A real routing instance followed by a tolerated nil element.
	cfg.RoutingInstances = []*config.RoutingInstanceConfig{
		{Name: "vr-blue"},
		nil,
	}
	// A real redundancy group followed by a tolerated nil element.
	cfg.Chassis.Cluster = &config.ClusterConfig{
		RedundancyGroups: []*config.RedundancyGroup{
			{ID: 1},
			nil,
		},
	}
	return cfg
}

func assertNoEmptyCandidate(t *testing.T, cands []string) {
	t.Helper()
	for _, c := range cands {
		if c == "" {
			t.Fatalf("nil entry produced an empty completion candidate: %v", cands)
		}
	}
}

func TestRoutingInstanceCompletionNilEntryNoPanic(t *testing.T) {
	cfg := nilTolerantRIRGConfig()

	// Every routing-instance-name completer must skip the nil entry and
	// surface the real instance name without panicking.
	paths := [][]string{
		{"show", "route", "instance"},
		{"test", "routing", "instance"},
		{"ping", "routing-instance"},
		{"traceroute", "routing-instance"},
	}
	for _, p := range paths {
		cands := CompleteFromTree(OperationalTree, p, "", cfg)
		if !contains(cands, "vr-blue") {
			t.Fatalf("%v: expected routing instance vr-blue, got %v", p, cands)
		}
		assertNoEmptyCandidate(t, cands)
	}

	// `show route table` mixes the main tables with per-instance tables; the
	// nil entry must be skipped, the real instance's tables surfaced.
	cands := CompleteFromTree(OperationalTree, []string{"show", "route", "table"}, "", cfg)
	for _, want := range []string{"inet.0", "inet6.0", "vr-blue.inet.0", "vr-blue.inet6.0"} {
		if !contains(cands, want) {
			t.Fatalf("show route table: expected %q, got %v", want, cands)
		}
	}
	assertNoEmptyCandidate(t, cands)
}

func TestRedundancyGroupCompletionNilEntryNoPanic(t *testing.T) {
	cfg := nilTolerantRIRGConfig()

	paths := [][]string{
		{"request", "chassis", "cluster", "failover", "redundancy-group"},
		{"request", "chassis", "cluster", "failover", "reset", "redundancy-group"},
	}
	for _, p := range paths {
		cands := CompleteFromTree(OperationalTree, p, "", cfg)
		if !contains(cands, "1") {
			t.Fatalf("%v: expected redundancy-group id 1, got %v", p, cands)
		}
		assertNoEmptyCandidate(t, cands)
	}
}
