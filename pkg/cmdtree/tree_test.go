package cmdtree

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func contains(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}

func TestCompleteFromTree_PlaceholderWithChildrenDescends(t *testing.T) {
	cands := CompleteFromTree(OperationalTree, []string{"show", "route", "10.0.0.1"}, "", nil)
	if !contains(cands, "exact") || !contains(cands, "longer") || !contains(cands, "orlonger") {
		t.Fatalf("expected destination modifiers after placeholder, got %v", cands)
	}
	if contains(cands, "summary") {
		t.Fatalf("unexpected sibling completions after destination placeholder: %v", cands)
	}
}

func TestCompleteFromTree_PlaceholderWithoutChildrenStaysLevel(t *testing.T) {
	cands := CompleteFromTree(OperationalTree, []string{"ping", "8.8.8.8"}, "", nil)
	if !contains(cands, "count") || !contains(cands, "source") || !contains(cands, "size") {
		t.Fatalf("expected ping option completions after host placeholder, got %v", cands)
	}
}

func TestCompleteFromTree_RequestFailoverSupportsNodeAfterRGValue(t *testing.T) {
	cfg := &config.Config{
		Chassis: config.ChassisConfig{
			Cluster: &config.ClusterConfig{
				RedundancyGroups: []*config.RedundancyGroup{
					{ID: 1},
				},
			},
		},
	}

	cands := CompleteFromTree(
		OperationalTree,
		[]string{"request", "chassis", "cluster", "failover", "redundancy-group", "1"},
		"",
		cfg,
	)
	if !contains(cands, "node") {
		t.Fatalf("expected 'node' completion after redundancy-group value, got %v", cands)
	}
}

func TestCompleteFromTree_ShowRouteTableDynamicNames(t *testing.T) {
	cfg := &config.Config{
		RoutingInstances: []*config.RoutingInstanceConfig{
			{Name: "blue"},
		},
	}

	cands := CompleteFromTree(OperationalTree, []string{"show", "route", "table"}, "", cfg)
	if !contains(cands, "inet.0") || !contains(cands, "inet6.0") {
		t.Fatalf("expected default table names, got %v", cands)
	}
	if !contains(cands, "blue.inet.0") || !contains(cands, "blue.inet6.0") {
		t.Fatalf("expected per-instance table names, got %v", cands)
	}
}

func TestCompleteFromTree_UniquePrefixWordsDescend(t *testing.T) {
	cands := CompleteFromTree(OperationalTree, []string{"sh", "sec"}, "", nil)
	if !contains(cands, "flow") || !contains(cands, "nat") {
		t.Fatalf("expected security subtree completions after unique prefixes, got %v", cands)
	}
}

func TestCompleteFromTree_AmbiguousLastConsumedPrefixReturnsMatches(t *testing.T) {
	cands := CompleteFromTree(OperationalTree, []string{"show", "s"}, "", nil)
	if !contains(cands, "security") || !contains(cands, "services") || !contains(cands, "system") {
		t.Fatalf("expected ambiguous show subtree matches, got %v", cands)
	}
}

func TestLookupDesc_ResolvesUniquePrefixWords(t *testing.T) {
	if got := LookupDesc([]string{"show", "sec"}, "flow", false); got != "Show security flow information" {
		t.Fatalf("LookupDesc() = %q, want %q", got, "Show security flow information")
	}
}

func TestLookupDesc_ConfigModeResolvesUniquePrefixWords(t *testing.T) {
	if got := LookupDesc([]string{"com"}, "confirmed", true); got != "Automatically rollback if not confirmed" {
		t.Fatalf("LookupDesc() = %q, want %q", got, "Automatically rollback if not confirmed")
	}
}
