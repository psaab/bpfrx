package nftables

import (
	"net/netip"
	"testing"
)

func TestBuildRSTSuppressionPlanSkipsDeleteWhenTableMissing(t *testing.T) {
	plan := buildRSTSuppressionPlan(false, []netip.Addr{netip.MustParseAddr("172.16.80.8")}, nil)
	if plan.deleteTable {
		t.Fatal("plan.deleteTable = true, want false")
	}
	if len(plan.v4Addrs) != 1 {
		t.Fatalf("len(plan.v4Addrs) = %d, want 1", len(plan.v4Addrs))
	}
	if len(plan.v6Addrs) != 0 {
		t.Fatalf("len(plan.v6Addrs) = %d, want 0", len(plan.v6Addrs))
	}
}

func TestBuildRSTSuppressionPlanDeleteOnlyRequiresExistingTable(t *testing.T) {
	plan := buildRSTSuppressionPlan(false, nil, nil)
	if plan.deleteTable {
		t.Fatal("plan.deleteTable = true for missing table, want false")
	}
	if len(plan.v4Addrs) != 0 || len(plan.v6Addrs) != 0 {
		t.Fatalf("unexpected addresses in empty missing-table plan: %+v", plan)
	}

	plan = buildRSTSuppressionPlan(true, nil, nil)
	if !plan.deleteTable {
		t.Fatal("plan.deleteTable = false for existing table, want true")
	}
	if len(plan.v4Addrs) != 0 || len(plan.v6Addrs) != 0 {
		t.Fatalf("unexpected addresses in delete-only plan: %+v", plan)
	}
}
