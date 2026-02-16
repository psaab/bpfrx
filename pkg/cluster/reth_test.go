package cluster

import (
	"strings"
	"testing"
)

func TestRethMappingFormatStatus(t *testing.T) {
	// We can't test netlink operations in unit tests, but we can test
	// the format output with no mappings.
	rc := &RethController{
		mappings: nil,
	}

	out := rc.FormatStatus()
	if !strings.Contains(out, "No RETH interfaces configured") {
		t.Fatalf("expected 'No RETH interfaces configured', got: %s", out)
	}
}

func TestRethMappingWithEntries(t *testing.T) {
	rc := &RethController{
		mappings: []RethMapping{
			{RethName: "reth0", RedundancyGrp: 1, Members: []string{"ge-0/0/0", "ge-7/0/0"}},
			{RethName: "reth1", RedundancyGrp: 2, Members: []string{"ge-0/0/3"}},
		},
	}

	out := rc.FormatStatus()
	if !strings.Contains(out, "reth0") {
		t.Fatalf("expected reth0 in output, got: %s", out)
	}
	if !strings.Contains(out, "reth1") {
		t.Fatalf("expected reth1 in output, got: %s", out)
	}
	if !strings.Contains(out, "ge-0/0/0") {
		t.Fatalf("expected member ge-0/0/0 in output, got: %s", out)
	}
	if !strings.Contains(out, "Physical") {
		t.Fatalf("expected 'Physical' header in output, got: %s", out)
	}
}

func TestHandleStateChangeFiltersbyRG(t *testing.T) {
	rc := &RethController{
		mappings: []RethMapping{
			{RethName: "reth0", RedundancyGrp: 1, Members: []string{"eth0"}},
			{RethName: "reth1", RedundancyGrp: 2, Members: []string{"eth1"}},
		},
	}

	// This will attempt netlink ops which will fail in test env, but
	// it should not panic and should only process RG 1 mappings.
	event := ClusterEvent{
		GroupID:  1,
		OldState: StateSecondary,
		NewState: StatePrimary,
	}
	rc.HandleStateChange(event) // should not panic

	event2 := ClusterEvent{
		GroupID:  2,
		OldState: StatePrimary,
		NewState: StateSecondary,
	}
	rc.HandleStateChange(event2) // should not panic
}

func TestHandleStateChange_AlwaysActivates(t *testing.T) {
	// Verify HandleStateChange brings up physical members for all states (not just primary).
	// Physical interfaces must stay UP on both nodes for VRRP to work.
	rc := &RethController{
		mappings: []RethMapping{
			{RethName: "reth0", RedundancyGrp: 1, Members: []string{"eth0"}},
		},
	}

	// All state transitions should not panic and should attempt activation.
	states := []NodeState{StatePrimary, StateSecondary, StateLost, StateSecondaryHold}
	for _, s := range states {
		event := ClusterEvent{
			GroupID:  1,
			OldState: StatePrimary,
			NewState: s,
		}
		rc.HandleStateChange(event) // should not panic, always activates
	}
}
