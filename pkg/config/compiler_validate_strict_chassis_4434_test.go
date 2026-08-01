package config

import (
	"fmt"
	"strings"
	"testing"
)

// #4434 (codex-172 C172-H02): the HA heartbeat group-count field and each
// per-group id byte are uint8 (pkg/cluster/heartbeat.go), and neither the
// chassis schema nor compileChassis bounded the redundancy-group cardinality
// or id. So a config with 256+ redundancy-groups advertised a count byte of 0
// (wire desync against the 256 records still written) and a redundancy-group
// id > 255 truncated on the wire and collided with another group.
// validateChassisClusterStrict makes both an operator-visible commit error.
//
// FAIL-ON-REVERT: remove the validateChassisClusterStrict dispatch in
// compileExpanded (compiler.go) or the range checks in the validator and the
// over-size / over-id subtests go green on the BAD config — exactly the
// wire-desync regression this test exists to catch. The tolerant-path and
// in-range subtests pin that the gate does not over-reject.

// rgSetLines returns the flat-set lines that define n redundancy groups with
// sequential ids 0..n-1, each with a well-formed node priority so the compiler
// materializes a RedundancyGroup instance.
func rgSetLines(n int) []string {
	lines := make([]string, 0, n+2)
	lines = append(lines, "set chassis cluster cluster-id 1")
	lines = append(lines, "set chassis cluster authentication-key test-cluster-psk-6611")
	for i := 0; i < n; i++ {
		lines = append(lines,
			fmt.Sprintf("set chassis cluster redundancy-group %d node 0 priority 100", i))
	}
	return lines
}

func TestChassisRedundancyGroupCardinalityFailsCommit(t *testing.T) {
	// 256 groups (ids 0..255) — the count byte would wrap uint8(256) == 0.
	tree := buildTree(t, rgSetLines(MaxHeartbeatRedundancyGroups+1))

	cfg, err := CompileConfig(tree)
	if err == nil {
		t.Fatalf("expected commit to reject %d redundancy-groups (heartbeat "+
			"count byte is uint8), got nil error", MaxHeartbeatRedundancyGroups+1)
	}
	if !strings.Contains(err.Error(), "redundancy-groups exceeds") {
		t.Fatalf("error %q does not describe the redundancy-group cardinality cap", err.Error())
	}
	_ = cfg

	// Tolerant path (load / peer-sync) must NOT brick — it downgrades to a
	// warning so an already-persisted config still boots.
	lcfg, lerr := CompileConfigLenient(tree)
	if lerr != nil {
		t.Fatalf("lenient compile must not reject an over-size RG set (no-brick), got %v", lerr)
	}
	if !warningsContain(lcfg.Warnings, "chassis cluster redundancy-group") {
		t.Fatalf("lenient compile should have warned about the RG cardinality; warnings=%v", lcfg.Warnings)
	}
}

func TestChassisRedundancyGroupIDFailsCommit(t *testing.T) {
	// A single group with an id > 255 truncates on the wire.
	tree := buildTree(t, []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster authentication-key test-cluster-psk-6611",
		"set chassis cluster redundancy-group 300 node 0 priority 100",
	})

	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatalf("expected commit to reject redundancy-group id 300 (heartbeat " +
			"id byte is uint8), got nil error")
	}
	if !strings.Contains(err.Error(), "id 300") || !strings.Contains(err.Error(), "out of") {
		t.Fatalf("error %q does not name the out-of-range redundancy-group id", err.Error())
	}
}

func TestChassisRedundancyGroupInRangeCommits(t *testing.T) {
	// The boundary: 255 groups (ids 0..254) and an id of exactly 255 both fit
	// the uint8 wire fields and must commit cleanly.
	tree := buildTree(t, rgSetLines(MaxHeartbeatRedundancyGroups))
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("commit rejected %d in-range redundancy-groups: %v", MaxHeartbeatRedundancyGroups, err)
	}

	boundary := buildTree(t, []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster authentication-key test-cluster-psk-6611",
		"set chassis cluster redundancy-group 0 node 0 priority 200",
		fmt.Sprintf("set chassis cluster redundancy-group %d node 1 priority 100", MaxHeartbeatRedundancyGroupID),
	})
	if _, err := CompileConfig(boundary); err != nil {
		t.Fatalf("commit rejected a boundary redundancy-group id %d: %v", MaxHeartbeatRedundancyGroupID, err)
	}

	// A cluster with no redundancy-group stanza at all is unaffected.
	none := buildTree(t, []string{"set chassis cluster cluster-id 1",
		"set chassis cluster authentication-key test-cluster-psk-6611"})
	if _, err := CompileConfig(none); err != nil {
		t.Fatalf("commit rejected a cluster with no redundancy-groups: %v", err)
	}
}
