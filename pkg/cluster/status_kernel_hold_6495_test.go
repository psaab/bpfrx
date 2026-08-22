package cluster

import (
	"strings"
	"testing"
)

// #6495: a node parked SECONDARY by the kernel-candidate promotion gate must
// SAY SO in the cluster status. Before this, `Manager.FormatStatus` rendered
// priorities, preempt, manual-failover and monitor failures — and nothing for
// the hold, so a node held by the expected gate was indistinguishable from one
// demoted by a monitor failure or a manual failover. That ambiguity lands
// during a kernel roll, which is exactly when an operator is trying to decide
// whether what they are looking at is normal.

func TestFormatStatusAnnotatesTheKernelUpgradeHold(t *testing.T) {
	m := NewManager(0, 1)
	if got := m.FormatStatus(); strings.Contains(got, "Held secondary") {
		t.Fatalf("an unheld node must NOT claim a hold:\n%s", got)
	}
	m.SetKernelUpgradeHold()
	got := m.FormatStatus()
	if !strings.Contains(got, "Held secondary") {
		t.Fatalf("a kernel-upgrade hold is invisible in `show chassis cluster "+
			"status` — indistinguishable from a monitor failure (#6495):\n%s", got)
	}
	if !strings.Contains(got, KernelUpgradeHoldReason) {
		t.Errorf("the hold must name its REASON:\n%s", got)
	}
}

func TestFormatInformationAnnotatesTheKernelUpgradeHold(t *testing.T) {
	m := NewManager(0, 1)
	if got := m.FormatInformation(); strings.Contains(got, "Held secondary") {
		t.Fatalf("an unheld node must NOT claim a hold:\n%s", got)
	}
	m.SetKernelUpgradeHold()
	got := m.FormatInformation()
	if !strings.Contains(got, "Held secondary") {
		t.Fatalf("the hold is invisible in `show chassis cluster information`:\n%s", got)
	}
}

// The hold must NOT be folded into node health. The node is healthy; it is
// deliberately not eligible. Reporting it as degraded would tell the operator
// something false and could send them chasing a fault that does not exist.
func TestKernelUpgradeHoldDoesNotDegradeNodeHealth(t *testing.T) {
	m := NewManager(0, 1)
	m.SetKernelUpgradeHold()
	got := m.FormatInformation()
	for _, ln := range strings.Split(got, "\n") {
		if strings.HasPrefix(strings.TrimSpace(ln), "Local node:") {
			if strings.Contains(ln, "degraded") {
				t.Errorf("the kernel-upgrade hold degraded node health: %q", ln)
			}
			return
		}
	}
	t.Fatalf("no `Local node:` health line in:\n%s", got)
}

// Clearing the hold must clear the annotation. A status that keeps reporting a
// released hold is worse than one that never reported it: the operator would
// wait for a gate that already finished.
func TestClearingTheHoldClearsTheAnnotation(t *testing.T) {
	m := NewManager(0, 1)
	m.SetKernelUpgradeHold()
	m.ClearKernelUpgradeHold()
	if got := m.FormatStatus(); strings.Contains(got, "Held secondary") {
		t.Errorf("a released hold is still annotated:\n%s", got)
	}
}

// The annotation must not be parseable as a node row.
//
// deploy_rolling_secondary_node (test/incus/deploy-lib.sh — the authoritative
// parser; this is a guard on the OUTPUT it consumes, not a copy of it) picks
// the RG0 secondary by awk-matching `$1 == "node0"` INSIDE a
// "Redundancy group: N" block, and a rolling cluster deploy uses the answer to
// decide which node to restart first. A line it misread would restart the
// PRIMARY first and cause a spurious mid-deploy failover (#4009).
//
// Two properties make that impossible: the annotation appears ABOVE every
// "Redundancy group:" header, so no RG is in scope when awk reaches it, and
// its first field is not a node token.
func TestHoldAnnotationCannotBeMistakenForANodeRow(t *testing.T) {
	m := NewManager(0, 1)
	m.SetKernelUpgradeHold()
	lines := strings.Split(m.FormatStatus(), "\n")

	holdIdx, rgIdx := -1, -1
	for i, ln := range lines {
		if holdIdx < 0 && strings.Contains(ln, "Held secondary") {
			holdIdx = i
		}
		if rgIdx < 0 && strings.HasPrefix(ln, "Redundancy group:") {
			rgIdx = i
		}
	}
	if holdIdx < 0 {
		t.Fatal("no hold annotation rendered")
	}
	if rgIdx >= 0 && holdIdx > rgIdx {
		t.Errorf("the hold annotation (line %d) is INSIDE a redundancy-group "+
			"block (first header at line %d) — the rolling-deploy parser reads "+
			"rows there: %q", holdIdx, rgIdx, lines[holdIdx])
	}
	fields := strings.Fields(lines[holdIdx])
	if len(fields) == 0 {
		t.Fatalf("empty hold annotation line")
	}
	if strings.HasPrefix(fields[0], "node") {
		t.Errorf("the annotation's first field %q reads as a node row: %q",
			fields[0], lines[holdIdx])
	}
}
