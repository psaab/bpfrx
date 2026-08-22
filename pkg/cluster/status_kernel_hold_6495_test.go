package cluster

import (
	"strings"
	"testing"
)

// #6495: a node parked SECONDARY by the kernel-upgrade gate must SAY SO — and
// say WHICH gate. Before this, `Manager.FormatStatus` rendered priorities,
// preempt, manual-failover and monitor failures, and nothing for the hold, so a
// node held by the expected gate was indistinguishable from one demoted by a
// monitor failure or a manual failover.
//
// The second half matters as much as the first. The daemon sets ONE flag for
// TWO conditions — a genuinely armed candidate, and the #5682 fail-closed hold
// taken when the journal cannot be read — and their remedies differ. Surfacing
// only "held: yes/no" would satisfy the letter of the issue while leaving the
// operator exactly as unable to act.

func heldStatusLine(t *testing.T, out string) string {
	t.Helper()
	for _, ln := range strings.Split(out, "\n") {
		if strings.Contains(ln, "Held secondary") {
			return ln
		}
	}
	return ""
}

func TestFormatStatusAnnotatesTheKernelUpgradeHold(t *testing.T) {
	m := NewManager(0, 1)
	if got := m.FormatStatus(); strings.Contains(got, "Held secondary") {
		t.Fatalf("an unheld node must NOT claim a hold:\n%s", got)
	}
	m.SetKernelUpgradeHold(KernelUpgradeHoldCandidate)
	got := m.FormatStatus()
	if !strings.Contains(got, "Held secondary") {
		t.Fatalf("a kernel-upgrade hold is invisible in `show chassis cluster "+
			"status` — indistinguishable from a monitor failure (#6495):\n%s", got)
	}
	if !strings.Contains(got, KernelUpgradeHoldCandidate) {
		t.Errorf("the hold must name its REASON:\n%s", got)
	}
}

func TestFormatInformationAnnotatesTheKernelUpgradeHold(t *testing.T) {
	m := NewManager(0, 1)
	if got := m.FormatInformation(); strings.Contains(got, "Held secondary") {
		t.Fatalf("an unheld node must NOT claim a hold:\n%s", got)
	}
	m.SetKernelUpgradeHold(KernelUpgradeHoldCandidate)
	if got := m.FormatInformation(); !strings.Contains(got, "Held secondary") {
		t.Fatalf("the hold is invisible in `show chassis cluster information`:\n%s", got)
	}
}

// The two holds must render DIFFERENTLY, and the fail-closed one must not
// promise a resolution it cannot deliver.
//
// "Held until the promotion marker confirms the running kernel" is FALSE on a
// fail-closed hold: the daemon reached that branch precisely because it could
// not establish whether anything is armed, so there may be no candidate and no
// marker will ever be written. The operator's action there is to repair
// /var/lib/xpf, not to wait. RED on revert: collapse the two constants into one
// and the inequality below flips.
func TestTheTwoHoldsRenderDistinguishably(t *testing.T) {
	if KernelUpgradeHoldCandidate == KernelUpgradeHoldUnreadableJournal {
		t.Fatal("the two hold reasons are the same string — an operator cannot " +
			"tell an armed candidate from an unreadable journal, and the remedies differ")
	}

	armed := NewManager(0, 1)
	armed.SetKernelUpgradeHold(KernelUpgradeHoldCandidate)
	failClosed := NewManager(0, 1)
	failClosed.SetKernelUpgradeHold(KernelUpgradeHoldUnreadableJournal)

	a := heldStatusLine(t, armed.FormatStatus())
	f := heldStatusLine(t, failClosed.FormatStatus())
	if a == "" || f == "" {
		t.Fatalf("missing hold line (armed=%q failClosed=%q)", a, f)
	}
	if a == f {
		t.Fatalf("both holds render the SAME line:\n%s", a)
	}
	if strings.Contains(f, "promotion marker confirms") {
		t.Errorf("the fail-closed hold claims a promotion marker will resolve it; "+
			"the daemon does not know a candidate exists at all:\n%s", f)
	}
	if !strings.Contains(f, "unreadable") {
		t.Errorf("the fail-closed hold does not name its actual cause:\n%s", f)
	}
}

// The operator-visible causes of SECONDARY must be separable in ONE render.
// This is the issue's actual complaint: "a node parked SECONDARY 'awaiting
// kernel promote' is indistinguishable from one demoted by a monitor failure or
// manual failover".
func TestKernelHoldIsSeparableFromMonitorFailureAndManualFailover(t *testing.T) {
	m := NewManager(0, 1)
	m.UpdateConfig(makeConfig(makeRG(0, false, map[int]int{0: 200})))
	m.SetKernelUpgradeHold(KernelUpgradeHoldCandidate)

	out := m.FormatStatus()
	hold := heldStatusLine(t, out)
	if hold == "" {
		t.Fatalf("no hold line:\n%s", out)
	}
	// The hold reports on its OWN axis, not by borrowing the monitor-failure or
	// manual-failover columns — otherwise an operator reading those columns
	// would be told a fault exists that does not.
	if !strings.Contains(out, "Monitor-failures") {
		t.Fatalf("no status table rendered:\n%s", out)
	}
	for _, ln := range strings.Split(out, "\n") {
		if !strings.HasPrefix(ln, "node") {
			continue
		}
		if strings.Contains(ln, "kernel") {
			t.Errorf("the kernel hold leaked into a node row's columns — an "+
				"operator reading Monitor-failures would see a fault that does "+
				"not exist: %q", ln)
		}
	}
}

// The hold must NOT be folded into node health. The node is healthy; it is
// deliberately not eligible. Reporting it as degraded would send an operator
// chasing a fault that does not exist.
func TestKernelUpgradeHoldDoesNotDegradeNodeHealth(t *testing.T) {
	for _, reason := range []string{KernelUpgradeHoldCandidate, KernelUpgradeHoldUnreadableJournal} {
		m := NewManager(0, 1)
		m.SetKernelUpgradeHold(reason)
		got := m.FormatInformation()
		found := false
		for _, ln := range strings.Split(got, "\n") {
			if strings.HasPrefix(strings.TrimSpace(ln), "Local node:") {
				found = true
				if strings.Contains(ln, "degraded") {
					t.Errorf("hold %q degraded node health: %q", reason, ln)
				}
			}
		}
		if !found {
			t.Fatalf("no `Local node:` health line in:\n%s", got)
		}
	}
}

// Clearing the hold clears BOTH the flag and the reason. A status that keeps
// reporting a released hold is worse than one that never reported it: the
// operator would wait for a gate that already finished.
func TestClearingTheHoldClearsTheAnnotationAndReason(t *testing.T) {
	m := NewManager(0, 1)
	m.SetKernelUpgradeHold(KernelUpgradeHoldCandidate)
	m.ClearKernelUpgradeHold()
	if got := m.FormatStatus(); strings.Contains(got, "Held secondary") {
		t.Errorf("a released hold is still annotated:\n%s", got)
	}
	if r := m.KernelUpgradeHoldReason(); r != "" {
		t.Errorf("KernelUpgradeHoldReason() = %q after clear, want \"\"", r)
	}
}

// An unheld manager must report no reason — so a caller cannot render a stale
// string from a previous hold.
func TestKernelUpgradeHoldReasonIsEmptyWhenNotHeld(t *testing.T) {
	m := NewManager(0, 1)
	if r := m.KernelUpgradeHoldReason(); r != "" {
		t.Errorf("KernelUpgradeHoldReason() = %q on an unheld node", r)
	}
}

// Re-setting with a different reason must take effect: the daemon converts a
// fail-closed hold into an armed hold in place when the journal becomes
// readable and a candidate IS armed.
func TestResettingTheHoldUpdatesTheReasonInPlace(t *testing.T) {
	m := NewManager(0, 1)
	m.SetKernelUpgradeHold(KernelUpgradeHoldUnreadableJournal)
	m.SetKernelUpgradeHold(KernelUpgradeHoldCandidate)
	if !m.KernelUpgradeHeld() {
		t.Fatal("re-setting the hold must leave it held")
	}
	if got := m.KernelUpgradeHoldReason(); got != KernelUpgradeHoldCandidate {
		t.Errorf("reason = %q, want the candidate reason — a node whose journal "+
			"became readable would keep being reported as unreadable", got)
	}
}

// The annotation must not be parseable as a node row.
//
// deploy_rolling_secondary_node (test/incus/deploy-lib.sh — the authoritative
// parser; this guards the OUTPUT it consumes, not a copy of it) picks the RG0
// secondary by awk-matching `$1 == "node0"` INSIDE a "Redundancy group: N"
// block, and a rolling cluster deploy uses the answer to decide which node to
// restart first. A line it misread would restart the PRIMARY first and cause a
// spurious mid-deploy failover (#4009).
func TestHoldAnnotationCannotBeMistakenForANodeRow(t *testing.T) {
	m := NewManager(0, 1)
	m.SetKernelUpgradeHold(KernelUpgradeHoldCandidate)
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
