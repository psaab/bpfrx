package daemon

import (
	"bytes"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/upgrade"
)

// #6495: the hold string must AGREE across the two surfaces.
//
// `show chassis cluster status` renders cluster.KernelUpgradeHoldReason
// directly; `show system kernel-upgrade` renders whatever the daemon puts in
// ChannelStatus.HoldReason. pkg/upgrade cannot import pkg/cluster (its own
// tests already import pkg/cluster — a cycle), so the constant is carried
// across HERE, and here is the only place both are reachable to assert they
// are the same string.
//
// This is the agreement, not one copy of it: an operator comparing the two
// commands mid-roll must not have to decide whether two phrasings mean one
// hold. RED on revert: substitute a literal in kernelUpgradeStatus and the
// equality below flips while both commands still "work".
func TestKernelUpgradeHoldReasonAgreesAcrossSurfaces(t *testing.T) {
	m := cluster.NewManager(0, 1)
	m.SetKernelUpgradeHold()
	d := &Daemon{cluster: m}

	st := d.kernelUpgradeStatus()
	if st.HoldReason == "" {
		t.Fatal("a held node reported no hold reason in the kernel-upgrade " +
			"status — the operator sees the node parked SECONDARY with nothing " +
			"naming the gate")
	}
	if st.HoldReason != cluster.KernelUpgradeHoldReason {
		t.Fatalf("hold reason diverged between surfaces:\n"+
			"  show system kernel-upgrade: %q\n"+
			"  show chassis cluster status: %q",
			st.HoldReason, cluster.KernelUpgradeHoldReason)
	}

	// Both RENDERS must carry it, not just the struct field.
	var chan_ bytes.Buffer
	upgrade.RenderChannelStatus(&chan_, st)
	if !strings.Contains(chan_.String(), cluster.KernelUpgradeHoldReason) {
		t.Errorf("`show system kernel-upgrade` does not render the hold "+
			"reason:\n%s", chan_.String())
	}
	if !strings.Contains(m.FormatStatus(), cluster.KernelUpgradeHoldReason) {
		t.Errorf("`show chassis cluster status` does not render the hold reason")
	}
}

// An UNHELD node must report no hold. A status that always claims a hold is
// worse than one that never does: mid-roll the operator would wait for a gate
// that is not there.
func TestKernelUpgradeStatusReportsNoHoldWhenNotHeld(t *testing.T) {
	m := cluster.NewManager(0, 1)
	d := &Daemon{cluster: m}
	if got := d.kernelUpgradeStatus(); got.HoldReason != "" {
		t.Errorf("unheld node reported HoldReason = %q", got.HoldReason)
	}
}

// A standalone (non-clustered) daemon must not panic reaching for a cluster
// manager that does not exist. `show system kernel-upgrade` is a day-0-relevant
// command and a standalone box is the common case.
func TestKernelUpgradeStatusOnAStandaloneDaemon(t *testing.T) {
	d := &Daemon{}
	st := d.kernelUpgradeStatus()
	if st.HoldReason != "" {
		t.Errorf("standalone daemon reported a cluster hold: %q", st.HoldReason)
	}
	var b bytes.Buffer
	upgrade.RenderChannelStatus(&b, st)
	if b.Len() == 0 {
		t.Error("standalone daemon rendered nothing")
	}
}
