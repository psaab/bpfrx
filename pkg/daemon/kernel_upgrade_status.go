package daemon

import (
	"github.com/psaab/xpf/pkg/upgrade"
)

// kernelUpgradeStatus assembles the operator-facing #1930 kernel-channel state
// for `show system kernel-upgrade` (#6495).
//
// It is a named method rather than a closure at each wiring site for the same
// reason as bootstrapShowSnapshot: there are TWO sites (the gRPC server config
// and the in-process CLI hook), and a hand-copied assembly that diverged would
// show an operator two different answers about one node mid-roll — the exact
// thing the shared renderer exists to prevent.
//
// Read-only. It loads the durable journal, the promotion marker and the
// last-roll record, and mutates nothing, so it is safe at operator polling
// frequency.
//
// The cluster hold is added HERE and not inside pkg/upgrade because the
// election hold is cluster state, not channel state: pkg/upgrade records what
// was armed, pkg/cluster decides what that means for eligibility, and only the
// daemon holds both. (It is also a literal import cycle — pkg/upgrade's tests
// already import pkg/cluster.) The reason comes from
// Manager.KernelUpgradeHoldReason(), the SAME value `show chassis cluster
// status` renders, so the two surfaces cannot phrase one hold two ways — nor
// name the WRONG one of the two holds — and leave an operator comparing them
// mid-roll to guess which applies.
func (d *Daemon) kernelUpgradeStatus() upgrade.ChannelStatus {
	// d.newKernelSystem(), not upgrade.NewKernelSystem() directly: that is the
	// package's injectable seam (kernelSystemFn), and bypassing it made this
	// path untestable and inconsistent with the rest of the file.
	st := upgrade.ReadChannelStatus(upgrade.DefaultKernelJournalPath,
		d.newKernelSystem())
	// The REASON, not a literal. The manager holds for two different conditions
	// and KernelUpgradeHeld() alone cannot tell them apart, so asking it for the
	// reason is what keeps this surface and `show chassis cluster status`
	// agreeing about WHICH hold is in force (#6495).
	if d.cluster != nil {
		st.HoldReason = d.cluster.KernelUpgradeHoldReason()
	}
	return st
}
