package daemon

import (
	"github.com/psaab/xpf/pkg/cluster"
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
// already import pkg/cluster.) The reason STRING is
// cluster.KernelUpgradeHoldReason, the same constant `show chassis cluster
// status` renders, so the two surfaces cannot phrase one hold two ways and
// leave an operator comparing them mid-roll to guess whether they mean the
// same thing.
func (d *Daemon) kernelUpgradeStatus() upgrade.ChannelStatus {
	st := upgrade.ReadChannelStatus(upgrade.DefaultKernelJournalPath,
		upgrade.NewKernelSystem())
	if d.cluster != nil && d.cluster.KernelUpgradeHeld() {
		st.HoldReason = cluster.KernelUpgradeHoldReason
	}
	return st
}
