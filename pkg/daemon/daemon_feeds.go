package daemon

import "github.com/psaab/xpf/pkg/config"

// feedSnapshotSetter caches the dynamic-address feed-prefix overlay for the
// next full snapshot build (#2049). Implemented by the userspace dataplane
// manager (SetFeedSnapshots), mirroring routeOverlaySetter.
type feedSnapshotSetter interface {
	SetFeedSnapshots(map[string][]string)
}

// feedSnapshotsForConfig joins the INCOMING config's dynamic-address bindings
// to the live feed snapshots held by the feed manager (#2049). The result is
// an address-name -> union-of-feed-CIDRs overlay that the dataplane manager
// merges into the address book the AF_XDP helper enforces.
//
// Filtering against cfg (not the active config) means a commit that REMOVES or
// edits a binding stops enforcing the removed feed — the overlay only carries
// names that the incoming config still binds. Returns nil when there is no
// feed manager or the config declares no bindings, in which case the dataplane
// clears its overlay (no feed-backed names to enforce).
func (d *Daemon) feedSnapshotsForConfig(cfg *config.Config) map[string][]string {
	if d == nil || d.feeds == nil || cfg == nil {
		return nil
	}
	if len(cfg.Security.DynamicAddress.AddressBindings) == 0 {
		return nil
	}
	return d.feeds.SnapshotForBindings(&cfg.Security.DynamicAddress)
}
