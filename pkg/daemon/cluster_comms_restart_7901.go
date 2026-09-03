package daemon

// Cluster-comms restart debt (#7901).
//
// A teardown that does NOT restart comms owes one, and this is where that debt
// lives. Split out of daemon_ha_sync.go rather than taken as a modularity
// exemption: the flag, its two accessors and the reasoning for the one-shot
// shape are a self-contained unit, and the file it came from crossed the 1500
// LOC WATCH floor on this change.

// markClusterCommsRestartNeeded records that comms were torn down WITHOUT a
// restart, so the next apply must bring them back.
//
// #7901: bootstrap.go's rollback teardown is a genuine stop-without-start -- it
// calls stopClusterComms and RETURNS -- and the only other production
// startClusterComms site is daemon_run.go's boot path. Recovery therefore
// depended on the corrected commit happening to MOVE a transport endpoint:
//
//	corrected commit, key DIFFERS:    restarts=1  -> comms recover
//	corrected commit, key IDENTICAL:  restarts=0  -> comms stay DOWN
//
// This is a ONE-SHOT flag rather than a "are comms down?" predicate, and that
// distinction is the whole design. Making step 20 restart whenever comms are
// down fires on EVERY apply in that state, which breaks two deliberately
// asserted properties: a key commit must not restart comms (#5078 -- it drops
// the session-sync connection at the moment the primary becomes keyed, the only
// path by which the key reaches a config read-only secondary, and the rollout
// deadlocks), and an unchanged transport must not restart (#6878 -- step 20
// firing on every apply makes that test's completion assertion pass for the
// wrong reason). Measured: the broad form reds three cells across those two
// issues.
func (d *Daemon) markClusterCommsRestartNeeded() {
	d.clusterCommsMu.Lock()
	defer d.clusterCommsMu.Unlock()
	d.clusterCommsRestartNeeded = true
}

// takeClusterCommsRestartNeeded consumes the flag, returning whether a restart
// is owed. Consuming rather than reading keeps it to a single recovery: a
// second apply must not restart comms again for the same teardown.
func (d *Daemon) takeClusterCommsRestartNeeded() bool {
	d.clusterCommsMu.Lock()
	defer d.clusterCommsMu.Unlock()
	owed := d.clusterCommsRestartNeeded
	d.clusterCommsRestartNeeded = false
	return owed
}
