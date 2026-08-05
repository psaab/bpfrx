package daemon

import "github.com/psaab/xpf/pkg/dataplane"

// setDataplane installs (or clears) the runtime dataplane AND the external
// consumers' facade in one step (#5275 PR2).
//
// It exists so the two cannot drift. Before the facade, `d.dp = nil` was the
// daemon's whole "drop the dataplane" gesture — and it did not reach the
// aliases gRPC/REST/CLI had already captured. Now dropping the dataplane also
// REVOKES the handle those consumers hold, so a single assignment site cannot
// half-close the door.
//
// Revoking the OLD facade rather than only replacing the pointer matters: a
// consumer constructed earlier still points at the old facade object, so
// leaving it live would leave exactly the alias this change removes.
func (d *Daemon) setDataplane(dp dataplane.RuntimeDataPlane) {
	if d.dpFacade != nil {
		d.dpFacade.Revoke()
	}
	d.dp = dp
	if dp == nil {
		d.dpFacade = nil
		return
	}
	d.dpFacade = newDataplaneFacade(dp)
}
