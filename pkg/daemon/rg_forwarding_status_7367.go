package daemon

import "github.com/psaab/xpf/pkg/cluster"

// rgForwardingStatus reports a redundancy group's DATAPLANE-side state to the
// cluster manager's `show chassis cluster status` render.
//
// #7367: the status render carried no forwarding term, so a node that owns an
// RG while forwarding nothing for it was indistinguishable from a healthy
// primary — the shape of the #6656 incident, which showed a healthy cluster on
// both nodes at once.
//
// Deliberately a READ-ONLY lookup, not getOrCreateRGState: this runs from an
// operator command, and a `show` must never bring a state machine into
// existence as a side effect. A group with no state machine reports ok=false so
// the render OMITS the line rather than printing a zero value, which would
// assert "not forwarding" about a group whose forwarding state is simply
// unknown here.
func (d *Daemon) rgForwardingStatus(rgID int) (cluster.RGForwarding, bool) {
	d.rgStatesMu.RLock()
	s := d.rgStates[rgID]
	d.rgStatesMu.RUnlock()
	if s == nil {
		return cluster.RGForwarding{}, false
	}
	// IsActive is the APPLIED value, not DesiredActive. The distinction is the
	// point of the render: a group whose desired state is active but whose
	// apply failed is exactly the divergence being surfaced, and reporting the
	// desired value would render it as healthy.
	return cluster.RGForwarding{
		Active:        s.IsActive(),
		AllVRRPMaster: s.AllVRRPMaster(),
		AnyVRRPMaster: s.AnyVRRPMaster(),
	}, true
}
