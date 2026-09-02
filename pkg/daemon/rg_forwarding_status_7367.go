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
	// #8326: AppliedActive, not IsActive. The comment that stood here asserted
	// "IsActive is the APPLIED value, not DesiredActive" and was FALSE --
	// IsActive returns s.active (desired) and DesiredActive returned the same
	// field, so there was no distinction to draw. The sentence named the exact
	// failure it caused: a group whose desired state is active but whose apply
	// failed rendered as healthy, which is the divergence this surface exists
	// to show. It was reassuring enough that a reviewer checking this precise
	// question would have stopped reading.
	return cluster.RGForwarding{
		Active:        s.AppliedActive(),
		AllVRRPMaster: s.AllVRRPMaster(),
		AnyVRRPMaster: s.AnyVRRPMaster(),
	}, true
}
