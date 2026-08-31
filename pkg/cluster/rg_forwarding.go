package cluster

import "fmt"

// RGForwarding is the DATAPLANE-side view of one redundancy group, supplied by
// the daemon through SetRGForwardingFunc.
//
// #7367: `show chassis cluster status` renders the cluster state machine's view
// and only that — LocalPriority, State, preempt, manual, monitor-fails. None of
// those terms says whether the node is actually FORWARDING. That is not a
// cosmetic gap: rgStateMachine.reconcileLocked computes
// `desired = clusterPri || allMasterLocked()` in non-strict mode, so ownership
// and forwarding are an OR rather than an identity, and "primary but receiving
// nothing" is a representable state that renders as a completely healthy
// cluster on both nodes at once.
type RGForwarding struct {
	// Active is rg_active as the daemon last APPLIED it to the dataplane —
	// rgStateMachine.IsActive(), not the desired value. The distinction is
	// the whole point: a node whose desired state is active but whose apply
	// failed is exactly the case this render exists to surface.
	Active bool

	// AllVRRPMaster reports whether this node is VRRP master on EVERY member
	// interface of the group. Partial mastership is the shape that produces a
	// split forwarding path, so it is tracked separately from Active rather
	// than folded into it.
	AllVRRPMaster bool

	// AnyVRRPMaster reports whether this node is VRRP master on at least one
	// member interface. Together with AllVRRPMaster this distinguishes "no
	// mastership" from "partial mastership"; a single bool cannot.
	AnyVRRPMaster bool
}

// RGForwardingVerdict is the classification of an (ownership, forwarding) pair.
type RGForwardingVerdict int

const (
	// RGForwardingConsistent: ownership and forwarding agree.
	RGForwardingConsistent RGForwardingVerdict = iota
	// RGForwardingOwnedNotForwarding: this node owns the RG but is not
	// forwarding for it. This is the #6656 incident's shape — node0 showed
	// primary for RG0/RG1/RG2 with 1 session and 4,728 rx packets while node1
	// carried 33 sessions and 4,675,178.
	RGForwardingOwnedNotForwarding
	// RGForwardingForwardingNotOwned: this node is forwarding for an RG it
	// does not own. The dual-active direction; the more dangerous of the two.
	RGForwardingForwardingNotOwned
	// RGForwardingPartialVRRP: this node is VRRP master on some but not all
	// member interfaces, so the forwarding path is split across the pair
	// regardless of what ownership says.
	RGForwardingPartialVRRP
)

// ClassifyRGForwarding compares an RG's OWNERSHIP against its FORWARDING state.
//
// Extracted as a named function rather than inlined into FormatStatus so the
// verdict can be tested without asserting on rendered text: a guard that can
// only be reached through a Fprintf is a guard whose mutation coverage depends
// on string formatting, and the property here is not a formatting property.
func ClassifyRGForwarding(owned bool, fwd RGForwarding) RGForwardingVerdict {
	// Partial mastership is reported ahead of the ownership comparison. It is
	// a defect under EITHER ownership value — a node that owns the group is
	// forwarding on only some members, and one that does not is holding VIPs
	// it should have resigned — so classifying it by ownership would file the
	// same wire condition under two different verdicts and hide half of them.
	if fwd.AnyVRRPMaster && !fwd.AllVRRPMaster {
		return RGForwardingPartialVRRP
	}
	switch {
	case owned && !fwd.Active:
		return RGForwardingOwnedNotForwarding
	case !owned && fwd.Active:
		return RGForwardingForwardingNotOwned
	default:
		return RGForwardingConsistent
	}
}

// String renders the verdict for the operator.
//
// The DIVERGENCE strings deliberately avoid the tokens "primary" and
// "secondary". `show chassis cluster status` is parsed by whole-line regexes in
// the smoke harness — test-failover.sh greps `node1.*primary` over the entire
// output, and deploy-lib.sh awk-matches `$1 == "node0"` then reads `$3` — so a
// line carrying a node token next to a state token can be read as a node row
// and steer a rolling deploy into restarting the PRIMARY first (#4009).
func (v RGForwardingVerdict) String() string {
	switch v {
	case RGForwardingOwnedNotForwarding:
		return "DIVERGENCE: this node owns the group but is not forwarding for it"
	case RGForwardingForwardingNotOwned:
		return "DIVERGENCE: this node is forwarding for a group it does not own"
	case RGForwardingPartialVRRP:
		return "DIVERGENCE: VRRP master on only some member interfaces"
	default:
		return "consistent"
	}
}

// FormatRGForwarding renders the forwarding sub-line's value.
func FormatRGForwarding(owned bool, fwd RGForwarding) string {
	active := "inactive"
	if fwd.Active {
		active = "active"
	}
	vrrp := "none"
	switch {
	case fwd.AllVRRPMaster:
		vrrp = "all"
	case fwd.AnyVRRPMaster:
		vrrp = "partial"
	}
	v := ClassifyRGForwarding(owned, fwd)
	s := fmt.Sprintf("rg-active=%s vrrp-master=%s", active, vrrp)
	if v != RGForwardingConsistent {
		s += " -- " + v.String()
	}
	return s
}
