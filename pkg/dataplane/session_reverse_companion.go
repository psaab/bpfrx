package dataplane

// The reverse companion's "not yet observed" reset (#7917).
//
// When a forward session is installed, a REVERSE companion is synthesized for
// it so the reply direction is already present before it is needed. The
// companion is built by copying the forward value and adjusting the parts that
// are direction-dependent — the zone pair is swapped, `IsReverse` is set, and
// `ReverseKey` points back.
//
// Some fields must additionally be CLEARED, because they record an OBSERVATION
// the reverse direction has not made yet:
//
//   - the cached FIB result. It is the forward direction's resolved egress; the
//     reply's egress is a different lookup and must be re-resolved locally.
//   - the #4983 ingress identity. `pkg/dataplane/types.go` names the reverse
//     companion as the first legitimate-`0` population and gives the reason:
//     "its own ingress has not been OBSERVED yet ... the forward flow's egress
//     IS known at install — it is the wrong datum, being a PREDICTION of where
//     the reply will arrive rather than an OBSERVATION of where it did, and
//     routing may be asymmetric."
//
// WHY THIS IS NOT `ScrubNodeLocal` (#7097), THE OTHER RESET OVER THESE FIELDS.
// The two overlap but are different rules, and as of #7095 they no longer even
// cover the same fields:
//
//   - `ScrubNodeLocal` strips values that BELONG TO ANOTHER NODE. It must NOT
//     touch `IngressIfaceFold`, whose entire purpose is to be cluster-stable and
//     cross the wire so the #4983 identity survives a failover.
//   - this reset strips values the reverse direction HAS NOT OBSERVED. It MUST
//     clear `IngressIfaceFold`, because "where the first packet arrived" is
//     exactly as unobserved for the reply as the node-local ifindex is — and the
//     helper wire request derives its ingress identity FROM the fold
//     (`buildSessionSyncRequestV4` -> `resolveIngressFold`), so leaving it set
//     stamps the FORWARD direction's ingress binding onto the companion.
//
// Folding the two would make every future node-local field automatically a
// reverse-companion reset, and every future companion reset automatically a
// cross-node scrub. Neither implication holds.
// `TestCompanionResetAndNodeLocalScrubAreDifferentRules7917` pins the divergence.

// ResetUnobservedForReverseCompanion clears every field that records something
// the REVERSE direction has not observed yet. Call it on the copy destined to
// become a forward session's reverse companion, after the zone swap.
func (v *SessionValue) ResetUnobservedForReverseCompanion() {
	// Forward egress — the reply's egress is a separate lookup.
	v.FibIfindex = 0
	v.FibVlanID = 0
	v.FibDmac = [6]byte{}
	v.FibSmac = [6]byte{}
	v.FibGen = 0
	// Forward ingress — where the reply will arrive is a prediction, not an
	// observation, and routing may be asymmetric.
	v.IngressIfindex = 0
	v.IngressVlanID = 0
	v.IngressIfaceFold = 0
}

// ResetUnobservedForReverseCompanion is the IPv6 twin.
func (v *SessionValueV6) ResetUnobservedForReverseCompanion() {
	v.FibIfindex = 0
	v.FibVlanID = 0
	v.FibDmac = [6]byte{}
	v.FibSmac = [6]byte{}
	v.FibGen = 0
	v.IngressIfindex = 0
	v.IngressVlanID = 0
	v.IngressIfaceFold = 0
}
