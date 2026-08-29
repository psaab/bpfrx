package dataplane

// Node-local session fields, and the single place they are stripped (#7097).
//
// A chassis-cluster session installed from a PEER carries the peer's view of
// values that only mean something on the node that produced them. Two classes
// exist on SessionValue / SessionValueV6:
//
//   - the cached FIB result (FibIfindex, FibVlanID, FibDmac, FibSmac, FibGen) —
//     the resolved EGRESS of a lookup the ORIGINATING node performed against
//     ITS routing and neighbour state;
//   - the #4983 ingress identity (IngressIfindex, IngressVlanID) — the binding
//     the session's first packet arrived on, on the originating node.
//
// Both are ifindex-shaped, and an ifindex is node-local: node 0's `ge-0-0-1`
// and node 1's `ge-7-0-1` are different numbers for the same logical RETH
// member. Adopting a peer's number does not degrade the answer, it INVERTS it —
// `show security flow session interface <name>` would name a confidently WRONG
// interface, which is strictly worse than the zero the consumer falls back on
// (it approximates from the ingress zone instead, exactly as it did before
// #4983). docs/session-sync-architecture.md states this contract.
//
// #7097 is what happens when that contract is enforced by a hand-maintained
// list at each install site instead of one function. #6928 added the ingress
// pair to the ABI; the FIB list at all FOUR peer-install sites — the v4 and v6
// store fallbacks in session_store.go and the v4 and v6 userspace-manager
// installers in pkg/dataplane/userspace/manager_sessions.go — silently stopped
// covering the node-local field class it was written to cover, in the same
// change, at every site, because there was nothing to notice. Nothing reached
// those sites with a non-zero value (pkg/cluster's session wire never encodes
// the pair, so a decoded peer row has it at 0), so it was latent rather than
// live; a defence-in-depth list going quietly incomplete is the failure mode
// the list exists to prevent, not a reason to leave it incomplete.
//
// So there is now ONE list. A future node-local field is added here and every
// install site gets it; a site that grows its own list again is what
// TestClusterSyncedInstallSitesDelegateTheScrub7097 fails on.

// ScrubNodeLocal zeroes every field of the value that is meaningful only on the
// node that produced it. Call it on a COPY destined for the local session maps
// when the row is owned by the cluster peer.
func (v *SessionValue) ScrubNodeLocal() {
	v.FibIfindex = 0
	v.FibVlanID = 0
	v.FibDmac = [6]byte{}
	v.FibSmac = [6]byte{}
	v.FibGen = 0
	v.IngressIfindex = 0
	v.IngressVlanID = 0
}

// ScrubNodeLocal is the IPv6 twin. The two structs are separate declarations
// with separate field sets, so this is a separate list — but both are reached
// by the same census test, which is the point.
func (v *SessionValueV6) ScrubNodeLocal() {
	v.FibIfindex = 0
	v.FibVlanID = 0
	v.FibDmac = [6]byte{}
	v.FibSmac = [6]byte{}
	v.FibGen = 0
	v.IngressIfindex = 0
	v.IngressVlanID = 0
}
