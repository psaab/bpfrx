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
	v.IngressIfindex = 0
	v.IngressVlanID = 0
	// #8612: FibGen is CONDITIONALLY node-local, and which condition holds is
	// what LogFlagUserspaceTunnelEndpoint says.
	//
	// As a FIB generation it is node-local and must be zeroed. But
	// daemon_ha_userspace_convert.go OVERLOADS it: under this flag it carries a
	// tunnel endpoint id, and that id is the OPPOSITE of node-local. It is
	// `config.StableTunnelEndpointID(ifName)` -- FNV-1a over the interface NAME
	// alone, never over runtime state -- and pkg/config/tunnelid.go says why in
	// terms that name this very field:
	//
	//	THE FOLD IS WIRE-ADJACENT AND MUST NEVER CHANGE (#1873): tunnel
	//	endpoint ids cross the cluster as bare numbers (SessionValue.FibGen
	//	in pkg/cluster/sync_protocol.go), and both HA nodes must compute
	//	identical ids from identical config. ... both nodes agree by
	//	construction.
	//
	// So the value under this flag is not merely SAFE to carry across the
	// cluster, it is PURPOSE-BUILT to, and pkg/cluster/sync_protocol.go really
	// does encode it on the wire. #7097's scrub swept the field up by name
	// without the overload in view, and #8613 then resolved the resulting
	// flag/value inconsistency in the destructive direction -- clearing the bit
	// as well -- which made the invariant true by completing the erasure.
	//
	// Preserving both satisfies the same invariant in the direction that keeps
	// the datum: flag set implies value present, because both survive.
	//
	// What the erasure cost: with FibGen zeroed, sessionSyncEgressLocked(0) and
	// sessionSyncTunnelEndpointIDLocked(0) both seed from a scrubbed ifindex and
	// return 0, the carried override at manager_sessionsync_request.go declines
	// on `FibGen != 0`, and the Rust side's
	// lookup_forwarding_resolution_for_session_with_cache branches on
	// `tunnel_endpoint_id != 0` at its top -- so a peer-imported tunnel session
	// was resolved as if it were not a tunnel session at all, with no
	// resolve_tunnel_outer underlay resolution. The #1873 stale-id guard sits
	// inside that same branch and was dead code for the population.
	//
	// A receiver that does not have the named tunnel is safe by construction:
	// the id resolves through a NAME both nodes fold identically, so an id for a
	// tunnel this node lacks simply misses the TunnelEndpoints lookup and local
	// re-derivation stands. Builder-side fold collisions are already refused
	// deterministically (#1873 drops the later-sorting tunnel), identically on
	// both nodes.
	if v.LogFlags&LogFlagUserspaceTunnelEndpoint == 0 {
		v.FibGen = 0
	}
}

// ScrubNodeLocal is the IPv6 twin. The two structs are separate declarations
// with separate field sets, so this is a separate list — but both are reached
// by the same census test, which is the point.
func (v *SessionValueV6) ScrubNodeLocal() {
	v.FibIfindex = 0
	v.FibVlanID = 0
	v.FibDmac = [6]byte{}
	v.FibSmac = [6]byte{}
	v.IngressIfindex = 0
	v.IngressVlanID = 0
	// #8612: see the v4 twin. FibGen is CONDITIONALLY node-local -- a node-local
	// FIB generation with the bit clear, a cluster-stable
	// StableTunnelEndpointID with it set -- so it is zeroed only in the former
	// case and the flag is left alone.
	if v.LogFlags&LogFlagUserspaceTunnelEndpoint == 0 {
		v.FibGen = 0
	}
}
