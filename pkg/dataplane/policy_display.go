package dataplane

// Session policy-name display resolution.
//
// A session row carries the admitting policy as a bare `policy_id` u32
// (SessionValue.PolicyID, stamped by the userspace dataplane per #3056). Two
// values in that space are RESERVED and do not name a configured policy;
// resolving either one through the compiled rule-id -> name map produces a
// confident, wrong attribution. Every session-row display surface must go
// through SessionPolicyName rather than indexing the map directly.

// UnattributedPolicyID is the `policy_id` a session carries when no configured
// security policy admitted it (#4626 L01).
//
// It is ZERO, which is also the id of the literal first configured policy
// (PolicySetID 0, rule index 0 — see compilePolicies' `policySetID*
// MaxRulesPerPolicy + i`). The value is genuinely OVERLOADED on the wire, and
// nothing else on the session distinguishes the two readings: SessionValue's
// flag bits are NAT-only (SessFlagSNAT/DNAT/StaticNAT/NAT64/NPTV6), so there is
// no host-inbound / fabric / tunnel marker to disambiguate against.
//
// Who carries it, and it is not a rare population:
//
//   - non-policy-forwarded sessions — host-inbound, neighbor-seed, fabric and
//     tunnel installs all stamp 0 (userspace-dp publish_conntrack.rs: "`0` stays
//     the value for non-policy-forwarded sessions");
//   - every pre-#3056 session, which only ever carried the bare wire scalar;
//   - every session synced from an OLDER HA peer during a rolling upgrade —
//     that is the peer's WHOLE table, not a corner case.
//
// Retiring the overload means reserving the id space so real policies start at
// 1, which is a cross-plane change (userspace-dp `policy.rs`, the #3056 stamping
// path, the runtime-id assignment, HA wire compatibility) tracked as the
// remaining half of #4626 and deliberately NOT done here. Note that reserving
// the space would still not repair an old peer's sessions during the upgrade
// window — it keeps sending a bare 0 — so a render-side guard is required
// either way and is not made redundant by that work.
const UnattributedPolicyID uint32 = 0

// UnattributedPolicyName is rendered in place of a policy name for a session
// carrying UnattributedPolicyID.
//
// This is deliberately an UNDER-claim. Because the wire value is ambiguous,
// every possible rendering is wrong for one of the two populations: naming the
// first configured policy is wrong for every host-inbound/fabric/tunnel/synced
// session, and naming this pseudo-policy is wrong for the first policy's own
// sessions. Under-claiming is the safer error on a security surface — an
// operator who sees "unattributed" investigates, whereas one who sees a real
// policy name on a host-inbound session draws a false conclusion about which
// rule admitted traffic and may leave a policy in place believing it is load
// bearing. It is also the direction the codebase already chose for this exact
// overload on the behavioral path: deletedPolicyRuntimeIDs excludes id 0 from
// the deletion-clear as a documented "fail-SAFE under-clear"
// (pkg/daemon/daemon_policy_invalidate.go). The display should not claim a
// precision the wire cannot support while the enforcement path refuses to.
//
// The numeric id is still shown beside the name on every surface (the CLI
// prints `Policy name: <name>/<id>`; REST and gRPC carry PolicyID as its own
// field), so nothing is hidden by this substitution.
const UnattributedPolicyName = "unattributed"

// SessionPolicyName resolves a session's PolicyID to the policy name a display
// surface should render, honouring both reserved ids before consulting the
// compiled map.
//
// policyNames is the compiled rule-id -> name map (CompileResult.PolicyNames);
// a nil map is fine and is the normal state before the first apply publishes
// one. Callers keep their own not-found behaviour for an unreserved id that is
// simply absent — this returns "" for that case exactly as a direct map index
// did, so the CLI's numeric fallback and REST/gRPC's empty field are unchanged.
//
// DefaultPolicySentinelID is handled here as well. compilePolicies seeds the map
// with it, so on the published path a direct index already resolved it; taking
// it authoritatively means a session row rendered before any apply (nil map)
// cannot fall through to a raw "4294967295" either. That is belt-and-braces for
// the unpublished-map case, not a change to the normal path, and it matches how
// pkg/logging resolvePolicyName treats the same sentinel for RT_FLOW records
// (#3057).
func SessionPolicyName(policyNames map[uint32]string, id uint32) string {
	// LOAD-BEARING ORDERING: the reserved check must come BEFORE the map
	// lookup, and must not be "rewritten" as a lookup with a fallback.
	// `policyNames[0]` is POPULATED — it is the first configured policy — so
	// any form that consults the map first silently restores the #4626
	// misattribution while still looking like a guard.
	if name, ok := ReservedPolicyName(id); ok {
		return name
	}
	return policyNames[id]
}

// ReservedPolicyName reports whether `id` is one of the two reserved policy ids
// and, if so, the fixed pseudo-policy name that must be rendered for it.
//
// This is the SSOT for "which ids must never reach a name map", shared by every
// resolver: the session-row surfaces via SessionPolicyName, the cluster-peer
// fan-out via PeerSessionPolicyName, and pkg/logging's RT_FLOW record resolver,
// which keeps its own numeric fallback for an unreserved id and so cannot call
// SessionPolicyName directly.
//
// Expressed as an explicit (name, ok) rather than leaving each caller to
// re-derive the set: a caller that instead probed `SessionPolicyName(nil, id)`
// for a non-empty result would get the right answer today only because a nil
// map yields "" for every unreserved id — a property no one is obliged to
// preserve, and whose loss would silently route unreserved ids away from the
// caller's own map.
func ReservedPolicyName(id uint32) (string, bool) {
	switch id {
	case UnattributedPolicyID:
		return UnattributedPolicyName, true
	case DefaultPolicySentinelID:
		return DefaultPolicyName, true
	default:
		return "", false
	}
}

// PeerSessionPolicyName resolves the policy name to render for a session
// fetched from a CLUSTER PEER, given the name that peer already resolved and
// the session's raw id.
//
// #6851: an include_peer fan-out attaches the peer's response and the peer
// resolved the name itself. A peer running a pre-#4626 build resolved
// UnattributedPolicyID through its own compiled map and therefore sent the name
// of ITS first configured policy — so the local guard, which only covers
// sessions this node renders, is bypassed entirely by a name arriving as DATA.
// The wrong attribution is then republished on every local surface (gRPC
// clients, the REST `peer` block via sessionListFromPB, and the CLI).
//
// The choice made here, and WHY it is not "re-resolve everything from the id":
// policy ids are NODE-LOCAL. `compilePolicies` assigns them from the local
// config's rule ordering, so the peer's id space is the peer's, and the peer is
// authoritative for the names of its OWN sessions. Re-resolving an unreserved
// peer id against the LOCAL policyNames map would name whichever local policy
// happens to occupy that slot — a fresh misattribution, and one that fires on
// every mixed-config cluster rather than only on an old peer.
//
// So only the RESERVED ids are overridden, and the peer's name is kept for
// everything else. The two behave identically when the peer is the same
// version (it already sends `unattributed` / `default-policy` for those ids);
// they differ only for an older peer, which is exactly the population that
// needs correcting. An empty peerName for an unreserved id stays empty, so a
// caller's own not-found handling is unchanged.
//
// WHERE THIS IS BOUND (#6851 review): there is no direct unit test of this
// function in pkg/dataplane. The reserved-before-peer-name ordering documented
// above is bound TRANSITIVELY — reversing it reds pkg/cli and pkg/grpcapi while
// pkg/dataplane stays green. The property is covered; it is just not covered in
// the package where it is documented, so do not go looking for the guard here.
func PeerSessionPolicyName(peerName string, id uint32) string {
	// Same LOAD-BEARING ordering as SessionPolicyName: the reserved check must
	// precede any use of peerName. A form that trusts a non-empty peerName
	// first restores the misattribution for exactly the old-peer population
	// this exists for, while still looking like a guard.
	if name, ok := ReservedPolicyName(id); ok {
		return name
	}
	return peerName
}
