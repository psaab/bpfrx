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
	switch id {
	case UnattributedPolicyID:
		// LOAD-BEARING: this arm must come BEFORE the map lookup, and must not
		// be "rewritten" as a lookup with a fallback. `policyNames[0]` is
		// populated — it is the first configured policy — so any form that
		// consults the map first silently restores the #4626 misattribution
		// while still looking like a guard.
		return UnattributedPolicyName
	case DefaultPolicySentinelID:
		return DefaultPolicyName
	default:
		return policyNames[id]
	}
}
