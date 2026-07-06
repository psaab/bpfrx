package daemon

import (
	"log/slog"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// deletedPolicyRuntimeIDs returns the set of numeric runtime policy IDs (the
// value stamped on an admitted session's policy_id, #3056) belonging to
// policies present in oldCfg but ABSENT from newCfg. Identity is the stable
// string key (userspace.StablePolicyRuleID: "<from>-><to>/<name>"), so a
// sibling policy's deletion never shifts a survivor's key.
//
// Only DELETED policies are reported. A policy whose match/action CHANGED but
// whose zones+name are unchanged keeps the same stable key, is present in both
// maps, and is therefore NOT reported here — that in-progress re-evaluation is
// the deferred #4234 modified-policy (policy-rematch) half, intentionally out of
// scope for the Junos-default deletion-clear.
//
// policy_id 0 is EXCLUDED from the returned set even when the literal first
// policy (PolicySetID 0, RuleIndex 0 — policyID() == 0) is deleted or renamed.
// The wire value 0 is OVERLOADED: it is both that first policy's id AND the
// "unspecified"/legacy zero-value carried by non-security sessions
// (host-inbound / neighbor-seed / fabric / tunnel installs stamp policy_id 0)
// and by any pre-#3056 or older-HA-peer session that only ever carried the wire
// scalar. userspace-dp already special-cases 0 for exactly this reason —
// policy.rs `DuplicatePolicyId` (M01) excludes 0 from its uniqueness check, and
// `reresolve_session_policy_id` treats the idx-0 non-policy sessions as
// unbound. Clearing every policy_id==0 session because the first policy was
// deleted/renamed (a rename is delete+add by stable key) would sweep all those
// host-local/fabric/tunnel/synced sessions — a forwarding blip on a common op,
// and during a rolling upgrade an old peer syncs its WHOLE table with
// policy_id 0, so a first-policy delete would wipe it (mass loss / TCP resets
// on failover, the #1960 rolling-upgrade class, amplified by the #2468
// delete-sync propagation). Excluding 0 is a fail-SAFE under-clear: only the
// literal first policy's OWN sessions idle out instead of clearing (identical
// to the pre-#4234 behavior for that one policy); every OTHER deleted policy
// (id >= 1) still clears correctly, and no should-be-denied session that a
// DIFFERENT deleted policy covered is kept — so it is not a security
// regression.
//
// Correctness depends on running BEFORE the ~1s live-row refresh
// (#3395 reresolve_session_policy_id) re-stamps a session's policy_id: a
// deleted policy's rule_id no longer resolves, so after a refresh tick its
// sessions carry DEFAULT_POLICY_SENTINEL_ID (u32::MAX) rather than their old
// numeric id and would no longer match. The clear runs synchronously in the
// apply path (right after the dataplane ApplyConfig), before the next refresh
// tick, so the deleted-policy sessions still carry the OLD id this set targets.
// A narrow residual remains for two commits inside one refresh window
// (reorder-then-delete): a session re-stamped between them could carry an id
// this diff no longer recognizes — bounded and self-healing (the next refresh
// or idle timeout resolves it), accepted for the Junos-default deletion-clear.
//
// Returns nil when oldCfg is nil (boot / first commit — nothing to invalidate)
// or nothing was deleted.
func deletedPolicyRuntimeIDs(oldCfg, newCfg *config.Config) map[uint32]struct{} {
	if oldCfg == nil {
		return nil
	}
	oldIDs := dpuserspace.PolicyIDsByStableKey(oldCfg)
	if len(oldIDs) == 0 {
		return nil
	}
	newIDs := dpuserspace.PolicyIDsByStableKey(newCfg)
	var deleted map[uint32]struct{}
	for key, id := range oldIDs {
		if id == 0 {
			// Overloaded wire value — never sweep policy_id==0 sessions. See the
			// doc comment above (mirrors policy.rs DuplicatePolicyId M01).
			continue
		}
		if _, stillPresent := newIDs[key]; stillPresent {
			continue
		}
		if deleted == nil {
			deleted = make(map[uint32]struct{})
		}
		deleted[id] = struct{}{}
	}
	return deleted
}

// clearSessionsForDeletedPolicies invalidates, at commit time, every live
// session admitted by a policy that the just-committed config removed — the
// Junos-DEFAULT behavior that drops a deleted policy's sessions immediately
// rather than leaving them forwarding until idle timeout (#4234 deletion-clear
// half). It is deliberately bounded:
//
//   - It runs ONLY when at least one policy was deleted (deletedPolicyRuntimeIDs
//     returns a non-empty set); a commit with no policy deletion pays no
//     session-table scan.
//   - It clears ONLY sessions whose stored policy_id matches a deleted policy;
//     a MODIFIED policy (same zones+name) keeps its key and is never touched
//     (the deferred policy-rematch half).
//
// The clear reuses the same companion-aware delete the GC and cluster-stale
// reconcile use (SessionStore.DeleteBatchKnownV4/V6 removes the forward entry,
// its reverse companion, and any dynamic DNAT/NAT64 companion), and propagates
// each deletion to the HA peer through the identical delete-sync channel the GC
// delete callback uses (#2468 QueueDeleteV4/V6) — so a session dropped on the
// owner is dropped on the standby too and cannot resurrect on failover.
//
// Handles both zone-pair and global (junos-global) policies uniformly: the
// stable key already encodes each policy's scope, so a deleted policy in either
// namespace contributes its numeric ID to the deleted set.
//
// Caller must hold d.applySem (all commit/sync/rollback call sites do), so this
// cannot race a concurrent apply that would reprogram the policy-ID namespace.
func (d *Daemon) clearSessionsForDeletedPolicies(oldCfg, newCfg *config.Config) {
	d.clearSessionsForPolicyIDs(
		deletedPolicyRuntimeIDs(oldCfg, newCfg),
		dataplane.DeleteReasonPolicyDeleted,
		"deleted",
	)
}

// clearSessionsForModifiedPolicies invalidates, at commit time, every live
// session admitted by a policy that survives the commit (same zones+name) but
// whose MATCH or ACTION changed — the Junos `security policies policy-rematch`
// behavior of re-evaluating in-progress sessions against the changed policy set
// (#4234 modified-policy half). It is gated on `policy-rematch` being set in the
// committed config (changedPolicyRuntimeIDs returns nil otherwise) and, like the
// deletion-clear, is bounded to sessions whose stored policy_id matches a
// changed policy; an unchanged policy's sessions are never touched.
//
// A cleared session's next packet re-enters policy evaluation and is admitted or
// dropped by the NEW policy — so a tightened (permit→deny, narrowed-match)
// policy takes effect on live traffic instead of lingering until idle timeout.
//
// The `extensive` sub-case (Junos re-evaluates sessions of UNCHANGED policies
// when a referenced address-book / application object changes) is deliberately
// NOT implemented here — this clears only the policies whose own match/action
// text changed. `policy-rematch extensive` stays tracked as a follow-up
// (compiler_validate_warn.go advisory).
func (d *Daemon) clearSessionsForModifiedPolicies(oldCfg, newCfg *config.Config) {
	d.clearSessionsForPolicyIDs(
		changedPolicyRuntimeIDs(oldCfg, newCfg),
		dataplane.DeleteReasonPolicyModified,
		"modified (policy-rematch)",
	)
}

// clearSessionsForPolicyIDs is the shared core behind the deletion-clear
// (#4234) and the modified-policy re-eval: it drops every live session whose
// stored policy_id is in ids, using the same companion-aware delete + HA
// delete-sync propagation the GC and cluster-stale reconcile use. ids is the
// set of OLD numeric policy IDs the target sessions carry; an empty set is a
// no-op (a commit with no matching policy change pays no session-table scan).
// reason is the documentary delete label; what labels the change class in the
// summary log line.
//
// Caller must hold d.applySem (all commit/sync/rollback call sites do), so this
// cannot race a concurrent apply that would reprogram the policy-ID namespace.
func (d *Daemon) clearSessionsForPolicyIDs(ids map[uint32]struct{}, reason dataplane.DeleteReason, what string) {
	if d.dp == nil || len(ids) == 0 {
		return
	}

	store := d.dp.Sessions()
	if store == nil {
		return
	}
	// Whether to propagate the local deletes to the HA peer. Mirrors the GC
	// delete callback (daemon_run.go): only a node that is primary for some RG
	// owns the authoritative session and syncs its deletes; the peer ignores
	// deletes for sessions it does not hold.
	syncPeer := d.cluster != nil && d.cluster.IsLocalPrimaryAny() && d.sessionSync != nil

	// Collect forward entries only; DeleteBatchKnownV4/V6 expands each to its
	// reverse + DNAT companions. A reverse entry carries the SAME policy_id as
	// its forward, so including it would double-delete the same session and, for
	// a NAT'd flow, target the translated tuple instead of the install key.
	var v4Entries []dataplane.SessionEntryV4
	_ = store.ForEachV4(func(key dataplane.SessionKey, val dataplane.SessionValue) bool {
		if val.IsReverse != 0 {
			return true
		}
		if _, hit := ids[val.PolicyID]; hit {
			v4Entries = append(v4Entries, dataplane.SessionEntryV4{Key: key, Value: val})
		}
		return true
	})

	var v6Entries []dataplane.SessionEntryV6
	_ = store.ForEachV6(func(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
		if val.IsReverse != 0 {
			return true
		}
		if _, hit := ids[val.PolicyID]; hit {
			v6Entries = append(v6Entries, dataplane.SessionEntryV6{Key: key, Value: val})
		}
		return true
	})

	if len(v4Entries) == 0 && len(v6Entries) == 0 {
		return
	}

	v4Cleared := 0
	if len(v4Entries) > 0 {
		if n, err := store.DeleteBatchKnownV4(v4Entries, reason); err != nil {
			slog.Warn("policy session invalidation: v4 clear failed",
				"reason", reason, "policies", len(ids), "matched", len(v4Entries), "err", err)
		} else {
			v4Cleared = n
		}
		if syncPeer {
			for _, e := range v4Entries {
				d.sessionSync.QueueDeleteV4(e.Key)
			}
		}
	}

	v6Cleared := 0
	if len(v6Entries) > 0 {
		if n, err := store.DeleteBatchKnownV6(v6Entries, reason); err != nil {
			slog.Warn("policy session invalidation: v6 clear failed",
				"reason", reason, "policies", len(ids), "matched", len(v6Entries), "err", err)
		} else {
			v6Cleared = n
		}
		if syncPeer {
			for _, e := range v6Entries {
				d.sessionSync.QueueDeleteV6(e.Key)
			}
		}
	}

	// One-time state transition, not a per-session/per-tick event — slog.Info is
	// the right level (project logging rules).
	slog.Info("cleared sessions of changed policies at commit",
		"change", what,
		"policies", len(ids),
		"v4_cleared", v4Cleared,
		"v6_cleared", v6Cleared,
		"ha_sync", syncPeer)
}

// changedPolicyRuntimeIDs returns the OLD numeric runtime IDs of policies that
// survive the commit (present in BOTH oldCfg and newCfg by stable key) but whose
// MATCH or ACTION changed — the set the modified-policy re-evaluation clears.
//
// It is GATED on `security policies policy-rematch` in the committed (new)
// config: Junos re-evaluates in-progress sessions against a modified policy only
// when policy-rematch is set. Without it, a modified policy's sessions keep
// forwarding until idle timeout (the historical xpf behavior), which the commit
// advisory documents.
//
// Only MODIFIED survivors are reported: a DELETED policy (absent from newCfg) is
// the deletion-clear's job (deletedPolicyRuntimeIDs) and is skipped here; an
// UNCHANGED policy keeps forwarding. The OLD numeric ID is used because live
// sessions were stamped under the old config and carry it (identical rationale
// to deletedPolicyRuntimeIDs). policy_id 0 is excluded for the same overloaded-
// wire-value reason documented there (host-inbound / fabric / tunnel / synced
// sessions and old HA peers all carry 0).
//
// Returns nil when oldCfg is nil (boot), policy-rematch is unset, or nothing
// changed.
func changedPolicyRuntimeIDs(oldCfg, newCfg *config.Config) map[uint32]struct{} {
	if oldCfg == nil || newCfg == nil || !newCfg.Security.PolicyRematch {
		return nil
	}
	oldIDs := dpuserspace.PolicyIDsByStableKey(oldCfg)
	if len(oldIDs) == 0 {
		return nil
	}
	newIDs := dpuserspace.PolicyIDsByStableKey(newCfg)
	oldPolicies := dpuserspace.PoliciesByStableKey(oldCfg)
	newPolicies := dpuserspace.PoliciesByStableKey(newCfg)

	var changed map[uint32]struct{}
	for key, id := range oldIDs {
		if id == 0 {
			// Overloaded wire value — never sweep policy_id==0 sessions.
			continue
		}
		if _, stillPresent := newIDs[key]; !stillPresent {
			// Deleted — handled by the deletion-clear, not here.
			continue
		}
		oldPol := oldPolicies[key]
		newPol := newPolicies[key]
		if oldPol == nil || newPol == nil {
			continue
		}
		if !policyMatchOrActionChanged(oldPol, newPol) {
			continue
		}
		if changed == nil {
			changed = make(map[uint32]struct{})
		}
		changed[id] = struct{}{}
	}
	return changed
}

// policyMatchOrActionChanged reports whether two same-identity policies differ
// in a way that changes the verdict for an in-progress session: the terminal
// ACTION (permit/deny/reject) or any MATCH predicate (source/destination
// addresses, applications, the address-excluded senses, or a global policy's
// from/to zone scope). Address and application lists are compared as SETS so a
// pure reordering — which does not change what the policy matches — does not
// trigger a needless session clear. Non-verdict attributes (description, count,
// log, scheduler-name) are intentionally ignored: they do not affect whether a
// live session should still be permitted.
func policyMatchOrActionChanged(oldPol, newPol *config.Policy) bool {
	if oldPol.Action != newPol.Action {
		return true
	}
	om, nm := oldPol.Match, newPol.Match
	if om.SourceAddressExcluded != nm.SourceAddressExcluded ||
		om.DestinationAddressExcluded != nm.DestinationAddressExcluded ||
		om.FromZone != nm.FromZone ||
		om.ToZone != nm.ToZone {
		return true
	}
	return !sameStringSet(om.SourceAddresses, nm.SourceAddresses) ||
		!sameStringSet(om.DestinationAddresses, nm.DestinationAddresses) ||
		!sameStringSet(om.Applications, nm.Applications)
}

// sameStringSet reports whether two string slices contain the same elements
// irrespective of order or duplicates.
func sameStringSet(a, b []string) bool {
	if len(a) == 0 && len(b) == 0 {
		return true
	}
	sa := make(map[string]struct{}, len(a))
	for _, v := range a {
		sa[v] = struct{}{}
	}
	sb := make(map[string]struct{}, len(b))
	for _, v := range b {
		sb[v] = struct{}{}
	}
	if len(sa) != len(sb) {
		return false
	}
	for k := range sa {
		if _, ok := sb[k]; !ok {
			return false
		}
	}
	return true
}
