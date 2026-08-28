package daemon

import (
	"errors"
	"fmt"
	"log/slog"
	"time"

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
// maps, and is therefore NOT reported here.
//
// That is a division of labour, NOT a gap. The changed-policy case is handled
// by changedPolicyRuntimeIDs / clearSessionsForModifiedPolicies in this file,
// gated on `security policies policy-rematch`, and
// clearSessionsForPolicyChanges runs both on every commit. An earlier revision
// of this comment called it "the deferred #4234 modified-policy
// (policy-rematch) half, intentionally out of scope" — which was true when it
// was written and stopped being true when that half shipped. It matters
// because this is the first comment a reader hits when tracing commit-time
// session invalidation: following it to a now-closed issue leads to the
// conclusion that a shipped, security-relevant behaviour (in-progress sessions
// re-evaluated against a tightened policy) is missing, and then to
// re-implementing it or telling an operator xpf does not do it.
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
//     HERE — clearSessionsForModifiedPolicies covers it under `policy-rematch`.
//     (This said "the deferred policy-rematch half"; it is not deferred, it
//     ships in this file.)
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
//
// Returns a non-nil error when the invalidation was PARTIAL (a session-table
// enumerate or batch-delete failed): some sessions of the deleted policy may
// keep forwarding under the now-revoked authorization, so the caller MUST join
// this into the commit/sync/rollback result rather than let it be lost to a log
// line (#5578).
func (d *Daemon) clearSessionsForDeletedPolicies(oldCfg, newCfg *config.Config) error {
	return d.clearSessionsForPolicyIDs(
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
// A surviving policy whose SCHEDULER binding effectively flipped active→inactive
// is treated as a verdict change too (#4343): policyRuleInactive (userspace-dp
// policies.go) is FAIL-CLOSED, so an inactive-scheduled policy is skipped in the
// rule chain — its live sessions must re-enter evaluation exactly like a
// permit→deny action change. The old/new per-scheduler active-state maps are
// evaluated at commit time from each config's schedulers via the same helper the
// apply transaction uses (policySchedulerActiveStateForApplyLocked); the caller
// holds d.applySem so d.scheduler cannot race.
//
// The `extensive` sub-case (Junos re-evaluates sessions of UNCHANGED policies
// when a referenced address-book / application object changes) is deliberately
// NOT implemented here — this clears only the policies whose own match/action
// text changed. `policy-rematch extensive` stays tracked as a follow-up
// (compiler_validate_warn.go advisory).
//
// Returns a non-nil error on a PARTIAL invalidation (enumerate/delete failure)
// so the caller can surface the stale-authorization gap; see
// clearSessionsForDeletedPolicies (#5578).
func (d *Daemon) clearSessionsForModifiedPolicies(oldCfg, newCfg *config.Config) error {
	now := time.Now()
	oldSched := d.policySchedulerActiveStateForApplyLocked(oldCfg, now)
	newSched := d.policySchedulerActiveStateForApplyLocked(newCfg, now)
	return d.clearSessionsForPolicyIDs(
		changedPolicyRuntimeIDs(oldCfg, newCfg, oldSched, newSched),
		dataplane.DeleteReasonPolicyModified,
		"modified (policy-rematch)",
	)
}

// defaultPolicyChanged reports whether the implicit default-policy changed in a
// way that must invalidate live default-PERMIT sessions, and whether the clear
// is UNCONDITIONAL (a verdict change) or gated on `policy-rematch` (a log-only
// flip). The implicit default-policy is the catch-all a flow hits when it
// matches no configured zone-pair / global / wildcard rule; a default-PERMIT
// verdict installs a session stamped DefaultPolicySentinelID (0xFFFFFFFF), which
// the named-policy invalidators never touch because they diff only
// PolicyIDsByStableKey (configured policies, never emitting the sentinel). So a
// `default-policy permit-all` -> `deny-all` (or reject) commit otherwise leaves
// the existing default-permit flows forwarding until idle timeout — the #4342
// stale-intent gap.
//
//   - An ACTION change (permit<->deny/reject) is a verdict change: clear
//     UNCONDITIONALLY, mirroring the always-on deletion-clear. A tightening
//     (permit->deny) must drop the now-should-be-denied sessions; the reverse
//     (deny->permit) installs nothing to sweep, so the clear is a harmless no-op
//     there (no session carries the sentinel under a default-deny).
//   - A LOG-only flip (action unchanged, session-init/session-close toggled) is
//     re-evaluation, not a verdict change: gate it on `policy-rematch` so a live
//     default-permit session re-installs under the new logging intent only when
//     the operator opted into rematch, matching the modified-policy half's
//     posture. Without policy-rematch the flip applies to new sessions only.
func defaultPolicyChanged(oldCfg, newCfg *config.Config) (changed, unconditional bool) {
	if oldCfg == nil || newCfg == nil {
		return false, false
	}
	if oldCfg.Security.DefaultPolicy != newCfg.Security.DefaultPolicy {
		return true, true
	}
	if oldCfg.Security.DefaultPolicyLogSessionInit != newCfg.Security.DefaultPolicyLogSessionInit ||
		oldCfg.Security.DefaultPolicyLogSessionClose != newCfg.Security.DefaultPolicyLogSessionClose {
		return true, false
	}
	return false, false
}

// clearSessionsForDefaultPolicyChange invalidates, at commit time, every live
// default-PERMIT session (policy_id == DefaultPolicySentinelID) when the
// implicit default-policy's verdict or logging intent changed (#4342). It reuses
// the shared clearSessionsForPolicyIDs core, so the drop is companion-aware and
// HA-delete-synced to the standby exactly like the named-policy clears.
//
// The overloaded-id-0 fail-safe that deletedPolicyRuntimeIDs / changedPolicy-
// RuntimeIDs apply does NOT apply here: the target id is the 0xFFFFFFFF sentinel,
// which by construction can never alias policy_id 0 (host-inbound / fabric /
// tunnel / synced sessions and old HA peers all carry 0, never 0xFFFFFFFF — see
// DefaultPolicySentinelID). Sweeping the sentinel is therefore safe and precise.
//
// Caller must hold d.applySem (all commit/sync/rollback call sites do).
//
// Returns a non-nil error on a PARTIAL invalidation (enumerate/delete failure)
// so the caller can surface the stale-authorization gap; see
// clearSessionsForDeletedPolicies (#5578).
func (d *Daemon) clearSessionsForDefaultPolicyChange(oldCfg, newCfg *config.Config) error {
	changed, unconditional := defaultPolicyChanged(oldCfg, newCfg)
	if !changed {
		return nil
	}
	if !unconditional && (newCfg == nil || !newCfg.Security.PolicyRematch) {
		// Log-only flip without policy-rematch: leave live default-permit
		// sessions to log per their install-time intent (Junos re-evaluates
		// in-progress sessions only under policy-rematch).
		return nil
	}
	return d.clearSessionsForPolicyIDs(
		map[uint32]struct{}{dataplane.DefaultPolicySentinelID: {}},
		dataplane.DeleteReasonDefaultPolicyChanged,
		"default-policy changed",
	)
}

// clearSessionsForPolicyChanges runs the three commit-time session
// invalidations — the deletion-clear (#4234), the modified-policy re-eval
// (policy-rematch), and the default-policy change clear (#4342) — in order and
// JOINS their errors so a caller can surface a PARTIAL invalidation in one
// place (#5578). errors.Join evaluates all three arguments, so every clear is
// attempted even if an earlier one fails; a non-nil return means at least one
// clear could not fully drop its target sessions, so some traffic may keep
// forwarding under stale authorization after a tightening/deleting commit.
// Returns nil when every clear was a no-op or fully succeeded.
//
// Caller must hold d.applySem (all commit/sync/rollback call sites do).
func (d *Daemon) clearSessionsForPolicyChanges(oldCfg, newCfg *config.Config) error {
	return errors.Join(
		d.clearSessionsForDeletedPolicies(oldCfg, newCfg),
		d.clearSessionsForModifiedPolicies(oldCfg, newCfg),
		d.clearSessionsForDefaultPolicyChange(oldCfg, newCfg),
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
//
// Error contract (#5578): the return value AGGREGATES every enumerate and
// batch-delete failure (errors.Join). A non-nil return means the invalidation
// was PARTIAL — a failed ForEachV4/V6 iteration leaves UNVISITED sessions in the
// live table, and a failed DeleteBatchKnownV4/V6 leaves MATCHED sessions
// INSTALLED — so traffic the new policy should now DENY may keep forwarding
// under the old session's stale authorization. The slog.Error/Warn lines are
// kept for operator diagnostics, but the error is ALSO returned so the caller
// can join it into the commit/sync/rollback result instead of the security gap
// being silently swallowed. Both families are always attempted before the error
// is returned (a partial clear is strictly better than none). Returns nil when
// there was nothing to do (no ids / no dataplane / no matching sessions) or the
// clear fully succeeded.
func (d *Daemon) clearSessionsForPolicyIDs(ids map[uint32]struct{}, reason dataplane.DeleteReason, what string) error {
	rt := d.dataplane()
	if rt == nil || len(ids) == 0 {
		return nil
	}

	store := rt.Sessions()
	if store == nil {
		return nil
	}
	// Whether to propagate the local deletes to the HA peer. Mirrors the GC
	// delete callback (daemon_run.go): only a node that is primary for some RG
	// owns the authoritative session and syncs its deletes; the peer ignores
	// deletes for sessions it does not hold.
	ss := d.getSessionSync()
	syncPeer := d.cluster != nil && d.cluster.IsLocalPrimaryAny() && ss != nil

	// Collect forward entries only; DeleteBatchKnownV4/V6 expands each to its
	// reverse + DNAT companions. A reverse entry carries the SAME policy_id as
	// its forward, so including it would double-delete the same session and, for
	// a NAT'd flow, target the translated tuple instead of the install key.
	//
	// Capture the enumerate error: a failed iteration yields a partial (or empty)
	// entry set, so clearing what we gathered would silently leave should-be-
	// cleared sessions forwarding while logging an apparently-clean invalidation.
	// Surface it loudly and suppress the success line so the partial clear is
	// observable, not masked (Copilot #4320).
	// #6948: the id set was computed from the OLD config's numbering, and
	// runtime policy ids are POSITIONAL — deleting a policy renumbers every
	// later one. The dataplane starts admitting under the NEW numbering as soon
	// as the apply publishes it, which happens long before this sweep runs, so a
	// session admitted in between by a policy that INHERITED a deleted policy's
	// id matches `ids` and would be dropped while correctly permitted.
	//
	// admittedAfterActivation is the discriminator. It is STRICTLY greater on
	// purpose: Created has one-second granularity, so a session created in the
	// same integer second as the stamp is ambiguous, and an ambiguous session is
	// still cleared — the direction this code already chose (over-clear is
	// fail-safe for security; under-clear is a stale-authorization gap).
	//
	// That leaves a residual: this narrows the over-clear from the entire
	// post-activation apply, tail included, to at most one second. It does not
	// eliminate it, and nothing here should be read as claiming otherwise —
	// closing it fully needs either an admission fence across
	// activation->invalidation or a stable admitting-rule identity on the row.
	activationSecs := d.policyActivationSecs
	admittedAfterActivation := func(created uint64) bool {
		return activationSecs != 0 && created > activationSecs
	}

	var v4Entries []dataplane.SessionEntryV4
	v4EnumErr := store.ForEachV4(func(key dataplane.SessionKey, val dataplane.SessionValue) bool {
		if val.IsReverse != 0 {
			return true
		}
		if admittedAfterActivation(val.Created) {
			return true
		}
		if _, hit := ids[val.PolicyID]; hit {
			v4Entries = append(v4Entries, dataplane.SessionEntryV4{Key: key, Value: val})
		}
		return true
	})

	var v6Entries []dataplane.SessionEntryV6
	v6EnumErr := store.ForEachV6(func(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
		if val.IsReverse != 0 {
			return true
		}
		// #6948: same boundary as v4. Both families must apply it or the defect
		// simply moves to the other address family.
		if admittedAfterActivation(val.Created) {
			return true
		}
		if _, hit := ids[val.PolicyID]; hit {
			v6Entries = append(v6Entries, dataplane.SessionEntryV6{Key: key, Value: val})
		}
		return true
	})
	// errs accumulates every enumerate/delete failure so the caller can join it
	// into the commit/sync/rollback result (#5578) — the failure is no longer
	// lost to a log line while the commit reports success with stale authorized
	// sessions still forwarding.
	var errs []error
	if v4EnumErr != nil || v6EnumErr != nil {
		slog.Error("policy session invalidation: session-table enumerate failed; clear is PARTIAL — some sessions of changed policies may keep forwarding",
			"change", what, "reason", reason, "policies", len(ids),
			"v4_err", v4EnumErr, "v6_err", v6EnumErr,
			"v4_matched", len(v4Entries), "v6_matched", len(v6Entries))
		if v4EnumErr != nil {
			errs = append(errs, fmt.Errorf("policy session invalidation (%s): v4 enumerate: %w", what, v4EnumErr))
		}
		if v6EnumErr != nil {
			errs = append(errs, fmt.Errorf("policy session invalidation (%s): v6 enumerate: %w", what, v6EnumErr))
		}
		// Fall through to clear what we DID enumerate — a partial clear is
		// strictly better than none — but the error log above ensures the
		// partial state is visible and the success line below is skipped.
	}

	if len(v4Entries) == 0 && len(v6Entries) == 0 {
		return errors.Join(errs...)
	}

	v4Cleared := 0
	if len(v4Entries) > 0 {
		if n, err := store.DeleteBatchKnownV4(v4Entries, reason); err != nil {
			slog.Warn("policy session invalidation: v4 clear failed",
				"reason", reason, "policies", len(ids), "matched", len(v4Entries), "err", err)
			errs = append(errs, fmt.Errorf("policy session invalidation (%s): v4 delete: %w", what, err))
		} else {
			v4Cleared = n
		}
		if syncPeer {
			for _, e := range v4Entries {
				ss.QueueDeleteV4(e.Key)
			}
		}
	}

	v6Cleared := 0
	if len(v6Entries) > 0 {
		if n, err := store.DeleteBatchKnownV6(v6Entries, reason); err != nil {
			slog.Warn("policy session invalidation: v6 clear failed",
				"reason", reason, "policies", len(ids), "matched", len(v6Entries), "err", err)
			errs = append(errs, fmt.Errorf("policy session invalidation (%s): v6 delete: %w", what, err))
		} else {
			v6Cleared = n
		}
		if syncPeer {
			for _, e := range v6Entries {
				ss.QueueDeleteV6(e.Key)
			}
		}
	}

	// One-time state transition, not a per-session/per-tick event — slog.Info is
	// the right level (project logging rules). Suppress the success line when the
	// enumerate failed: the counts describe only what we managed to gather, so an
	// Info "cleared" line would misreport a partial clear as complete (the Error
	// line above already recorded it).
	if v4EnumErr == nil && v6EnumErr == nil && len(errs) == 0 {
		slog.Info("cleared sessions of changed policies at commit",
			"change", what,
			"policies", len(ids),
			"v4_cleared", v4Cleared,
			"v6_cleared", v6Cleared,
			"ha_sync", syncPeer)
	}
	return errors.Join(errs...)
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
// oldSched / newSched are the per-scheduler active-state maps under the old and
// new configs, evaluated at the same commit-time instant (nil when a config has
// no schedulers). They drive the #4343 scheduler active->inactive verdict-change
// detection (policySchedulerBecameInactive); pass nil/nil to consider only
// match/action changes.
//
// Returns nil when oldCfg is nil (boot), policy-rematch is unset, or nothing
// changed.
func changedPolicyRuntimeIDs(oldCfg, newCfg *config.Config, oldSched, newSched map[string]bool) map[uint32]struct{} {
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
		if !policyMatchOrActionChanged(oldPol, newPol) &&
			!policySchedulerBecameInactive(oldPol, newPol, oldSched, newSched) {
			continue
		}
		if changed == nil {
			changed = make(map[uint32]struct{})
		}
		changed[id] = struct{}{}
	}
	return changed
}

// policySchedulerBecameInactive reports whether a surviving policy's EFFECTIVE
// enforcement state flipped from active to inactive across the commit — the
// scheduler-binding analogue of an action tightening (#4343). policyRuleInactive
// (userspace-dp policies.go, exported as PolicyInactive) is FAIL-CLOSED: a policy
// bound to an inactive-or-undefined scheduler is stamped Inactive and its rule is
// SKIPPED in the chain, so an active->inactive flip is a verdict change for a
// live session — its next packet no longer matches this policy and re-enters
// evaluation (falling through to a later rule or the default-policy). This covers
// both a scheduler-name BINDING change (unscheduled->scheduled-and-inactive, or
// active-scheduler->inactive-scheduler) and a same-binding scheduler whose active
// WINDOW the commit redefined out from under the current instant.
//
// The inactive->active direction is intentionally NOT a clear trigger: while the
// policy was inactive it admitted no sessions, so none carry its policy_id — a
// sweep would be a pure no-op. Only the tightening direction (active->inactive)
// has live sessions to re-evaluate.
func policySchedulerBecameInactive(oldPol, newPol *config.Policy, oldSched, newSched map[string]bool) bool {
	wasActive := !dpuserspace.PolicyInactive(oldPol.SchedulerName, oldSched)
	nowInactive := dpuserspace.PolicyInactive(newPol.SchedulerName, newSched)
	return wasActive && nowInactive
}

// policyMatchOrActionChanged reports whether two same-identity policies differ
// in a way that changes the verdict for an in-progress session: the terminal
// ACTION (permit/deny/reject) or any MATCH predicate (source/destination
// addresses, applications, the address-excluded senses, or a global policy's
// from/to zone scope). Address and application lists are compared as SETS so a
// pure reordering — which does not change what the policy matches — does not
// trigger a needless session clear. Non-verdict attributes (description, count,
// log) are intentionally ignored: they do not affect whether a live session
// should still be permitted. scheduler-name is NOT ignored — it gates
// fail-closed enforcement (policyRuleInactive), so a scheduler active->inactive
// transition is handled separately by policySchedulerBecameInactive (#4343),
// which needs the runtime scheduler active-state and so cannot be decided from
// the two Policy structs alone.
func policyMatchOrActionChanged(oldPol, newPol *config.Policy) bool {
	if oldPol.Action != newPol.Action {
		return true
	}
	om, nm := oldPol.Match, newPol.Match
	if om.SourceAddressExcluded != nm.SourceAddressExcluded ||
		om.DestinationAddressExcluded != nm.DestinationAddressExcluded {
		return true
	}
	// #4626 M03: a global policy's from/to-zone scope is a zone SET; compare as
	// sets (like the address/application lists) so a pure reordering of the
	// scope does not trigger a needless session clear.
	return !sameStringSet(om.FromZones, nm.FromZones) ||
		!sameStringSet(om.ToZones, nm.ToZones) ||
		!sameStringSet(om.SourceAddresses, nm.SourceAddresses) ||
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
