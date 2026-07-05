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
// sibling policy's deletion never shifts a survivor's key and a deleted
// policy's still-live sessions remain identifiable by the ID they already
// carry.
//
// Only DELETED policies are reported. A policy whose match/action CHANGED but
// whose zones+name are unchanged keeps the same stable key, is present in both
// maps, and is therefore NOT reported here — that in-progress re-evaluation is
// the deferred #4234 modified-policy (policy-rematch) half, intentionally out of
// scope for the Junos-default deletion-clear.
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
	if d.dp == nil {
		return
	}
	deleted := deletedPolicyRuntimeIDs(oldCfg, newCfg)
	if len(deleted) == 0 {
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
		if _, hit := deleted[val.PolicyID]; hit {
			v4Entries = append(v4Entries, dataplane.SessionEntryV4{Key: key, Value: val})
		}
		return true
	})

	var v6Entries []dataplane.SessionEntryV6
	_ = store.ForEachV6(func(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
		if val.IsReverse != 0 {
			return true
		}
		if _, hit := deleted[val.PolicyID]; hit {
			v6Entries = append(v6Entries, dataplane.SessionEntryV6{Key: key, Value: val})
		}
		return true
	})

	if len(v4Entries) == 0 && len(v6Entries) == 0 {
		return
	}

	v4Cleared := 0
	if len(v4Entries) > 0 {
		if n, err := store.DeleteBatchKnownV4(v4Entries, dataplane.DeleteReasonPolicyDeleted); err != nil {
			slog.Warn("policy-delete session invalidation: v4 clear failed",
				"deleted_policies", len(deleted), "matched", len(v4Entries), "err", err)
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
		if n, err := store.DeleteBatchKnownV6(v6Entries, dataplane.DeleteReasonPolicyDeleted); err != nil {
			slog.Warn("policy-delete session invalidation: v6 clear failed",
				"deleted_policies", len(deleted), "matched", len(v6Entries), "err", err)
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
	slog.Info("cleared sessions of deleted policies at commit",
		"deleted_policies", len(deleted),
		"v4_cleared", v4Cleared,
		"v6_cleared", v6Cleared,
		"ha_sync", syncPeer)
}
