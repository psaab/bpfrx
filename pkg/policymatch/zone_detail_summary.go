package policymatch

import (
	"fmt"
	"strings"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// zoneScopeLabel renders a global policy's optional from/to-zone match scope
// (#3148) for the zone-detail summary: an empty scope is the historical
// "all-zones" wildcard and prints as "any" (the idiomatic Junos token). An
// explicit "any" (#3680) is already "any" and passes through unchanged. This is
// the SSOT the local CLI and gRPC-text zone-detail renderers share so the scope
// label cannot drift between the two surfaces (#3684 L10). It mirrors the label
// the pre-#3684 pkg/cli + pkg/grpcapi hand-rolled copies used.
func zoneScopeLabel(zone string) string {
	if zone == "" {
		return "any"
	}
	return zone
}

// zoneDetailModifiers renders the trailing "[...]" annotation appended to a
// zone-detail policy summary line. It threads the per-rule metadata the
// REST/gRPC inventory already carries but the pre-#3684 name+action summary
// dropped:
//
//   - id <N>                      runtime/RT_FLOW policy id (#3684 M11) — the
//     identity the session/event/RT_FLOW telemetry logs, so the summary can be
//     joined to "this packet hit policy_id=N".
//   - scheduler <name>            scheduler binding (#3624); when the runtime
//     reports the scheduler currently inactive the rule is skipped by the
//     dataplane, so it renders "scheduler <name> (inactive)" (#3684 H03) — a
//     scheduled-off rule can no longer read as an active participant.
//   - log <modes>                 session-log triggers via the config
//     SessionLogModes SSOT (#3667), joined at-create/at-close (#3684 M12).
//   - count                       `then count` hit-count accounting (#3684 M12).
//   - source-address (except) /   Junos source/destination-address-excluded
//     destination-address (except) inverted matches, using the ExceptSuffix SSOT
//     shared with the match-policies renderer (#3684 M12).
//
// The id token is always present; the remaining tokens appear only when set.
func zoneDetailModifiers(id uint32, schedulerName string, inactive bool, log *config.PolicyLog, count, srcExcluded, dstExcluded bool) string {
	tokens := []string{fmt.Sprintf("id %d", id)}
	if schedulerName != "" {
		if inactive {
			tokens = append(tokens, fmt.Sprintf("scheduler %s (inactive)", schedulerName))
		} else {
			tokens = append(tokens, fmt.Sprintf("scheduler %s", schedulerName))
		}
	}
	if modes := log.SessionLogModes(); len(modes) > 0 {
		tokens = append(tokens, "log "+strings.Join(modes, ","))
	}
	if count {
		tokens = append(tokens, "count")
	}
	if srcExcluded {
		tokens = append(tokens, "source-address"+ExceptSuffix(true))
	}
	if dstExcluded {
		tokens = append(tokens, "destination-address"+ExceptSuffix(true))
	}
	return "[" + strings.Join(tokens, ", ") + "]"
}

// ZoneDetailPolicySummary renders the "Policy summary" block of
// `show security zones detail` for one zone. It is the single source of truth
// consumed by the local CLI (pkg/cli), gRPC-text (pkg/grpcapi), and any other
// detail surface, so the three former hand-rolled renderers can no longer drift
// (#3684 L10). Each returned element is one complete, already-indented output
// line WITHOUT a trailing newline; the caller prints each line verbatim, so the
// CLI and gRPC-text output stay byte-identical.
//
// The lines span the three tiers the runtime evaluates in order — zone-pair,
// applicable global (#3148/#3680 scope), then the effective default-policy
// catch-all (#3658) — and thread the inventory metadata the pre-#3684 summary
// omitted: the runtime/RT_FLOW policy id (M11), scheduler binding + runtime
// inactive state (H03/#3624), the log/count/address-exclusion modifiers (M12),
// and the default-policy log posture + reserved sentinel id (M13).
//
// The runtime policy ids are span-accumulated exactly as the snapshot builder
// assigns them (dpuserspace.RuntimePolicyIDs / RuntimePolicyIndex), so the
// displayed id equals the numeric policy id the RT_FLOW/event path logs even
// after a multi-application policy shifts the id namespace.
//
// schedActive / haveSched come from the caller's live scheduler-state provider
// (Manager.PolicySchedulerActiveState). When haveSched is false the runtime
// scheduler state is unknown and no rule is claimed inactive, matching the
// #3062 policy-detail renderer. A nil cfg returns nil.
func ZoneDetailPolicySummary(cfg *config.Config, zone string, schedActive map[string]bool, haveSched bool) []string {
	if cfg == nil {
		return nil
	}
	runtimeIDs := dpuserspace.RuntimePolicyIDs(cfg)
	lines := []string{"  Policy summary (evaluation order: zone-pair, global, default-policy):"}

	// Tier 1: zone-pair policies. Track policySetID across ALL zone-pair sets
	// (matching or not, nil or not) exactly like the runtime walker so the
	// displayed id lands in the correct span-accumulated namespace.
	zonePairPolicies := 0
	var policySetID uint32
	for _, zpp := range cfg.Security.Policies {
		// #3476: skip a nil zone-pair set (tolerant / HA-sync path) while
		// advancing the policy-set ID, rather than dereferencing zpp.FromZone.
		if zpp == nil {
			policySetID++
			continue
		}
		if zpp.FromZone == zone || zpp.ToZone == zone {
			for i, pol := range zpp.Policies {
				// #3476: skip a nil rule like the runtime walker does.
				if pol == nil {
					continue
				}
				id := dpuserspace.RuntimePolicyIndex(runtimeIDs, policySetID, uint32(i))
				inactive := haveSched && dpuserspace.PolicyInactive(pol.SchedulerName, schedActive)
				mods := zoneDetailModifiers(id, pol.SchedulerName, inactive, pol.Log,
					pol.Count, pol.Match.SourceAddressExcluded, pol.Match.DestinationAddressExcluded)
				lines = append(lines, fmt.Sprintf("    [zone-pair] %s -> %s: %s (%s) %s",
					zpp.FromZone, zpp.ToZone, pol.Name, ActionString(pol.Action), mods))
				zonePairPolicies++
			}
		}
		policySetID++
	}

	// Tier 2: applicable GLOBAL policies. The global tier's policySetID is the
	// count of zone-pair sets (policySetID after the loop), mirroring the
	// snapshot builder + REST/gRPC inventory.
	globalPolicies := 0
	for i, gp := range cfg.Security.GlobalPolicies {
		// #3476-style defensiveness: skip a nil global rule.
		if gp == nil {
			continue
		}
		if !config.GlobalPolicyAppliesToZone(gp.Match, zone) {
			continue
		}
		id := dpuserspace.RuntimePolicyIndex(runtimeIDs, policySetID, uint32(i))
		inactive := haveSched && dpuserspace.PolicyInactive(gp.SchedulerName, schedActive)
		mods := zoneDetailModifiers(id, gp.SchedulerName, inactive, gp.Log,
			gp.Count, gp.Match.SourceAddressExcluded, gp.Match.DestinationAddressExcluded)
		lines = append(lines, fmt.Sprintf("    [global] %s -> %s: %s (%s) %s",
			zoneScopeLabel(gp.Match.FromZone), zoneScopeLabel(gp.Match.ToZone),
			gp.Name, ActionString(gp.Action), mods))
		globalPolicies++
	}
	if zonePairPolicies == 0 && globalPolicies == 0 {
		lines = append(lines, "    (no zone-pair or global policies affecting this zone)")
	}

	// Tier 3: the effective default-policy catch-all — always surfaced so the
	// unmatched-transit disposition is never hidden (#3658 M05). M13: thread the
	// reserved DefaultPolicySentinelID (the id the default-verdict RT_FLOW logs)
	// and the default-policy log posture (DefaultPolicyLogSessionInit/Close),
	// which requests RT_FLOW session logging for flows that hit the implicit
	// default verdict.
	defLog := &config.PolicyLog{
		SessionInit:  cfg.Security.DefaultPolicyLogSessionInit,
		SessionClose: cfg.Security.DefaultPolicyLogSessionClose,
	}
	defMods := zoneDetailModifiers(dataplane.DefaultPolicySentinelID, "", false, defLog, false, false, false)
	lines = append(lines, fmt.Sprintf("    [default] %s: %s %s",
		dataplane.DefaultPolicyName, ActionString(cfg.Security.DefaultPolicy), defMods))
	return lines
}
