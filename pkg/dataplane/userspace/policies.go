package userspace

import (
	"fmt"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

func buildPolicySnapshots(cfg *config.Config) []PolicyRuleSnapshot {
	return buildPolicySnapshotsWithSchedulerState(cfg, nil)
}

func buildPolicySnapshotsWithSchedulerState(cfg *config.Config, activeState map[string]bool) []PolicyRuleSnapshot {
	if cfg == nil || (len(cfg.Security.Policies) == 0 && len(cfg.Security.GlobalPolicies) == 0) {
		return nil
	}
	out := make([]PolicyRuleSnapshot, 0)
	policySetID := uint32(0)
	for _, zpp := range cfg.Security.Policies {
		if zpp == nil {
			policySetID++
			continue
		}
		ruleIndex := uint32(0)
		for _, pol := range zpp.Policies {
			if pol == nil {
				continue
			}
			policyID := policySetID*dataplane.MaxRulesPerPolicy + ruleIndex
			sourceAddresses, ok := expandUserspacePolicyAddresses(cfg, pol.Match.SourceAddresses)
			if !ok {
				sourceAddresses = append([]string(nil), pol.Match.SourceAddresses...)
			}
			destinationAddresses, ok := expandUserspacePolicyAddresses(cfg, pol.Match.DestinationAddresses)
			if !ok {
				destinationAddresses = append([]string(nil), pol.Match.DestinationAddresses...)
			}
			applicationTerms, ok := expandUserspacePolicyApplications(cfg, pol.Match.Applications)
			if !ok {
				applicationTerms = nil
			}
			schedulerName := pol.SchedulerName
			out = append(out, PolicyRuleSnapshot{
				RuleID:               stablePolicyRuleID(zpp.FromZone, zpp.ToZone, pol.Name),
				PolicyID:             policyID,
				Name:                 pol.Name,
				FromZone:             zpp.FromZone,
				ToZone:               zpp.ToZone,
				SchedulerName:        schedulerName,
				Inactive:             policyRuleInactive(schedulerName, activeState),
				SourceAddresses:      sourceAddresses,
				DestinationAddresses: destinationAddresses,
				Applications:         append([]string(nil), pol.Match.Applications...),
				ApplicationTerms:     applicationTerms,
				Action:               policyActionString(pol.Action),
			})
			ruleIndex += userspacePolicyRuleExpansionCount(cfg, pol.Match.Applications)
		}
		policySetID++
	}
	// Global policies match traffic regardless of zone pair.
	globalRuleIndex := uint32(0)
	for _, pol := range cfg.Security.GlobalPolicies {
		if pol == nil {
			continue
		}
		policyID := policySetID*dataplane.MaxRulesPerPolicy + globalRuleIndex
		sourceAddresses, ok := expandUserspacePolicyAddresses(cfg, pol.Match.SourceAddresses)
		if !ok {
			sourceAddresses = append([]string(nil), pol.Match.SourceAddresses...)
		}
		destinationAddresses, ok := expandUserspacePolicyAddresses(cfg, pol.Match.DestinationAddresses)
		if !ok {
			destinationAddresses = append([]string(nil), pol.Match.DestinationAddresses...)
		}
		applicationTerms, ok := expandUserspacePolicyApplications(cfg, pol.Match.Applications)
		if !ok {
			applicationTerms = nil
		}
		schedulerName := pol.SchedulerName
		out = append(out, PolicyRuleSnapshot{
			RuleID:               stablePolicyRuleID("junos-global", "junos-global", pol.Name),
			PolicyID:             policyID,
			Name:                 pol.Name,
			FromZone:             "junos-global",
			ToZone:               "junos-global",
			SchedulerName:        schedulerName,
			Inactive:             policyRuleInactive(schedulerName, activeState),
			SourceAddresses:      sourceAddresses,
			DestinationAddresses: destinationAddresses,
			Applications:         append([]string(nil), pol.Match.Applications...),
			ApplicationTerms:     applicationTerms,
			Action:               policyActionString(pol.Action),
		})
		globalRuleIndex += userspacePolicyRuleExpansionCount(cfg, pol.Match.Applications)
	}
	return out
}

func stablePolicyRuleID(fromZone, toZone, ruleName string) string {
	return fmt.Sprintf("%s->%s/%s", fromZone, toZone, ruleName)
}

func userspacePolicyRuleExpansionCount(cfg *config.Config, apps []string) uint32 {
	if len(apps) == 0 {
		return 1
	}
	seen := make(map[string]struct{}, len(apps))
	for _, appName := range apps {
		if appName == "" || appName == "any" {
			return 1
		}
		resolved, ok := resolveUserspaceApplicationNames(cfg, appName)
		if !ok || len(resolved) == 0 {
			return 1
		}
		for _, name := range resolved {
			seen[name] = struct{}{}
		}
	}
	if len(seen) == 0 {
		return 1
	}
	return uint32(len(seen))
}

func policyRuleInactive(schedulerName string, activeState map[string]bool) bool {
	if schedulerName == "" {
		return false
	}
	if activeState == nil {
		return true
	}
	active, ok := activeState[schedulerName]
	return !ok || !active
}

func policyActionString(action config.PolicyAction) string {
	switch action {
	case config.PolicyPermit:
		return "permit"
	case config.PolicyReject:
		return "reject"
	default:
		return "deny"
	}
}
