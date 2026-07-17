package userspace

import (
	"log/slog"

	"github.com/psaab/xpf/pkg/config"
)

func buildNptv6Snapshots(cfg *config.Config) []Nptv6RuleSnapshot {
	if cfg == nil || len(cfg.Security.NAT.Static) == 0 {
		return nil
	}
	var out []Nptv6RuleSnapshot
	for _, rs := range cfg.Security.NAT.Static {
		if rs == nil {
			continue
		}
		// #5818 fail-closed: the NPTv6 wire/dataplane carry only `from zone`
		// (Nptv6RuleSnapshot has no interface/routing-instance/source field). A
		// rule-set scoped `from interface` / `from routing-instance` cannot be
		// honored, so emitting the rule would install an over-broad zone/global
		// rewrite that translates traffic the operator scoped OUT — the security-
		// widening #5818 closes. The strict commit gate (validateNPTv6ScopeStrict)
		// rejects this; on the tolerant load / peer-sync path (where that gate only
		// warns, #1960 no-brick) exclude the rule here so nothing installs rather
		// than a widened rewrite.
		scopeUnsupported := rs.FromInterface != "" || rs.FromRoutingInstance != ""
		for _, rule := range rs.Rules {
			if rule == nil || !rule.IsNPTv6 {
				continue
			}
			// A per-rule `match source-address` OR `match destination-port` is
			// likewise dropped by the wire, so a source- or port-scoped rule would
			// translate every source / every port — exclude it too (#5818, incl. the
			// destination-port review residual).
			if scopeUnsupported || len(rule.SourceAddresses) > 0 || rule.SourceAddress != "" || rule.MatchDestinationPort != 0 {
				slog.Warn("userspace snapshot: dropping NPTv6 rule carrying an unsupported match scope "+
					"(from-interface/from-routing-instance/source-address/destination-port); the NPTv6 dataplane "+
					"honors only from-zone, so installing it would widen the rewrite (fail-closed, #5818)",
					"rule_set", rs.Name, "rule", rule.Name,
					"from_interface", rs.FromInterface, "from_routing_instance", rs.FromRoutingInstance)
				continue
			}
			out = append(out, Nptv6RuleSnapshot{
				Name:           rule.Name,
				FromZone:       rs.FromZone,
				ExternalPrefix: rule.Match,
				InternalPrefix: rule.Then,
			})
		}
	}
	return out
}

// hasNonNptv6StaticNAT returns true if the config has any static NAT rules
// that are NOT NPTv6. NPTv6 rules are supported by the userspace dataplane.
func hasNonNptv6StaticNAT(cfg *config.Config) bool {
	if cfg == nil {
		return false
	}
	for _, rs := range cfg.Security.NAT.Static {
		if rs == nil {
			continue
		}
		for _, rule := range rs.Rules {
			if rule != nil && !rule.IsNPTv6 {
				return true
			}
		}
	}
	return false
}
