package config

// Fail-closed "not installed" verdicts for NAT rules, in the composition every
// operator surface needs (#7473).
//
// The PREDICATES already lived here — `SourceNATPoolUnusableReason` and
// `DestinationNATRuleExcludedReason`. What did not was the two lines around
// them: which pool map to look the rule's pool up in, and what to answer when
// it is absent. `pkg/cli` had that composition privately; `pkg/api` and
// `pkg/grpcapi` were about to grow their own copies for the structured
// surfaces, and three copies of "which map, and what if it is missing" is three
// chances to answer it differently for the same rule.
//
// So the composition is exported once and all three surfaces call it. The text
// renderers and the JSON/protobuf objects then cannot disagree about which
// rules are armed, which is the whole point of the #6534 family: a surface that
// disagrees with the builder is the defect, and two surfaces that disagree with
// each other is the same defect twice.

// SourceNATRuleNotInstalledReason reports why the snapshot builder will not
// install this source-NAT rule, or "" when it is armed.
//
// Only pool-mode rules can be disarmed this way: interface-mode source NAT has
// no pool to be unusable, which is why the empty-pool-name arm returns "" and
// not a reason. That mirrors the builder, which gates on a non-empty pool name
// for exactly the same reason.
func SourceNATRuleNotInstalledReason(cfg *Config, rule *NATRule) string {
	if cfg == nil || rule == nil || rule.Then.PoolName == "" {
		return ""
	}
	pool, ok := cfg.Security.NAT.SourcePools[rule.Then.PoolName]
	if !ok || pool == nil {
		return ""
	}
	return SourceNATPoolUnusableReason(pool)
}

// DestinationNATRuleNotInstalledReason reports why the snapshot builder will
// not install this destination-NAT rule, or "" when it is armed.
//
// The destination predicate already returns operator prose, where the source
// one returns a token that `SourceNATDisarmReasonText` expands. Callers that
// render the reason must respect that difference; callers that only need the
// boolean can treat both alike.
func DestinationNATRuleNotInstalledReason(cfg *Config, rule *NATRule) string {
	if cfg == nil || rule == nil || cfg.Security.NAT.Destination == nil {
		return ""
	}
	return DestinationNATRuleExcludedReason(cfg.Security.NAT.Destination, rule)
}
