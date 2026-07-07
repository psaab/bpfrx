package userspace

import (
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

// clampPort coerces a compiler-stored port (int, 0 = unset) into the u16
// wire slot. An out-of-range value is rejected at strict commit-check
// (compiler_nat.go validateNATHostMaskStrict), but the lenient load/peer-sync
// path can still carry one; clamp it to 0 ("no port translation") so a bad
// value fails CLOSED on the wire instead of wrapping to a wrong u16. #2491.
func clampPort(p int) uint16 {
	if p < 1 || p > 65535 {
		return 0
	}
	return uint16(p)
}

func buildStaticNATSnapshots(cfg *config.Config, natCounterIDs map[string]uint32) []StaticNATRuleSnapshot {
	if cfg == nil || len(cfg.Security.NAT.Static) == 0 {
		return nil
	}
	out := make([]StaticNATRuleSnapshot, 0)
	for _, rs := range cfg.Security.NAT.Static {
		if rs == nil {
			continue
		}
		for _, rule := range rs.Rules {
			if rule == nil || rule.IsNPTv6 {
				continue
			}
			// #3435: carry the `match source-address` constraint into the
			// snapshot. Prefer the full bracket-list (SourceAddresses); fall
			// back to the singular SourceAddress for an older typed config.
			// Empty = match any source (unscoped, pre-#3435 behavior).
			sourceAddrs := append([]string(nil), rule.SourceAddresses...)
			if len(sourceAddrs) == 0 && rule.SourceAddress != "" {
				sourceAddrs = append(sourceAddrs, rule.SourceAddress)
			}
			out = append(out, StaticNATRuleSnapshot{
				Name:                 rule.Name,
				FromZone:             rs.FromZone,
				FromInterface:        rs.FromInterface,
				FromRoutingInstance:  rs.FromRoutingInstance,
				SourceAddresses:      sourceAddrs,
				ExternalIP:           rule.Match,
				InternalIP:           rule.Then,
				MatchDestinationPort: clampPort(rule.MatchDestinationPort),
				MappedPort:           clampPort(rule.MappedPort),
				CounterID:            natCounterID(natCounterIDs, dataplane.NATCounterTypeStatic, rs.Name, rule.Name),
			})
		}
	}
	return out
}
