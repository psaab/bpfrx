package natshow

import (
	"fmt"
	"io"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

// RenderDestRuleDetail renders detailed destination NAT rule
// information, including pool address/port, translation hit counters,
// and active session counts per rule-set.
//
// The nil/empty guard reproduces the gRPC contract verbatim
// (cfg == nil, no Destination config, or no rule-sets all emit the same
// "No destination NAT rules configured" line). The CLI dispatcher keeps
// its own pre-guard; for the non-empty path it routes here and renders
// identically.
//
// crFn lazily supplies the apply result; like RenderSourceRuleDetail it
// is invoked only after the empty-config guard, preserving the master
// ordering where applyResult() ran after the guard.
func RenderDestRuleDetail(w io.Writer, cfg *config.Config, dp Reader, crFn func() *dataplane.ApplyResult) {
	if cfg == nil || cfg.Security.NAT.Destination == nil || len(cfg.Security.NAT.Destination.RuleSets) == 0 {
		io.WriteString(w, "No destination NAT rules configured\n")
		return
	}
	dnat := cfg.Security.NAT.Destination
	var cr *dataplane.ApplyResult
	if crFn != nil {
		cr = crFn()
	}
	type ruleSetKey struct{ from, to string }
	rsSessions := make(map[ruleSetKey]int)
	if dp != nil && dp.IsLoaded() && cr != nil {
		zoneByID := make(map[uint16]string, len(cr.ZoneIDs))
		for name, id := range cr.ZoneIDs {
			zoneByID[id] = name
		}
		_ = dp.IterateSessions(func(_ dataplane.SessionKey, val dataplane.SessionValue) bool {
			if val.IsReverse == 0 && val.Flags&dataplane.SessFlagDNAT != 0 {
				rsSessions[ruleSetKey{zoneByID[val.IngressZone], zoneByID[val.EgressZone]}]++
			}
			return true
		})
		_ = dp.IterateSessionsV6(func(_ dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
			if val.IsReverse == 0 && val.Flags&dataplane.SessFlagDNAT != 0 {
				rsSessions[ruleSetKey{zoneByID[val.IngressZone], zoneByID[val.EgressZone]}]++
			}
			return true
		})
	}

	ruleIdx := 0
	for _, rs := range dnat.RuleSets {
		for _, rule := range rs.Rules {
			ruleIdx++
			action := "off"
			if rule.Then.PoolName != "" {
				action = "pool " + rule.Then.PoolName
			}
			dstMatch := "0.0.0.0/0"
			if rule.Match.DestinationAddress != "" {
				dstMatch = rule.Match.DestinationAddress
			}
			fmt.Fprintf(w, "destination NAT rule: %s\n", rule.Name)
			fmt.Fprintf(w, "  Rule-set: %s                        ID: %d\n", rs.Name, ruleIdx)
			fmt.Fprintf(w, "    From zone: %s    To zone: %s\n", rs.FromZone, rs.ToZone)
			fmt.Fprintf(w, "    Match:\n")
			fmt.Fprintf(w, "      Destination addresses: %s\n", dstMatch)
			if rule.Match.DestinationPort != 0 {
				fmt.Fprintf(w, "      Destination port:      %d\n", rule.Match.DestinationPort)
			}
			if rule.Match.Protocol != "" {
				fmt.Fprintf(w, "      IP protocol:           %s\n", rule.Match.Protocol)
			}
			if rule.Match.Application != "" {
				fmt.Fprintf(w, "      Application:           %s\n", rule.Match.Application)
			}
			fmt.Fprintf(w, "    Action:                  %s\n", action)

			if rule.Then.PoolName != "" && dnat.Pools != nil {
				if pool, ok := dnat.Pools[rule.Then.PoolName]; ok {
					fmt.Fprintf(w, "    Pool address:            %s\n", pool.Address)
					if pool.Port != 0 {
						fmt.Fprintf(w, "    Pool port:               %d\n", pool.Port)
					}
				}
			}

			if dp != nil && cr != nil {
				ruleKey := rs.Name + "/" + rule.Name
				if cid, ok := cr.NATCounterIDs[ruleKey]; ok {
					cnt, err := dp.ReadNATRuleCounter(uint32(cid))
					if err == nil {
						fmt.Fprintf(w, "    Translation hits:        %d packets  %d bytes\n",
							cnt.Packets, cnt.Bytes)
					}
				}
			}

			sessions := rsSessions[ruleSetKey{rs.FromZone, rs.ToZone}]
			fmt.Fprintf(w, "    Number of sessions:      %d\n\n", sessions)
		}
	}
}
