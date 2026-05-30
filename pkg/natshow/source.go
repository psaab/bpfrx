package natshow

import (
	"fmt"
	"io"
	"strings"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

// RenderSourceRuleDetail renders detailed source NAT rule information,
// including pool details, translation hit counters, and active session
// counts per rule-set. A nil dp/cr reproduces the "not loaded" path
// (no session counts, no translation hits).
func RenderSourceRuleDetail(w io.Writer, cfg *config.Config, dp Reader, cr *dataplane.ApplyResult) {
	if cfg == nil || len(cfg.Security.NAT.Source) == 0 {
		io.WriteString(w, "No source NAT rules configured\n")
		return
	}
	// Count active SNAT sessions per rule-set
	type ruleSetKey struct{ from, to string }
	rsSessions := make(map[ruleSetKey]int)
	if dp != nil && dp.IsLoaded() && cr != nil {
		zoneByID := make(map[uint16]string, len(cr.ZoneIDs))
		for name, id := range cr.ZoneIDs {
			zoneByID[id] = name
		}
		_ = dp.IterateSessions(func(_ dataplane.SessionKey, val dataplane.SessionValue) bool {
			if val.IsReverse == 0 && val.Flags&dataplane.SessFlagSNAT != 0 {
				rsSessions[ruleSetKey{zoneByID[val.IngressZone], zoneByID[val.EgressZone]}]++
			}
			return true
		})
		_ = dp.IterateSessionsV6(func(_ dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
			if val.IsReverse == 0 && val.Flags&dataplane.SessFlagSNAT != 0 {
				rsSessions[ruleSetKey{zoneByID[val.IngressZone], zoneByID[val.EgressZone]}]++
			}
			return true
		})
	}

	ruleIdx := 0
	for _, rs := range cfg.Security.NAT.Source {
		for _, rule := range rs.Rules {
			ruleIdx++
			action := "interface"
			if rule.Then.PoolName != "" {
				action = "pool " + rule.Then.PoolName
			} else if rule.Then.Off {
				action = "off"
			}
			srcMatch := "0.0.0.0/0"
			if rule.Match.SourceAddress != "" {
				srcMatch = rule.Match.SourceAddress
			}
			dstMatch := "0.0.0.0/0"
			if rule.Match.DestinationAddress != "" {
				dstMatch = rule.Match.DestinationAddress
			}
			fmt.Fprintf(w, "source NAT rule: %s\n", rule.Name)
			fmt.Fprintf(w, "  Rule-set: %s                        ID: %d\n", rs.Name, ruleIdx)
			fmt.Fprintf(w, "    From zone: %s    To zone: %s\n", rs.FromZone, rs.ToZone)
			fmt.Fprintf(w, "    Match:\n")
			fmt.Fprintf(w, "      Source addresses:      %s\n", srcMatch)
			fmt.Fprintf(w, "      Destination addresses: %s\n", dstMatch)
			if rule.Match.Protocol != "" {
				fmt.Fprintf(w, "      IP protocol:           %s\n", rule.Match.Protocol)
			}
			fmt.Fprintf(w, "    Action:                  %s\n", action)

			if rule.Then.PoolName != "" && cfg.Security.NAT.SourcePools != nil {
				if pool, ok := cfg.Security.NAT.SourcePools[rule.Then.PoolName]; ok {
					if pool.PersistentNAT != nil {
						fmt.Fprintf(w, "    Persistent NAT:          enabled\n")
					}
					if len(pool.Addresses) > 0 {
						fmt.Fprintf(w, "    Pool addresses:          %s\n", strings.Join(pool.Addresses, ", "))
					}
					portLow, portHigh := pool.PortLow, pool.PortHigh
					if portLow == 0 {
						portLow = 1024
					}
					if portHigh == 0 {
						portHigh = 65535
					}
					fmt.Fprintf(w, "    Port range:              %d-%d\n", portLow, portHigh)
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
