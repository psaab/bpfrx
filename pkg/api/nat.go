package api

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/psaab/xpf/pkg/dataplane"
)

func (s *Server) natSourceHandler(w http.ResponseWriter, _ *http.Request) {
	cfg := s.store.ActiveConfig()
	if cfg == nil {
		writeOK(w, []NATSourceInfo{})
		return
	}

	var result []NATSourceInfo
	for _, rs := range cfg.Security.NAT.Source {
		for _, rule := range rs.Rules {
			info := NATSourceInfo{
				FromZone: rs.FromZone,
				ToZone:   rs.ToZone,
			}
			if rule.Then.Interface {
				info.Type = "interface"
			} else if rule.Then.PoolName != "" {
				info.Type = "pool"
				info.Pool = rule.Then.PoolName
			}
			result = append(result, info)
		}
	}
	writeOK(w, result)
}

func (s *Server) natDestHandler(w http.ResponseWriter, _ *http.Request) {
	cfg := s.store.ActiveConfig()
	if cfg == nil || cfg.Security.NAT.Destination == nil {
		writeOK(w, []NATDestInfo{})
		return
	}

	var result []NATDestInfo
	for _, rs := range cfg.Security.NAT.Destination.RuleSets {
		for _, rule := range rs.Rules {
			info := NATDestInfo{
				Name:    rule.Name,
				DstAddr: rule.Match.DestinationAddress,
			}
			if rule.Match.DestinationPort > 0 {
				info.DstPort = uint16(rule.Match.DestinationPort)
			}
			if pool, ok := cfg.Security.NAT.Destination.Pools[rule.Then.PoolName]; ok {
				info.TranslateIP = pool.Address
				if pool.Port > 0 {
					info.TranslatePort = uint16(pool.Port)
				}
			}
			result = append(result, info)
		}
	}
	writeOK(w, result)
}

func (s *Server) natPoolStatsHandler(w http.ResponseWriter, _ *http.Request) {
	cfg := s.store.ActiveConfig()
	if cfg == nil {
		writeOK(w, []NATPoolStatsInfo{})
		return
	}

	var result []NATPoolStatsInfo
	var cr *dataplane.ApplyResult
	if s.dp != nil && s.dp.IsLoaded() {
		cr = s.applyResult()
	}

	// Named pools
	for name, pool := range cfg.Security.NAT.SourcePools {
		portLow, portHigh := pool.PortLow, pool.PortHigh
		if portLow == 0 {
			portLow = 1024
		}
		if portHigh == 0 {
			portHigh = 65535
		}
		totalPorts := (portHigh - portLow + 1) * len(pool.Addresses)
		used := 0

		if cr != nil {
			if id, ok := cr.PoolIDs[name]; ok {
				cnt, err := s.dp.ReadNATPortCounter(uint32(id))
				if err == nil {
					used = int(cnt)
				}
			}
		}

		avail := totalPorts - used
		if avail < 0 {
			avail = 0
		}
		util := "0.0%"
		if totalPorts > 0 {
			util = fmt.Sprintf("%.1f%%", float64(used)/float64(totalPorts)*100)
		}

		result = append(result, NATPoolStatsInfo{
			Name:           name,
			Address:        strings.Join(pool.Addresses, ","),
			TotalPorts:     totalPorts,
			UsedPorts:      used,
			AvailablePorts: avail,
			Utilization:    util,
		})
	}

	// Interface-mode pools
	for _, rs := range cfg.Security.NAT.Source {
		for _, rule := range rs.Rules {
			if rule.Then.Interface {
				used := 0
				if s.dp != nil && s.dp.IsLoaded() {
					_ = s.dp.IterateSessions(func(_ dataplane.SessionKey, val dataplane.SessionValue) bool {
						if val.IsReverse == 0 && val.Flags&dataplane.SessFlagSNAT != 0 {
							used++
						}
						return true
					})
				}
				result = append(result, NATPoolStatsInfo{
					Name:        fmt.Sprintf("%s->%s", rs.FromZone, rs.ToZone),
					Address:     "interface",
					UsedPorts:   used,
					IsInterface: true,
				})
			}
		}
	}

	if result == nil {
		result = []NATPoolStatsInfo{}
	}
	writeOK(w, result)
}

func (s *Server) natRuleStatsHandler(w http.ResponseWriter, r *http.Request) {
	cfg := s.store.ActiveConfig()
	if cfg == nil {
		writeOK(w, []NATRuleStatsInfo{})
		return
	}

	ruleSetFilter := r.URL.Query().Get("rule_set")
	var result []NATRuleStatsInfo
	var cr *dataplane.ApplyResult
	if s.dp != nil && s.dp.IsLoaded() {
		cr = s.applyResult()
	}

	for _, rs := range cfg.Security.NAT.Source {
		if ruleSetFilter != "" && rs.Name != ruleSetFilter {
			continue
		}
		for _, rule := range rs.Rules {
			action := "interface"
			if rule.Then.PoolName != "" {
				action = "pool " + rule.Then.PoolName
			}
			srcMatch := "0.0.0.0/0"
			if rule.Match.SourceAddress != "" {
				srcMatch = rule.Match.SourceAddress
			}
			dstMatch := "0.0.0.0/0"
			if rule.Match.DestinationAddress != "" {
				dstMatch = rule.Match.DestinationAddress
			}

			var hitPkts, hitBytes uint64
			if cr != nil {
				ruleKey := rs.Name + "/" + rule.Name
				if cid, ok := cr.NATCounterIDs[ruleKey]; ok {
					cnt, err := s.dp.ReadNATRuleCounter(uint32(cid))
					if err == nil {
						hitPkts = cnt.Packets
						hitBytes = cnt.Bytes
					}
				}
			}

			result = append(result, NATRuleStatsInfo{
				RuleSet:    rs.Name,
				RuleName:   rule.Name,
				FromZone:   rs.FromZone,
				ToZone:     rs.ToZone,
				Action:     action,
				SrcMatch:   srcMatch,
				DstMatch:   dstMatch,
				HitPackets: hitPkts,
				HitBytes:   hitBytes,
			})
		}
	}

	if result == nil {
		result = []NATRuleStatsInfo{}
	}
	writeOK(w, result)
}
