package api

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// runtimeSourceNATPools returns the userspace helper's live source-NAT pool
// status, deduplicated by pool name. Rules sharing a pool reference the same
// Arc<PortAllocatorShared> and report identical occupancy, so a single entry
// per pool is kept (never summed) — matching the AppliedNATView dedup contract
// in pkg/dataplane/userspace/applied_nat_view.go.
//
// This is the SSOT for in-use / capacity under the AF_XDP userspace dataplane
// (#2938): the helper publishes the authoritative AddressCount / PortLow /
// PortHigh / UsedPorts (it rejects malformed addresses, splits pools by IP
// family, and shares allocator state across rules), which config text and the
// retired-eBPF port counter cannot. Returns nil when the helper is not running
// or does not expose a runtime status — callers then fall back to the
// config-derived view.
func (s *Server) runtimeSourceNATPools() map[string]dpuserspace.SourceNATPoolStatus {
	if s.dp == nil || !s.dp.IsLoaded() {
		return nil
	}
	provider, ok := s.dp.(interface {
		Status() (dpuserspace.ProcessStatus, error)
	})
	if !ok {
		return nil
	}
	status, err := provider.Status()
	if err != nil {
		return nil
	}
	if len(status.SourceNATPools) == 0 {
		return nil
	}
	pools := make(map[string]dpuserspace.SourceNATPoolStatus, len(status.SourceNATPools))
	for _, p := range status.SourceNATPools {
		if p.PoolName == "" {
			continue
		}
		if _, seen := pools[p.PoolName]; seen {
			continue
		}
		pools[p.PoolName] = p
	}
	return pools
}

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

	// #2938: in-use / capacity must come from the userspace helper's live
	// runtime status, not config text + the retired-eBPF port counter. The
	// helper rejects malformed addresses, splits pools by IP family, reports
	// actual used ports, and shares allocator state across rules — config text
	// can over-report capacity and the legacy ReadNATPortCounter is dead under
	// the AF_XDP dataplane. runtime[name] is the SSOT when present.
	runtime := s.runtimeSourceNATPools()

	// Named pools
	for name, pool := range cfg.Security.NAT.SourcePools {
		// Config-derived fallback for capacity (used only when the helper has
		// no runtime entry for this pool — e.g. before the first apply lands).
		portLow, portHigh := pool.PortLow, pool.PortHigh
		if portLow == 0 {
			portLow = 1024
		}
		if portHigh == 0 {
			portHigh = 65535
		}
		addrCount := len(pool.Addresses)
		used := 0

		if rp, ok := runtime[name]; ok {
			// Runtime SSOT: the helper's applied address count, port window,
			// and live used-port occupancy.
			if rp.AddressCount > 0 {
				addrCount = rp.AddressCount
			}
			if rp.PortLow != 0 {
				portLow = int(rp.PortLow)
			}
			if rp.PortHigh != 0 {
				portHigh = int(rp.PortHigh)
			}
			used = int(rp.UsedPorts)
		} else if cr != nil {
			// No runtime entry (helper not running / pre-first-apply): fall
			// back to the legacy port counter so the surface is not blank.
			if id, ok := cr.PoolIDs[name]; ok {
				cnt, err := s.dp.ReadNATPortCounter(uint32(id))
				if err == nil {
					used = int(cnt)
				}
			}
		}

		totalPorts := 0
		if portHigh >= portLow {
			totalPorts = (portHigh - portLow + 1) * addrCount
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
					// A partial scan under-counts interface-mode NAT
					// usage; fail rather than report a healthy-but-low
					// figure (#2469).
					if err := s.dp.IterateSessions(func(_ dataplane.SessionKey, val dataplane.SessionValue) bool {
						if val.IsReverse == 0 && val.Flags&dataplane.SessFlagSNAT != 0 {
							used++
						}
						return true
					}); err != nil {
						writeError(w, http.StatusInternalServerError, "iterate sessions: "+err.Error())
						return
					}
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
				ruleKey := dataplane.NATCounterKey(dataplane.NATCounterTypeSource, rs.Name, rule.Name)
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
