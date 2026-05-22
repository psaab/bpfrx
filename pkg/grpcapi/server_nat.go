package grpcapi

import (
	"context"
	"fmt"
	"strings"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"github.com/psaab/xpf/pkg/vrrp"
)

func (s *Server) GetNATSource(_ context.Context, _ *pb.GetNATSourceRequest) (*pb.GetNATSourceResponse, error) {
	cfg := s.store.ActiveConfig()
	if cfg == nil {
		return &pb.GetNATSourceResponse{}, nil
	}

	resp := &pb.GetNATSourceResponse{}
	for _, rs := range cfg.Security.NAT.Source {
		for _, rule := range rs.Rules {
			info := &pb.NATSourceInfo{
				FromZone: rs.FromZone,
				ToZone:   rs.ToZone,
			}
			if rule.Then.Interface {
				info.Type = "interface"
			} else if rule.Then.PoolName != "" {
				info.Type = "pool"
				info.Pool = rule.Then.PoolName
			}
			resp.Rules = append(resp.Rules, info)
		}
	}
	return resp, nil
}

func (s *Server) GetNATDestination(_ context.Context, _ *pb.GetNATDestinationRequest) (*pb.GetNATDestinationResponse, error) {
	cfg := s.store.ActiveConfig()
	if cfg == nil || cfg.Security.NAT.Destination == nil {
		return &pb.GetNATDestinationResponse{}, nil
	}

	resp := &pb.GetNATDestinationResponse{}
	for _, rs := range cfg.Security.NAT.Destination.RuleSets {
		for _, rule := range rs.Rules {
			info := &pb.NATDestInfo{
				Name:    rule.Name,
				DstAddr: rule.Match.DestinationAddress,
			}
			if rule.Match.DestinationPort > 0 {
				info.DstPort = uint32(rule.Match.DestinationPort)
			}
			if pool, ok := cfg.Security.NAT.Destination.Pools[rule.Then.PoolName]; ok {
				info.TranslateIp = pool.Address
				if pool.Port > 0 {
					info.TranslatePort = uint32(pool.Port)
				}
			}
			resp.Rules = append(resp.Rules, info)
		}
	}

	// Count active DNAT sessions and per-rule-set breakdown
	if s.dataplaneLoaded() {
		var zoneByID map[uint16]string
		if cr := s.applyResult(); cr != nil {
			zoneByID = make(map[uint16]string, len(cr.ZoneIDs))
			for name, id := range cr.ZoneIDs {
				zoneByID[id] = name
			}
		}
		counts := s.countDNATSessions(zoneByID)
		resp.TotalActiveTranslations = counts.total
		for _, rs := range cfg.Security.NAT.Destination.RuleSets {
			key := natRuleSetKey{rs.FromZone, rs.ToZone}
			if cnt, ok := counts.ruleSetSessions[key]; ok {
				resp.RuleSetSessions = append(resp.RuleSetSessions, &pb.NATRuleSetSessions{
					FromZone: rs.FromZone,
					ToZone:   rs.ToZone,
					Sessions: cnt,
				})
			}
		}
	}

	return resp, nil
}

func (s *Server) GetNATPoolStats(_ context.Context, _ *pb.GetNATPoolStatsRequest) (*pb.GetNATPoolStatsResponse, error) {
	cfg := s.store.ActiveConfig()
	if cfg == nil {
		return &pb.GetNATPoolStatsResponse{}, nil
	}

	resp := &pb.GetNATPoolStatsResponse{}
	cr := s.loadedApplyResult()
	telemetry := s.telemetry()

	// Named pools
	for name, pool := range cfg.Security.NAT.SourcePools {
		portLow, portHigh := pool.PortLow, pool.PortHigh
		if portLow == 0 {
			portLow = 1024
		}
		if portHigh == 0 {
			portHigh = 65535
		}
		totalPorts := int32((portHigh - portLow + 1) * len(pool.Addresses))
		used := int32(0)

		if cr != nil {
			if id, ok := cr.PoolIDs[name]; ok {
				cnt, err := telemetry.NATPortCounter(uint32(id))
				if err == nil {
					used = int32(cnt)
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

		resp.Pools = append(resp.Pools, &pb.NATPoolStats{
			Name:           name,
			Address:        strings.Join(pool.Addresses, ","),
			TotalPorts:     totalPorts,
			UsedPorts:      used,
			AvailablePorts: avail,
			Utilization:    util,
		})
	}

	// Count active SNAT sessions and per-rule-set breakdown
	var counts natSessionCounts
	if s.dataplaneLoaded() {
		var zoneByID map[uint16]string
		if cr != nil {
			zoneByID = make(map[uint16]string, len(cr.ZoneIDs))
			for name, id := range cr.ZoneIDs {
				zoneByID[id] = name
			}
		}
		counts = s.countSNATSessions(zoneByID)
	}
	resp.TotalActiveTranslations = counts.total

	// Interface-mode pools
	for _, rs := range cfg.Security.NAT.Source {
		for _, rule := range rs.Rules {
			if rule.Then.Interface {
				resp.Pools = append(resp.Pools, &pb.NATPoolStats{
					Name:        fmt.Sprintf("%s->%s", rs.FromZone, rs.ToZone),
					Address:     "interface",
					UsedPorts:   counts.total,
					IsInterface: true,
				})
			}
		}
	}

	// Per-rule-set session counts
	for _, rs := range cfg.Security.NAT.Source {
		key := natRuleSetKey{rs.FromZone, rs.ToZone}
		if cnt, ok := counts.ruleSetSessions[key]; ok {
			resp.RuleSetSessions = append(resp.RuleSetSessions, &pb.NATRuleSetSessions{
				FromZone: rs.FromZone,
				ToZone:   rs.ToZone,
				Sessions: cnt,
			})
		}
	}

	return resp, nil
}

func (s *Server) GetNATRuleStats(_ context.Context, req *pb.GetNATRuleStatsRequest) (*pb.GetNATRuleStatsResponse, error) {
	cfg := s.store.ActiveConfig()
	if cfg == nil {
		return &pb.GetNATRuleStatsResponse{}, nil
	}

	resp := &pb.GetNATRuleStatsResponse{}
	cr := s.loadedApplyResult()
	telemetry := s.telemetry()

	// Helper to read NAT rule counters
	readCounter := func(rsName, ruleName string) (uint64, uint64) {
		if cr != nil {
			ruleKey := rsName + "/" + ruleName
			if cid, ok := cr.NATCounterIDs[ruleKey]; ok {
				cnt, err := telemetry.NATRuleCounter(uint32(cid))
				if err == nil {
					return cnt.Packets, cnt.Bytes
				}
			}
		}
		return 0, 0
	}

	// Source NAT rules (default when nat_type is empty or "source")
	if req.NatType == "" || req.NatType == "source" {
		for _, rs := range cfg.Security.NAT.Source {
			if req.RuleSet != "" && rs.Name != req.RuleSet {
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
				hitPkts, hitBytes := readCounter(rs.Name, rule.Name)
				resp.Rules = append(resp.Rules, &pb.NATRuleStats{
					RuleSet:          rs.Name,
					RuleName:         rule.Name,
					FromZone:         rs.FromZone,
					ToZone:           rs.ToZone,
					Action:           action,
					SourceMatch:      srcMatch,
					DestinationMatch: dstMatch,
					HitPackets:       hitPkts,
					HitBytes:         hitBytes,
				})
			}
		}
	}

	// Destination NAT rules
	if req.NatType == "destination" {
		if dnat := cfg.Security.NAT.Destination; dnat != nil {
			for _, rs := range dnat.RuleSets {
				if req.RuleSet != "" && rs.Name != req.RuleSet {
					continue
				}
				for _, rule := range rs.Rules {
					action := "off"
					if rule.Then.PoolName != "" {
						action = "pool " + rule.Then.PoolName
					}
					dstMatch := "0.0.0.0/0"
					if rule.Match.DestinationAddress != "" {
						dstMatch = rule.Match.DestinationAddress
					}
					if rule.Match.DestinationPort != 0 {
						dstMatch += fmt.Sprintf(":%d", rule.Match.DestinationPort)
					}
					hitPkts, hitBytes := readCounter(rs.Name, rule.Name)
					resp.Rules = append(resp.Rules, &pb.NATRuleStats{
						RuleSet:          rs.Name,
						RuleName:         rule.Name,
						FromZone:         rs.FromZone,
						ToZone:           rs.ToZone,
						Action:           action,
						DestinationMatch: dstMatch,
						HitPackets:       hitPkts,
						HitBytes:         hitBytes,
					})
				}
			}
		}
	}

	return resp, nil
}

func (s *Server) GetVRRPStatus(_ context.Context, _ *pb.GetVRRPStatusRequest) (*pb.GetVRRPStatusResponse, error) {
	cfg := s.store.ActiveConfig()
	resp := &pb.GetVRRPStatusResponse{}

	if cfg != nil {
		instances := vrrp.CollectInstances(cfg)
		if s.cluster != nil {
			instances = append(instances, vrrp.CollectRethInstances(cfg, s.cluster.LocalPriorities())...)
		}
		var runtimeStates map[string]string
		if s.vrrpMgr != nil {
			runtimeStates = s.vrrpMgr.States()
		}
		for _, inst := range instances {
			key := fmt.Sprintf("VI_%s_%d", inst.Interface, inst.GroupID)
			state := "INIT"
			if s, ok := runtimeStates[key]; ok {
				state = s
			}
			resp.Instances = append(resp.Instances, &pb.VRRPInstanceInfo{
				Interface:        inst.Interface,
				GroupId:          int32(inst.GroupID),
				State:            state,
				Priority:         int32(inst.Priority),
				VirtualAddresses: inst.VirtualAddresses,
				Preempt:          inst.Preempt,
			})
		}
	}

	if s.vrrpMgr != nil {
		resp.ServiceStatus = s.vrrpMgr.Status()
	} else {
		resp.ServiceStatus = "VRRP: not running\n"
	}

	return resp, nil
}
