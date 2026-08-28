package grpcapi

import (
	"context"
	"fmt"
	"math"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"github.com/psaab/xpf/pkg/vrrp"
)

// clampInt32 saturates a non-negative int64 to the int32 range so a large
// NAT port-pool size (which is computed in int64) does not wrap negative
// when stored in an int32 protobuf field (#2282).
func clampInt32(v int64) int32 {
	if v > math.MaxInt32 {
		return math.MaxInt32
	}
	if v < math.MinInt32 {
		return math.MinInt32
	}
	return int32(v)
}

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

func (s *Server) GetNATDestination(ctx context.Context, _ *pb.GetNATDestinationRequest) (*pb.GetNATDestinationResponse, error) {
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
		// #6553: same admission contract as GetNATPoolStats above. This walk
		// has no REST counterpart at all (natDestHandler does not scan), so it
		// was the only NAT surface on any transport driving an ungated
		// full-table walk.
		release, walkCtx, err := sessionWalkLimiter.AcquireCtx(ctx)
		if err != nil {
			return nil, status.Error(codes.ResourceExhausted,
				"nat destination stats concurrency limit reached; retry shortly")
		}
		defer release()

		var zoneByID map[uint16]string
		if cr := s.applyResult(); cr != nil {
			zoneByID = make(map[uint16]string, len(cr.ZoneIDs))
			for name, id := range cr.ZoneIDs {
				zoneByID[id] = name
			}
		}
		counts := s.countDNATSessions(walkCtx, zoneByID)
		resp.TotalActiveTranslations = clampInt32(counts.total)
		for _, rs := range cfg.Security.NAT.Destination.RuleSets {
			key := natRuleSetKey{rs.FromZone, rs.ToZone}
			if cnt, ok := counts.ruleSetSessions[key]; ok {
				resp.RuleSetSessions = append(resp.RuleSetSessions, &pb.NATRuleSetSessions{
					FromZone: rs.FromZone,
					ToZone:   rs.ToZone,
					Sessions: clampInt32(cnt),
				})
			}
		}
	}

	return resp, nil
}

func (s *Server) GetNATPoolStats(ctx context.Context, _ *pb.GetNATPoolStatsRequest) (*pb.GetNATPoolStatsResponse, error) {
	cfg := s.store.ActiveConfig()
	if cfg == nil {
		return &pb.GetNATPoolStatsResponse{}, nil
	}

	resp := &pb.GetNATPoolStatsResponse{}
	cr := s.loadedApplyResult()
	telemetry := s.telemetry()

	// Named pools
	grpcOverBudget := config.SourceNATAggregateOverBudgetPools(cfg)
	for name, pool := range cfg.Security.NAT.SourcePools {
		portLow, portHigh := pool.PortLow, pool.PortHigh
		if portLow == 0 {
			portLow = 1024
		}
		if portHigh == 0 {
			portHigh = 65535
		}
		// Port-pool size, in int64 and via the single shared formula: it can
		// exceed int32 for a large pool (a /16 over the default 64512-port
		// window is ~4.2e9) and a bare int32() cast would wrap negative and
		// corrupt the avail=total-used display, so proto assignment saturates
		// through clampInt32 (#2282). config.NATPoolTotalPorts also carries
		// the portHigh >= portLow guard REST had and the other three surfaces
		// did not (#6553).
		// #7000: the cardinality fed into that formula was the wrong part.
		// `len(pool.Addresses)` reported capacity for a REFUSED pool,
		// under-reported a prefix member (a /24 installs 256, not 1), and
		// missed the singular `address` field. The compiler's verdict answers
		// all three; the shared multiplication above is unchanged.
		totalPorts64, _ := config.SourceNATPoolReportablePorts(pool, name, portLow, portHigh, grpcOverBudget)
		var used64 int64
		if cr != nil {
			if id, ok := cr.PoolIDs[name]; ok {
				cnt, err := telemetry.NATPortCounter(uint32(id))
				if err != nil {
					// A counter read FAILURE must fail the RPC as unavailable,
					// not return a healthy zero-usage pool (#5046, #3345
					// counter-error contract, matching GetZones/GetPolicies).
					return nil, status.Errorf(codes.Internal,
						"NAT pool port counter read failed for pool %q: %v", name, err)
				}
				used64 = int64(cnt)
			}
		}

		avail64 := totalPorts64 - used64
		if avail64 < 0 {
			avail64 = 0
		}
		util := "0.0%"
		if totalPorts64 > 0 {
			util = fmt.Sprintf("%.1f%%", float64(used64)/float64(totalPorts64)*100)
		}

		resp.Pools = append(resp.Pools, &pb.NATPoolStats{
			Name:           name,
			Address:        strings.Join(pool.Addresses, ","),
			TotalPorts:     clampInt32(totalPorts64),
			UsedPorts:      clampInt32(used64),
			AvailablePorts: clampInt32(avail64),
			Utilization:    util,
		})
	}

	// Count active SNAT sessions and per-rule-set breakdown
	var counts natSessionCounts
	if s.dataplaneLoaded() {
		// #6553: this is a full v4+v6 conntrack walk and it had NO admission
		// gate — the REST twin acquired one in #6216. Take the slot at this
		// external trust boundary, inside the dataplane-loaded branch so a
		// config-only response is never refused, and honour the returned lease
		// context so a disconnected client's walk stops instead of holding a
		// slot the (hardened) REST surface is queueing for. The two surfaces
		// share ONE 4-slot diagcmd.SessionWalkLimiter, so the un-hardened one
		// starves the hardened one.
		release, walkCtx, err := sessionWalkLimiter.AcquireCtx(ctx)
		if err != nil {
			return nil, status.Error(codes.ResourceExhausted,
				"nat pool stats concurrency limit reached; retry shortly")
		}
		defer release()

		var zoneByID map[uint16]string
		if cr != nil {
			zoneByID = make(map[uint16]string, len(cr.ZoneIDs))
			for name, id := range cr.ZoneIDs {
				zoneByID[id] = name
			}
		}
		counts = s.countSNATSessions(walkCtx, zoneByID)
	}
	resp.TotalActiveTranslations = clampInt32(counts.total)

	// Interface-mode pools. Each interface-mode rule set must report only
	// the SNAT sessions that traversed its own from/to zone pair, not the
	// firewall-wide SNAT total — otherwise per-uplink/per-tenant pool usage
	// is masked by every row showing the global count (#3417). The
	// per-rule-set breakdown is already computed in counts.ruleSetSessions
	// (keyed by ingress/egress zone name) and surfaced via resp.RuleSetSessions.
	for _, rs := range cfg.Security.NAT.Source {
		for _, rule := range rs.Rules {
			if rule.Then.Interface {
				resp.Pools = append(resp.Pools, &pb.NATPoolStats{
					Name:        fmt.Sprintf("%s->%s", rs.FromZone, rs.ToZone),
					Address:     "interface",
					UsedPorts:   clampInt32(counts.ruleSetSessions[natRuleSetKey{rs.FromZone, rs.ToZone}]),
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
				Sessions: clampInt32(cnt),
			})
		}
	}

	return resp, nil
}

func (s *Server) GetNATRuleStats(_ context.Context, req *pb.GetNATRuleStatsRequest) (*pb.GetNATRuleStatsResponse, error) {
	// Reject an unknown nat_type selector rather than silently returning an
	// empty result. Only "" (default = source), "source", and "destination"
	// select a NAT-rule family below; any other value (a typo like "src" or
	// "static") would fall through BOTH branches and render as "no NAT rules"
	// — a false-empty diagnostic indistinguishable from a firewall that
	// genuinely has no rules. Surface the bad selector as InvalidArgument so
	// the operator sees the typo (codex-review-182 C-API selector hardening,
	// same discipline as the show routing/zones/firewall unknown-selector
	// diagnostics #4589/#4814/#3696).
	if req.NatType != "" && req.NatType != "source" && req.NatType != "destination" {
		return nil, status.Errorf(codes.InvalidArgument,
			"unknown NAT stats selector nat_type=%q (want \"source\" or \"destination\")", req.NatType)
	}

	cfg := s.store.ActiveConfig()
	if cfg == nil {
		return &pb.GetNATRuleStatsResponse{}, nil
	}

	resp := &pb.GetNATRuleStatsResponse{}
	cr := s.loadedApplyResult()
	telemetry := s.telemetry()

	// Helper to read NAT rule counters. natType MUST match the type the
	// compiler stamped (#2218): same-named source/destination/static rules use
	// distinct counter IDs keyed by dataplane.NATCounterKey.
	//
	// A counter READ FAILURE is returned as an error, not swallowed to (0,0):
	// the RPC must fail as unavailable rather than render a telemetry-bridge
	// failure as a healthy zero hit count (#5046, #3345 counter-error contract).
	readCounter := func(natType, rsName, ruleName string) (uint64, uint64, error) {
		if cr != nil {
			ruleKey := dataplane.NATCounterKey(natType, rsName, ruleName)
			if cid, ok := cr.NATCounterIDs[ruleKey]; ok {
				cnt, err := telemetry.NATRuleCounter(uint32(cid))
				if err != nil {
					return 0, 0, err
				}
				return cnt.Packets, cnt.Bytes, nil
			}
		}
		return 0, 0, nil
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
				hitPkts, hitBytes, err := readCounter(dataplane.NATCounterTypeSource, rs.Name, rule.Name)
				if err != nil {
					return nil, status.Errorf(codes.Internal,
						"NAT rule counter read failed for %s/%s: %v", rs.Name, rule.Name, err)
				}
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
					hitPkts, hitBytes, err := readCounter(dataplane.NATCounterTypeDest, rs.Name, rule.Name)
					if err != nil {
						return nil, status.Errorf(codes.Internal,
							"NAT rule counter read failed for %s/%s: %v", rs.Name, rule.Name, err)
					}
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
			key := vrrp.StateKey(inst.Interface, inst.GroupID, inst.Family)
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
