package grpcapi

import (
	"context"
	"sort"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

func (s *Server) GetZones(_ context.Context, _ *pb.GetZonesRequest) (*pb.GetZonesResponse, error) {
	cfg := s.store.ActiveConfig()
	if cfg == nil {
		return &pb.GetZonesResponse{}, nil
	}

	cr := s.applyResult()

	// #3408: a per-zone counter read failure must surface as codes.Internal
	// rather than a clean-zero field, mirroring GetGlobalStats (#3345).
	var readErr error
	resp := &pb.GetZonesResponse{}
	for zoneName, zone := range cfg.Security.Zones {
		if zone == nil { // #3493: tolerant/HA-sync path may carry a nil zone value
			continue
		}
		zi := &pb.ZoneInfo{
			Name:        zoneName,
			Description: zone.Description,
			Interfaces:  zone.Interfaces,
			TcpRst:      zone.TCPRst,
		}
		if zone.ScreenProfile != "" {
			zi.ScreenProfile = zone.ScreenProfile
		}
		// #3328: surface the host-inbound admission posture distinctly. The
		// legacy host_inbound_services list stays as a flattened back-compat
		// alias (system-services + protocols), but the split fields below let
		// automation tell a service apart from a protocol and — via
		// host_inbound_configured — tell "no stanza" (admit-all) apart from an
		// explicit empty stanza (deny-all).
		if zone.HostInboundTraffic != nil {
			zi.HostInboundServices = append(zi.HostInboundServices, zone.HostInboundTraffic.SystemServices...)
			zi.HostInboundServices = append(zi.HostInboundServices, zone.HostInboundTraffic.Protocols...)
			zi.HostInboundSystemServices = append(zi.HostInboundSystemServices, zone.HostInboundTraffic.SystemServices...)
			zi.HostInboundProtocols = append(zi.HostInboundProtocols, zone.HostInboundTraffic.Protocols...)
		}
		// host_inbound_configured mirrors ZoneSnapshot.HostInboundConfigured
		// (#3070/#3362): the zone is host-inbound ENFORCING when it declares a
		// zone-level stanza OR carries any per-interface override.
		zi.HostInboundConfigured = zone.HostInboundTraffic != nil || len(zone.InterfaceHostInbound) > 0
		for _, ref := range zone.SortedInterfaceHostInboundRefs() {
			hib := zone.InterfaceHostInbound[ref]
			zi.InterfaceHostInbound = append(zi.InterfaceHostInbound, &pb.InterfaceHostInbound{
				Interface:      ref,
				Configured:     true,
				SystemServices: append([]string{}, hib.SystemServices...),
				Protocols:      append([]string{}, hib.Protocols...),
			})
		}
		if zi.Interfaces == nil {
			zi.Interfaces = []string{}
		}
		if zi.HostInboundServices == nil {
			zi.HostInboundServices = []string{}
		}

		if cr != nil {
			if id, ok := cr.ZoneIDs[zoneName]; ok {
				zi.Id = uint32(id)
				if s.dp != nil && s.dp.IsLoaded() {
					if ing, err := s.dp.ReadZoneCounters(id, 0); err == nil {
						zi.IngressPackets = ing.Packets
						zi.IngressBytes = ing.Bytes
					} else if readErr == nil {
						readErr = err
					}
					if eg, err := s.dp.ReadZoneCounters(id, 1); err == nil {
						zi.EgressPackets = eg.Packets
						zi.EgressBytes = eg.Bytes
					} else if readErr == nil {
						readErr = err
					}
				}
			}
		}
		resp.Zones = append(resp.Zones, zi)
	}
	if readErr != nil {
		return nil, status.Errorf(codes.Internal, "reading zone counter: %v", readErr)
	}
	sort.Slice(resp.Zones, func(i, j int) bool { return resp.Zones[i].Name < resp.Zones[j].Name })
	return resp, nil
}

func (s *Server) GetPolicies(_ context.Context, _ *pb.GetPoliciesRequest) (*pb.GetPoliciesResponse, error) {
	cfg := s.store.ActiveConfig()
	if cfg == nil {
		return &pb.GetPoliciesResponse{}, nil
	}

	// Honor `set security policy-stats system-wide enable` (#2008 M4 /
	// #2118): per-policy hit counters are populated only when policy-stats
	// is enabled system-wide (default off), matching the Prometheus
	// collector and the CLI/gRPC text surfaces. When the knob is off,
	// HitPackets/HitBytes stay 0 (we skip the dataplane read).
	statsEnabled := cfg.Security.PolicyStatsEnabled
	// #3408: surface a per-policy counter read failure as codes.Internal.
	var readErr error
	resp := &pb.GetPoliciesResponse{}
	// #3336: span-accumulated runtime/RT_FLOW policy IDs, keyed
	// [policySetID, sliceIndex] — the same identity the event path logs, so
	// automation can join a policy_id back to a rule. The raw ordinal stays the
	// counter handle below.
	runtimeIDs := dpuserspace.RuntimePolicyIDs(cfg)
	var policySetID uint32
	for _, zpp := range cfg.Security.Policies {
		// #3476: skip a nil zone-pair set (tolerant / HA-sync path) while
		// advancing the policy-set ID, mirroring the runtime walker, rather
		// than dereferencing zpp.FromZone.
		if zpp == nil {
			policySetID++
			continue
		}
		pi := &pb.PolicyInfo{
			FromZone: zpp.FromZone,
			ToZone:   zpp.ToZone,
		}
		for i, rule := range zpp.Policies {
			// #3476: skip a nil rule like the runtime walker does.
			if rule == nil {
				continue
			}
			pr := &pb.PolicyRule{
				Name:        rule.Name,
				Description: rule.Description,
				Action:      policyActionStr(rule.Action),
				// #3358: unqualify synthetic zone-local keys (#3061) so the
				// inventory exposes the authored book name, not the internal
				// compiler token. DisplayAddressNames returns a new slice.
				SrcAddresses: config.DisplayAddressNames(rule.Match.SourceAddresses),
				DstAddresses: config.DisplayAddressNames(rule.Match.DestinationAddresses),
				Applications: rule.Match.Applications,
				Log:          rule.Log != nil,
				Count:        rule.Count,
				// #3336: match-inversion flags — without these an audit reading
				// src/dst_addresses sees a `source-address-excluded` rule's
				// meaning inverted. Additive; false for an un-inverted rule.
				SourceAddressExcluded:      rule.Match.SourceAddressExcluded,
				DestinationAddressExcluded: rule.Match.DestinationAddressExcluded,
				// #3336: independent session-init / session-close log modes the
				// collapsed `log` bool hides.
				LogSessionInit:  rule.Log != nil && rule.Log.SessionInit,
				LogSessionClose: rule.Log != nil && rule.Log.SessionClose,
				// #3336: runtime identity for event correlation.
				PolicyId: dpuserspace.RuntimePolicyIndex(runtimeIDs, policySetID, uint32(i)),
				RuleId:   dpuserspace.StablePolicyRuleID(zpp.FromZone, zpp.ToZone, rule.Name),
			}
			if pr.SrcAddresses == nil {
				pr.SrcAddresses = []string{}
			}
			if pr.DstAddresses == nil {
				pr.DstAddresses = []string{}
			}
			if pr.Applications == nil {
				pr.Applications = []string{}
			}
			if (statsEnabled || rule.Count) && s.dp != nil && s.dp.IsLoaded() {
				policyID := policySetID*dataplane.MaxRulesPerPolicy + uint32(i)
				if ctrs, err := s.dp.ReadPolicyCounters(policyID); err == nil {
					pr.HitPackets = ctrs.Packets
					pr.HitBytes = ctrs.Bytes
				} else if readErr == nil {
					readErr = err
				}
			}
			pi.Rules = append(pi.Rules, pr)
		}
		if pi.Rules == nil {
			pi.Rules = []*pb.PolicyRule{}
		}
		resp.Policies = append(resp.Policies, pi)
		policySetID++
	}

	// Global policies
	if len(cfg.Security.GlobalPolicies) > 0 {
		pi := &pb.PolicyInfo{
			FromZone: "*",
			ToZone:   "*",
		}
		for i, rule := range cfg.Security.GlobalPolicies {
			// #3476: skip a nil global rule (GlobalPolicies is []*Policy)
			// like the runtime walker does.
			if rule == nil {
				continue
			}
			pr := &pb.PolicyRule{
				Name:        rule.Name,
				Description: rule.Description,
				Action:      policyActionStr(rule.Action),
				// #3358: unqualify synthetic zone-local keys (#3061) so the
				// inventory exposes the authored book name, not the internal
				// compiler token. DisplayAddressNames returns a new slice.
				SrcAddresses: config.DisplayAddressNames(rule.Match.SourceAddresses),
				DstAddresses: config.DisplayAddressNames(rule.Match.DestinationAddresses),
				Applications: rule.Match.Applications,
				Log:          rule.Log != nil,
				Count:        rule.Count,
				// #3286: a scoped global policy (#3148) narrows the
				// all-zones group to a zone pair. Carry the configured
				// from/to-zone so the inventory shows the real scope
				// instead of the group-level "*"/"*". Empty for an
				// unscoped (all-zones) global — no regression.
				MatchFromZone: rule.Match.FromZone,
				MatchToZone:   rule.Match.ToZone,
				// #3336: match-inversion flags + log modes + runtime identity.
				// Global rule_id uses the "junos-global" sentinel zones, matching
				// the snapshot builder so the rule_id joins to the same event.
				SourceAddressExcluded:      rule.Match.SourceAddressExcluded,
				DestinationAddressExcluded: rule.Match.DestinationAddressExcluded,
				LogSessionInit:             rule.Log != nil && rule.Log.SessionInit,
				LogSessionClose:            rule.Log != nil && rule.Log.SessionClose,
				PolicyId:                   dpuserspace.RuntimePolicyIndex(runtimeIDs, policySetID, uint32(i)),
				RuleId:                     dpuserspace.StablePolicyRuleID("junos-global", "junos-global", rule.Name),
			}
			if pr.SrcAddresses == nil {
				pr.SrcAddresses = []string{}
			}
			if pr.DstAddresses == nil {
				pr.DstAddresses = []string{}
			}
			if pr.Applications == nil {
				pr.Applications = []string{}
			}
			if (statsEnabled || rule.Count) && s.dp != nil && s.dp.IsLoaded() {
				policyID := policySetID*dataplane.MaxRulesPerPolicy + uint32(i)
				if ctrs, err := s.dp.ReadPolicyCounters(policyID); err == nil {
					pr.HitPackets = ctrs.Packets
					pr.HitBytes = ctrs.Bytes
				} else if readErr == nil {
					readErr = err
				}
			}
			pi.Rules = append(pi.Rules, pr)
		}
		if pi.Rules == nil {
			pi.Rules = []*pb.PolicyRule{}
		}
		resp.Policies = append(resp.Policies, pi)
	}

	// #3363: the IMPLICIT default-policy catch-all has a reserved hit counter
	// (read via the DefaultPolicySentinelID handle). Surface it as a final
	// synthetic policy set ("-"/"-") with one rule named
	// dataplane.DefaultPolicyName so structured automation reading GetPolicies
	// sees the same default-deny/permit row REST/CLI/text/Prometheus render.
	// Counts gate on policy-stats like every other rule.
	{
		defRule := &pb.PolicyRule{
			Name:         dataplane.DefaultPolicyName,
			Action:       policyActionStr(cfg.Security.DefaultPolicy),
			SrcAddresses: []string{},
			DstAddresses: []string{},
			Applications: []string{},
			PolicyId:     dataplane.DefaultPolicySentinelID,
			RuleId:       dataplane.DefaultPolicyName,
		}
		if statsEnabled && s.dp != nil && s.dp.IsLoaded() {
			if ctrs, err := s.dp.ReadPolicyCounters(dataplane.DefaultPolicySentinelID); err == nil {
				defRule.HitPackets = ctrs.Packets
				defRule.HitBytes = ctrs.Bytes
			} else if readErr == nil {
				readErr = err
			}
		}
		resp.Policies = append(resp.Policies, &pb.PolicyInfo{
			FromZone: "-",
			ToZone:   "-",
			Rules:    []*pb.PolicyRule{defRule},
		})
	}

	if readErr != nil {
		return nil, status.Errorf(codes.Internal, "reading policy counter: %v", readErr)
	}
	return resp, nil
}

func (s *Server) GetScreen(_ context.Context, _ *pb.GetScreenRequest) (*pb.GetScreenResponse, error) {
	cfg := s.store.ActiveConfig()
	if cfg == nil {
		return &pb.GetScreenResponse{}, nil
	}

	resp := &pb.GetScreenResponse{}
	for name, profile := range cfg.Security.Screen {
		si := &pb.ScreenInfo{
			Name:   name,
			Checks: screenChecks(profile),
		}
		if si.Checks == nil {
			si.Checks = []string{}
		}
		if th := config.ScreenThresholds(profile); len(th) > 0 {
			si.Thresholds = make(map[string]int64, len(th))
			for k, v := range th {
				si.Thresholds[k] = int64(v)
			}
		}
		resp.Screens = append(resp.Screens, si)
	}
	sort.Slice(resp.Screens, func(i, j int) bool { return resp.Screens[i].Name < resp.Screens[j].Name })
	return resp, nil
}
