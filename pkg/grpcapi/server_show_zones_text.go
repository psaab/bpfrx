// Phase 8 of #1043: extract the `zones-detail` ShowText case body
// into a dedicated method. Same methodology as Phases 1-7 (#1148,
// #1150, #1151, #1153, #1154, #1155, #1156): semantic relocation, no
// behavior change. The case body is moved verbatim apart from
// (a) `&buf` references becoming `buf` (passed-in `*strings.Builder`)
// and (b) the original `if cfg == nil { … } else { … long body }`
// flattened into early-return form. Output is unchanged.

package grpcapi

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// showZonesDetail renders per-zone configuration plus dataplane traffic
// counters, policy references, interface details, screen profile
// breakdown, and policy-rule summaries.
func (s *Server) showZonesDetail(cfg *config.Config, buf *strings.Builder) {
	if cfg == nil || len(cfg.Security.Zones) == 0 {
		buf.WriteString("No security zones configured\n")
		return
	}
	zoneNames := make([]string, 0, len(cfg.Security.Zones))
	for name := range cfg.Security.Zones {
		zoneNames = append(zoneNames, name)
	}
	sort.Strings(zoneNames)
	cr := s.applyResult()
	// #3408: surface a per-zone counter read failure as a warning AFTER all
	// zones rather than silently dropping the traffic-statistics block.
	var readErr error
	for _, name := range zoneNames {
		zone := cfg.Security.Zones[name]
		if zone == nil { // #3493: tolerant/HA-sync path may carry a nil zone value
			continue
		}
		var zoneID uint16
		if cr != nil {
			zoneID = cr.ZoneIDs[name]
		}
		if zoneID > 0 {
			fmt.Fprintf(buf, "Zone: %s (id: %d)\n", name, zoneID)
		} else {
			fmt.Fprintf(buf, "Zone: %s\n", name)
		}
		if zone.Description != "" {
			fmt.Fprintf(buf, "  Description: %s\n", zone.Description)
		}
		fmt.Fprintf(buf, "  Interfaces: %s\n", strings.Join(zone.Interfaces, ", "))
		if zone.TCPRst {
			buf.WriteString("  TCP RST: enabled\n")
		}
		if zone.ScreenProfile != "" {
			fmt.Fprintf(buf, "  Screen: %s\n", zone.ScreenProfile)
		}
		// #3654: render the zone-level admitted set, the no-stanza default-deny
		// posture line, AND any per-interface host-inbound override through the
		// shared config presenter (H07/M03) so gRPC text stays in lockstep with
		// the local CLI and the structured inventory. #3682: the presenter also
		// renders the management/cluster-control lifeline interfaces excluded
		// from host-inbound deny scoping so the implicit exemption is auditable.
		for _, line := range zone.HostInboundViewWithLifelines(
			config.HostInboundLifelineSet(cfg)).Render(config.HostInboundLabels{
			Indent:         "  ",
			Sep:            ", ",
			ServicesLabel:  "Host-inbound system-services",
			ProtocolsLabel: "Host-inbound protocols",
		}) {
			buf.WriteString(line)
			buf.WriteString("\n")
		}
		// Traffic counters
		if s.dp != nil && s.dp.IsLoaded() && zoneID > 0 {
			ingress, errIn := s.dp.ReadZoneCounters(zoneID, 0)
			egress, errOut := s.dp.ReadZoneCounters(zoneID, 1)
			switch {
			case errors.Is(errIn, dataplane.ErrCounterNotPopulated) ||
				errors.Is(errOut, dataplane.ErrCounterNotPopulated):
				// #3643 HIDE: per-zone traffic counters are not sourced by the
				// userspace dataplane. Say so explicitly rather than a
				// misleading 0.
				buf.WriteString("  Traffic statistics: not available " +
					"(per-zone accounting not implemented in the userspace dataplane)\n")
			case errIn == nil && errOut == nil:
				buf.WriteString("  Traffic statistics:\n")
				fmt.Fprintf(buf, "    Input:  %d packets, %d bytes\n", ingress.Packets, ingress.Bytes)
				fmt.Fprintf(buf, "    Output: %d packets, %d bytes\n", egress.Packets, egress.Bytes)
			default:
				if readErr == nil {
					if errIn != nil {
						readErr = errIn
					} else {
						readErr = errOut
					}
				}
			}
		}
		// Policies referencing this zone
		var policyRefs []string
		for _, zpp := range cfg.Security.Policies {
			// #3476: skip a nil zone-pair set (tolerant / HA-sync config
			// path the runtime walker skips) rather than dereferencing
			// zpp.FromZone.
			if zpp == nil {
				continue
			}
			if zpp.FromZone == name || zpp.ToZone == name {
				dir := "from"
				peer := zpp.ToZone
				if zpp.ToZone == name {
					dir = "to"
					peer = zpp.FromZone
				}
				policyRefs = append(policyRefs, fmt.Sprintf("%s %s (%d rules)", dir, peer, len(zpp.Policies)))
			}
		}
		if len(policyRefs) > 0 {
			fmt.Fprintf(buf, "  Policies: %s\n", strings.Join(policyRefs, ", "))
		}
		// Detail: per-interface info
		if len(zone.Interfaces) > 0 {
			buf.WriteString("  Interface details:\n")
			for _, ifName := range zone.Interfaces {
				fmt.Fprintf(buf, "    %s:\n", ifName)
				if ifc, ok := cfg.Interfaces.Interfaces[ifName]; ok {
					for _, unit := range ifc.Units {
						for _, addr := range unit.Addresses {
							fmt.Fprintf(buf, "      Address: %s\n", addr)
						}
						if unit.DHCP {
							buf.WriteString("      DHCPv4: enabled\n")
						}
						if unit.DHCPv6 {
							buf.WriteString("      DHCPv6: enabled\n")
						}
					}
				}
			}
		}
		// Screen profile detail
		if zone.ScreenProfile != "" {
			// #3476: a present-but-nil screen-profile map value (tolerant /
			// HA-sync config path) must not panic on profile.TCP.Land.
			if profile, ok := cfg.Security.Screen[zone.ScreenProfile]; ok && profile != nil {
				fmt.Fprintf(buf, "  Screen profile details (%s):\n", zone.ScreenProfile)
				// #3327: route the enabled-check inventory through the shared
				// SSOT (config.ScreenChecks / config.ScreenThresholds via
				// screenEnabledCheckList) instead of a hand-built list that
				// omitted port-scan, ip-sweep, the source/destination session
				// limits, and icmp-fragment.
				if checks := screenEnabledCheckList(profile); len(checks) > 0 {
					fmt.Fprintf(buf, "    Enabled checks: %s\n", strings.Join(checks, ", "))
				}
			}
		}
		// Policy detail breakdown. #3658 (M04/M05): span all THREE tiers the
		// runtime evaluates in order — zone-pair, applicable GLOBAL policies,
		// then the effective default-policy catch-all — so this gRPC-text peer
		// of the local-CLI renderer (pkg/cli/cli_show_security_zones.go) can no
		// longer hide a global rule that affects the zone (M04) nor collapse to
		// a bare "(no policies)" that obscures the unmatched-transit disposition
		// (M05). Parity with REST (pkg/api/security.go) + gRPC GetPolicies
		// (#3363).
		buf.WriteString("  Policy summary (evaluation order: zone-pair, global, default-policy):\n")
		zonePairPolicies := 0
		for _, zpp := range cfg.Security.Policies {
			// #3476: skip a nil zone-pair set rather than dereferencing
			// zpp.FromZone.
			if zpp == nil {
				continue
			}
			if zpp.FromZone == name || zpp.ToZone == name {
				for _, pol := range zpp.Policies {
					// #3476: skip a nil rule rather than dereferencing
					// pol.Action / pol.Name.
					if pol == nil {
						continue
					}
					fmt.Fprintf(buf, "    [zone-pair] %s -> %s: %s (%s)\n",
						zpp.FromZone, zpp.ToZone, pol.Name,
						policyActionStr(pol.Action))
					zonePairPolicies++
				}
			}
		}
		globalPolicies := 0
		for _, gp := range cfg.Security.GlobalPolicies {
			// #3476-style defensiveness: skip a nil global rule.
			if gp == nil {
				continue
			}
			if !config.GlobalPolicyAppliesToZone(gp.Match, name) {
				continue
			}
			fmt.Fprintf(buf, "    [global] %s -> %s: %s (%s)\n",
				globalZoneScopeLabel(gp.Match.FromZone),
				globalZoneScopeLabel(gp.Match.ToZone),
				gp.Name, policyActionStr(gp.Action))
			globalPolicies++
		}
		if zonePairPolicies == 0 && globalPolicies == 0 {
			buf.WriteString("    (no zone-pair or global policies affecting this zone)\n")
		}
		// M05: always surface the effective default-policy catch-all instead of
		// hiding it behind "(no policies)".
		fmt.Fprintf(buf, "    [default] %s: %s\n",
			dataplane.DefaultPolicyName,
			policyActionStr(cfg.Security.DefaultPolicy))
		buf.WriteString("\n")
	}
	if readErr != nil {
		fmt.Fprintf(buf, "warning: zone counter read failed (traffic statistics may be incomplete): %v\n", readErr)
	}
}

// --- #1700: residual ShowText branches ---

func (s *Server) showTestZone(req *pb.ShowTextRequest, cfg *config.Config, buf *strings.Builder) (*pb.ShowTextResponse, error) {
	params := strings.TrimPrefix(req.Topic, "test-zone:")
	var ifName string
	for _, kv := range strings.Split(params, ",") {
		parts := strings.SplitN(kv, "=", 2)
		if len(parts) == 2 && parts[0] == "interface" {
			ifName = parts[1]
		}
	}
	if cfg == nil {
		buf.WriteString("No active configuration\n")
	} else if ifName == "" {
		buf.WriteString("Missing interface parameter\n")
	} else {
		found := false
		for zoneName, zone := range cfg.Security.Zones {
			if zone == nil { // #3493: tolerant/HA-sync path may carry a nil zone value
				continue
			}
			for _, iface := range zone.Interfaces {
				if iface == ifName {
					fmt.Fprintf(buf, "Interface %s belongs to zone: %s\n", ifName, zoneName)
					if zone.Description != "" {
						fmt.Fprintf(buf, "  Description: %s\n", zone.Description)
					}
					if zone.ScreenProfile != "" {
						fmt.Fprintf(buf, "  Screen:      %s\n", zone.ScreenProfile)
					}
					// #3654 (H08/M03): this is the per-interface admission
					// DIAGNOSTIC, so report the EFFECTIVE (zone UNION interface)
					// set for THIS interface and flag when it is governed by an
					// interface-local override rather than only the zone set.
					// #3682: also flag when THIS interface is a management /
					// cluster-control lifeline excluded from host-inbound deny.
					lifeline := config.HostInboundLifelineInterface(
						ifName, config.HostInboundLifelineSet(cfg))
					for _, line := range zone.RenderInterfaceHostInbound(ifName, lifeline,
						config.HostInboundLabels{
							Indent:         "  ",
							Sep:            ", ",
							ServicesLabel:  "Host-inbound services",
							ProtocolsLabel: "Host-inbound protocols",
						}) {
						buf.WriteString(line)
						buf.WriteString("\n")
					}
					found = true
					break
				}
			}
			if found {
				break
			}
		}
		if !found {
			fmt.Fprintf(buf, "Interface %s is not assigned to any security zone\n", ifName)
		}
	}
	return &pb.ShowTextResponse{Output: buf.String()}, nil
}
