package cli

import (
	"fmt"
	"sort"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

func (c *CLI) showZonesDisplay(cfg *config.Config, detail bool, filterZone string) error {
	// Sort zone names for stable output
	zoneNames := make([]string, 0, len(cfg.Security.Zones))
	for name := range cfg.Security.Zones {
		zoneNames = append(zoneNames, name)
	}
	sort.Strings(zoneNames)
	cr := c.applyResult()

	for _, name := range zoneNames {
		if filterZone != "" && name != filterZone {
			continue
		}
		zone := cfg.Security.Zones[name]

		// Resolve zone ID for counter lookup
		var zoneID uint16
		if cr != nil {
			zoneID = cr.ZoneIDs[name]
		}

		// Junos format: "Security zone: <name>"
		fmt.Printf("Security zone: %s\n", name)
		if zoneID > 0 {
			fmt.Printf("  Zone ID: %d\n", zoneID)
		}
		if zone.Description != "" {
			fmt.Printf("  Description: %s\n", zone.Description)
		}
		tcpRstStr := "Off"
		if zone.TCPRst {
			tcpRstStr = "On"
		}
		fmt.Printf("  Send reset for non-SYN session TCP packets: %s\n", tcpRstStr)
		fmt.Printf("  Policy configurable: Yes\n")
		if zone.ScreenProfile != "" {
			fmt.Printf("  Screen: %s\n", zone.ScreenProfile)
		}
		fmt.Printf("  Interfaces bound: %d\n", len(zone.Interfaces))
		fmt.Printf("  Interfaces:\n")
		for _, ifName := range zone.Interfaces {
			fmt.Printf("    %s\n", ifName)
		}
		if zone.HostInboundTraffic != nil {
			if len(zone.HostInboundTraffic.SystemServices) > 0 {
				fmt.Printf("  Allowed host-inbound traffic: %s\n",
					strings.Join(zone.HostInboundTraffic.SystemServices, " "))
			}
			if len(zone.HostInboundTraffic.Protocols) > 0 {
				fmt.Printf("  Allowed host-inbound protocols: %s\n",
					strings.Join(zone.HostInboundTraffic.Protocols, " "))
			}
		}

		// Per-zone traffic counters (xpf extension, not in Junos)
		if c.dp != nil && c.dp.IsLoaded() && zoneID > 0 {
			ingress, errIn := c.dp.ReadZoneCounters(zoneID, 0)
			egress, errOut := c.dp.ReadZoneCounters(zoneID, 1)
			if errIn == nil && errOut == nil {
				fmt.Println("  Traffic statistics:")
				fmt.Printf("    Input:  %d packets, %d bytes\n",
					ingress.Packets, ingress.Bytes)
				fmt.Printf("    Output: %d packets, %d bytes\n",
					egress.Packets, egress.Bytes)
			}
		}

		// Detail mode: per-interface breakdown, per-policy details, screen profile summary
		if detail {
			// Per-interface detail
			if len(zone.Interfaces) > 0 {
				fmt.Println("  Interface details:")
				for _, ifName := range zone.Interfaces {
					fmt.Printf("    %s:\n", ifName)
					if ifc, ok := cfg.Interfaces.Interfaces[ifName]; ok {
						for _, unit := range ifc.Units {
							for _, addr := range unit.Addresses {
								fmt.Printf("      Address: %s\n", addr)
							}
							if unit.DHCP {
								fmt.Printf("      DHCPv4: enabled\n")
							}
							if unit.DHCPv6 {
								fmt.Printf("      DHCPv6: enabled\n")
							}
						}
					}
				}
			}

			// Screen profile details
			if zone.ScreenProfile != "" {
				if profile, ok := cfg.Security.Screen[zone.ScreenProfile]; ok {
					fmt.Printf("  Screen profile details (%s):\n", zone.ScreenProfile)
					var checks []string
					if profile.TCP.Land {
						checks = append(checks, "land")
					}
					if profile.TCP.SynFin {
						checks = append(checks, "syn-fin")
					}
					if profile.TCP.NoFlag {
						checks = append(checks, "no-flag")
					}
					if profile.TCP.FinNoAck {
						checks = append(checks, "fin-no-ack")
					}
					if profile.TCP.WinNuke {
						checks = append(checks, "winnuke")
					}
					if profile.TCP.SynFrag {
						checks = append(checks, "syn-frag")
					}
					if profile.TCP.SynFlood != nil {
						checks = append(checks, fmt.Sprintf("syn-flood(threshold:%d)", profile.TCP.SynFlood.AttackThreshold))
					}
					if profile.ICMP.PingDeath {
						checks = append(checks, "ping-death")
					}
					if profile.ICMP.FloodThreshold > 0 {
						checks = append(checks, fmt.Sprintf("icmp-flood(threshold:%d)", profile.ICMP.FloodThreshold))
					}
					if profile.IP.SourceRouteOption {
						checks = append(checks, "source-route-option")
					}
					if profile.IP.TearDrop {
						checks = append(checks, "teardrop")
					}
					if profile.UDP.FloodThreshold > 0 {
						checks = append(checks, fmt.Sprintf("udp-flood(threshold:%d)", profile.UDP.FloodThreshold))
					}
					if len(checks) > 0 {
						fmt.Printf("    Enabled checks: %s\n", strings.Join(checks, ", "))
					} else {
						fmt.Printf("    Enabled checks: (none)\n")
					}
				}
			}

			// Policy detail breakdown
			fmt.Println("  Policy summary:")
			totalPolicies := 0
			for _, zpp := range cfg.Security.Policies {
				if zpp.FromZone == name || zpp.ToZone == name {
					for _, pol := range zpp.Policies {
						action := "permit"
						switch pol.Action {
						case 1:
							action = "deny"
						case 2:
							action = "reject"
						}
						fmt.Printf("    %s -> %s: %s (%s)\n",
							zpp.FromZone, zpp.ToZone, pol.Name, action)
						totalPolicies++
					}
				}
			}
			if totalPolicies == 0 {
				fmt.Println("    (no policies)")
			}
		}

		fmt.Println()
	}
	if filterZone != "" {
		if _, ok := cfg.Security.Zones[filterZone]; !ok {
			fmt.Printf("Zone '%s' not found\n", filterZone)
		}
	}
	return nil
}
