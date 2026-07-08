package cli

import (
	"fmt"
	"sort"
	"strings"

	"github.com/vishvananda/netlink"
)

func (c *CLI) showInterfacesStatistics() error {
	links, err := netlink.LinkList()
	if err != nil {
		return fmt.Errorf("listing links: %w", err)
	}

	sort.Slice(links, func(i, j int) bool {
		return links[i].Attrs().Name < links[j].Attrs().Name
	})

	fmt.Printf("%-16s %15s %15s %15s %15s %10s %10s\n",
		"Interface", "Input packets", "Input bytes", "Output packets", "Output bytes", "In errors", "Out errors")

	for _, l := range links {
		name := l.Attrs().Name
		if name == "lo" || strings.HasPrefix(name, "vrf-") ||
			strings.HasPrefix(name, "xfrm") || strings.HasPrefix(name, "gre-") {
			continue
		}
		stats := l.Attrs().Statistics
		if stats == nil {
			continue
		}
		fmt.Printf("%-16s %15d %15d %15d %15d %10d %10d\n",
			name, stats.RxPackets, stats.RxBytes, stats.TxPackets, stats.TxBytes,
			stats.RxErrors, stats.TxErrors)
	}
	return nil
}

// showVlans displays VLAN assignments per interface (like Junos "show vlans").

func (c *CLI) showVlans() error {
	cfg := c.store.ActiveConfig()
	if cfg == nil {
		fmt.Println("No active configuration")
		return nil
	}

	// Build zone lookup: interface name → zone name
	ifZone := make(map[string]string)
	for zoneName, zone := range cfg.Security.Zones {
		if zone == nil { // #3493: tolerant/HA-sync path may carry a nil zone value
			continue
		}
		for _, iface := range zone.Interfaces {
			ifZone[iface] = zoneName
		}
	}

	// Collect VLAN entries
	type vlanEntry struct {
		iface  string
		unit   int
		vlanID int
		zone   string
		trunk  bool
	}
	var entries []vlanEntry
	for _, ifc := range cfg.Interfaces.Interfaces {
		for unitNum, unit := range ifc.Units {
			if unit.VlanID > 0 || ifc.VlanTagging {
				zone := ifZone[ifc.Name]
				entries = append(entries, vlanEntry{
					iface:  ifc.Name,
					unit:   unitNum,
					vlanID: unit.VlanID,
					zone:   zone,
					trunk:  ifc.VlanTagging,
				})
			}
		}
	}

	if len(entries) == 0 {
		fmt.Println("No VLANs configured")
		return nil
	}

	sort.Slice(entries, func(i, j int) bool {
		if entries[i].iface != entries[j].iface {
			return entries[i].iface < entries[j].iface
		}
		return entries[i].unit < entries[j].unit
	})

	fmt.Printf("%-16s %-6s %-8s %-12s %s\n", "Interface", "Unit", "VLAN ID", "Zone", "Mode")
	for _, e := range entries {
		mode := "access"
		if e.trunk {
			mode = "trunk"
		}
		vid := fmt.Sprintf("%d", e.vlanID)
		if e.vlanID == 0 {
			vid = "native"
		}
		fmt.Printf("%-16s %-6d %-8s %-12s %s\n", e.iface, e.unit, vid, e.zone, mode)
	}
	return nil
}
