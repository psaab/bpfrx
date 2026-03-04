// Package vrrp manages native VRRPv3 instances for VRRP high availability.
package vrrp

import (
	"fmt"
	"sort"

	"github.com/psaab/bpfrx/pkg/config"
)

// Instance describes a single VRRP instance.
type Instance struct {
	Interface         string
	GroupID           int
	Priority          int
	Preempt           bool
	AcceptData        bool
	AdvertiseInterval int // milliseconds (wire format is centiseconds)
	VirtualAddresses  []string // CIDR notation
	AuthType          string   // "" or "md5"
	AuthKey           string
	TrackInterface    string
	TrackPriorityCost int
	GARPCount         int // gratuitous ARP count per VIP on failover; 0 = default (3)
}

// CollectInstances extracts VRRP instances from the interface config.
func CollectInstances(cfg *config.Config) []*Instance {
	if cfg == nil {
		return nil
	}
	var instances []*Instance
	for ifName, ifc := range cfg.Interfaces.Interfaces {
		for _, unit := range ifc.Units {
			for _, vg := range unit.VRRPGroups {
				inst := &Instance{
					Interface:         ifName,
					GroupID:           vg.ID,
					Priority:          vg.Priority,
					Preempt:           vg.Preempt,
					AcceptData:        vg.AcceptData,
					AdvertiseInterval: vg.AdvertiseInterval,
					VirtualAddresses:  vg.VirtualAddresses,
					AuthType:          vg.AuthType,
					AuthKey:           vg.AuthKey,
					TrackInterface:    vg.TrackInterface,
					TrackPriorityCost: vg.TrackPriorityDelta,
				}
				if inst.AdvertiseInterval == 0 {
					inst.AdvertiseInterval = 1000 // default 1s
				} else {
					inst.AdvertiseInterval *= 1000 // config seconds → ms
				}
				instances = append(instances, inst)
			}
		}
	}
	return instances
}

// CollectRethInstances generates VRRP instances for RETH interfaces that have
// a RedundancyGroup > 0. These provide VRRP-backed failover for HA cluster
// RETH interfaces. VRID = 100 + redundancyGroupID.
//
// The advertisement interval defaults to 30ms for sub-100ms failover detection.
// Override via chassis cluster reth-advertise-interval in config.
// GARP counts are read per-RG from chassis cluster redundancy-group gratuitous-arp-count.
func CollectRethInstances(cfg *config.Config, localPriority map[int]int) []*Instance {
	if cfg == nil {
		return nil
	}
	// When no-reth-vrrp is set, the cluster state machine directly manages
	// VIPs/GARPs — skip RETH VRRP instance creation.
	if cc := cfg.Chassis.Cluster; cc != nil && (cc.NoRethVRRP || cc.PrivateRGElection) {
		return nil
	}
	rethToPhys := cfg.RethToPhysical()

	// Read cluster-level settings for RETH VRRP instances.
	advertInterval := 30 // 30ms default for sub-100ms failover
	garpCounts := map[int]int{}
	preemptMap := map[int]bool{}
	if cc := cfg.Chassis.Cluster; cc != nil {
		if cc.RethAdvertiseInterval > 0 {
			advertInterval = cc.RethAdvertiseInterval
		}
		for _, rg := range cc.RedundancyGroups {
			if rg.GratuitousARPCount > 0 {
				garpCounts[rg.ID] = rg.GratuitousARPCount
			}
			preemptMap[rg.ID] = rg.Preempt
		}
	}

	// Sort interface names for deterministic output.
	names := make([]string, 0, len(cfg.Interfaces.Interfaces))
	for name := range cfg.Interfaces.Interfaces {
		names = append(names, name)
	}
	sort.Strings(names)

	var instances []*Instance
	for _, name := range names {
		ifc := cfg.Interfaces.Interfaces[name]
		if ifc.RedundancyGroup <= 0 {
			continue
		}
		rgID := ifc.RedundancyGroup

		pri := localPriority[rgID]
		if pri == 0 {
			pri = 100 // default to secondary priority
		}

		gc := garpCounts[rgID] // 0 = use default (3)

		// Resolve reth → physical member (no bond device)
		physName := ifc.Name
		if phys, ok := rethToPhys[ifc.Name]; ok {
			physName = phys
		}
		linuxName := config.LinuxIfName(physName)

		// For VLAN-tagged interfaces, create one VRRP instance per
		// sub-interface (e.g. reth0.50) since the parent has no
		// IPv4 and VRRP requires one for advertisements.
		// For non-VLAN interfaces, use the base interface.
		unitNums := make([]int, 0, len(ifc.Units))
		for n := range ifc.Units {
			unitNums = append(unitNums, n)
		}
		sort.Ints(unitNums)

		if ifc.VlanTagging {
			for _, n := range unitNums {
				unit := ifc.Units[n]
				if len(unit.Addresses) == 0 {
					continue
				}
				subIface := linuxName
				if unit.VlanID > 0 {
					subIface = fmt.Sprintf("%s.%d", linuxName, unit.VlanID)
				}
				instances = append(instances, &Instance{
					Interface:         subIface,
					GroupID:           100 + rgID,
					Priority:          pri,
					Preempt:           preemptMap[rgID],
					AcceptData:        true,
					AdvertiseInterval: advertInterval,
					GARPCount:         gc,
					VirtualAddresses:  unit.Addresses,
				})
			}
		} else {
			var vips []string
			for _, n := range unitNums {
				vips = append(vips, ifc.Units[n].Addresses...)
			}
			if len(vips) == 0 {
				continue
			}
			instances = append(instances, &Instance{
				Interface:         linuxName,
				GroupID:           100 + rgID,
				Priority:          pri,
				Preempt:           preemptMap[rgID],
				AcceptData:        true,
				AdvertiseInterval: advertInterval,
				GARPCount:         gc,
				VirtualAddresses:  vips,
			})
		}
	}
	return instances
}

// RethVIPsForRG returns the VIPs (CIDR strings) per Linux interface name for
// RETH interfaces belonging to the given redundancy group. Used by
// direct VIP mode (when no-reth-vrrp is set) where the daemon manages VIPs without VRRP.
func RethVIPsForRG(cfg *config.Config, rgID int) map[string][]string {
	if cfg == nil {
		return nil
	}
	rethToPhys := cfg.RethToPhysical()

	result := make(map[string][]string)
	for _, name := range sortedIfNames(cfg) {
		ifc := cfg.Interfaces.Interfaces[name]
		if ifc.RedundancyGroup != rgID {
			continue
		}

		physName := ifc.Name
		if phys, ok := rethToPhys[ifc.Name]; ok {
			physName = phys
		}
		linuxName := config.LinuxIfName(physName)

		unitNums := make([]int, 0, len(ifc.Units))
		for n := range ifc.Units {
			unitNums = append(unitNums, n)
		}
		sort.Ints(unitNums)

		if ifc.VlanTagging {
			for _, n := range unitNums {
				unit := ifc.Units[n]
				if len(unit.Addresses) == 0 {
					continue
				}
				subIface := linuxName
				if unit.VlanID > 0 {
					subIface = fmt.Sprintf("%s.%d", linuxName, unit.VlanID)
				}
				result[subIface] = append(result[subIface], unit.Addresses...)
			}
		} else {
			var vips []string
			for _, n := range unitNums {
				vips = append(vips, ifc.Units[n].Addresses...)
			}
			if len(vips) > 0 {
				result[linuxName] = append(result[linuxName], vips...)
			}
		}
	}
	return result
}

// sortedIfNames returns sorted interface names from config for deterministic iteration.
func sortedIfNames(cfg *config.Config) []string {
	names := make([]string, 0, len(cfg.Interfaces.Interfaces))
	for name := range cfg.Interfaces.Interfaces {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
