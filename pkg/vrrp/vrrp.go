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
	AdvertiseInterval int
	VirtualAddresses  []string // CIDR notation
	AuthType          string   // "" or "md5"
	AuthKey           string
	TrackInterface    string
	TrackPriorityCost int
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
					inst.AdvertiseInterval = 1
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
func CollectRethInstances(cfg *config.Config, localPriority map[int]int) []*Instance {
	if cfg == nil {
		return nil
	}
	rethToPhys := cfg.RethToPhysical()

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
					Preempt:           true,
					AcceptData:        true,
					AdvertiseInterval: 1,
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
				Preempt:           true,
				AcceptData:        true,
				AdvertiseInterval: 1,
				VirtualAddresses:  vips,
			})
		}
	}
	return instances
}
