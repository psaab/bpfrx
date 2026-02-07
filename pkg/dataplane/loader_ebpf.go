package dataplane

import (
	"fmt"

	"github.com/cilium/ebpf"
)

// loadAllObjects loads all eBPF programs and populates the Manager's
// maps and programs using the bpf2go-generated types.
func (m *Manager) loadAllObjects() error {
	// Load XDP main program first -- it owns all the shared maps.
	var mainObjs bpfrxXdpMainObjects
	if err := loadBpfrxXdpMainObjects(&mainObjs, nil); err != nil {
		return fmt.Errorf("load xdp_main: %w", err)
	}

	// Store map references.
	m.maps["sessions"] = mainObjs.Sessions
	m.maps["iface_zone_map"] = mainObjs.IfaceZoneMap
	m.maps["zone_configs"] = mainObjs.ZoneConfigs
	m.maps["zone_pair_policies"] = mainObjs.ZonePairPolicies
	m.maps["policy_rules"] = mainObjs.PolicyRules
	m.maps["address_book_v4"] = mainObjs.AddressBookV4
	m.maps["address_membership"] = mainObjs.AddressMembership
	m.maps["applications"] = mainObjs.Applications
	m.maps["global_counters"] = mainObjs.GlobalCounters
	m.maps["policy_counters"] = mainObjs.PolicyCounters
	m.maps["zone_counters"] = mainObjs.ZoneCounters
	m.maps["tx_ports"] = mainObjs.TxPorts
	m.maps["xdp_progs"] = mainObjs.XdpProgs
	m.maps["tc_progs"] = mainObjs.TcProgs
	m.maps["events"] = mainObjs.Events
	m.maps["pkt_meta_scratch"] = mainObjs.PktMetaScratch
	m.maps["dnat_table"] = mainObjs.DnatTable
	m.maps["snat_rules"] = mainObjs.SnatRules

	// Store main program.
	m.programs["xdp_main_prog"] = mainObjs.XdpMainProg

	// Build map replacements so tail call programs share the same maps.
	replaceOpts := &ebpf.CollectionOptions{
		MapReplacements: map[string]*ebpf.Map{
			"pkt_meta_scratch":  mainObjs.PktMetaScratch,
			"iface_zone_map":    mainObjs.IfaceZoneMap,
			"zone_configs":      mainObjs.ZoneConfigs,
			"sessions":          mainObjs.Sessions,
			"global_counters":   mainObjs.GlobalCounters,
			"tx_ports":          mainObjs.TxPorts,
			"xdp_progs":         mainObjs.XdpProgs,
			"tc_progs":          mainObjs.TcProgs,
			"zone_pair_policies": mainObjs.ZonePairPolicies,
			"policy_rules":      mainObjs.PolicyRules,
			"address_book_v4":   mainObjs.AddressBookV4,
			"address_membership": mainObjs.AddressMembership,
			"applications":      mainObjs.Applications,
			"policy_counters":   mainObjs.PolicyCounters,
			"zone_counters":     mainObjs.ZoneCounters,
			"events":            mainObjs.Events,
			"dnat_table":        mainObjs.DnatTable,
			"snat_rules":        mainObjs.SnatRules,
		},
	}

	// Load XDP zone program.
	var zoneObjs bpfrxXdpZoneObjects
	if err := loadBpfrxXdpZoneObjects(&zoneObjs, replaceOpts); err != nil {
		return fmt.Errorf("load xdp_zone: %w", err)
	}
	m.programs["xdp_zone_prog"] = zoneObjs.XdpZoneProg

	// Load XDP conntrack program.
	var ctObjs bpfrxXdpConntrackObjects
	if err := loadBpfrxXdpConntrackObjects(&ctObjs, replaceOpts); err != nil {
		return fmt.Errorf("load xdp_conntrack: %w", err)
	}
	m.programs["xdp_conntrack_prog"] = ctObjs.XdpConntrackProg

	// Load XDP policy program.
	var polObjs bpfrxXdpPolicyObjects
	if err := loadBpfrxXdpPolicyObjects(&polObjs, replaceOpts); err != nil {
		return fmt.Errorf("load xdp_policy: %w", err)
	}
	m.programs["xdp_policy_prog"] = polObjs.XdpPolicyProg

	// Load XDP NAT program.
	var natObjs bpfrxXdpNatObjects
	if err := loadBpfrxXdpNatObjects(&natObjs, replaceOpts); err != nil {
		return fmt.Errorf("load xdp_nat: %w", err)
	}
	m.programs["xdp_nat_prog"] = natObjs.XdpNatProg

	// Load XDP forward program.
	var fwdObjs bpfrxXdpForwardObjects
	if err := loadBpfrxXdpForwardObjects(&fwdObjs, replaceOpts); err != nil {
		return fmt.Errorf("load xdp_forward: %w", err)
	}
	m.programs["xdp_forward_prog"] = fwdObjs.XdpForwardProg

	// Populate tail call program array.
	xdpProgs := mainObjs.XdpProgs
	tailCalls := map[uint32]*ebpf.Program{
		XDPProgZone:      zoneObjs.XdpZoneProg,
		XDPProgConntrack: ctObjs.XdpConntrackProg,
		XDPProgPolicy:    polObjs.XdpPolicyProg,
		XDPProgNAT:       natObjs.XdpNatProg,
		XDPProgForward:   fwdObjs.XdpForwardProg,
	}
	for idx, prog := range tailCalls {
		fd := uint32(prog.FD())
		if err := xdpProgs.Update(idx, fd, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("xdp tail call index %d: %w", idx, err)
		}
	}

	return nil
}
