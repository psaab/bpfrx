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
	m.maps["sessions_v6"] = mainObjs.SessionsV6
	m.maps["address_book_v6"] = mainObjs.AddressBookV6
	m.maps["dnat_table_v6"] = mainObjs.DnatTableV6
	m.maps["snat_rules_v6"] = mainObjs.SnatRulesV6
	m.maps["session_v6_scratch"] = mainObjs.SessionV6Scratch
	m.maps["screen_configs"] = mainObjs.ScreenConfigs
	m.maps["flood_counters"] = mainObjs.FloodCounters
	m.maps["nat_pool_configs"] = mainObjs.NatPoolConfigs
	m.maps["nat_pool_ips_v4"] = mainObjs.NatPoolIpsV4
	m.maps["nat_pool_ips_v6"] = mainObjs.NatPoolIpsV6
	m.maps["nat_port_counters"] = mainObjs.NatPortCounters
	m.maps["interface_counters"] = mainObjs.InterfaceCounters
	m.maps["default_policy"] = mainObjs.DefaultPolicy
	m.maps["static_nat_v4"] = mainObjs.StaticNatV4
	m.maps["static_nat_v6"] = mainObjs.StaticNatV6
	m.maps["flow_timeouts"] = mainObjs.FlowTimeouts

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
			"sessions_v6":       mainObjs.SessionsV6,
			"address_book_v6":   mainObjs.AddressBookV6,
			"dnat_table_v6":     mainObjs.DnatTableV6,
			"snat_rules_v6":     mainObjs.SnatRulesV6,
			"session_v6_scratch": mainObjs.SessionV6Scratch,
			"screen_configs":     mainObjs.ScreenConfigs,
			"flood_counters":     mainObjs.FloodCounters,
			"interface_counters": mainObjs.InterfaceCounters,
			"default_policy":     mainObjs.DefaultPolicy,
			"static_nat_v4":      mainObjs.StaticNatV4,
			"static_nat_v6":      mainObjs.StaticNatV6,
			"flow_timeouts":      mainObjs.FlowTimeouts,
		},
	}

	// Extended replacements for xdp_policy which also includes NAT pool maps.
	policyReplaceOpts := &ebpf.CollectionOptions{
		MapReplacements: map[string]*ebpf.Map{},
	}
	for k, v := range replaceOpts.MapReplacements {
		policyReplaceOpts.MapReplacements[k] = v
	}
	policyReplaceOpts.MapReplacements["nat_pool_configs"] = mainObjs.NatPoolConfigs
	policyReplaceOpts.MapReplacements["nat_pool_ips_v4"] = mainObjs.NatPoolIpsV4
	policyReplaceOpts.MapReplacements["nat_pool_ips_v6"] = mainObjs.NatPoolIpsV6
	policyReplaceOpts.MapReplacements["nat_port_counters"] = mainObjs.NatPortCounters

	// Load XDP screen program.
	var screenObjs bpfrxXdpScreenObjects
	if err := loadBpfrxXdpScreenObjects(&screenObjs, replaceOpts); err != nil {
		return fmt.Errorf("load xdp_screen: %w", err)
	}
	m.programs["xdp_screen_prog"] = screenObjs.XdpScreenProg

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

	// Load XDP policy program (uses NAT pool maps).
	var polObjs bpfrxXdpPolicyObjects
	if err := loadBpfrxXdpPolicyObjects(&polObjs, policyReplaceOpts); err != nil {
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

	// Populate XDP tail call program array.
	xdpProgs := mainObjs.XdpProgs
	tailCalls := map[uint32]*ebpf.Program{
		XDPProgScreen:    screenObjs.XdpScreenProg,
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

	// Load TC main program.
	var tcMainObjs bpfrxTcMainObjects
	if err := loadBpfrxTcMainObjects(&tcMainObjs, replaceOpts); err != nil {
		return fmt.Errorf("load tc_main: %w", err)
	}
	m.programs["tc_main_prog"] = tcMainObjs.TcMainProg

	// Load TC conntrack program.
	var tcCtObjs bpfrxTcConntrackObjects
	if err := loadBpfrxTcConntrackObjects(&tcCtObjs, replaceOpts); err != nil {
		return fmt.Errorf("load tc_conntrack: %w", err)
	}
	m.programs["tc_conntrack_prog"] = tcCtObjs.TcConntrackProg

	// Load TC NAT program.
	var tcNatObjs bpfrxTcNatObjects
	if err := loadBpfrxTcNatObjects(&tcNatObjs, replaceOpts); err != nil {
		return fmt.Errorf("load tc_nat: %w", err)
	}
	m.programs["tc_nat_prog"] = tcNatObjs.TcNatProg

	// Load TC screen egress program.
	var tcScreenObjs bpfrxTcScreenEgressObjects
	if err := loadBpfrxTcScreenEgressObjects(&tcScreenObjs, replaceOpts); err != nil {
		return fmt.Errorf("load tc_screen_egress: %w", err)
	}
	m.programs["tc_screen_egress_prog"] = tcScreenObjs.TcScreenEgressProg

	// Load TC forward program.
	var tcFwdObjs bpfrxTcForwardObjects
	if err := loadBpfrxTcForwardObjects(&tcFwdObjs, replaceOpts); err != nil {
		return fmt.Errorf("load tc_forward: %w", err)
	}
	m.programs["tc_forward_prog"] = tcFwdObjs.TcForwardProg

	// Populate TC tail call program array.
	tcProgs := mainObjs.TcProgs
	tcTailCalls := map[uint32]*ebpf.Program{
		TCProgConntrack:    tcCtObjs.TcConntrackProg,
		TCProgNAT:          tcNatObjs.TcNatProg,
		TCProgScreenEgress: tcScreenObjs.TcScreenEgressProg,
		TCProgForward:      tcFwdObjs.TcForwardProg,
	}
	for idx, prog := range tcTailCalls {
		fd := uint32(prog.FD())
		if err := tcProgs.Update(idx, fd, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("tc tail call index %d: %w", idx, err)
		}
	}

	return nil
}
