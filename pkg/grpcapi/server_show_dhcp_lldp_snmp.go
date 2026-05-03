// Phase 4 of #1043: extract the DHCP, LLDP, and SNMP ShowText case
// bodies into dedicated methods. Same methodology as Phases 1-3
// (#1148, #1150, #1151): semantic relocation, no behavior change. Each
// case body is moved verbatim apart from `&buf` references becoming
// `buf` (passed-in `*strings.Builder`) and the original
// `if … { … } else { … }` flattened into an early-return form. Output
// is unchanged.

package grpcapi

import (
	"fmt"
	"strings"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// showSNMP renders `cli show snmp` — community/trap-group/USM-user
// summary from configuration.
func (s *Server) showSNMP(cfg *config.Config, buf *strings.Builder) {
	if cfg == nil || cfg.System.SNMP == nil {
		buf.WriteString("No SNMP configured\n")
		return
	}
	snmpCfg := cfg.System.SNMP
	if snmpCfg.Location != "" {
		fmt.Fprintf(buf, "Location:    %s\n", snmpCfg.Location)
	}
	if snmpCfg.Contact != "" {
		fmt.Fprintf(buf, "Contact:     %s\n", snmpCfg.Contact)
	}
	if snmpCfg.Description != "" {
		fmt.Fprintf(buf, "Description: %s\n", snmpCfg.Description)
	}
	if len(snmpCfg.Communities) > 0 {
		buf.WriteString("Communities:\n")
		for name, comm := range snmpCfg.Communities {
			fmt.Fprintf(buf, "  %s: %s\n", name, comm.Authorization)
		}
	}
	if len(snmpCfg.TrapGroups) > 0 {
		buf.WriteString("Trap groups:\n")
		for name, tg := range snmpCfg.TrapGroups {
			fmt.Fprintf(buf, "  %s: %s\n", name, strings.Join(tg.Targets, ", "))
		}
	}
	if len(snmpCfg.V3Users) > 0 {
		buf.WriteString("SNMPv3 USM users:\n")
		for name, u := range snmpCfg.V3Users {
			auth := u.AuthProtocol
			if auth == "" {
				auth = "none"
			}
			priv := u.PrivProtocol
			if priv == "" {
				priv = "none"
			}
			fmt.Fprintf(buf, "  %s: auth=%s priv=%s\n", name, auth, priv)
		}
	}
}

// showSNMPv3 renders the SNMPv3 USM user table.
func (s *Server) showSNMPv3(cfg *config.Config, buf *strings.Builder) {
	if cfg == nil || cfg.System.SNMP == nil || len(cfg.System.SNMP.V3Users) == 0 {
		buf.WriteString("No SNMPv3 users configured\n")
		return
	}
	buf.WriteString("SNMPv3 USM Users:\n")
	fmt.Fprintf(buf, "  %-20s %-12s %-12s\n", "User", "Auth", "Privacy")
	for _, u := range cfg.System.SNMP.V3Users {
		auth := u.AuthProtocol
		if auth == "" {
			auth = "none"
		}
		priv := u.PrivProtocol
		if priv == "" {
			priv = "none"
		}
		fmt.Fprintf(buf, "  %-20s %-12s %-12s\n", u.Name, auth, priv)
	}
}

// showDHCPServer renders the active DHCPv4/v6 lease tables from the
// running Kea-backed DHCP server.
func (s *Server) showDHCPServer(buf *strings.Builder) {
	if s.dhcpServer == nil || !s.dhcpServer.IsRunning() {
		buf.WriteString("DHCP server not running\n")
		return
	}
	leases4, _ := s.dhcpServer.GetLeases4()
	leases6, _ := s.dhcpServer.GetLeases6()
	if len(leases4) == 0 && len(leases6) == 0 {
		buf.WriteString("No active leases\n")
	}
	if len(leases4) > 0 {
		buf.WriteString("DHCPv4 Leases:\n")
		fmt.Fprintf(buf, "  %-18s %-20s %-15s %-12s %s\n", "Address", "MAC", "Hostname", "Lifetime", "Expires")
		for _, l := range leases4 {
			fmt.Fprintf(buf, "  %-18s %-20s %-15s %-12s %s\n",
				l.Address, l.HWAddress, l.Hostname, l.ValidLife, l.ExpireTime)
		}
	}
	if len(leases6) > 0 {
		buf.WriteString("DHCPv6 Leases:\n")
		fmt.Fprintf(buf, "  %-40s %-20s %-15s %-12s %s\n", "Address", "DUID", "Hostname", "Lifetime", "Expires")
		for _, l := range leases6 {
			fmt.Fprintf(buf, "  %-40s %-20s %-15s %-12s %s\n",
				l.Address, l.HWAddress, l.Hostname, l.ValidLife, l.ExpireTime)
		}
	}
}

// showDHCPServerDetail renders the configured DHCP pools plus the live
// lease tables annotated with subnet IDs.
func (s *Server) showDHCPServerDetail(cfg *config.Config, buf *strings.Builder) {
	if cfg == nil || (cfg.System.DHCPServer.DHCPLocalServer == nil && cfg.System.DHCPServer.DHCPv6LocalServer == nil) {
		buf.WriteString("No DHCP server configured\n")
		return
	}
	// Pool configuration
	if srv := cfg.System.DHCPServer.DHCPLocalServer; srv != nil && len(srv.Groups) > 0 {
		buf.WriteString("DHCPv4 Server Configuration:\n")
		for name, group := range srv.Groups {
			fmt.Fprintf(buf, "  Group: %s\n", name)
			if len(group.Interfaces) > 0 {
				fmt.Fprintf(buf, "    Interfaces: %s\n", strings.Join(group.Interfaces, ", "))
			}
			for _, pool := range group.Pools {
				fmt.Fprintf(buf, "    Pool: %s\n", pool.Name)
				if pool.Subnet != "" {
					fmt.Fprintf(buf, "      Subnet: %s\n", pool.Subnet)
				}
				if pool.RangeLow != "" {
					fmt.Fprintf(buf, "      Range: %s - %s\n", pool.RangeLow, pool.RangeHigh)
				}
				if pool.Router != "" {
					fmt.Fprintf(buf, "      Router: %s\n", pool.Router)
				}
				if len(pool.DNSServers) > 0 {
					fmt.Fprintf(buf, "      DNS: %s\n", strings.Join(pool.DNSServers, ", "))
				}
				if pool.LeaseTime > 0 {
					fmt.Fprintf(buf, "      Lease time: %ds\n", pool.LeaseTime)
				}
			}
		}
		buf.WriteString("\n")
	}
	if srv := cfg.System.DHCPServer.DHCPv6LocalServer; srv != nil && len(srv.Groups) > 0 {
		buf.WriteString("DHCPv6 Server Configuration:\n")
		for name, group := range srv.Groups {
			fmt.Fprintf(buf, "  Group: %s\n", name)
			if len(group.Interfaces) > 0 {
				fmt.Fprintf(buf, "    Interfaces: %s\n", strings.Join(group.Interfaces, ", "))
			}
			for _, pool := range group.Pools {
				fmt.Fprintf(buf, "    Pool: %s\n", pool.Name)
				if pool.Subnet != "" {
					fmt.Fprintf(buf, "      Subnet: %s\n", pool.Subnet)
				}
				if pool.RangeLow != "" {
					fmt.Fprintf(buf, "      Range: %s - %s\n", pool.RangeLow, pool.RangeHigh)
				}
			}
		}
		buf.WriteString("\n")
	}
	// Leases with subnet IDs
	if s.dhcpServer != nil && s.dhcpServer.IsRunning() {
		leases4, _ := s.dhcpServer.GetLeases4()
		leases6, _ := s.dhcpServer.GetLeases6()
		if len(leases4) == 0 && len(leases6) == 0 {
			buf.WriteString("Active leases: none\n")
		}
		if len(leases4) > 0 {
			fmt.Fprintf(buf, "DHCPv4 Leases (%d active):\n", len(leases4))
			fmt.Fprintf(buf, "  %-18s %-20s %-15s %-10s %-12s %s\n", "Address", "MAC", "Hostname", "Subnet", "Lifetime", "Expires")
			for _, l := range leases4 {
				fmt.Fprintf(buf, "  %-18s %-20s %-15s %-10s %-12s %s\n",
					l.Address, l.HWAddress, l.Hostname, l.SubnetID, l.ValidLife, l.ExpireTime)
			}
		}
		if len(leases6) > 0 {
			fmt.Fprintf(buf, "DHCPv6 Leases (%d active):\n", len(leases6))
			fmt.Fprintf(buf, "  %-40s %-20s %-15s %-10s %-12s %s\n", "Address", "DUID", "Hostname", "Subnet", "Lifetime", "Expires")
			for _, l := range leases6 {
				fmt.Fprintf(buf, "  %-40s %-20s %-15s %-10s %-12s %s\n",
					l.Address, l.HWAddress, l.Hostname, l.SubnetID, l.ValidLife, l.ExpireTime)
			}
		}
	} else {
		buf.WriteString("DHCP server not running (no lease data)\n")
	}
}

// showDHCPRelay renders the configured DHCP relay server-groups and
// relay-groups.
func (s *Server) showDHCPRelay(cfg *config.Config, buf *strings.Builder) {
	if cfg == nil || cfg.ForwardingOptions.DHCPRelay == nil {
		buf.WriteString("No DHCP relay configured\n")
		return
	}
	relay := cfg.ForwardingOptions.DHCPRelay
	if len(relay.ServerGroups) > 0 {
		buf.WriteString("Server groups:\n")
		for name, sg := range relay.ServerGroups {
			fmt.Fprintf(buf, "  %s: %s\n", name, strings.Join(sg.Servers, ", "))
		}
	}
	if len(relay.Groups) > 0 {
		buf.WriteString("Relay groups:\n")
		for name, g := range relay.Groups {
			fmt.Fprintf(buf, "  %s:\n", name)
			fmt.Fprintf(buf, "    Interfaces: %s\n", strings.Join(g.Interfaces, ", "))
			fmt.Fprintf(buf, "    Active server group: %s\n", g.ActiveServerGroup)
		}
	}
}

// showLLDP renders the configured LLDP transmit interval, hold
// multiplier, hold time, monitored interfaces, and current neighbor
// count.
func (s *Server) showLLDP(cfg *config.Config, buf *strings.Builder) {
	if cfg == nil || cfg.Protocols.LLDP == nil {
		buf.WriteString("LLDP not configured\n")
		return
	}
	lldpCfg := cfg.Protocols.LLDP
	if lldpCfg.Disable {
		buf.WriteString("LLDP: disabled\n")
		return
	}
	interval := lldpCfg.Interval
	if interval <= 0 {
		interval = 30
	}
	holdMult := lldpCfg.HoldMultiplier
	if holdMult <= 0 {
		holdMult = 4
	}
	buf.WriteString("LLDP:\n")
	fmt.Fprintf(buf, "  Transmit interval: %ds\n", interval)
	fmt.Fprintf(buf, "  Hold multiplier:   %d\n", holdMult)
	fmt.Fprintf(buf, "  Hold time:         %ds\n", interval*holdMult)
	if len(lldpCfg.Interfaces) > 0 {
		var ifNames []string
		for _, iface := range lldpCfg.Interfaces {
			if iface.Disable {
				ifNames = append(ifNames, iface.Name+" (disabled)")
			} else {
				ifNames = append(ifNames, iface.Name)
			}
		}
		fmt.Fprintf(buf, "  Interfaces:        %s\n", strings.Join(ifNames, ", "))
	}
	if s.lldpNeighborsFn != nil {
		neighbors := s.lldpNeighborsFn()
		fmt.Fprintf(buf, "  Neighbors:         %d\n", len(neighbors))
	}
}

// showLLDPNeighbors renders the live LLDP neighbor table.
func (s *Server) showLLDPNeighbors(buf *strings.Builder) {
	if s.lldpNeighborsFn == nil {
		buf.WriteString("LLDP not running\n")
		return
	}
	neighbors := s.lldpNeighborsFn()
	if len(neighbors) == 0 {
		buf.WriteString("No LLDP neighbors discovered\n")
		return
	}
	fmt.Fprintf(buf, "%-12s %-20s %-16s %-20s %-6s %s\n",
		"Interface", "Chassis ID", "Port ID", "System Name", "TTL", "Age")
	for _, n := range neighbors {
		age := time.Since(n.LastSeen).Truncate(time.Second)
		fmt.Fprintf(buf, "%-12s %-20s %-16s %-20s %-6d %s\n",
			n.Interface, n.ChassisID, n.PortID, n.SystemName, n.TTL, age)
	}
}
