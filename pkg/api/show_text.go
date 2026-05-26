package api

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

func (s *Server) showTextHandler(w http.ResponseWriter, r *http.Request) {
	topic := r.URL.Query().Get("topic")
	if topic == "" {
		writeError(w, http.StatusBadRequest, "topic parameter required")
		return
	}

	cfg := s.store.ActiveConfig()
	var buf strings.Builder

	switch topic {
	case "schedulers":
		if cfg == nil || len(cfg.Schedulers) == 0 {
			buf.WriteString("No schedulers configured\n")
		} else {
			for name, sched := range cfg.Schedulers {
				fmt.Fprintf(&buf, "Scheduler: %s\n", name)
				if sched.StartTime != "" {
					fmt.Fprintf(&buf, "  Start time: %s\n", sched.StartTime)
				}
				if sched.StopTime != "" {
					fmt.Fprintf(&buf, "  Stop time:  %s\n", sched.StopTime)
				}
				if sched.StartDate != "" {
					fmt.Fprintf(&buf, "  Start date: %s\n", sched.StartDate)
				}
				if sched.StopDate != "" {
					fmt.Fprintf(&buf, "  Stop date:  %s\n", sched.StopDate)
				}
				if sched.Daily {
					buf.WriteString("  Recurrence: daily\n")
				}
				buf.WriteString("\n")
			}
		}

	case "snmp":
		if cfg == nil || cfg.System.SNMP == nil {
			buf.WriteString("No SNMP configured\n")
		} else {
			snmpCfg := cfg.System.SNMP
			if snmpCfg.Location != "" {
				fmt.Fprintf(&buf, "Location:    %s\n", snmpCfg.Location)
			}
			if snmpCfg.Contact != "" {
				fmt.Fprintf(&buf, "Contact:     %s\n", snmpCfg.Contact)
			}
			if snmpCfg.Description != "" {
				fmt.Fprintf(&buf, "Description: %s\n", snmpCfg.Description)
			}
			if len(snmpCfg.Communities) > 0 {
				buf.WriteString("Communities:\n")
				for name, comm := range snmpCfg.Communities {
					fmt.Fprintf(&buf, "  %s: %s\n", name, comm.Authorization)
				}
			}
			if len(snmpCfg.TrapGroups) > 0 {
				buf.WriteString("Trap groups:\n")
				for name, tg := range snmpCfg.TrapGroups {
					fmt.Fprintf(&buf, "  %s: %s\n", name, strings.Join(tg.Targets, ", "))
				}
			}
		}

	case "dhcp-relay":
		if cfg == nil || cfg.ForwardingOptions.DHCPRelay == nil {
			buf.WriteString("No DHCP relay configured\n")
		} else {
			relay := cfg.ForwardingOptions.DHCPRelay
			if len(relay.ServerGroups) > 0 {
				buf.WriteString("Server groups:\n")
				for name, sg := range relay.ServerGroups {
					fmt.Fprintf(&buf, "  %s: %s\n", name, strings.Join(sg.Servers, ", "))
				}
			}
			if len(relay.Groups) > 0 {
				buf.WriteString("Relay groups:\n")
				for name, g := range relay.Groups {
					fmt.Fprintf(&buf, "  %s:\n", name)
					fmt.Fprintf(&buf, "    Interfaces: %s\n", strings.Join(g.Interfaces, ", "))
					fmt.Fprintf(&buf, "    Active server group: %s\n", g.ActiveServerGroup)
				}
			}
		}

	case "firewall":
		hasFilters := cfg != nil && (len(cfg.Firewall.FiltersInet) > 0 || len(cfg.Firewall.FiltersInet6) > 0)
		if !hasFilters {
			buf.WriteString("No firewall filters configured\n")
		} else {
			printFilters := func(family string, filters map[string]*config.FirewallFilter) {
				for name, filter := range filters {
					fmt.Fprintf(&buf, "Filter: %s (family: %s)\n", name, family)
					for _, term := range filter.Terms {
						fmt.Fprintf(&buf, "  Term: %s\n", term.Name)
						if term.Protocol != "" {
							fmt.Fprintf(&buf, "    From protocol: %s\n", term.Protocol)
						}
						if len(term.DestinationPorts) > 0 {
							fmt.Fprintf(&buf, "    From destination-port: %s\n", strings.Join(term.DestinationPorts, ", "))
						}
						if len(term.SourceAddresses) > 0 {
							fmt.Fprintf(&buf, "    From source-address: %s\n", strings.Join(term.SourceAddresses, ", "))
						}
						if term.DSCP != "" {
							fmt.Fprintf(&buf, "    From dscp: %s\n", term.DSCP)
						}
						if term.Action != "" {
							fmt.Fprintf(&buf, "    Then: %s\n", term.Action)
						}
					}
					buf.WriteString("\n")
				}
			}
			printFilters("inet", cfg.Firewall.FiltersInet)
			printFilters("inet6", cfg.Firewall.FiltersInet6)
		}

	case "alg":
		if cfg == nil {
			buf.WriteString("No active configuration\n")
		} else {
			alg := cfg.Security.ALG
			boolStr := func(b bool) string {
				if b {
					return "enabled"
				}
				return "disabled"
			}
			fmt.Fprintf(&buf, "SIP:  %s\n", boolStr(!alg.SIPDisable))
			fmt.Fprintf(&buf, "FTP:  %s\n", boolStr(!alg.FTPDisable))
			fmt.Fprintf(&buf, "TFTP: %s\n", boolStr(!alg.TFTPDisable))
			fmt.Fprintf(&buf, "DNS:  %s\n", boolStr(!alg.DNSDisable))
		}

	case "dynamic-address":
		if cfg == nil || len(cfg.Security.DynamicAddress.FeedServers) == 0 {
			buf.WriteString("No dynamic address feeds configured\n")
		} else {
			for name, feed := range cfg.Security.DynamicAddress.FeedServers {
				fmt.Fprintf(&buf, "Feed server: %s\n", name)
				fmt.Fprintf(&buf, "  URL: %s\n", feed.URL)
				if feed.FeedName != "" {
					fmt.Fprintf(&buf, "  Feed name: %s\n", feed.FeedName)
				}
				if feed.UpdateInterval > 0 {
					fmt.Fprintf(&buf, "  Update interval: %ds\n", feed.UpdateInterval)
				}
				if feed.HoldInterval > 0 {
					fmt.Fprintf(&buf, "  Hold interval: %ds\n", feed.HoldInterval)
				}
				buf.WriteString("\n")
			}
		}

	case "address-book":
		if cfg == nil || cfg.Security.AddressBook == nil {
			buf.WriteString("No address book configured\n")
		} else {
			ab := cfg.Security.AddressBook
			if len(ab.Addresses) > 0 {
				buf.WriteString("Addresses:\n")
				for name, addr := range ab.Addresses {
					fmt.Fprintf(&buf, "  %-20s %s\n", name, addr.Value)
				}
			}
			if len(ab.AddressSets) > 0 {
				buf.WriteString("Address sets:\n")
				for name, as := range ab.AddressSets {
					fmt.Fprintf(&buf, "  %-20s members: %s\n", name, strings.Join(as.Addresses, ", "))
				}
			}
		}

	case "applications":
		if cfg == nil {
			buf.WriteString("No active configuration\n")
		} else {
			if len(cfg.Applications.Applications) > 0 {
				buf.WriteString("Applications:\n")
				for name, app := range cfg.Applications.Applications {
					fmt.Fprintf(&buf, "  %-20s proto=%-6s", name, app.Protocol)
					if app.DestinationPort != "" {
						fmt.Fprintf(&buf, " dst-port=%s", app.DestinationPort)
					}
					buf.WriteString("\n")
				}
			}
			if len(cfg.Applications.ApplicationSets) > 0 {
				buf.WriteString("Application sets:\n")
				for name, as := range cfg.Applications.ApplicationSets {
					fmt.Fprintf(&buf, "  %-20s members: %s\n", name, strings.Join(as.Applications, ", "))
				}
			}
		}

	case "flow-monitoring":
		if cfg == nil || cfg.Services.FlowMonitoring == nil || cfg.Services.FlowMonitoring.Version9 == nil {
			buf.WriteString("No flow monitoring configured\n")
		} else {
			v9 := cfg.Services.FlowMonitoring.Version9
			buf.WriteString("Flow monitoring (NetFlow v9):\n")
			for name, tmpl := range v9.Templates {
				fmt.Fprintf(&buf, "  Template: %s\n", name)
				if tmpl.FlowActiveTimeout > 0 {
					fmt.Fprintf(&buf, "    Active timeout: %ds\n", tmpl.FlowActiveTimeout)
				}
				if tmpl.FlowInactiveTimeout > 0 {
					fmt.Fprintf(&buf, "    Inactive timeout: %ds\n", tmpl.FlowInactiveTimeout)
				}
				if tmpl.TemplateRefreshRate > 0 {
					fmt.Fprintf(&buf, "    Template refresh: %ds\n", tmpl.TemplateRefreshRate)
				}
			}
		}

	case "flow-timeouts":
		if cfg == nil {
			buf.WriteString("No active configuration\n")
		} else {
			flow := cfg.Security.Flow
			buf.WriteString("Flow session timeouts:\n")
			if flow.TCPSession != nil {
				fmt.Fprintf(&buf, "  TCP established:      %ds\n", flow.TCPSession.EstablishedTimeout)
				fmt.Fprintf(&buf, "  TCP initial:          %ds\n", flow.TCPSession.InitialTimeout)
				fmt.Fprintf(&buf, "  TCP closing:          %ds\n", flow.TCPSession.ClosingTimeout)
				fmt.Fprintf(&buf, "  TCP time-wait:        %ds\n", flow.TCPSession.TimeWaitTimeout)
			}
			fmt.Fprintf(&buf, "  UDP session:          %ds\n", flow.UDPSessionTimeout)
			fmt.Fprintf(&buf, "  ICMP session:         %ds\n", flow.ICMPSessionTimeout)
			if flow.TCPMSSIPsecVPN > 0 {
				fmt.Fprintf(&buf, "  TCP MSS (IPsec VPN):  %d\n", flow.TCPMSSIPsecVPN)
			}
			if flow.TCPMSSGreIn > 0 {
				fmt.Fprintf(&buf, "  TCP MSS (GRE in):     %d\n", flow.TCPMSSGreIn)
			}
			if flow.TCPMSSGreOut > 0 {
				fmt.Fprintf(&buf, "  TCP MSS (GRE out):    %d\n", flow.TCPMSSGreOut)
			}
			if flow.AllowDNSReply {
				buf.WriteString("  Allow DNS reply:      enabled\n")
			}
			if flow.AllowEmbeddedICMP {
				buf.WriteString("  Allow embedded ICMP:  enabled\n")
			}
		}

	case "nat-static":
		if cfg == nil || len(cfg.Security.NAT.Static) == 0 {
			buf.WriteString("No static NAT rules configured.\n")
		} else {
			for _, rs := range cfg.Security.NAT.Static {
				fmt.Fprintf(&buf, "Static NAT rule-set: %s\n", rs.Name)
				fmt.Fprintf(&buf, "  From zone: %s\n", rs.FromZone)
				for _, rule := range rs.Rules {
					fmt.Fprintf(&buf, "  Rule: %s\n", rule.Name)
					fmt.Fprintf(&buf, "    Match destination-address: %s\n", rule.Match)
					if rule.IsNPTv6 {
						fmt.Fprintf(&buf, "    Then nptv6-prefix:         %s\n", rule.Then)
					} else {
						fmt.Fprintf(&buf, "    Then static-nat prefix:    %s\n", rule.Then)
					}
				}
				buf.WriteString("\n")
			}
		}

	case "nat-nptv6":
		if cfg == nil || len(cfg.Security.NAT.Static) == 0 {
			buf.WriteString("No NPTv6 rules configured.\n")
		} else {
			found := false
			for _, rs := range cfg.Security.NAT.Static {
				for _, rule := range rs.Rules {
					if !rule.IsNPTv6 {
						continue
					}
					if !found {
						fmt.Fprintf(&buf, "%-20s %-20s %-50s %-50s\n",
							"Rule-set", "Rule", "External prefix", "Internal prefix")
						found = true
					}
					fmt.Fprintf(&buf, "%-20s %-20s %-50s %-50s\n",
						rs.Name, rule.Name, rule.Match, rule.Then)
				}
			}
			if !found {
				buf.WriteString("No NPTv6 rules configured.\n")
			}
		}

	default:
		writeError(w, http.StatusBadRequest, fmt.Sprintf("unknown topic: %s", topic))
		return
	}

	writeOK(w, TextResponse{Output: buf.String()})
}
