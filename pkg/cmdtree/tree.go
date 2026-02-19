// Package cmdtree defines the canonical CLI command trees for bpfrx.
//
// This is the SINGLE SOURCE OF TRUTH for all command trees used by:
//   - pkg/cli (local interactive CLI)
//   - pkg/grpcapi (gRPC completion handler)
//   - cmd/cli (remote CLI client)
//
// When adding a new command, add it here and it automatically appears
// in tab completion, ? help, and resolveCommand across all CLIs.
package cmdtree

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/psaab/bpfrx/pkg/config"
)

// Node defines a completion tree node with description, children, and optional dynamic values.
type Node struct {
	Desc      string
	Children  map[string]*Node
	DynamicFn func(cfg *config.Config) []string
	// ContextDynamicFn is like DynamicFn but receives the consumed words
	// so completions can depend on earlier arguments (e.g. zone pair).
	ContextDynamicFn func(cfg *config.Config, words []string) []string
}

// HasDynamic returns true if the node has any dynamic completion function.
func (n *Node) HasDynamic() bool {
	return n.DynamicFn != nil || n.ContextDynamicFn != nil
}

// DynamicValues returns dynamic completion values, preferring ContextDynamicFn.
func (n *Node) DynamicValues(cfg *config.Config, words []string) []string {
	if n.ContextDynamicFn != nil {
		return n.ContextDynamicFn(cfg, words)
	}
	if n.DynamicFn != nil {
		return n.DynamicFn(cfg)
	}
	return nil
}

// Candidate holds a command name and its description for display.
type Candidate struct {
	Name string
	Desc string
}

// OperationalTree defines tab completion for operational mode.
// This is the canonical source — all other trees derive from this.
var OperationalTree = map[string]*Node{
	"configure": {Desc: "Manipulate software configuration information", Children: map[string]*Node{
		"exclusive": {Desc: "Enter exclusive configuration mode"},
	}},
	"show": {Desc: "Show system information", Children: map[string]*Node{
		"chassis": {Desc: "Show chassis information", Children: map[string]*Node{
			"cluster": {Desc: "Show cluster/HA status", Children: map[string]*Node{
			"status":      {Desc: "Show cluster node status"},
			"interfaces":  {Desc: "Show cluster interfaces"},
			"information": {Desc: "Show cluster configuration details"},
			"statistics":  {Desc: "Show cluster statistics"},
		}},
			"alarms":         {Desc: "Show chassis alarm status"},
			"environment":    {Desc: "Show chassis environment"},
			"hardware":       {Desc: "Show installed hardware components"},
			"routing-engine": {Desc: "Show Routing Engine status"},
		}},
		"class-of-service": {Desc: "Show class-of-service information", Children: map[string]*Node{
			"interface": {Desc: "Show per-interface CoS configuration"},
		}},
		"configuration": {Desc: "Show active configuration", Children: map[string]*Node{
			"applications":       {Desc: "Application protocol definitions"},
			"chassis":            {Desc: "Chassis configuration"},
			"class-of-service":   {Desc: "Class-of-service configuration"},
			"event-options":      {Desc: "Event processing configuration"},
			"firewall":           {Desc: "Firewall filter configuration"},
			"forwarding-options": {Desc: "Forwarding options configuration"},
			"interfaces":         {Desc: "Interface configuration"},
			"policy-options":     {Desc: "Policy framework configuration"},
			"protocols":          {Desc: "Routing protocol configuration"},
			"routing-instances":  {Desc: "Routing instance configuration"},
			"routing-options":    {Desc: "Protocol-independent routing options"},
			"schedulers":         {Desc: "Scheduler configuration"},
			"security":           {Desc: "Security configuration"},
			"services":           {Desc: "Service configuration"},
			"snmp":               {Desc: "SNMP configuration"},
			"system":             {Desc: "System configuration"},
		}},
		"dhcp": {Desc: "Show DHCP information", Children: map[string]*Node{
			"leases":            {Desc: "Show DHCP leases"},
			"client-identifier": {Desc: "Show DHCPv6 DUID(s)"},
		}},
		"firewall": {Desc: "Show firewall filter configuration", Children: map[string]*Node{
			"filter": {Desc: "Show specific filter by name", DynamicFn: func(cfg *config.Config) []string {
				if cfg == nil {
					return nil
				}
				names := make([]string, 0, len(cfg.Firewall.FiltersInet)+len(cfg.Firewall.FiltersInet6))
				for n := range cfg.Firewall.FiltersInet {
					names = append(names, n)
				}
				for n := range cfg.Firewall.FiltersInet6 {
					names = append(names, n)
				}
				return names
			}},
		}},
		"flow-monitoring": {Desc: "Show flow monitoring/NetFlow configuration"},
		"log":             {Desc: "Show daemon log entries [N]"},
		"route": {Desc: "Show routing table information", Children: map[string]*Node{
			"<destination>": {Desc: "IP address or prefix to look up"},
			"terse":         {Desc: "Display terse output"},
			"detail":        {Desc: "Display detailed output"},
			"summary":       {Desc: "Show routing table statistics"},
			"table":         {Desc: "Show routes in named routing table"},
			"protocol":      {Desc: "Show routes learned from named protocol"},
			"instance": {Desc: "Show routes for a routing instance", DynamicFn: func(cfg *config.Config) []string {
				if cfg == nil {
					return nil
				}
				names := make([]string, 0, len(cfg.RoutingInstances))
				for _, ri := range cfg.RoutingInstances {
					names = append(names, ri.Name)
				}
				return names
			}},
		}},
		"security": {Desc: "Show security information", Children: map[string]*Node{
			"zones": {Desc: "Show security zone information", DynamicFn: func(cfg *config.Config) []string {
				if cfg == nil {
					return nil
				}
				names := make([]string, 0, len(cfg.Security.Zones))
				for name := range cfg.Security.Zones {
					names = append(names, name)
				}
				return names
			}, Children: map[string]*Node{
				"detail": {Desc: "Show detailed zone information"},
				"terse":  {Desc: "Display terse output"},
			}},
			"policies": {Desc: "Show security firewall policies", Children: map[string]*Node{
				"global":      {Desc: "Show global security policy information"},
				"policy-name": {Desc: "Show policy matching a specific name"},
				"brief":     {Desc: "Show brief policy summary"},
				"detail":    {Desc: "Show detailed policy information"},
				"hit-count": {Desc: "Show policy hit counters [from-zone X to-zone Y]"},
				"from-zone": {Desc: "Filter by source zone", DynamicFn: func(cfg *config.Config) []string {
					if cfg == nil {
						return nil
					}
					names := make([]string, 0, len(cfg.Security.Zones))
					for name := range cfg.Security.Zones {
						names = append(names, name)
					}
					return names
				}, Children: map[string]*Node{
					"to-zone": {Desc: "Filter by destination zone", DynamicFn: func(cfg *config.Config) []string {
						if cfg == nil {
							return nil
						}
						names := make([]string, 0, len(cfg.Security.Zones))
						for name := range cfg.Security.Zones {
							names = append(names, name)
						}
						return names
					}, Children: map[string]*Node{
						"policy": {Desc: "Filter by policy name", ContextDynamicFn: func(cfg *config.Config, words []string) []string {
							if cfg == nil {
								return nil
							}
							// Extract from-zone and to-zone from consumed words.
							var fromZone, toZone string
							for i, w := range words {
								if w == "from-zone" && i+1 < len(words) {
									fromZone = words[i+1]
								}
								if w == "to-zone" && i+1 < len(words) {
									toZone = words[i+1]
								}
							}
							if fromZone == "" || toZone == "" {
								return nil
							}
							for _, zpp := range cfg.Security.Policies {
								if zpp.FromZone == fromZone && zpp.ToZone == toZone {
									names := make([]string, 0, len(zpp.Policies))
									for _, p := range zpp.Policies {
										names = append(names, p.Name)
									}
									return names
								}
							}
							return nil
						}},
					}},
				}},
			}},
			"screen": {Desc: "Show screen service information", Children: map[string]*Node{
				"ids-option": {Desc: "Show configured screen profile", DynamicFn: func(cfg *config.Config) []string {
					if cfg == nil {
						return nil
					}
					names := make([]string, 0, len(cfg.Security.Screen))
					for name := range cfg.Security.Screen {
						names = append(names, name)
					}
					return names
				}, Children: map[string]*Node{
					"detail": {Desc: "Show detailed screen profile with thresholds"},
				}},
				"statistics": {Desc: "Show screen statistics", Children: map[string]*Node{
					"zone": {Desc: "Show per-zone screen counters", DynamicFn: func(cfg *config.Config) []string {
						if cfg == nil {
							return nil
						}
						names := make([]string, 0, len(cfg.Security.Zones))
						for name := range cfg.Security.Zones {
							names = append(names, name)
						}
						return names
					}},
				}},
			}},
			"alarms": {Desc: "Show active security alarm information", Children: map[string]*Node{
				"detail": {Desc: "Show detailed security alarm information"},
			}},
			"alg": {Desc: "Show ALG status"},
			"dynamic-address": {Desc: "Show dynamic address feeds"},
			"flow": {Desc: "Show security flow information", Children: map[string]*Node{
				"session": {Desc: "Show session table", Children: map[string]*Node{
					"summary":            {Desc: "Show session count summary"},
					"brief":              {Desc: "Show sessions in compact table"},
					"application":        {Desc: "Filter sessions by application name"},
					"interface":          {Desc: "Filter sessions by interface"},
					"source-prefix":      {Desc: "Filter by source IP prefix"},
					"destination-prefix": {Desc: "Filter by destination IP prefix"},
					"source-port":        {Desc: "Filter by source port"},
					"destination-port":   {Desc: "Filter by destination port"},
					"protocol":           {Desc: "Filter by IP protocol"},
					"zone": {Desc: "Filter by security zone", DynamicFn: func(cfg *config.Config) []string {
						if cfg == nil {
							return nil
						}
						names := make([]string, 0, len(cfg.Security.Zones))
						for name := range cfg.Security.Zones {
							names = append(names, name)
						}
						return names
					}},
					"nat-only": {Desc: "Show only sessions with NAT translation"},
					"sort-by": {Desc: "Sort sessions for top-talkers", Children: map[string]*Node{
						"bytes":   {Desc: "Sort by total bytes (descending)"},
						"packets": {Desc: "Sort by total packets (descending)"},
					}},
				}},
				"statistics":   {Desc: "Show security flow statistics"},
				"traceoptions": {Desc: "Show flow trace configuration"},
			}},
			"nat": {Desc: "Show Network Address Translation information", Children: map[string]*Node{
				"source": {Desc: "Show source NAT", Children: map[string]*Node{
					"summary":              {Desc: "Show source NAT summary"},
					"pool":                 {Desc: "Show source NAT pools"},
					"persistent-nat-table": {Desc: "Show persistent NAT bindings", Children: map[string]*Node{
						"detail": {Desc: "Show detailed persistent NAT bindings"},
					}},
					"rule": {Desc: "Show source NAT rules", Children: map[string]*Node{
						"detail": {Desc: "Show detailed source NAT rules"},
					}},
					"rule-set":             {Desc: "Show source NAT rule sets"},
				}},
				"destination": {Desc: "Show destination NAT", Children: map[string]*Node{
					"summary":  {Desc: "Show destination NAT summary"},
					"pool":     {Desc: "Show destination NAT pools"},
					"rule": {Desc: "Show destination NAT rules", Children: map[string]*Node{
						"detail": {Desc: "Show detailed destination NAT rules"},
					}},
					"rule-set": {Desc: "Show destination NAT rule sets"},
				}},
				"static": {Desc: "Show static NAT"},
				"nptv6":  {Desc: "Show NPTv6 prefix translation rules"},
				"nat64":  {Desc: "Show NAT64 rules"},
			}},
			"address-book": {Desc: "Show address book entries"},
			"applications": {Desc: "Show application definitions"},
			"log": {Desc: "Show recent security events", Children: map[string]*Node{
				"zone": {Desc: "Filter by security zone", DynamicFn: func(cfg *config.Config) []string {
					if cfg == nil {
						return nil
					}
					names := make([]string, 0, len(cfg.Security.Zones))
					for name := range cfg.Security.Zones {
						names = append(names, name)
					}
					return names
				}},
				"protocol": {Desc: "Filter by IP protocol"},
				"action":   {Desc: "Filter by action (permit, deny, reject)"},
			}},
			"statistics": {Desc: "Show global statistics", Children: map[string]*Node{
				"detail": {Desc: "Show detailed statistics with screen and session breakdown"},
			}},
			"ike": {Desc: "Show Internet Key Exchange information", Children: map[string]*Node{
				"security-associations": {Desc: "Show IKE SAs"},
			}},
			"ipsec": {Desc: "Show IP Security information", Children: map[string]*Node{
				"security-associations": {Desc: "Show IPsec SAs"},
				"statistics":            {Desc: "Show IPsec statistics"},
			}},
			"vrrp":           {Desc: "Show VRRP high availability status"},
			"match-policies": {Desc: "Match 5-tuple against policies"},
		}},
		"services": {Desc: "Show services information", Children: map[string]*Node{
			"rpm": {Desc: "Show RPM probe results", Children: map[string]*Node{
				"probe-results": {Desc: "Show RPM probe results"},
			}},
		}},
		"interfaces": {Desc: "Show interface information", DynamicFn: func(cfg *config.Config) []string {
			if cfg == nil || cfg.Interfaces.Interfaces == nil {
				return nil
			}
			names := make([]string, 0, len(cfg.Interfaces.Interfaces))
			for name := range cfg.Interfaces.Interfaces {
				names = append(names, name)
			}
			return names
		}, Children: map[string]*Node{
			"terse":      {Desc: "Display terse output"},
			"detail":     {Desc: "Display detailed output"},
			"extensive":  {Desc: "Display extensive output"},
			"statistics": {Desc: "Display statistics and detailed output"},
			"tunnel":     {Desc: "Show tunnel interfaces"},
		}},
		"protocols": {Desc: "Show protocol information", Children: map[string]*Node{
			"ospf": {Desc: "Show OSPF information", Children: map[string]*Node{
				"neighbor": {Desc: "Show OSPF neighbors", Children: map[string]*Node{
					"detail": {Desc: "Show detailed OSPF neighbor information"},
				}},
				"database":  {Desc: "Show OSPF database"},
				"interface": {Desc: "Show OSPF interface details"},
				"routes":    {Desc: "Show OSPF routes"},
			}},
			"bgp": {Desc: "Show BGP information", Children: map[string]*Node{
				"summary":  {Desc: "Show BGP peer summary"},
				"routes":   {Desc: "Show BGP routes"},
				"neighbor": {Desc: "Show BGP neighbor details", Children: map[string]*Node{
					"received-routes":  {Desc: "Show received routes from neighbor"},
					"advertised-routes": {Desc: "Show advertised routes to neighbor"},
				}},
			}},
			"bfd": {Desc: "Show BFD status", Children: map[string]*Node{
				"peers": {Desc: "Show BFD peer status"},
			}},
			"rip":  {Desc: "Show RIP information"},
			"isis": {Desc: "Show IS-IS information", Children: map[string]*Node{
				"adjacency": {Desc: "Show IS-IS adjacencies", Children: map[string]*Node{
					"detail": {Desc: "Show detailed IS-IS adjacency information"},
				}},
				"database": {Desc: "Show IS-IS link-state database"},
				"routes":   {Desc: "Show IS-IS routes"},
			}},
			"lldp": {Desc: "Show LLDP protocol status", Children: map[string]*Node{
				"neighbors": {Desc: "Show LLDP neighbors"},
			}},
		}},
		"arp":         {Desc: "Show system ARP table entries"},
		"ipv6": {Desc: "Show IPv6 information", Children: map[string]*Node{
			"neighbors": {Desc: "Show IPv6 neighbor cache"},
		}},
		"schedulers":        {Desc: "Show policy schedulers"},
		"dhcp-relay":        {Desc: "Show DHCP relay status"},
		"dhcp-server": {Desc: "Show DHCP server leases", Children: map[string]*Node{
			"detail": {Desc: "Show detailed DHCP server information with pool utilization"},
		}},
		"snmp": {Desc: "Show SNMP statistics", Children: map[string]*Node{
			"v3": {Desc: "Show SNMPv3 USM user information"},
		}},
		"lldp": {Desc: "Show LLDP information", Children: map[string]*Node{
			"neighbors": {Desc: "Show LLDP neighbor table"},
		}},
		"system": {Desc: "Show system information", Children: map[string]*Node{
			"alarms":        {Desc: "Show system alarm status"},
			"boot-messages": {Desc: "Show boot time messages"},
			"commit": {Desc: "Show pending and historical commit information", Children: map[string]*Node{
				"history": {Desc: "Show recent commit log"},
			}},
			"connections":   {Desc: "Show system connection activity"},
			"core-dumps":    {Desc: "Show system core dumps"},
			"rollback": {Desc: "Show rolled back configuration", Children: map[string]*Node{
				"compare": {Desc: "Compare rollback with active config"},
			}},
			"backup-router":      {Desc: "Show backup router configuration"},
			"buffers": {Desc: "Show buffer utilization", Children: map[string]*Node{
				"detail": {Desc: "Show detailed per-map statistics"},
			}},
			"internet-options":   {Desc: "Show internet options"},
			"license":            {Desc: "Show system license"},
			"login":              {Desc: "Show login configuration"},
			"memory":             {Desc: "Show system memory usage"},
			"ntp":                {Desc: "Show NTP status"},
			"processes":          {Desc: "Show system process table"},
			"root-authentication": {Desc: "Show root authentication"},
			"configuration": {Desc: "Show configuration info", Children: map[string]*Node{
				"rescue": {Desc: "Show rescue configuration"},
			}},
			"services":           {Desc: "Show configured system services"},
			"storage":            {Desc: "Show local filesystem usage"},
			"syslog":             {Desc: "Show system syslog configuration"},
			"uptime":             {Desc: "Show time since last reboot"},
			"users":              {Desc: "Show configured login users"},
		}},
		"task": {Desc: "Show daemon task/runtime information"},
		"route-map":          {Desc: "Show route-map information"},
		"routing-options":    {Desc: "Show routing options"},
		"routing-instances": {Desc: "Show routing instances", Children: map[string]*Node{
			"detail": {Desc: "Show detailed routing instance information"},
		}},
		"policy-options":     {Desc: "Show policy options"},
		"event-options":      {Desc: "Show event policies"},
		"forwarding-options": {Desc: "Show forwarding options", Children: map[string]*Node{
			"port-mirroring": {Desc: "Show port mirroring instances"},
		}},
		"vlans":              {Desc: "Show VLAN configuration"},
		"version":            {Desc: "Show software process revision levels"},
	}},
	"monitor": {Desc: "Show real-time debugging information", Children: map[string]*Node{
		"traffic": {Desc: "Capture traffic on interface", Children: map[string]*Node{
			"interface": {Desc: "Interface name to capture on", DynamicFn: func(cfg *config.Config) []string {
				if cfg == nil || cfg.Interfaces.Interfaces == nil {
					return nil
				}
				names := make([]string, 0, len(cfg.Interfaces.Interfaces))
				for name := range cfg.Interfaces.Interfaces {
					names = append(names, name)
				}
				return names
			}},
			"matching": {Desc: "Filter expression (tcpdump syntax)"},
			"count":    {Desc: "Number of packets to capture"},
		}},
	}},
	"clear": {Desc: "Clear statistics and protocol information", Children: map[string]*Node{
		"arp": {Desc: "Clear ARP table"},
		"interfaces": {Desc: "Clear interface information", Children: map[string]*Node{
			"statistics": {Desc: "Clear interface statistics counters"},
		}},
		"ipv6": {Desc: "Clear IPv6 information", Children: map[string]*Node{
			"neighbors": {Desc: "Clear IPv6 neighbor cache"},
		}},
		"security": {Desc: "Clear security statistics and tables", Children: map[string]*Node{
			"flow": {Desc: "Clear flow information", Children: map[string]*Node{
				"session": {Desc: "Clear session table entries", Children: map[string]*Node{
					"source-prefix":      {Desc: "Filter sessions by source IP prefix"},
					"destination-prefix": {Desc: "Filter sessions by destination IP prefix"},
					"source-port":        {Desc: "Filter sessions by source port"},
					"destination-port":   {Desc: "Filter sessions by destination port"},
					"protocol":           {Desc: "Filter sessions by IP protocol"},
					"zone": {Desc: "Filter sessions by security zone", DynamicFn: func(cfg *config.Config) []string {
						if cfg == nil {
							return nil
						}
						names := make([]string, 0, len(cfg.Security.Zones))
						for name := range cfg.Security.Zones {
							names = append(names, name)
						}
						return names
					}},
					"interface": {Desc: "Filter sessions by interface", DynamicFn: func(cfg *config.Config) []string {
						if cfg == nil || cfg.Interfaces.Interfaces == nil {
							return nil
						}
						names := make([]string, 0, len(cfg.Interfaces.Interfaces))
						for name := range cfg.Interfaces.Interfaces {
							names = append(names, name)
						}
						return names
					}},
					"application": {Desc: "Filter sessions by application name"},
					"nat-only":    {Desc: "Clear only sessions with NAT translation"},
				}},
			}},
			"counters": {Desc: "Clear all security counters"},
			"policies": {Desc: "Clear policy information", Children: map[string]*Node{
				"hit-count": {Desc: "Clear policy hit counters"},
			}},
			"nat": {Desc: "Clear NAT information", Children: map[string]*Node{
				"source": {Desc: "Clear source NAT", Children: map[string]*Node{
					"persistent-nat-table": {Desc: "Clear persistent NAT bindings"},
				}},
				"statistics": {Desc: "Clear NAT translation statistics"},
			}},
		}},
		"firewall": {Desc: "Clear firewall counters", Children: map[string]*Node{
			"all": {Desc: "Clear all firewall filter counters"},
		}},
		"dhcp": {Desc: "Clear DHCP information", Children: map[string]*Node{
			"client-identifier": {Desc: "Clear DHCPv6 DUID(s)"},
		}},
	}},
	"request": {Desc: "Make system-level requests", Children: map[string]*Node{
		"chassis": {Desc: "Perform chassis-specific operations", Children: map[string]*Node{
			"cluster": {Desc: "Cluster operations", Children: map[string]*Node{
				"failover": {Desc: "Trigger cluster failover", Children: map[string]*Node{
					"redundancy-group": {Desc: "Failover a specific redundancy group"},
					"reset":            {Desc: "Reset manual failover", Children: map[string]*Node{
						"redundancy-group": {Desc: "Reset failover for a redundancy group"},
					}},
				}},
			}},
		}},
		"dhcp": {Desc: "Perform DHCP operations", Children: map[string]*Node{
			"renew": {Desc: "Renew DHCP lease on an interface"},
		}},
		"protocols": {Desc: "Protocol operations", Children: map[string]*Node{
			"ospf": {Desc: "OSPF operations", Children: map[string]*Node{
				"clear": {Desc: "Clear OSPF process"},
			}},
			"bgp": {Desc: "BGP operations", Children: map[string]*Node{
				"clear": {Desc: "Clear BGP sessions"},
			}},
		}},
		"security": {Desc: "Request security operations", Children: map[string]*Node{
			"ipsec": {Desc: "IPsec operations", Children: map[string]*Node{
				"sa": {Desc: "IPsec SA operations", Children: map[string]*Node{
					"clear": {Desc: "Clear all IPsec SAs"},
				}},
			}},
		}},
		"system": {Desc: "Perform system-level operations", Children: map[string]*Node{
			"reboot":    {Desc: "Reboot the system"},
			"halt":      {Desc: "Halt the system"},
			"power-off": {Desc: "Power off the system"},
			"zeroize":   {Desc: "Factory reset (erase all config)"},
			"configuration": {Desc: "Manage configuration", Children: map[string]*Node{
				"rescue": {Desc: "Rescue configuration", Children: map[string]*Node{
					"save":   {Desc: "Save rescue configuration"},
					"delete": {Desc: "Delete rescue configuration"},
				}},
			}},
			"software": {Desc: "Software management", Children: map[string]*Node{
				"in-service-upgrade": {Desc: "Prepare node for in-service software upgrade (ISSU)"},
			}},
		}},
	}},
	"test": {Desc: "Perform diagnostic testing", Children: map[string]*Node{
		"policy": {Desc: "Test security policy lookup", Children: map[string]*Node{
			"from-zone": {Desc: "Source zone", DynamicFn: func(cfg *config.Config) []string {
				if cfg == nil {
					return nil
				}
				names := make([]string, 0, len(cfg.Security.Zones))
				for name := range cfg.Security.Zones {
					names = append(names, name)
				}
				return names
			}, Children: map[string]*Node{
				"to-zone": {Desc: "Destination zone", DynamicFn: func(cfg *config.Config) []string {
					if cfg == nil {
						return nil
					}
					names := make([]string, 0, len(cfg.Security.Zones))
					for name := range cfg.Security.Zones {
						names = append(names, name)
					}
					return names
				}, Children: map[string]*Node{
					"source-ip": {Desc: "Source IP address", Children: map[string]*Node{
						"destination-ip": {Desc: "Destination IP address", Children: map[string]*Node{
							"destination-port": {Desc: "Destination port number", Children: map[string]*Node{
								"protocol": {Desc: "IP protocol (tcp, udp)"},
							}},
						}},
					}},
				}},
			}},
		}},
		"routing": {Desc: "Test route lookup", Children: map[string]*Node{
			"destination": {Desc: "Destination IP or prefix to look up"},
			"instance": {Desc: "Routing instance for route lookup", DynamicFn: func(cfg *config.Config) []string {
				if cfg == nil {
					return nil
				}
				names := make([]string, 0, len(cfg.RoutingInstances))
				for _, ri := range cfg.RoutingInstances {
					names = append(names, ri.Name)
				}
				return names
			}},
		}},
		"security-zone": {Desc: "Show zone for interface", Children: map[string]*Node{
			"interface": {Desc: "Interface name", DynamicFn: func(cfg *config.Config) []string {
				if cfg == nil || cfg.Interfaces.Interfaces == nil {
					return nil
				}
				names := make([]string, 0, len(cfg.Interfaces.Interfaces))
				for name := range cfg.Interfaces.Interfaces {
					names = append(names, name)
				}
				return names
			}},
		}},
	}},
	"ping": {Desc: "Ping remote host", Children: map[string]*Node{
		"<host>":  {Desc: "Hostname or IP address of remote host"},
		"count":   {Desc: "Number of ping requests to send"},
		"source":  {Desc: "Source address to use"},
		"size":    {Desc: "Request data size in bytes"},
		"routing-instance": {Desc: "Routing instance for route lookup", DynamicFn: func(cfg *config.Config) []string {
			if cfg == nil {
				return nil
			}
			names := make([]string, 0, len(cfg.RoutingInstances))
			for _, ri := range cfg.RoutingInstances {
				names = append(names, ri.Name)
			}
			return names
		}},
	}},
	"traceroute": {Desc: "Trace route to remote host", Children: map[string]*Node{
		"<host>": {Desc: "Hostname or IP address of remote host"},
		"source": {Desc: "Source address to use"},
		"routing-instance": {Desc: "Routing instance for route lookup", DynamicFn: func(cfg *config.Config) []string {
			if cfg == nil {
				return nil
			}
			names := make([]string, 0, len(cfg.RoutingInstances))
			for _, ri := range cfg.RoutingInstances {
				names = append(names, ri.Name)
			}
			return names
		}},
	}},
	"quit":       {Desc: "Exit CLI"},
	"exit":       {Desc: "Exit CLI"},
}

// ConfigTopLevel defines tab completion for config mode top-level commands.
var ConfigTopLevel = map[string]*Node{
	"annotate": {Desc: "Annotate the configuration statement"},
	"copy":     {Desc: "Copy a configuration statement"},
	"insert":   {Desc: "Insert a new ordered configuration statement"},
	"rename":   {Desc: "Rename a configuration statement"},
	"set":      {Desc: "Set a configuration parameter"},
	"delete":   {Desc: "Delete a configuration statement"},
	"show":     {Desc: "Show configuration"},
	"commit": {Desc: "Commit current set of changes", Children: map[string]*Node{
		"check":     {Desc: "Check correctness of syntax; do not apply changes"},
		"comment":   {Desc: "Add comment to commit"},
		"confirmed": {Desc: "Automatically rollback if not confirmed"},
	}},
	"load": {Desc: "Load configuration from ASCII file", Children: map[string]*Node{
		"override": {Desc: "Override existing configuration"},
		"merge":    {Desc: "Merge contents with existing configuration"},
		"set":      {Desc: "Execute set commands from terminal"},
	}},
	"edit":     {Desc: "Edit a sub-level of configuration"},
	"top":      {Desc: "Exit to top level of configuration"},
	"up":       {Desc: "Exit one level of configuration"},
	"rollback": {Desc: "Roll back to a previous committed configuration"},
	"run":      {Desc: "Run an operational-mode command"},
	"exit":     {Desc: "Exit configuration mode"},
	"quit":     {Desc: "Exit configuration mode"},
}

// --- Helper functions ---

// KeysFromTree returns a sorted list of keys from a Node map.
func KeysFromTree(tree map[string]*Node) []string {
	keys := make([]string, 0, len(tree))
	for k := range tree {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// HelpCandidates returns Candidates from a tree's children for help display.
func HelpCandidates(tree map[string]*Node) []Candidate {
	candidates := make([]Candidate, 0, len(tree))
	for name, node := range tree {
		candidates = append(candidates, Candidate{Name: name, Desc: node.Desc})
	}
	return candidates
}

// CompleteFromTree walks the tree to find completion candidates for the given words and partial.
func CompleteFromTree(tree map[string]*Node, words []string, partial string, cfg *config.Config) []string {
	current := tree
	var currentNode *Node
	dynamicConsumed := false
	for wi, w := range words {
		dynamicConsumed = false
		node, ok := current[w]
		if !ok {
			if currentNode != nil && currentNode.HasDynamic() {
				dynamicConsumed = true
				continue
			}
			return nil
		}
		currentNode = node
		if node.Children == nil {
			if node.HasDynamic() && wi < len(words)-1 {
				dynamicConsumed = true
				continue
			}
			if node.HasDynamic() && cfg != nil {
				return FilterPrefix(node.DynamicValues(cfg, words), partial)
			}
			return nil
		}
		current = node.Children
	}
	candidates := KeysOf(current)
	if !dynamicConsumed && currentNode != nil && currentNode.HasDynamic() && cfg != nil {
		candidates = append(candidates, currentNode.DynamicValues(cfg, words)...)
	}
	return FilterPrefix(candidates, partial)
}

// CompleteFromTreeWithDesc walks the tree returning name+description pairs.
func CompleteFromTreeWithDesc(tree map[string]*Node, words []string, partial string, cfg *config.Config) []Candidate {
	current := tree
	var currentNode *Node
	dynamicConsumed := false
	for wi, w := range words {
		dynamicConsumed = false
		node, ok := current[w]
		if !ok {
			if currentNode != nil && currentNode.HasDynamic() {
				dynamicConsumed = true
				continue
			}
			return nil
		}
		currentNode = node
		if node.Children == nil {
			if node.HasDynamic() && wi < len(words)-1 {
				dynamicConsumed = true
				continue
			}
			if node.HasDynamic() && cfg != nil {
				var candidates []Candidate
				for _, name := range node.DynamicValues(cfg, words) {
					if strings.HasPrefix(name, partial) {
						candidates = append(candidates, Candidate{Name: name, Desc: "(configured)"})
					}
				}
				return candidates
			}
			return nil
		}
		current = node.Children
	}

	var candidates []Candidate
	for name, node := range current {
		if strings.HasPrefix(name, partial) {
			candidates = append(candidates, Candidate{Name: name, Desc: node.Desc})
		}
	}
	if !dynamicConsumed && currentNode != nil && currentNode.HasDynamic() && cfg != nil {
		for _, name := range currentNode.DynamicValues(cfg, words) {
			if strings.HasPrefix(name, partial) {
				candidates = append(candidates, Candidate{Name: name, Desc: "(configured)"})
			}
		}
	}
	return candidates
}

// LookupDesc finds the description for a candidate name given the command path words.
// Works for both operational and config mode.
func LookupDesc(words []string, name string, configMode bool) string {
	var tree map[string]*Node
	if configMode {
		if len(words) == 0 {
			if node, ok := ConfigTopLevel[name]; ok {
				return node.Desc
			}
			return ""
		}
		if words[0] == "run" {
			tree = OperationalTree
			words = words[1:]
		} else {
			// Walk config top-level children (e.g. "commit" → "check")
			node, ok := ConfigTopLevel[words[0]]
			if !ok {
				return ""
			}
			for _, w := range words[1:] {
				if node.Children == nil {
					return ""
				}
				node, ok = node.Children[w]
				if !ok {
					return ""
				}
			}
			if node.Children != nil {
				if child, ok := node.Children[name]; ok {
					return child.Desc
				}
			}
			return ""
		}
	} else {
		tree = OperationalTree
	}

	// Walk operational tree
	current := tree
	var currentNode *Node
	for _, w := range words {
		node, ok := current[w]
		if !ok {
			// Dynamic value — skip but stay at same children level.
			if currentNode != nil && currentNode.DynamicFn != nil {
				continue
			}
			return ""
		}
		currentNode = node
		if node.Children == nil {
			return ""
		}
		current = node.Children
	}
	if node, ok := current[name]; ok {
		return node.Desc
	}
	return ""
}

// WriteHelp prints aligned completion candidates to w.
// The entire output is built as a single string and written in one call
// so that readline's wrapWriter triggers only one Refresh cycle.
func WriteHelp(w io.Writer, candidates []Candidate) {
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].Name < candidates[j].Name })
	maxWidth := 20
	for _, c := range candidates {
		if len(c.Name)+2 > maxWidth {
			maxWidth = len(c.Name) + 2
		}
	}
	var sb strings.Builder
	sb.WriteString("Possible completions:\n")
	for _, c := range candidates {
		if c.Desc != "" {
			fmt.Fprintf(&sb, "  %-*s %s\n", maxWidth, c.Name, c.Desc)
		} else {
			fmt.Fprintf(&sb, "  %s\n", c.Name)
		}
	}
	io.WriteString(w, sb.String())
}

// PrintTreeHelp prints self-generating help from a tree path.
func PrintTreeHelp(header string, tree map[string]*Node, path ...string) {
	fmt.Println(header)
	current := tree
	for _, p := range path {
		node, ok := current[p]
		if !ok {
			return
		}
		if node.Children == nil {
			return
		}
		current = node.Children
	}
	WriteHelp(os.Stdout, HelpCandidates(current))
}

// CommonPrefix returns the longest shared prefix among the given strings.
func CommonPrefix(items []string) string {
	if len(items) == 0 {
		return ""
	}
	prefix := items[0]
	for _, s := range items[1:] {
		for !strings.HasPrefix(s, prefix) {
			prefix = prefix[:len(prefix)-1]
			if prefix == "" {
				return ""
			}
		}
	}
	return prefix
}

// KeysOf returns an unsorted list of keys from a Node map.
func KeysOf(m map[string]*Node) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// FilterPrefix returns only items that start with the given prefix.
func FilterPrefix(items []string, prefix string) []string {
	if prefix == "" {
		return items
	}
	var result []string
	for _, item := range items {
		if strings.HasPrefix(item, prefix) {
			result = append(result, item)
		}
	}
	return result
}
