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
}

// Candidate holds a command name and its description for display.
type Candidate struct {
	Name string
	Desc string
}

// OperationalTree defines tab completion for operational mode.
// This is the canonical source — all other trees derive from this.
var OperationalTree = map[string]*Node{
	"configure": {Desc: "Enter configuration mode"},
	"show": {Desc: "Show information", Children: map[string]*Node{
		"chassis": {Desc: "Show hardware information", Children: map[string]*Node{
			"cluster":     {Desc: "Show cluster/HA status"},
			"environment": {Desc: "Show temperature and power"},
			"hardware":    {Desc: "Show hardware details"},
		}},
		"configuration": {Desc: "Show active configuration"},
		"dhcp": {Desc: "Show DHCP information", Children: map[string]*Node{
			"leases":            {Desc: "Show DHCP leases"},
			"client-identifier": {Desc: "Show DHCPv6 DUID(s)"},
		}},
		"flow-monitoring": {Desc: "Show flow monitoring/NetFlow configuration"},
		"log":             {Desc: "Show daemon log entries [N]"},
		"route": {Desc: "Show routing table [instance <name>]", Children: map[string]*Node{
			"summary":  {Desc: "Show route summary by protocol"},
			"table":    {Desc: "Show routes for a VRF table"},
			"protocol": {Desc: "Show routes by protocol (static, connected, bgp, ospf, dhcp)"},
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
			"zones": {Desc: "Show security zones", DynamicFn: func(cfg *config.Config) []string {
				if cfg == nil {
					return nil
				}
				names := make([]string, 0, len(cfg.Security.Zones))
				for name := range cfg.Security.Zones {
					names = append(names, name)
				}
				return names
			}},
			"policies": {Desc: "Show security policies", Children: map[string]*Node{
				"brief":     {Desc: "Show brief policy summary"},
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
				}},
				"to-zone": {Desc: "Filter by destination zone"},
			}},
			"screen":          {Desc: "Show screen/IDS profiles"},
			"alg":             {Desc: "Show ALG status"},
			"dynamic-address": {Desc: "Show dynamic address feeds"},
			"flow": {Desc: "Show flow information", Children: map[string]*Node{
				"session":      {Desc: "Show active sessions"},
				"statistics":   {Desc: "Show flow statistics"},
				"traceoptions": {Desc: "Show flow trace configuration"},
			}},
			"nat": {Desc: "Show NAT information", Children: map[string]*Node{
				"source":      {Desc: "Show source NAT"},
				"destination": {Desc: "Show destination NAT"},
				"static":      {Desc: "Show static NAT"},
				"nat64":       {Desc: "Show NAT64 rules"},
			}},
			"address-book": {Desc: "Show address book entries"},
			"applications": {Desc: "Show application definitions"},
			"log":          {Desc: "Show recent security events [N] [zone <z>] [protocol <p>] [action <a>]"},
			"statistics":   {Desc: "Show global statistics"},
			"ike": {Desc: "Show IKE status", Children: map[string]*Node{
				"security-associations": {Desc: "Show IKE SAs"},
			}},
			"ipsec": {Desc: "Show IPsec status", Children: map[string]*Node{
				"security-associations": {Desc: "Show IPsec SAs"},
			}},
			"vrrp":           {Desc: "Show VRRP high availability status"},
			"match-policies": {Desc: "Match 5-tuple against policies"},
		}},
		"services": {Desc: "Show services information", Children: map[string]*Node{
			"rpm": {Desc: "Show RPM probe results", Children: map[string]*Node{
				"probe-results": {Desc: "Show RPM probe results"},
			}},
		}},
		"interfaces": {Desc: "Show interface status", DynamicFn: func(cfg *config.Config) []string {
			if cfg == nil || cfg.Interfaces.Interfaces == nil {
				return nil
			}
			names := make([]string, 0, len(cfg.Interfaces.Interfaces))
			for name := range cfg.Interfaces.Interfaces {
				names = append(names, name)
			}
			return names
		}, Children: map[string]*Node{
			"terse":     {Desc: "Show interface summary"},
			"extensive": {Desc: "Show detailed interface statistics"},
			"tunnel":    {Desc: "Show tunnel interfaces"},
		}},
		"protocols": {Desc: "Show protocol information", Children: map[string]*Node{
			"ospf": {Desc: "Show OSPF information", Children: map[string]*Node{
				"neighbor": {Desc: "Show OSPF neighbors"},
				"database": {Desc: "Show OSPF database"},
			}},
			"bgp": {Desc: "Show BGP information", Children: map[string]*Node{
				"summary": {Desc: "Show BGP peer summary"},
				"routes":  {Desc: "Show BGP routes"},
			}},
			"rip":  {Desc: "Show RIP information"},
			"isis": {Desc: "Show IS-IS information", Children: map[string]*Node{
				"adjacency": {Desc: "Show IS-IS adjacencies"},
				"routes":    {Desc: "Show IS-IS routes"},
			}},
		}},
		"arp":         {Desc: "Show ARP table"},
		"ipv6": {Desc: "Show IPv6 information", Children: map[string]*Node{
			"neighbors": {Desc: "Show IPv6 neighbor cache"},
		}},
		"schedulers":        {Desc: "Show policy schedulers"},
		"dhcp-relay":        {Desc: "Show DHCP relay status"},
		"dhcp-server":       {Desc: "Show DHCP server leases"},
		"snmp":              {Desc: "Show SNMP statistics"},
		"system": {Desc: "Show system information", Children: map[string]*Node{
			"alarms":        {Desc: "Show system alarms"},
			"connections":   {Desc: "Show system TCP connections"},
			"rollback": {Desc: "Show rollback history", Children: map[string]*Node{
				"compare": {Desc: "Compare rollback with active config"},
			}},
			"backup-router": {Desc: "Show backup router configuration"},
			"buffers":       {Desc: "Show BPF map utilization"},
			"license":       {Desc: "Show system license"},
			"memory":        {Desc: "Show memory usage"},
			"ntp":           {Desc: "Show NTP server status"},
			"processes":     {Desc: "Show running processes"},
			"services":      {Desc: "Show configured system services"},
			"storage":       {Desc: "Show filesystem usage"},
			"syslog":        {Desc: "Show system syslog configuration"},
			"uptime":        {Desc: "Show system uptime"},
			"users":         {Desc: "Show configured login users"},
		}},
		"routing-options":    {Desc: "Show routing options"},
		"routing-instances":  {Desc: "Show routing instances"},
		"policy-options":     {Desc: "Show policy options"},
		"event-options":      {Desc: "Show event policies"},
		"forwarding-options": {Desc: "Show forwarding options"},
		"version":            {Desc: "Show software version"},
	}},
	"monitor": {Desc: "Capture traffic", Children: map[string]*Node{
		"traffic": {Desc: "Capture traffic on interface", Children: map[string]*Node{
			"interface": {Desc: "Interface name to capture on"},
		}},
	}},
	"clear": {Desc: "Clear information", Children: map[string]*Node{
		"security": {Desc: "Clear security information", Children: map[string]*Node{
			"flow": {Desc: "Clear flow information", Children: map[string]*Node{
				"session": {Desc: "Clear sessions [source-prefix|destination-prefix|protocol|zone]"},
			}},
			"counters": {Desc: "Clear all counters"},
			"policies": {Desc: "Clear policy information", Children: map[string]*Node{
				"hit-count": {Desc: "Clear policy hit counters"},
			}},
			"nat": {Desc: "Clear NAT information", Children: map[string]*Node{
				"source": {Desc: "Clear source NAT", Children: map[string]*Node{
					"persistent-nat-table": {Desc: "Clear persistent NAT bindings"},
				}},
			}},
		}},
		"firewall": {Desc: "Clear firewall counters", Children: map[string]*Node{
			"all": {Desc: "Clear all firewall filter counters"},
		}},
		"dhcp": {Desc: "Clear DHCP information", Children: map[string]*Node{
			"client-identifier": {Desc: "Clear DHCPv6 DUID(s)"},
		}},
	}},
	"request": {Desc: "Perform system operations", Children: map[string]*Node{
		"dhcp": {Desc: "DHCP operations", Children: map[string]*Node{
			"renew": {Desc: "Renew DHCP lease on an interface"},
		}},
		"system": {Desc: "System operations", Children: map[string]*Node{
			"reboot":  {Desc: "Reboot the system"},
			"halt":    {Desc: "Halt the system"},
			"zeroize": {Desc: "Factory reset (erase all config)"},
		}},
	}},
	"ping":       {Desc: "Ping remote host"},
	"traceroute": {Desc: "Trace route to remote host"},
	"quit":       {Desc: "Exit CLI"},
	"exit":       {Desc: "Exit CLI"},
}

// ConfigTopLevel defines tab completion for config mode top-level commands.
var ConfigTopLevel = map[string]*Node{
	"set":      {Desc: "Set a configuration value"},
	"delete":   {Desc: "Delete a configuration element"},
	"show":     {Desc: "Show candidate configuration"},
	"commit": {Desc: "Commit configuration", Children: map[string]*Node{
		"check":     {Desc: "Validate without applying"},
		"confirmed": {Desc: "Auto-rollback if not confirmed [minutes]"},
	}},
	"load": {Desc: "Load configuration from file or terminal", Children: map[string]*Node{
		"override": {Desc: "Replace candidate with file or terminal input"},
		"merge":    {Desc: "Merge into candidate from file or terminal"},
	}},
	"rollback": {Desc: "Revert to previous configuration"},
	"run":      {Desc: "Run operational command"},
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
	for _, w := range words {
		node, ok := current[w]
		if !ok {
			return nil
		}
		currentNode = node
		if node.Children == nil {
			if node.DynamicFn != nil && cfg != nil {
				return FilterPrefix(node.DynamicFn(cfg), partial)
			}
			return nil
		}
		current = node.Children
	}
	candidates := KeysOf(current)
	if currentNode != nil && currentNode.DynamicFn != nil && cfg != nil {
		candidates = append(candidates, currentNode.DynamicFn(cfg)...)
	}
	return FilterPrefix(candidates, partial)
}

// CompleteFromTreeWithDesc walks the tree returning name+description pairs.
func CompleteFromTreeWithDesc(tree map[string]*Node, words []string, partial string, cfg *config.Config) []Candidate {
	current := tree
	var currentNode *Node
	for _, w := range words {
		node, ok := current[w]
		if !ok {
			return nil
		}
		currentNode = node
		if node.Children == nil {
			if node.DynamicFn != nil && cfg != nil {
				var candidates []Candidate
				for _, name := range node.DynamicFn(cfg) {
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
	if currentNode != nil && currentNode.DynamicFn != nil && cfg != nil {
		for _, name := range currentNode.DynamicFn(cfg) {
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
	for _, w := range words {
		node, ok := current[w]
		if !ok {
			return ""
		}
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
func WriteHelp(w io.Writer, candidates []Candidate) {
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].Name < candidates[j].Name })
	maxWidth := 20
	for _, c := range candidates {
		if len(c.Name)+2 > maxWidth {
			maxWidth = len(c.Name) + 2
		}
	}
	fmt.Fprintln(w, "Possible completions:")
	for _, c := range candidates {
		if c.Desc != "" {
			fmt.Fprintf(w, "  %-*s %s\n", maxWidth, c.Name, c.Desc)
		} else {
			fmt.Fprintf(w, "  %s\n", c.Name)
		}
	}
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
