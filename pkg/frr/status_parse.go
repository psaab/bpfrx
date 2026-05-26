// status_parse.go holds the parsed Get* methods and their public types.
//
// All vtysh shell-outs in this file go through m.executor().Vtysh(...) so
// tests can inject a fake executor and exercise the parsers without a
// real vtysh binary.
//
// Symbols (public types + methods):
//   - RIPRouteEntry, GetRIPRoutes
//   - ISISAdjacency, GetISISAdjacency
//   - OSPFNeighbor, GetOSPFNeighbors
//   - BGPPeerSummary, GetBGPSummary
//   - BGPRoute, GetBGPRoutes
//   - FRRRouteDetail, FRRNextHop, GetRouteDetailJSON
//   - FormatRouteDetail
//   - parseRouteJSON (package-private)
package frr

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// RIPRouteEntry represents a RIP route.
type RIPRouteEntry struct {
	Network   string
	NextHop   string
	Metric    string
	Interface string
}

// GetRIPRoutes queries FRR for RIP routes.
func (m *Manager) GetRIPRoutes() ([]RIPRouteEntry, error) {
	output, err := m.executor().Vtysh("show ip rip")
	if err != nil {
		return nil, err
	}
	var routes []RIPRouteEntry
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		// Skip headers
		if fields[0] == "Network" || strings.HasPrefix(line, "Codes") || strings.HasPrefix(line, " ") && len(fields) < 3 {
			continue
		}
		r := RIPRouteEntry{Network: fields[0]}
		if len(fields) >= 2 {
			r.NextHop = fields[1]
		}
		if len(fields) >= 3 {
			r.Metric = fields[2]
		}
		if len(fields) >= 4 {
			r.Interface = fields[3]
		}
		routes = append(routes, r)
	}
	return routes, nil
}

// ISISAdjacency represents an IS-IS adjacency.
type ISISAdjacency struct {
	SystemID  string
	Interface string
	Level     string
	State     string
	HoldTime  string
}

// GetISISAdjacency queries FRR for IS-IS adjacencies.
func (m *Manager) GetISISAdjacency() ([]ISISAdjacency, error) {
	output, err := m.executor().Vtysh("show isis neighbor")
	if err != nil {
		return nil, err
	}
	var adjs []ISISAdjacency
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		if fields[0] == "System" || strings.HasPrefix(line, "Area") {
			continue
		}
		adj := ISISAdjacency{
			SystemID: fields[0],
		}
		if len(fields) >= 2 {
			adj.Interface = fields[1]
		}
		if len(fields) >= 3 {
			adj.Level = fields[2]
		}
		if len(fields) >= 4 {
			adj.State = fields[3]
		}
		if len(fields) >= 5 {
			adj.HoldTime = fields[4]
		}
		adjs = append(adjs, adj)
	}
	return adjs, nil
}

// OSPFNeighbor represents an OSPF neighbor.
type OSPFNeighbor struct {
	NeighborID string
	Priority   string
	State      string
	Address    string
	Interface  string
}

// GetOSPFNeighbors queries FRR for OSPF neighbor state.
func (m *Manager) GetOSPFNeighbors() ([]OSPFNeighbor, error) {
	output, err := m.executor().Vtysh("show ip ospf neighbor")
	if err != nil {
		return nil, err
	}

	var neighbors []OSPFNeighbor
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		// Skip header lines
		if fields[0] == "Neighbor" || strings.HasPrefix(line, "-") {
			continue
		}
		n := OSPFNeighbor{
			NeighborID: fields[0],
			Priority:   fields[1],
			State:      fields[2],
		}
		if len(fields) >= 5 {
			n.Address = fields[len(fields)-2]
			n.Interface = fields[len(fields)-1]
		}
		neighbors = append(neighbors, n)
	}
	return neighbors, nil
}

// BGPPeerSummary represents a BGP peer in the summary.
type BGPPeerSummary struct {
	Neighbor string
	AS       string
	MsgRcvd  string
	MsgSent  string
	UpDown   string
	State    string
	PfxRcd   string
}

// GetBGPSummary queries FRR for BGP peer summary.
func (m *Manager) GetBGPSummary() ([]BGPPeerSummary, error) {
	output, err := m.executor().Vtysh("show bgp summary")
	if err != nil {
		return nil, err
	}

	var peers []BGPPeerSummary
	lines := strings.Split(output, "\n")
	inTable := false
	for _, line := range lines {
		if strings.HasPrefix(line, "Neighbor") {
			inTable = true
			continue
		}
		if !inTable {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		p := BGPPeerSummary{
			Neighbor: fields[0],
			AS:       fields[2],
		}
		if len(fields) >= 10 {
			p.MsgRcvd = fields[3]
			p.MsgSent = fields[4]
			p.UpDown = fields[8]
			p.State = fields[9]
		}
		peers = append(peers, p)
	}
	return peers, nil
}

// BGPRoute represents a BGP route.
type BGPRoute struct {
	Network string
	NextHop string
	Metric  string
	Path    string
}

// GetBGPRoutes queries FRR for BGP routes.
func (m *Manager) GetBGPRoutes() ([]BGPRoute, error) {
	output, err := m.executor().Vtysh("show bgp ipv4 unicast")
	if err != nil {
		return nil, err
	}

	var routes []BGPRoute
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if !strings.HasPrefix(line, "*") && !strings.HasPrefix(line, " ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		r := BGPRoute{
			Network: fields[1],
			NextHop: fields[2],
		}
		if len(fields) >= 5 {
			r.Path = strings.Join(fields[4:], " ")
		}
		routes = append(routes, r)
	}
	return routes, nil
}

// FRRRouteDetail holds detailed route information parsed from FRR's JSON output.
type FRRRouteDetail struct {
	Prefix    string
	Protocol  string
	Selected  bool
	Installed bool
	Distance  int
	Metric    int
	Uptime    string
	Table     string
	NextHops  []FRRNextHop
}

// FRRNextHop holds next-hop detail from FRR JSON.
type FRRNextHop struct {
	IP                string
	Interface         string
	DirectlyConnected bool
	Active            bool
	FIB               bool
	Recursive         bool
}

// frrRouteJSON maps the JSON output of "show ip route json".
type frrRouteJSON struct {
	Prefix    string           `json:"prefix"`
	Protocol  string           `json:"protocol"`
	Selected  bool             `json:"selected"`
	Installed bool             `json:"installed"`
	Distance  int              `json:"distance"`
	Metric    int              `json:"metric"`
	Uptime    string           `json:"uptime"`
	Table     int              `json:"table"`
	NextHops  []frrNextHopJSON `json:"nexthops"`
}

type frrNextHopJSON struct {
	IP                string `json:"ip"`
	InterfaceName     string `json:"interfaceName"`
	DirectlyConnected bool   `json:"directlyConnected"`
	Active            bool   `json:"active"`
	FIB               bool   `json:"fib"`
	Recursive         bool   `json:"recursive"`
}

// GetRouteDetailJSON queries FRR for detailed IPv4 and IPv6 routes via vtysh JSON output.
func (m *Manager) GetRouteDetailJSON() ([]FRRRouteDetail, error) {
	var all []FRRRouteDetail
	for _, cmd := range []string{"show ip route json", "show ipv6 route json"} {
		output, err := m.executor().Vtysh(cmd)
		if err != nil {
			continue
		}
		routes, err := parseRouteJSON(output)
		if err != nil {
			continue
		}
		all = append(all, routes...)
	}
	return all, nil
}

// parseRouteJSON parses FRR's JSON route output into FRRRouteDetail entries.
func parseRouteJSON(data string) ([]FRRRouteDetail, error) {
	var raw map[string][]frrRouteJSON
	if err := json.Unmarshal([]byte(data), &raw); err != nil {
		return nil, err
	}

	// Sort prefixes for deterministic output.
	prefixes := make([]string, 0, len(raw))
	for p := range raw {
		prefixes = append(prefixes, p)
	}
	sort.Strings(prefixes)

	var result []FRRRouteDetail
	for _, prefix := range prefixes {
		entries := raw[prefix]
		for _, e := range entries {
			d := FRRRouteDetail{
				Prefix:    e.Prefix,
				Protocol:  e.Protocol,
				Selected:  e.Selected,
				Installed: e.Installed,
				Distance:  e.Distance,
				Metric:    e.Metric,
				Uptime:    e.Uptime,
				Table:     strconv.Itoa(e.Table),
			}
			for _, nh := range e.NextHops {
				d.NextHops = append(d.NextHops, FRRNextHop{
					IP:                nh.IP,
					Interface:         nh.InterfaceName,
					DirectlyConnected: nh.DirectlyConnected,
					Active:            nh.Active,
					FIB:               nh.FIB,
					Recursive:         nh.Recursive,
				})
			}
			result = append(result, d)
		}
	}
	return result, nil
}

// FormatRouteDetail formats FRR route details in Junos-style output.
func FormatRouteDetail(routes []FRRRouteDetail) string {
	var b strings.Builder
	for _, r := range routes {
		active := " "
		if r.Selected {
			active = "*"
		}
		fmt.Fprintf(&b, "%s %s\n", active, r.Prefix)
		fmt.Fprintf(&b, "    Protocol: %s\n", r.Protocol)
		fmt.Fprintf(&b, "    Preference: %d/%d\n", r.Distance, r.Metric)
		if r.Uptime != "" {
			fmt.Fprintf(&b, "    Age: %s\n", r.Uptime)
		}
		if r.Installed {
			b.WriteString("    State: installed\n")
		}
		for _, nh := range r.NextHops {
			if nh.DirectlyConnected {
				fmt.Fprintf(&b, "    Next-hop: directly connected via %s\n", nh.Interface)
			} else if nh.IP != "" && nh.Interface != "" {
				fmt.Fprintf(&b, "    Next-hop: %s via %s\n", nh.IP, nh.Interface)
			} else if nh.IP != "" {
				label := "Next-hop"
				if nh.Recursive {
					label = "    Resolved"
				}
				fmt.Fprintf(&b, "    %s: %s\n", label, nh.IP)
			} else if nh.Interface != "" {
				fmt.Fprintf(&b, "    Next-hop: via %s\n", nh.Interface)
			}
		}
		b.WriteString("\n")
	}
	return b.String()
}
