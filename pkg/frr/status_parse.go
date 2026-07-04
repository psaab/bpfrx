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
	// AddressFamily is the AFI/SAFI the peer row belongs to
	// (e.g. "ipv4-unicast", "ipv6-unicast"). A neighbor activated in
	// more than one family produces one BGPPeerSummary per family, so
	// this field disambiguates the otherwise-duplicate neighbor rows.
	AddressFamily string
	AS            string
	MsgRcvd       string
	MsgSent       string
	UpDown        string
	State         string
	// PfxRcd is the count of prefixes received from the peer. FRR only
	// tracks a non-zero value once the session reaches Established.
	PfxRcd string
}

// bgpSummaryFamilyJSON maps one AFI/SAFI object in the top level of
// "show bgp summary json" (FRR keys the top level by camelCase AFI/SAFI
// name — e.g. "ipv4Unicast", "ipv6Unicast" — each carrying a peers map).
type bgpSummaryFamilyJSON struct {
	RouterID string                 `json:"routerId"`
	AS       int64                  `json:"as"`
	VRFName  string                 `json:"vrfName"`
	Peers    map[string]bgpPeerJSON `json:"peers"`
}

// bgpPeerJSON maps one peer object under a family's "peers" map. FRR
// puts the real prefix-received count in "pfxRcd" (present, non-zero
// once Established) and the session state string in "state" — the text
// summary instead overloads a single "State/PfxRcd" column, which the
// old scraper misread (it stored the pfxRcd digit as the State and never
// populated PfxRcd). #3942.
type bgpPeerJSON struct {
	RemoteAs   int64  `json:"remoteAs"`
	MsgRcvd    int64  `json:"msgRcvd"`
	MsgSent    int64  `json:"msgSent"`
	PeerUptime string `json:"peerUptime"`
	State      string `json:"state"`
	PfxRcd     int64  `json:"pfxRcd"`
	PfxSnt     int64  `json:"pfxSnt"`
}

// GetBGPSummary queries FRR for the BGP peer summary via the structured
// JSON output ("show bgp summary json") and parses it. JSON is used
// instead of scraping the text table because the text table overloads a
// single "State/PfxRcd" column and appends footer lines ("Total number
// of neighbors N", blank/legend lines) that the old field-count scraper
// misparsed as phantom peers with an empty PfxRcd. #3942.
func (m *Manager) GetBGPSummary() ([]BGPPeerSummary, error) {
	output, err := m.executor().Vtysh("show bgp summary json")
	if err != nil {
		return nil, err
	}
	return parseBGPSummaryJSON(output)
}

// parseBGPSummaryJSON parses FRR's "show bgp summary json" output into
// BGPPeerSummary entries, one per (address-family, neighbor). Output is
// deterministic: AFI/SAFI keys and neighbor addresses are both sorted.
// A non-JSON response (an older FRR "% BGP instance not found" banner, a
// wedged vtysh) or an empty/peerless summary yields no peers and no
// error — "no BGP peers" is a valid state on this observability path,
// not a failure.
func parseBGPSummaryJSON(data string) ([]BGPPeerSummary, error) {
	data = strings.TrimSpace(data)
	if data == "" {
		return nil, nil
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(data), &raw); err != nil {
		// Not JSON at all — treat as "no peers" rather than surfacing a
		// parse error on the show path.
		return nil, nil
	}

	// Sort the AFI/SAFI keys for deterministic output.
	afis := make([]string, 0, len(raw))
	for k := range raw {
		afis = append(afis, k)
	}
	sort.Strings(afis)

	var peers []BGPPeerSummary
	for _, afi := range afis {
		var fam bgpSummaryFamilyJSON
		if err := json.Unmarshal(raw[afi], &fam); err != nil {
			// A non-family sibling value (e.g. {"warning": "..."}).
			continue
		}
		if len(fam.Peers) == 0 {
			continue
		}
		// Sort neighbor addresses for deterministic output.
		addrs := make([]string, 0, len(fam.Peers))
		for a := range fam.Peers {
			addrs = append(addrs, a)
		}
		sort.Strings(addrs)

		af := bgpAFILabel(afi)
		for _, addr := range addrs {
			pj := fam.Peers[addr]
			peers = append(peers, BGPPeerSummary{
				Neighbor:      addr,
				AddressFamily: af,
				AS:            strconv.FormatInt(pj.RemoteAs, 10),
				MsgRcvd:       strconv.FormatInt(pj.MsgRcvd, 10),
				MsgSent:       strconv.FormatInt(pj.MsgSent, 10),
				UpDown:        pj.PeerUptime,
				State:         pj.State,
				PfxRcd:        strconv.FormatInt(pj.PfxRcd, 10),
			})
		}
	}
	return peers, nil
}

// bgpAFILabel maps FRR's camelCase AFI/SAFI JSON key to a readable
// hyphenated label; unknown keys are returned verbatim.
func bgpAFILabel(key string) string {
	switch key {
	case "ipv4Unicast":
		return "ipv4-unicast"
	case "ipv6Unicast":
		return "ipv6-unicast"
	case "ipv4Multicast":
		return "ipv4-multicast"
	case "ipv6Multicast":
		return "ipv6-multicast"
	case "l2VpnEvpn":
		return "l2vpn-evpn"
	default:
		return key
	}
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
