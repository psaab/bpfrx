package grpcapi

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/psaab/bpfrx/pkg/cluster"
	"github.com/psaab/bpfrx/pkg/cmdtree"
	"github.com/psaab/bpfrx/pkg/config"
	pb "github.com/psaab/bpfrx/pkg/grpcapi/bpfrxv1"
	"github.com/psaab/bpfrx/pkg/routing"
	"github.com/vishvananda/netlink"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// buildInterfacesInput gathers cluster interface data for FormatInterfaces.
func (s *Server) buildInterfacesInput() cluster.InterfacesInput {
	var input cluster.InterfacesInput
	cfg := s.store.ActiveConfig()
	if cfg == nil || cfg.Chassis.Cluster == nil {
		return input
	}
	cc := cfg.Chassis.Cluster
	input.ControlInterface = cc.ControlInterface
	input.FabricInterface = cc.FabricInterface
	if fabIfc, ok := cfg.Interfaces.Interfaces[cc.FabricInterface]; ok {
		input.FabricMembers = fabIfc.FabricMembers
	}
	input.Fabric1Interface = cc.Fabric1Interface
	if fab1Ifc, ok := cfg.Interfaces.Interfaces[cc.Fabric1Interface]; ok {
		input.Fabric1Members = fab1Ifc.FabricMembers
	}

	// Build RETH info from config.
	rethMap := cfg.RethToPhysical() // reth-name -> physical-member
	for name, ifc := range cfg.Interfaces.Interfaces {
		if ifc.RedundancyGroup > 0 && strings.HasPrefix(name, "reth") {
			status := "Up"
			if phys, ok := rethMap[name]; ok {
				linuxName := config.LinuxIfName(phys)
				link, err := netlink.LinkByName(linuxName)
				if err != nil || (link.Attrs().OperState != netlink.OperUp &&
					link.Attrs().Flags&net.FlagUp == 0) {
					status = "Down"
				}
			}
			input.Reths = append(input.Reths, cluster.RethInfo{
				Name:            name,
				RedundancyGroup: ifc.RedundancyGroup,
				Status:          status,
			})
		}
	}
	sort.Slice(input.Reths, func(i, j int) bool { return input.Reths[i].Name < input.Reths[j].Name })

	// Build local interface monitor info.
	localMonMap := make(map[string]bool) // track which interfaces are local
	monStatuses := make(map[int][]routing.InterfaceMonitorStatus)
	if s.routing != nil {
		if ms := s.routing.InterfaceMonitorStatuses(); ms != nil {
			monStatuses = ms
		}
	}
	for _, rg := range cc.RedundancyGroups {
		if statuses, ok := monStatuses[rg.ID]; ok {
			for _, st := range statuses {
				input.Monitors = append(input.Monitors, cluster.InterfaceMonitorInfo{
					Interface:       st.Interface,
					Weight:          st.Weight,
					Up:              st.Up,
					RedundancyGroup: rg.ID,
				})
				localMonMap[st.Interface] = true
			}
		} else {
			for _, mon := range rg.InterfaceMonitors {
				input.Monitors = append(input.Monitors, cluster.InterfaceMonitorInfo{
					Interface:       mon.Interface,
					Weight:          mon.Weight,
					Up:              true,
					RedundancyGroup: rg.ID,
				})
				localMonMap[mon.Interface] = true
			}
		}
	}

	// Build peer interface monitor info from heartbeat.
	if s.cluster != nil {
		peerLive := s.cluster.PeerMonitorStatuses()
		peerMap := make(map[string]bool)
		for _, pm := range peerLive {
			peerMap[pm.Interface] = true
			input.PeerMonitors = append(input.PeerMonitors, pm)
		}
		// Fill config-only peer monitors (not local, not in heartbeat) as down.
		for _, rg := range cc.RedundancyGroups {
			for _, mon := range rg.InterfaceMonitors {
				if localMonMap[mon.Interface] {
					continue
				}
				if peerMap[mon.Interface] {
					continue
				}
				input.PeerMonitors = append(input.PeerMonitors, cluster.InterfaceMonitorInfo{
					Interface:       mon.Interface,
					Weight:          mon.Weight,
					Up:              false,
					RedundancyGroup: rg.ID,
				})
			}
		}
	}

	return input
}

func (s *Server) MatchPolicies(_ context.Context, req *pb.MatchPoliciesRequest) (*pb.MatchPoliciesResponse, error) {
	cfg := s.store.ActiveConfig()
	if cfg == nil {
		return &pb.MatchPoliciesResponse{}, nil
	}

	parsedSrc := net.ParseIP(req.SourceIp)
	parsedDst := net.ParseIP(req.DestinationIp)
	dstPort := int(req.DestinationPort)

	for _, zpp := range cfg.Security.Policies {
		if zpp.FromZone != req.FromZone || zpp.ToZone != req.ToZone {
			continue
		}
		for _, pol := range zpp.Policies {
			if !matchPolicyAddr(pol.Match.SourceAddresses, parsedSrc, cfg) {
				continue
			}
			if !matchPolicyAddr(pol.Match.DestinationAddresses, parsedDst, cfg) {
				continue
			}
			if !matchPolicyApp(pol.Match.Applications, req.Protocol, dstPort, cfg) {
				continue
			}

			action := "permit"
			switch pol.Action {
			case 1:
				action = "deny"
			case 2:
				action = "reject"
			}

			return &pb.MatchPoliciesResponse{
				Matched:      true,
				PolicyName:   pol.Name,
				Action:       action,
				SrcAddresses: pol.Match.SourceAddresses,
				DstAddresses: pol.Match.DestinationAddresses,
				Applications: pol.Match.Applications,
			}, nil
		}
	}

	return &pb.MatchPoliciesResponse{
		Matched: false,
		Action:  "deny (default)",
	}, nil
}

// matchPolicyAddr checks if an IP matches a list of address-book references.
func matchPolicyAddr(addrs []string, ip net.IP, cfg *config.Config) bool {
	if len(addrs) == 0 || ip == nil {
		return true
	}
	for _, a := range addrs {
		if a == "any" {
			return true
		}
		if cfg.Security.AddressBook == nil {
			continue
		}
		if addr, ok := cfg.Security.AddressBook.Addresses[a]; ok {
			_, cidr, err := net.ParseCIDR(addr.Value)
			if err == nil && cidr.Contains(ip) {
				return true
			}
		}
		if matchPolicyAddrSet(a, ip, cfg, 0) {
			return true
		}
	}
	return false
}

func matchPolicyAddrSet(setName string, ip net.IP, cfg *config.Config, depth int) bool {
	if depth > 5 || cfg.Security.AddressBook == nil {
		return false
	}
	as, ok := cfg.Security.AddressBook.AddressSets[setName]
	if !ok {
		return false
	}
	for _, addrName := range as.Addresses {
		if addr, ok := cfg.Security.AddressBook.Addresses[addrName]; ok {
			_, cidr, err := net.ParseCIDR(addr.Value)
			if err == nil && cidr.Contains(ip) {
				return true
			}
		}
	}
	for _, nested := range as.AddressSets {
		if matchPolicyAddrSet(nested, ip, cfg, depth+1) {
			return true
		}
	}
	return false
}

// matchPolicyApp checks if a protocol/port matches application references.
func matchPolicyApp(apps []string, proto string, dstPort int, cfg *config.Config) bool {
	if len(apps) == 0 || proto == "" {
		return true
	}
	for _, a := range apps {
		if a == "any" {
			return true
		}
		if matchSingleApp(a, proto, dstPort, cfg) {
			return true
		}
		if cfg.Applications.ApplicationSets != nil {
			if as, ok := cfg.Applications.ApplicationSets[a]; ok {
				for _, appRef := range as.Applications {
					if matchSingleApp(appRef, proto, dstPort, cfg) {
						return true
					}
				}
			}
		}
	}
	return false
}

func matchSingleApp(appName, proto string, dstPort int, cfg *config.Config) bool {
	if cfg.Applications.Applications == nil {
		return false
	}
	app, ok := cfg.Applications.Applications[appName]
	if !ok {
		return false
	}
	if app.Protocol != "" && !strings.EqualFold(app.Protocol, proto) {
		return false
	}
	if app.DestinationPort != "" && dstPort > 0 {
		if strings.Contains(app.DestinationPort, "-") {
			parts := strings.SplitN(app.DestinationPort, "-", 2)
			lo, _ := strconv.Atoi(parts[0])
			hi, _ := strconv.Atoi(parts[1])
			if dstPort < lo || dstPort > hi {
				return false
			}
		} else {
			p, _ := strconv.Atoi(app.DestinationPort)
			if p != dstPort {
				return false
			}
		}
	}
	return true
}

// policyActionName returns a human-readable policy action name.
func policyActionName(a config.PolicyAction) string {
	switch a {
	case 1:
		return "deny"
	case 2:
		return "reject"
	default:
		return "permit"
	}
}

// matchShowPolicyAddr checks if an IP matches a list of address-book references.
func matchShowPolicyAddr(addrs []string, ip net.IP, cfg *config.Config) bool {
	if len(addrs) == 0 || ip == nil {
		return true
	}
	for _, a := range addrs {
		if a == "any" {
			return true
		}
		if cfg.Security.AddressBook == nil {
			continue
		}
		if addr, ok := cfg.Security.AddressBook.Addresses[a]; ok {
			_, cidr, err := net.ParseCIDR(addr.Value)
			if err == nil && cidr.Contains(ip) {
				return true
			}
		}
		if matchShowPolicyAddrSet(a, ip, cfg, 0) {
			return true
		}
	}
	return false
}

func matchShowPolicyAddrSet(setName string, ip net.IP, cfg *config.Config, depth int) bool {
	if depth > 5 || cfg.Security.AddressBook == nil {
		return false
	}
	as, ok := cfg.Security.AddressBook.AddressSets[setName]
	if !ok {
		return false
	}
	for _, addrName := range as.Addresses {
		if addr, ok := cfg.Security.AddressBook.Addresses[addrName]; ok {
			_, cidr, err := net.ParseCIDR(addr.Value)
			if err == nil && cidr.Contains(ip) {
				return true
			}
		}
	}
	for _, nested := range as.AddressSets {
		if matchShowPolicyAddrSet(nested, ip, cfg, depth+1) {
			return true
		}
	}
	return false
}

// matchShowPolicyApp checks if a protocol/port matches a list of application references.
func matchShowPolicyApp(apps []string, proto string, dstPort int, cfg *config.Config) bool {
	if len(apps) == 0 || proto == "" {
		return true
	}
	for _, a := range apps {
		if a == "any" {
			return true
		}
		if matchShowSingleApp(a, proto, dstPort, cfg) {
			return true
		}
		if cfg.Applications.ApplicationSets != nil {
			if as, ok := cfg.Applications.ApplicationSets[a]; ok {
				for _, appRef := range as.Applications {
					if matchShowSingleApp(appRef, proto, dstPort, cfg) {
						return true
					}
				}
			}
		}
	}
	return false
}

func matchShowSingleApp(appName, proto string, dstPort int, cfg *config.Config) bool {
	if cfg.Applications.Applications == nil {
		return false
	}
	app, ok := cfg.Applications.Applications[appName]
	if !ok {
		return false
	}
	if app.Protocol != "" && !strings.EqualFold(app.Protocol, proto) {
		return false
	}
	if app.DestinationPort != "" && dstPort > 0 {
		if strings.Contains(app.DestinationPort, "-") {
			parts := strings.SplitN(app.DestinationPort, "-", 2)
			lo, _ := strconv.Atoi(parts[0])
			hi, _ := strconv.Atoi(parts[1])
			if dstPort < lo || dstPort > hi {
				return false
			}
		} else {
			p, _ := strconv.Atoi(app.DestinationPort)
			if p != dstPort {
				return false
			}
		}
	}
	return true
}

// grpcResolveAddress looks up a named address in the global address book and returns its CIDR suffix.
func grpcResolveAddress(cfg *config.Config, name string) string {
	if name == "any" {
		return ""
	}
	ab := cfg.Security.AddressBook
	if ab == nil {
		return ""
	}
	if addr, ok := ab.Addresses[name]; ok && addr.Value != "" {
		return " (" + addr.Value + ")"
	}
	if _, ok := ab.AddressSets[name]; ok {
		return " (address-set)"
	}
	return ""
}

func (s *Server) Complete(_ context.Context, req *pb.CompleteRequest) (*pb.CompleteResponse, error) {
	text := req.Line
	if int(req.Pos) < len(text) {
		text = text[:req.Pos]
	}

	// Pipe filter completion: "show ... | <tab>"
	if candidates := s.completePipeFilter(text); candidates != nil {
		sort.Strings(candidates)
		return &pb.CompleteResponse{Candidates: candidates}, nil
	}

	words := strings.Fields(text)
	trailingSpace := len(text) > 0 && text[len(text)-1] == ' '

	var partial string
	if !trailingSpace && len(words) > 0 {
		partial = words[len(words)-1]
		words = words[:len(words)-1]
	}

	var pairs []completionPair
	if req.ConfigMode {
		pairs = s.completeConfigPairs(words, partial)
	} else {
		pairs = s.completeOperationalPairs(words, partial)
	}

	sort.Slice(pairs, func(i, j int) bool { return pairs[i].name < pairs[j].name })
	resp := &pb.CompleteResponse{
		Candidates:   make([]string, len(pairs)),
		Descriptions: make([]string, len(pairs)),
	}
	for i, p := range pairs {
		resp.Candidates[i] = p.name
		resp.Descriptions[i] = p.desc
	}
	return resp, nil
}

// pipeFilterNames lists available pipe filters for completion.
var pipeFilterNames = []string{"count", "display", "except", "find", "grep", "last", "match", "no-more"}

// completePipeFilter returns pipe filter candidates if the text contains "|".
// Returns nil if no pipe is present (caller should proceed with normal completion).
func (s *Server) completePipeFilter(text string) []string {
	idx := strings.LastIndex(text, "|")
	if idx < 0 {
		return nil
	}
	after := strings.TrimSpace(text[idx+1:])
	trailingSpace := len(text) > 0 && text[len(text)-1] == ' '

	// Right after "|" or "| " — all filters
	if after == "" || (trailingSpace && after == "") {
		return pipeFilterNames
	}

	// User has typed a complete filter + space — no more completions (freeform arg)
	if trailingSpace {
		return []string{}
	}

	// Partial filter name
	var candidates []string
	for _, f := range pipeFilterNames {
		if strings.HasPrefix(f, after) {
			candidates = append(candidates, f)
		}
	}
	return candidates
}

func filterCompletionPairs(tree map[string]*cmdtree.Node, prefix string) []completionPair {
	pairs := make([]completionPair, 0, len(tree))
	for name, node := range tree {
		if prefix == "" || strings.HasPrefix(name, prefix) {
			pairs = append(pairs, completionPair{name: name, desc: node.Desc})
		}
	}
	return pairs
}

func resolveShowConfigurationWords(words []string) ([]string, bool) {
	if len(words) < 2 {
		return nil, false
	}
	show, ok := cmdtree.ResolveUniquePrefix(cmdtree.KeysFromTree(cmdtree.OperationalTree), words[0])
	if !ok || show != "show" {
		return nil, false
	}
	showNode := cmdtree.OperationalTree[show]
	if showNode == nil || showNode.Children == nil {
		return nil, false
	}
	conf, ok := cmdtree.ResolveUniquePrefix(cmdtree.KeysFromTree(showNode.Children), words[1])
	if !ok || conf != "configuration" {
		return nil, false
	}
	return words[2:], true
}

func (s *Server) completionValueProvider() config.ValueProvider {
	if s == nil || s.store == nil {
		return nil
	}
	return s.valueProvider
}

func (s *Server) completeOperationalPairs(words []string, partial string) []completionPair {
	// "show configuration <path>" — delegate sub-path to config schema
	if subPath, ok := resolveShowConfigurationWords(words); ok {
		if resolvedPath, resolved := config.ResolveConsumedSetPathTokens(subPath); resolved {
			subPath = resolvedPath
		}
		schemaCompletions := config.CompleteSetPathWithValues(subPath, s.completionValueProvider())
		if schemaCompletions != nil {
			var pairs []completionPair
			for _, sc := range schemaCompletions {
				if partial == "" || strings.HasPrefix(sc.Name, partial) {
					pairs = append(pairs, completionPair{name: sc.Name, desc: sc.Desc})
				}
			}
			if len(pairs) > 0 {
				return pairs
			}
		}
	}
	var cfg *config.Config
	if s.store != nil {
		cfg = s.store.ActiveConfig()
	}
	candidates := cmdtree.CompleteFromTreeWithDesc(cmdtree.OperationalTree, words, partial, cfg)
	pairs := make([]completionPair, len(candidates))
	for i, c := range candidates {
		pairs[i] = completionPair{name: c.Name, desc: c.Desc}
	}
	return pairs
}

func (s *Server) completeConfigPairs(words []string, partial string) []completionPair {
	if len(words) == 0 {
		return filterCompletionPairs(cmdtree.ConfigTopLevel, partial)
	}

	resolvedTop, ok := cmdtree.ResolveUniquePrefix(cmdtree.KeysFromTree(cmdtree.ConfigTopLevel), words[0])
	if !ok {
		if len(words) == 1 {
			return filterCompletionPairs(cmdtree.ConfigTopLevel, words[0])
		}
		return nil
	}

	switch resolvedTop {
	case "set", "delete", "show", "edit":
		pathWords := words[1:]
		if resolvedPath, resolved := config.ResolveConsumedSetPathTokens(pathWords); resolved {
			pathWords = resolvedPath
		}
		schemaCompletions := config.CompleteSetPathWithValues(pathWords, s.completionValueProvider())
		if schemaCompletions == nil {
			return nil
		}
		var pairs []completionPair
		for _, sc := range schemaCompletions {
			if strings.HasPrefix(sc.Name, partial) {
				pairs = append(pairs, completionPair{name: sc.Name, desc: sc.Desc})
			}
		}
		return pairs
	case "run":
		var cfg *config.Config
		if s.store != nil {
			cfg = s.store.ActiveConfig()
		}
		names := cmdtree.CompleteFromTree(cmdtree.OperationalTree, words[1:], partial, cfg)
		var pairs []completionPair
		for _, name := range names {
			pairs = append(pairs, completionPair{name: name})
		}
		return pairs
	case "commit", "load":
		if len(words) == 1 {
			node := cmdtree.ConfigTopLevel[resolvedTop]
			if node == nil || node.Children == nil {
				return nil
			}
			var pairs []completionPair
			for name, child := range node.Children {
				if strings.HasPrefix(name, partial) {
					pairs = append(pairs, completionPair{name: name, desc: child.Desc})
				}
			}
			return pairs
		}
		return nil
	default:
		return nil
	}
}

func (s *Server) valueProvider(hint config.ValueHint, path []string) []config.SchemaCompletion {
	if s == nil || s.store == nil {
		return nil
	}
	cfg := s.store.ActiveConfig()
	if cfg == nil {
		return nil
	}
	switch hint {
	case config.ValueHintZoneName:
		var out []config.SchemaCompletion
		for name, zone := range cfg.Security.Zones {
			desc := zone.Description
			if desc == "" {
				desc = "(configured)"
			}
			out = append(out, config.SchemaCompletion{Name: name, Desc: desc})
		}
		return out
	case config.ValueHintAddressName:
		var out []config.SchemaCompletion
		if cfg.Security.AddressBook != nil {
			for _, addr := range cfg.Security.AddressBook.Addresses {
				out = append(out, config.SchemaCompletion{Name: addr.Name, Desc: addr.Value})
			}
			for _, as := range cfg.Security.AddressBook.AddressSets {
				out = append(out, config.SchemaCompletion{Name: as.Name, Desc: "address-set"})
			}
		}
		return out
	case config.ValueHintAppName:
		var out []config.SchemaCompletion
		for _, app := range cfg.Applications.Applications {
			out = append(out, config.SchemaCompletion{Name: app.Name, Desc: app.Description})
		}
		for _, as := range cfg.Applications.ApplicationSets {
			out = append(out, config.SchemaCompletion{Name: as.Name, Desc: "application-set"})
		}
		for name := range config.PredefinedApplications {
			out = append(out, config.SchemaCompletion{Name: name, Desc: "predefined"})
		}
		return out
	case config.ValueHintAppSetName:
		var out []config.SchemaCompletion
		for _, as := range cfg.Applications.ApplicationSets {
			out = append(out, config.SchemaCompletion{Name: as.Name, Desc: "application-set"})
		}
		return out
	case config.ValueHintPoolName:
		var out []config.SchemaCompletion
		for name := range cfg.Security.NAT.SourcePools {
			out = append(out, config.SchemaCompletion{Name: name, Desc: "source pool"})
		}
		if cfg.Security.NAT.Destination != nil {
			for name := range cfg.Security.NAT.Destination.Pools {
				out = append(out, config.SchemaCompletion{Name: name, Desc: "destination pool"})
			}
		}
		return out
	case config.ValueHintScreenProfile:
		var out []config.SchemaCompletion
		for name := range cfg.Security.Screen {
			out = append(out, config.SchemaCompletion{Name: name, Desc: "screen profile"})
		}
		return out
	case config.ValueHintStreamName:
		var out []config.SchemaCompletion
		for name := range cfg.Security.Log.Streams {
			out = append(out, config.SchemaCompletion{Name: name, Desc: "log stream"})
		}
		return out
	case config.ValueHintInterfaceName:
		var out []config.SchemaCompletion
		for name, iface := range cfg.Interfaces.Interfaces {
			desc := iface.Description
			if desc == "" {
				desc = "(configured)"
			}
			out = append(out, config.SchemaCompletion{Name: name, Desc: desc})
		}
		return out
	case config.ValueHintPolicyAddress:
		out := []config.SchemaCompletion{
			{Name: "any", Desc: "Any IPv4 or IPv6 address"},
			{Name: "any-ipv4", Desc: "Any IPv4 address"},
			{Name: "any-ipv6", Desc: "Any IPv6 address"},
		}
		if cfg.Security.AddressBook != nil {
			for _, addr := range cfg.Security.AddressBook.Addresses {
				out = append(out, config.SchemaCompletion{Name: addr.Name, Desc: addr.Value})
			}
			for _, as := range cfg.Security.AddressBook.AddressSets {
				out = append(out, config.SchemaCompletion{Name: as.Name, Desc: "address-set"})
			}
		}
		return out
	case config.ValueHintPolicyApp:
		out := []config.SchemaCompletion{
			{Name: "any", Desc: "Any application"},
		}
		for _, app := range cfg.Applications.Applications {
			out = append(out, config.SchemaCompletion{Name: app.Name, Desc: app.Description})
		}
		for _, as := range cfg.Applications.ApplicationSets {
			out = append(out, config.SchemaCompletion{Name: as.Name, Desc: "application-set"})
		}
		for name := range config.PredefinedApplications {
			out = append(out, config.SchemaCompletion{Name: name, Desc: "predefined"})
		}
		return out
	case config.ValueHintPolicyName:
		var policies []*config.Policy
		for i, tok := range path {
			if tok == "from-zone" && i+3 < len(path) && path[i+2] == "to-zone" {
				fromZone := path[i+1]
				toZone := path[i+3]
				for _, zpp := range cfg.Security.Policies {
					if zpp.FromZone == fromZone && zpp.ToZone == toZone {
						policies = zpp.Policies
						break
					}
				}
				break
			}
			if tok == "global" {
				policies = cfg.Security.GlobalPolicies
				break
			}
		}
		var out []config.SchemaCompletion
		for _, pol := range policies {
			desc := pol.Description
			if desc == "" {
				desc = "(configured)"
			}
			out = append(out, config.SchemaCompletion{Name: pol.Name, Desc: desc})
		}
		return out
	case config.ValueHintUnitNumber:
		var ifaceName string
		for i, tok := range path {
			if tok == "interfaces" && i+1 < len(path) {
				ifaceName = path[i+1]
				break
			}
		}
		if ifaceName == "" {
			return nil
		}
		iface := cfg.Interfaces.Interfaces[ifaceName]
		if iface == nil {
			return nil
		}
		var out []config.SchemaCompletion
		for num, unit := range iface.Units {
			desc := unit.Description
			if desc == "" {
				desc = "(configured)"
			}
			out = append(out, config.SchemaCompletion{Name: fmt.Sprintf("%d", num), Desc: desc})
		}
		return out
	}
	return nil
}

// --- Mutation RPCs ---

func (s *Server) ClearCounters(_ context.Context, _ *pb.ClearCountersRequest) (*pb.ClearCountersResponse, error) {
	if s.dp == nil || !s.dp.IsLoaded() {
		return nil, status.Error(codes.Unavailable, "dataplane not loaded")
	}
	if err := s.dp.ClearAllCounters(); err != nil {
		return nil, status.Errorf(codes.Internal, "%v", err)
	}
	return &pb.ClearCountersResponse{}, nil
}

// --- Completion RPC ---

// completionPair holds a candidate name and optional description.
type completionPair struct {
	name string
	desc string
}
