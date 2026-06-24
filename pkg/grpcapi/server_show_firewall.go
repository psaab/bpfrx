// Phase 1 of #1043: extract the `firewall` ShowText case body into a
// dedicated method to take the first ~130 LOC bite out of
// `server_show.go`'s 4,072-LOC modularity-discipline violation.
// Semantic relocation — the case body is moved verbatim apart from
// (a) `&buf` references becoming `buf` (now a passed-in
// `*strings.Builder`) and (b) the original `if !hasFilters { ... }
// else { ... }` structure flattened into an early-return form
// (`if !hasFilters { ...; return }; ...`). Output is unchanged.
// The dispatcher in `server_show.go` becomes
// `s.showFirewall(cfg, &buf)`.

package grpcapi

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// showFirewall renders the `cli show firewall` output. Writes to
// `buf`. Returns no error — the original case body had no error
// returns; counters that fail to load are silently skipped (same
// as the original).
func (s *Server) showFirewall(cfg *config.Config, buf *strings.Builder) {
	hasFilters := cfg != nil && (len(cfg.Firewall.FiltersInet) > 0 || len(cfg.Firewall.FiltersInet6) > 0)
	if !hasFilters {
		buf.WriteString("No firewall filters configured\n")
		return
	}
	var userspaceStatus *dpuserspace.ProcessStatus
	if status, err := s.userspaceDataplaneStatus(); err == nil {
		userspaceStatus = &status
	}
	userspaceCounters := dpuserspace.BuildFirewallFilterTermCounterIndex(userspaceStatus)
	// Resolve filter IDs for counter display
	var filterIDs map[string]uint32
	if s.dp != nil && s.dp.IsLoaded() {
		if cr := s.applyResult(); cr != nil {
			filterIDs = cr.FilterIDs
		}
	}

	printFilters := func(family string, filters map[string]*config.FirewallFilter) {
		names := make([]string, 0, len(filters))
		for name := range filters {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			filter := filters[name]
			fmt.Fprintf(buf, "Filter: %s (family %s)\n", name, family)

			// Get filter config for counter lookup
			var ruleStart uint32
			var hasCounters bool
			if filterIDs != nil {
				if fid, ok := filterIDs[family+":"+name]; ok {
					if fcfg, err := s.dp.ReadFilterConfig(fid); err == nil {
						ruleStart = fcfg.RuleStart
						hasCounters = true
					}
				}
			}
			ruleOffset := ruleStart

			for _, term := range filter.Terms {
				fmt.Fprintf(buf, "  Term: %s\n", term.Name)
				for _, d := range term.DSCPs {
					fmt.Fprintf(buf, "    from dscp %s\n", d)
				}
				for _, p := range term.Protocols {
					fmt.Fprintf(buf, "    from protocol %s\n", p)
				}
				for _, addr := range term.SourceAddresses {
					fmt.Fprintf(buf, "    from source-address %s\n", addr)
				}
				for _, pl := range term.SourcePrefixLists {
					if pl.Except {
						fmt.Fprintf(buf, "    from source-prefix-list %s except\n", pl.Name)
					} else {
						fmt.Fprintf(buf, "    from source-prefix-list %s\n", pl.Name)
					}
				}
				for _, addr := range term.DestAddresses {
					fmt.Fprintf(buf, "    from destination-address %s\n", addr)
				}
				for _, pl := range term.DestPrefixLists {
					if pl.Except {
						fmt.Fprintf(buf, "    from destination-prefix-list %s except\n", pl.Name)
					} else {
						fmt.Fprintf(buf, "    from destination-prefix-list %s\n", pl.Name)
					}
				}
				if len(term.SourcePorts) > 0 {
					fmt.Fprintf(buf, "    from source-port %s\n", strings.Join(term.SourcePorts, ", "))
				}
				if len(term.DestinationPorts) > 0 {
					fmt.Fprintf(buf, "    from destination-port %s\n", strings.Join(term.DestinationPorts, ", "))
				}
				for _, t := range term.ICMPTypes {
					fmt.Fprintf(buf, "    from icmp-type %d\n", t)
				}
				for _, c := range term.ICMPCodes {
					fmt.Fprintf(buf, "    from icmp-code %d\n", c)
				}
				if term.RoutingInstance != "" {
					fmt.Fprintf(buf, "    then routing-instance %s\n", term.RoutingInstance)
				}
				if term.Log {
					buf.WriteString("    then log\n")
				}
				if term.Count != "" {
					fmt.Fprintf(buf, "    then count %s\n", term.Count)
				}
				if term.ForwardingClass != "" {
					fmt.Fprintf(buf, "    then forwarding-class %s\n", term.ForwardingClass)
				}
				if term.LossPriority != "" {
					fmt.Fprintf(buf, "    then loss-priority %s\n", term.LossPriority)
				}
				action := term.Action
				if action == "" {
					action = "accept"
				}
				fmt.Fprintf(buf, "    then %s\n", action)

				numRules := firewallFilterTermExpansionCount(cfg, term)
				var totalPkts, totalBytes uint64
				if hasCounters {
					for i := uint32(0); i < numRules; i++ {
						if ctrs, err := s.dp.ReadFilterCounters(ruleOffset + i); err == nil {
							totalPkts += ctrs.Packets
							totalBytes += ctrs.Bytes
						}
					}
					ruleOffset += numRules
				}
				userspaceCounter, userspaceOk := userspaceCounters[dpuserspace.FirewallFilterTermCounterKey{
					Family: family, FilterName: name, TermName: term.Name,
				}]
				if userspaceOk {
					totalPkts += userspaceCounter.Packets
					totalBytes += userspaceCounter.Bytes
				}
				if hasCounters || userspaceOk {
					fmt.Fprintf(buf, "    Hit count: %d packets, %d bytes\n", totalPkts, totalBytes)
				}
			}
			buf.WriteString("\n")
		}
	}
	printFilters("inet", cfg.Firewall.FiltersInet)
	printFilters("inet6", cfg.Firewall.FiltersInet6)
}

// --- #1700: residual ShowText branches ---

func (s *Server) showTestPolicy(req *pb.ShowTextRequest, cfg *config.Config, buf *strings.Builder) (*pb.ShowTextResponse, error) {
	params := strings.TrimPrefix(req.Topic, "test-policy:")
	var fromZone, toZone, srcIP, dstIP, proto string
	var dstPort int
	for _, kv := range strings.Split(params, ",") {
		parts := strings.SplitN(kv, "=", 2)
		if len(parts) != 2 {
			continue
		}
		switch parts[0] {
		case "from":
			fromZone = parts[1]
		case "to":
			toZone = parts[1]
		case "src":
			srcIP = parts[1]
		case "dst":
			dstIP = parts[1]
		case "port":
			dstPort, _ = strconv.Atoi(parts[1])
		case "proto":
			proto = parts[1]
		}
	}
	if cfg == nil {
		buf.WriteString("No active configuration\n")
	} else if fromZone == "" || toZone == "" {
		buf.WriteString("Missing from/to zone parameters\n")
	} else if srcIP != "" && net.ParseIP(srcIP) == nil {
		// A non-empty but malformed src would parse to nil and be treated
		// as a wildcard by matchShowPolicyAddr, yielding a false-positive
		// policy match (#1711). Report it instead. Empty still means any.
		fmt.Fprintf(buf, "invalid src %q\n", srcIP)
	} else if dstIP != "" && net.ParseIP(dstIP) == nil {
		fmt.Fprintf(buf, "invalid dst %q\n", dstIP)
	} else {
		parsedSrc := net.ParseIP(srcIP)
		parsedDst := net.ParseIP(dstIP)
		found := false
		for _, zpp := range cfg.Security.Policies {
			if zpp.FromZone != fromZone || zpp.ToZone != toZone {
				continue
			}
			for _, pol := range zpp.Policies {
				if !matchShowPolicyAddr(pol.Match.SourceAddresses, parsedSrc, cfg) {
					continue
				}
				if !matchShowPolicyAddr(pol.Match.DestinationAddresses, parsedDst, cfg) {
					continue
				}
				if !matchShowPolicyApp(pol.Match.Applications, proto, dstPort, cfg) {
					continue
				}
				action := policyActionName(pol.Action)
				fmt.Fprintf(buf, "Policy match:\n")
				fmt.Fprintf(buf, "  From zone: %s\n  To zone:   %s\n", fromZone, toZone)
				fmt.Fprintf(buf, "  Policy:    %s\n", pol.Name)
				fmt.Fprintf(buf, "  Action:    %s\n", action)
				found = true
				break
			}
			if found {
				break
			}
		}
		if !found {
			// Check global policies
			for _, pol := range cfg.Security.GlobalPolicies {
				if !matchShowPolicyAddr(pol.Match.SourceAddresses, parsedSrc, cfg) {
					continue
				}
				if !matchShowPolicyAddr(pol.Match.DestinationAddresses, parsedDst, cfg) {
					continue
				}
				if !matchShowPolicyApp(pol.Match.Applications, proto, dstPort, cfg) {
					continue
				}
				action := policyActionName(pol.Action)
				fmt.Fprintf(buf, "Policy match (global):\n")
				fmt.Fprintf(buf, "  Policy:    %s\n", pol.Name)
				fmt.Fprintf(buf, "  Action:    %s\n", action)
				found = true
				break
			}
		}
		if !found {
			fmt.Fprintf(buf, "Default deny (no matching policy for %s -> %s)\n", fromZone, toZone)
		}
	}
	return &pb.ShowTextResponse{Output: buf.String()}, nil
}

func (s *Server) showFirewallFilter(req *pb.ShowTextRequest, cfg *config.Config, buf *strings.Builder) (*pb.ShowTextResponse, error) {
	filterTopic := strings.TrimPrefix(req.Topic, "firewall-filter:")
	filterName := filterTopic
	requestedFamily := ""
	if idx := strings.LastIndex(filterTopic, ":"); idx > 0 {
		filterName = filterTopic[:idx]
		requestedFamily = filterTopic[idx+1:]
	}
	if cfg == nil {
		buf.WriteString("No active configuration\n")
	} else {
		var filter *config.FirewallFilter
		var family string
		switch requestedFamily {
		case "":
			if f, ok := cfg.Firewall.FiltersInet[filterName]; ok {
				filter = f
				family = "inet"
			} else if f, ok := cfg.Firewall.FiltersInet6[filterName]; ok {
				filter = f
				family = "inet6"
			}
		case "inet":
			filter = cfg.Firewall.FiltersInet[filterName]
			family = "inet"
		case "inet6":
			filter = cfg.Firewall.FiltersInet6[filterName]
			family = "inet6"
		default:
			fmt.Fprintf(buf, "invalid family: %s\n", requestedFamily)
			return &pb.ShowTextResponse{Output: buf.String()}, nil
		}
		if filter == nil {
			if requestedFamily != "" {
				fmt.Fprintf(buf, "Filter not found: %s (family %s)\n", filterName, requestedFamily)
			} else {
				fmt.Fprintf(buf, "Filter not found: %s\n", filterName)
			}
		} else {
			var userspaceStatus *dpuserspace.ProcessStatus
			if status, err := s.userspaceDataplaneStatus(); err == nil {
				userspaceStatus = &status
			}
			userspaceCounters := dpuserspace.BuildFirewallFilterTermCounterIndex(userspaceStatus)
			var filterIDs map[string]uint32
			if s.dp != nil && s.dp.IsLoaded() {
				if cr := s.applyResult(); cr != nil {
					filterIDs = cr.FilterIDs
				}
			}
			var ruleStart uint32
			var hasCounters bool
			if filterIDs != nil {
				if fid, ok := filterIDs[family+":"+filterName]; ok {
					if fcfg, err := s.dp.ReadFilterConfig(fid); err == nil {
						ruleStart = fcfg.RuleStart
						hasCounters = true
					}
				}
			}
			fmt.Fprintf(buf, "Filter: %s (family %s)\n", filterName, family)
			ruleOffset := ruleStart
			for _, term := range filter.Terms {
				fmt.Fprintf(buf, "\n  Term: %s\n", term.Name)
				for _, d := range term.DSCPs {
					fmt.Fprintf(buf, "    from dscp %s\n", d)
				}
				for _, p := range term.Protocols {
					fmt.Fprintf(buf, "    from protocol %s\n", p)
				}
				for _, addr := range term.SourceAddresses {
					fmt.Fprintf(buf, "    from source-address %s\n", addr)
				}
				for _, pl := range term.SourcePrefixLists {
					if pl.Except {
						fmt.Fprintf(buf, "    from source-prefix-list %s except\n", pl.Name)
					} else {
						fmt.Fprintf(buf, "    from source-prefix-list %s\n", pl.Name)
					}
				}
				for _, addr := range term.DestAddresses {
					fmt.Fprintf(buf, "    from destination-address %s\n", addr)
				}
				for _, pl := range term.DestPrefixLists {
					if pl.Except {
						fmt.Fprintf(buf, "    from destination-prefix-list %s except\n", pl.Name)
					} else {
						fmt.Fprintf(buf, "    from destination-prefix-list %s\n", pl.Name)
					}
				}
				if len(term.SourcePorts) > 0 {
					fmt.Fprintf(buf, "    from source-port %s\n", strings.Join(term.SourcePorts, ", "))
				}
				if len(term.DestinationPorts) > 0 {
					fmt.Fprintf(buf, "    from destination-port %s\n", strings.Join(term.DestinationPorts, ", "))
				}
				for _, t := range term.ICMPTypes {
					fmt.Fprintf(buf, "    from icmp-type %d\n", t)
				}
				for _, c := range term.ICMPCodes {
					fmt.Fprintf(buf, "    from icmp-code %d\n", c)
				}
				if term.RoutingInstance != "" {
					fmt.Fprintf(buf, "    then routing-instance %s\n", term.RoutingInstance)
				}
				if term.ForwardingClass != "" {
					fmt.Fprintf(buf, "    then forwarding-class %s\n", term.ForwardingClass)
				}
				if term.LossPriority != "" {
					fmt.Fprintf(buf, "    then loss-priority %s\n", term.LossPriority)
				}
				if term.Log {
					buf.WriteString("    then log\n")
				}
				if term.Count != "" {
					fmt.Fprintf(buf, "    then count %s\n", term.Count)
				}
				action := term.Action
				if action == "" {
					action = "accept"
				}
				fmt.Fprintf(buf, "    then %s\n", action)
				numRules := firewallFilterTermExpansionCount(cfg, term)
				var totalPkts, totalBytes uint64
				if hasCounters {
					for i := uint32(0); i < numRules; i++ {
						if ctrs, err := s.dp.ReadFilterCounters(ruleOffset + i); err == nil {
							totalPkts += ctrs.Packets
							totalBytes += ctrs.Bytes
						}
					}
					ruleOffset += numRules
				}
				userspaceCounter, userspaceOk := userspaceCounters[dpuserspace.FirewallFilterTermCounterKey{
					Family: family, FilterName: filterName, TermName: term.Name,
				}]
				if userspaceOk {
					totalPkts += userspaceCounter.Packets
					totalBytes += userspaceCounter.Bytes
				}
				if hasCounters || userspaceOk {
					fmt.Fprintf(buf, "    Hit count: %d packets, %d bytes\n", totalPkts, totalBytes)
				}
			}
			buf.WriteString("\n")
		}
	}
	return &pb.ShowTextResponse{Output: buf.String()}, nil
}

// firewallFilterTermExpansionCount returns the rule-expansion count
// for a filter term (moved from server_show.go in #1700).
func firewallFilterTermExpansionCount(cfg *config.Config, term *config.FirewallFilterTerm) uint32 {
	nSrc := len(term.SourceAddresses)
	for _, ref := range term.SourcePrefixLists {
		if !ref.Except {
			if pl, ok := cfg.PolicyOptions.PrefixLists[ref.Name]; ok {
				nSrc += len(pl.Prefixes)
			}
		}
	}
	if nSrc == 0 {
		nSrc = 1
	}
	nDst := len(term.DestAddresses)
	for _, ref := range term.DestPrefixLists {
		if !ref.Except {
			if pl, ok := cfg.PolicyOptions.PrefixLists[ref.Name]; ok {
				nDst += len(pl.Prefixes)
			}
		}
	}
	if nDst == 0 {
		nDst = 1
	}
	nDstPorts := len(term.DestinationPorts)
	if nDstPorts == 0 {
		nDstPorts = 1
	}
	nSrcPorts := len(term.SourcePorts)
	if nSrcPorts == 0 {
		nSrcPorts = 1
	}
	return uint32(nSrc * nDst * nDstPorts * nSrcPorts)
}
