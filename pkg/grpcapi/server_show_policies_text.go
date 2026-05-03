// Phase 10 of #1043: extract the three policy-related ShowText case
// bodies (`policies-hit-count`, `policies-detail`, `policy-options`)
// into dedicated methods. Same methodology as Phases 1-9: semantic
// relocation, no behavior change. Each case body is moved verbatim
// apart from `&buf` references becoming `buf` (passed-in
// `*strings.Builder`) and `break`/early-`else` patterns flattened
// into early-return form.
//
// `showPoliciesHitCount` and `showPoliciesDetail` take a `filter`
// string parameter (originally `req.Filter`) so the bodies no longer
// reference the gRPC request struct directly.

package grpcapi

import (
	"fmt"
	"strings"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

// showPoliciesHitCount renders the per-policy packet/byte hit counters
// with a fixed-width tabular format. `filter` is parsed for
// `from-zone X to-zone Y` selectors.
func (s *Server) showPoliciesHitCount(filter string, buf *strings.Builder) {
	cfg := s.store.ActiveConfig()
	if cfg == nil {
		fmt.Fprintln(buf, "No active configuration")
		return
	}
	// Parse optional zone filter from filter: "from-zone X to-zone Y"
	var filterFrom, filterTo string
	if filter != "" {
		parts := strings.Fields(filter)
		for i := 0; i+1 < len(parts); i++ {
			switch parts[i] {
			case "from-zone":
				filterFrom = parts[i+1]
				i++
			case "to-zone":
				filterTo = parts[i+1]
				i++
			}
		}
	}
	fmt.Fprintf(buf, "%-12s %-12s %-24s %-8s %12s %16s\n",
		"From zone", "To zone", "Policy", "Action", "Packets", "Bytes")
	fmt.Fprintln(buf, strings.Repeat("-", 88))
	policySetID := uint32(0)
	var totalPkts, totalBytes uint64
	for _, zpp := range cfg.Security.Policies {
		if (filterFrom != "" && zpp.FromZone != filterFrom) ||
			(filterTo != "" && zpp.ToZone != filterTo) {
			policySetID++
			continue
		}
		for i, pol := range zpp.Policies {
			action := "permit"
			switch pol.Action {
			case 1:
				action = "deny"
			case 2:
				action = "reject"
			}
			ruleID := policySetID*dataplane.MaxRulesPerPolicy + uint32(i)
			var pkts, bytes uint64
			if s.dp != nil && s.dp.IsLoaded() {
				if counters, err := s.dp.ReadPolicyCounters(ruleID); err == nil {
					pkts = counters.Packets
					bytes = counters.Bytes
				}
			}
			totalPkts += pkts
			totalBytes += bytes
			fmt.Fprintf(buf, "%-12s %-12s %-24s %-8s %12d %16d\n",
				zpp.FromZone, zpp.ToZone, pol.Name, action, pkts, bytes)
		}
		policySetID++
	}
	fmt.Fprintln(buf, strings.Repeat("-", 88))
	fmt.Fprintf(buf, "%-48s %8s %12d %16d\n", "Total", "", totalPkts, totalBytes)
}

// showPoliciesDetail renders per-policy detail (match conditions,
// then-actions, session statistics) plus the global-policies block.
// `filter` is parsed for `from-zone X to-zone Y` selectors.
func (s *Server) showPoliciesDetail(filter string, buf *strings.Builder) {
	cfg := s.store.ActiveConfig()
	if cfg == nil {
		fmt.Fprintln(buf, "No active configuration")
		return
	}
	var filterFrom, filterTo string
	if filter != "" {
		parts := strings.Fields(filter)
		for i := 0; i+1 < len(parts); i++ {
			switch parts[i] {
			case "from-zone":
				filterFrom = parts[i+1]
				i++
			case "to-zone":
				filterTo = parts[i+1]
				i++
			}
		}
	}
	policySetID := uint32(0)
	for _, zpp := range cfg.Security.Policies {
		if (filterFrom != "" && zpp.FromZone != filterFrom) ||
			(filterTo != "" && zpp.ToZone != filterTo) {
			policySetID++
			continue
		}
		fmt.Fprintf(buf, "Policy: %s -> %s, State: enabled\n", zpp.FromZone, zpp.ToZone)
		for i, pol := range zpp.Policies {
			action := "permit"
			switch pol.Action {
			case 1:
				action = "deny"
			case 2:
				action = "reject"
			}
			capAction := strings.ToUpper(action[:1]) + action[1:]
			ruleID := policySetID*dataplane.MaxRulesPerPolicy + uint32(i)
			fmt.Fprintf(buf, "\n  Policy: %s, action-type: %s\n", pol.Name, capAction)
			if pol.Description != "" {
				fmt.Fprintf(buf, "    Description: %s\n", pol.Description)
			}
			fmt.Fprintf(buf, "    Match:\n")
			fmt.Fprintf(buf, "      Source zone: %s\n", zpp.FromZone)
			fmt.Fprintf(buf, "      Destination zone: %s\n", zpp.ToZone)
			fmt.Fprintf(buf, "      Source addresses:\n")
			for _, addr := range pol.Match.SourceAddresses {
				resolved := grpcResolveAddress(cfg, addr)
				fmt.Fprintf(buf, "        %s%s\n", addr, resolved)
			}
			fmt.Fprintf(buf, "      Destination addresses:\n")
			for _, addr := range pol.Match.DestinationAddresses {
				resolved := grpcResolveAddress(cfg, addr)
				fmt.Fprintf(buf, "        %s%s\n", addr, resolved)
			}
			fmt.Fprintf(buf, "      Applications:\n")
			for _, app := range pol.Match.Applications {
				fmt.Fprintf(buf, "        %s\n", app)
			}
			fmt.Fprintf(buf, "    Then:\n")
			fmt.Fprintf(buf, "      %s\n", action)
			if pol.Log != nil {
				fmt.Fprintf(buf, "      log\n")
			}
			if pol.Count {
				fmt.Fprintf(buf, "      count\n")
			}
			if s.dp != nil && s.dp.IsLoaded() {
				if counters, err := s.dp.ReadPolicyCounters(ruleID); err == nil {
					fmt.Fprintf(buf, "    Session statistics:\n")
					fmt.Fprintf(buf, "      %d packets, %d bytes\n", counters.Packets, counters.Bytes)
				}
			}
		}
		policySetID++
		fmt.Fprintln(buf)
	}
	// Global policies
	if len(cfg.Security.GlobalPolicies) > 0 && filterFrom == "" && filterTo == "" {
		fmt.Fprintf(buf, "Global policies:\n")
		for i, pol := range cfg.Security.GlobalPolicies {
			action := "permit"
			switch pol.Action {
			case 1:
				action = "deny"
			case 2:
				action = "reject"
			}
			capAction := strings.ToUpper(action[:1]) + action[1:]
			ruleID := policySetID*dataplane.MaxRulesPerPolicy + uint32(i)
			fmt.Fprintf(buf, "\n  Policy: %s, action-type: %s\n", pol.Name, capAction)
			if pol.Description != "" {
				fmt.Fprintf(buf, "    Description: %s\n", pol.Description)
			}
			fmt.Fprintf(buf, "    Match:\n")
			fmt.Fprintf(buf, "      Source addresses:\n")
			for _, addr := range pol.Match.SourceAddresses {
				resolved := grpcResolveAddress(cfg, addr)
				fmt.Fprintf(buf, "        %s%s\n", addr, resolved)
			}
			fmt.Fprintf(buf, "      Destination addresses:\n")
			for _, addr := range pol.Match.DestinationAddresses {
				resolved := grpcResolveAddress(cfg, addr)
				fmt.Fprintf(buf, "        %s%s\n", addr, resolved)
			}
			fmt.Fprintf(buf, "      Applications:\n")
			for _, app := range pol.Match.Applications {
				fmt.Fprintf(buf, "        %s\n", app)
			}
			fmt.Fprintf(buf, "    Then:\n")
			fmt.Fprintf(buf, "      %s\n", action)
			if pol.Log != nil {
				fmt.Fprintf(buf, "      log\n")
			}
			if pol.Count {
				fmt.Fprintf(buf, "      count\n")
			}
			if s.dp != nil && s.dp.IsLoaded() {
				if counters, err := s.dp.ReadPolicyCounters(ruleID); err == nil {
					fmt.Fprintf(buf, "    Session statistics:\n")
					fmt.Fprintf(buf, "      %d packets, %d bytes\n", counters.Packets, counters.Bytes)
				}
			}
		}
		fmt.Fprintln(buf)
	}
}

// showPolicyOptions renders prefix-lists and policy-statement terms
// from `policy-options { ... }` configuration.
func (s *Server) showPolicyOptions(cfg *config.Config, buf *strings.Builder) {
	if cfg == nil {
		buf.WriteString("No active configuration\n")
		return
	}
	po := &cfg.PolicyOptions
	if len(po.PrefixLists) > 0 {
		buf.WriteString("Prefix lists:\n")
		for name, pl := range po.PrefixLists {
			fmt.Fprintf(buf, "  %-30s %d prefixes\n", name, len(pl.Prefixes))
			for _, p := range pl.Prefixes {
				fmt.Fprintf(buf, "    %s\n", p)
			}
		}
	}
	if len(po.PolicyStatements) > 0 {
		if len(po.PrefixLists) > 0 {
			buf.WriteString("\n")
		}
		buf.WriteString("Policy statements:\n")
		for name, ps := range po.PolicyStatements {
			fmt.Fprintf(buf, "  %s", name)
			if ps.DefaultAction != "" {
				fmt.Fprintf(buf, " (default: %s)", ps.DefaultAction)
			}
			buf.WriteString("\n")
			for _, t := range ps.Terms {
				fmt.Fprintf(buf, "    term %s:\n", t.Name)
				if t.FromProtocol != "" {
					fmt.Fprintf(buf, "      from protocol %s\n", t.FromProtocol)
				}
				if t.PrefixList != "" {
					fmt.Fprintf(buf, "      from prefix-list %s\n", t.PrefixList)
				}
				for _, rf := range t.RouteFilters {
					match := rf.MatchType
					if rf.MatchType == "upto" && rf.UptoLen > 0 {
						match = fmt.Sprintf("upto /%d", rf.UptoLen)
					}
					fmt.Fprintf(buf, "      from route-filter %s %s\n", rf.Prefix, match)
				}
				if t.Action != "" {
					fmt.Fprintf(buf, "      then %s\n", t.Action)
				}
				if t.NextHop != "" {
					fmt.Fprintf(buf, "      then next-hop %s\n", t.NextHop)
				}
				if t.LoadBalance != "" {
					fmt.Fprintf(buf, "      then load-balance %s\n", t.LoadBalance)
				}
			}
		}
	}
	if len(po.PrefixLists) == 0 && len(po.PolicyStatements) == 0 {
		buf.WriteString("No policy-options configured\n")
	}
}
