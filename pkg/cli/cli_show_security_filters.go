package cli

import (
	"fmt"
	"sort"
	"strings"

	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

func (c *CLI) showFirewallFilters() error {
	cfg := c.store.ActiveConfig()
	if cfg == nil {
		fmt.Println("No active configuration")
		return nil
	}

	if len(cfg.Firewall.FiltersInet) == 0 && len(cfg.Firewall.FiltersInet6) == 0 {
		fmt.Println("No firewall filters configured")
		return nil
	}

	// Look up filter IDs from compile result for counter display
	var filterIDs map[string]uint32
	if c.dp != nil && c.dp.IsLoaded() {
		if cr := c.applyResult(); cr != nil {
			filterIDs = cr.FilterIDs
		}
	}
	var userspaceStatus *dpuserspace.ProcessStatus
	if status, err := c.userspaceDataplaneStatus(); err == nil {
		userspaceStatus = &status
	}
	userspaceCounters := dpuserspace.BuildFirewallFilterTermCounterIndex(userspaceStatus)

	showFilters := func(family string, filters map[string]*config.FirewallFilter, names []string) {
		for _, name := range names {
			f := filters[name]
			fmt.Printf("Filter: %s (family %s)\n", name, family)

			// Get filter config for counter lookup
			var ruleStart uint32
			var hasCounters bool
			if filterIDs != nil {
				if fid, ok := filterIDs[family+":"+name]; ok {
					if fcfg, err := c.dp.ReadFilterConfig(fid); err == nil {
						ruleStart = fcfg.RuleStart
						hasCounters = true
					}
				}
			}

			ruleOffset := ruleStart
			for _, term := range f.Terms {
				fmt.Printf("  Term: %s\n", term.Name)
				for _, d := range term.DSCPs {
					fmt.Printf("    from dscp %s\n", d)
				}
				for _, p := range term.Protocols {
					fmt.Printf("    from protocol %s\n", p)
				}
				for _, addr := range term.SourceAddresses {
					fmt.Printf("    from source-address %s\n", addr)
				}
				for _, addr := range term.DestAddresses {
					fmt.Printf("    from destination-address %s\n", addr)
				}
				for _, port := range term.DestinationPorts {
					fmt.Printf("    from destination-port %s\n", port)
				}
				for _, port := range term.SourcePorts {
					fmt.Printf("    from source-port %s\n", port)
				}
				for _, ref := range term.SourcePrefixLists {
					mod := ""
					if ref.Except {
						mod = " except"
					}
					fmt.Printf("    from source-prefix-list %s%s\n", ref.Name, mod)
				}
				for _, ref := range term.DestPrefixLists {
					mod := ""
					if ref.Except {
						mod = " except"
					}
					fmt.Printf("    from destination-prefix-list %s%s\n", ref.Name, mod)
				}
				for _, t := range term.ICMPTypes {
					fmt.Printf("    from icmp-type %d\n", t)
				}
				for _, c := range term.ICMPCodes {
					fmt.Printf("    from icmp-code %d\n", c)
				}
				action := term.Action
				if action == "" {
					action = "accept"
				}
				if term.RoutingInstance != "" {
					fmt.Printf("    then routing-instance %s\n", term.RoutingInstance)
				}
				if term.ForwardingClass != "" {
					fmt.Printf("    then forwarding-class %s\n", term.ForwardingClass)
				}
				if term.LossPriority != "" {
					fmt.Printf("    then loss-priority %s\n", term.LossPriority)
				}
				if term.DSCPRewrite != "" {
					fmt.Printf("    then dscp %s\n", term.DSCPRewrite)
				}
				if term.Log {
					fmt.Printf("    then log\n")
				}
				if term.Count != "" {
					fmt.Printf("    then count %s\n", term.Count)
				}
				fmt.Printf("    then %s\n", action)

				// Sum counters across all expanded BPF rules for this term.
				// Must match the cross-product in expandFilterTerm:
				// nSrc * nDst * nDstPorts * nSrcPorts
				numRules := filterTermExpansionCount(cfg, term)
				var totalPkts, totalBytes uint64
				if hasCounters {
					for i := uint32(0); i < numRules; i++ {
						if ctrs, err := c.dp.ReadFilterCounters(ruleOffset + i); err == nil {
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
					fmt.Printf("    Hit count: %d packets, %d bytes\n", totalPkts, totalBytes)
				}
			}
			fmt.Println()
		}
	}

	// Sort filter names for deterministic output (matches compiler order)
	inetNames := make([]string, 0, len(cfg.Firewall.FiltersInet))
	for name := range cfg.Firewall.FiltersInet {
		inetNames = append(inetNames, name)
	}
	sort.Strings(inetNames)

	inet6Names := make([]string, 0, len(cfg.Firewall.FiltersInet6))
	for name := range cfg.Firewall.FiltersInet6 {
		inet6Names = append(inet6Names, name)
	}
	sort.Strings(inet6Names)

	showFilters("inet", cfg.Firewall.FiltersInet, inetNames)
	showFilters("inet6", cfg.Firewall.FiltersInet6, inet6Names)
	return nil
}

func (c *CLI) showFirewallFilter(name, requestedFamily string) error {
	cfg := c.store.ActiveConfig()
	if cfg == nil {
		fmt.Println("No active configuration")
		return nil
	}

	requestedFamily = strings.TrimSpace(requestedFamily)
	if requestedFamily != "" && requestedFamily != "inet" && requestedFamily != "inet6" {
		fmt.Printf("invalid family: %s\n", requestedFamily)
		return nil
	}

	var filter *config.FirewallFilter
	var family string
	switch requestedFamily {
	case "inet":
		filter = cfg.Firewall.FiltersInet[name]
		family = "inet"
	case "inet6":
		filter = cfg.Firewall.FiltersInet6[name]
		family = "inet6"
	default:
		if f, ok := cfg.Firewall.FiltersInet[name]; ok {
			filter = f
			family = "inet"
		} else if f, ok := cfg.Firewall.FiltersInet6[name]; ok {
			filter = f
			family = "inet6"
		}
	}
	if filter == nil {
		if requestedFamily != "" {
			fmt.Printf("Filter not found: %s (family %s)\n", name, requestedFamily)
		} else {
			fmt.Printf("Filter not found: %s\n", name)
		}
		return nil
	}

	// Resolve filter IDs for counter display
	var ruleStart uint32
	var hasCounters bool
	if c.dp != nil && c.dp.IsLoaded() {
		if cr := c.applyResult(); cr != nil {
			if fid, ok := cr.FilterIDs[family+":"+name]; ok {
				if fcfg, err := c.dp.ReadFilterConfig(fid); err == nil {
					ruleStart = fcfg.RuleStart
					hasCounters = true
				}
			}
		}
	}
	var userspaceStatus *dpuserspace.ProcessStatus
	if status, err := c.userspaceDataplaneStatus(); err == nil {
		userspaceStatus = &status
	}
	userspaceCounters := dpuserspace.BuildFirewallFilterTermCounterIndex(userspaceStatus)

	fmt.Printf("Filter: %s (family %s)\n", name, family)

	ruleOffset := ruleStart
	for _, term := range filter.Terms {
		fmt.Printf("\n  Term: %s\n", term.Name)
		for _, d := range term.DSCPs {
			fmt.Printf("    from dscp %s\n", d)
		}
		for _, p := range term.Protocols {
			fmt.Printf("    from protocol %s\n", p)
		}
		for _, addr := range term.SourceAddresses {
			fmt.Printf("    from source-address %s\n", addr)
		}
		for _, ref := range term.SourcePrefixLists {
			mod := ""
			if ref.Except {
				mod = " except"
			}
			fmt.Printf("    from source-prefix-list %s%s\n", ref.Name, mod)
		}
		for _, addr := range term.DestAddresses {
			fmt.Printf("    from destination-address %s\n", addr)
		}
		for _, ref := range term.DestPrefixLists {
			mod := ""
			if ref.Except {
				mod = " except"
			}
			fmt.Printf("    from destination-prefix-list %s%s\n", ref.Name, mod)
		}
		if len(term.SourcePorts) > 0 {
			fmt.Printf("    from source-port %s\n", strings.Join(term.SourcePorts, ", "))
		}
		if len(term.DestinationPorts) > 0 {
			fmt.Printf("    from destination-port %s\n", strings.Join(term.DestinationPorts, ", "))
		}
		for _, t := range term.ICMPTypes {
			fmt.Printf("    from icmp-type %d\n", t)
		}
		for _, c := range term.ICMPCodes {
			fmt.Printf("    from icmp-code %d\n", c)
		}
		if term.RoutingInstance != "" {
			fmt.Printf("    then routing-instance %s\n", term.RoutingInstance)
		}
		if term.ForwardingClass != "" {
			fmt.Printf("    then forwarding-class %s\n", term.ForwardingClass)
		}
		if term.LossPriority != "" {
			fmt.Printf("    then loss-priority %s\n", term.LossPriority)
		}
		if term.DSCPRewrite != "" {
			fmt.Printf("    then dscp %s\n", term.DSCPRewrite)
		}
		if term.Log {
			fmt.Printf("    then log\n")
		}
		if term.Count != "" {
			fmt.Printf("    then count %s\n", term.Count)
		}
		action := term.Action
		if action == "" {
			action = "accept"
		}
		fmt.Printf("    then %s\n", action)

		// Sum counters across all expanded BPF rules for this term
		numRules := filterTermExpansionCount(cfg, term)
		var totalPkts, totalBytes uint64
		if hasCounters {
			for i := uint32(0); i < numRules; i++ {
				if ctrs, err := c.dp.ReadFilterCounters(ruleOffset + i); err == nil {
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
			fmt.Printf("    Hit count: %d packets, %d bytes\n", totalPkts, totalBytes)
		}
	}
	fmt.Println()
	return nil
}

func filterTermExpansionCount(cfg *config.Config, term *config.FirewallFilterTerm) uint32 {
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
