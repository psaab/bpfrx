package cli

import (
	"fmt"
	"sort"
	"strconv"
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

	// #3408: surface a filter counter read failure as a warning AFTER all
	// filters, rather than printing clean-zero / omitted hit counts.
	var readErr error
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
					} else if readErr == nil {
						readErr = err
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
				// Stride comes from the shared SSOT (#3459) so CLI, gRPC, and
				// Prometheus agree with the compiler's expandFilterTerm layout.
				numRules := config.FilterTermExpansionCount(term, cfg.PolicyOptions.PrefixLists)
				var totalPkts, totalBytes uint64
				if hasCounters {
					for i := uint32(0); i < numRules; i++ {
						if ctrs, err := c.dp.ReadFilterCounters(ruleOffset + i); err == nil {
							totalPkts += ctrs.Packets
							totalBytes += ctrs.Bytes
						} else if readErr == nil {
							readErr = err
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
	if readErr != nil {
		fmt.Printf("warning: filter counter read failed (hit counts may be incomplete): %v\n", readErr)
	}
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

	// Resolve filter IDs for counter display. #3408: surface a read failure
	// as a warning AFTER all terms rather than printing clean-zero counts.
	var readErr error
	var ruleStart uint32
	var hasCounters bool
	if c.dp != nil && c.dp.IsLoaded() {
		if cr := c.applyResult(); cr != nil {
			if fid, ok := cr.FilterIDs[family+":"+name]; ok {
				if fcfg, err := c.dp.ReadFilterConfig(fid); err == nil {
					ruleStart = fcfg.RuleStart
					hasCounters = true
				} else if readErr == nil {
					readErr = err
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
		numRules := config.FilterTermExpansionCount(term, cfg.PolicyOptions.PrefixLists)
		var totalPkts, totalBytes uint64
		if hasCounters {
			for i := uint32(0); i < numRules; i++ {
				if ctrs, err := c.dp.ReadFilterCounters(ruleOffset + i); err == nil {
					totalPkts += ctrs.Packets
					totalBytes += ctrs.Bytes
				} else if readErr == nil {
					readErr = err
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
	if readErr != nil {
		fmt.Printf("warning: filter counter read failed (hit counts may be incomplete): %v\n", readErr)
	}
	return nil
}

// showEffectiveFirewallFilters renders the EFFECTIVE (compiled) firewall-filter
// snapshots the userspace dataplane actually receives (#4422). Unlike
// showFirewallFilters (which prints the raw typed config), this rebuilds the
// FirewallFilterSnapshot the config compiler emits and prints the terms exactly
// as the matcher enforces them: prefix-list references resolved to literal
// prefixes, address/port `except` folded (positive-wins on a mixed term), DSCP
// tokens resolved to numeric code points, TCP-flags lowered to required/
// forbidden masks, `then next term` / modifier-only fall-through computed, and
// any unrepresentable match marked fail-closed. It is read-only — it derives the
// snapshot from the active config and never touches the dataplane.
func (c *CLI) showEffectiveFirewallFilters(family string) error {
	cfg := c.store.ActiveConfig()
	if cfg == nil {
		fmt.Println("No active configuration")
		return nil
	}
	family = strings.TrimSpace(family)
	if family != "" && family != "inet" && family != "inet6" {
		fmt.Printf("invalid family: %s\n", family)
		return nil
	}
	snaps := dpuserspace.BuildFirewallFilterSnapshots(cfg)
	rendered := 0
	for i := range snaps {
		if family != "" && snaps[i].Family != family {
			continue
		}
		renderEffectiveFilterSnapshot(&snaps[i])
		rendered++
	}
	if rendered == 0 {
		if family != "" {
			fmt.Printf("No firewall filters configured (family %s)\n", family)
		} else {
			fmt.Println("No firewall filters configured")
		}
	}
	return nil
}

// showEffectiveFirewallFilter renders the effective (compiled) snapshot for a
// single named filter (#4422). Family "" auto-selects whichever family defines
// the name (inet then inet6), matching showFirewallFilter.
func (c *CLI) showEffectiveFirewallFilter(name, family string) error {
	cfg := c.store.ActiveConfig()
	if cfg == nil {
		fmt.Println("No active configuration")
		return nil
	}
	family = strings.TrimSpace(family)
	if family != "" && family != "inet" && family != "inet6" {
		fmt.Printf("invalid family: %s\n", family)
		return nil
	}
	snaps := dpuserspace.BuildFirewallFilterSnapshots(cfg)
	found := false
	for i := range snaps {
		if snaps[i].Name != name {
			continue
		}
		if family != "" && snaps[i].Family != family {
			continue
		}
		renderEffectiveFilterSnapshot(&snaps[i])
		found = true
	}
	if !found {
		if family != "" {
			fmt.Printf("Filter not found: %s (family %s)\n", name, family)
		} else {
			fmt.Printf("Filter not found: %s\n", name)
		}
	}
	return nil
}

// renderEffectiveFilterSnapshot prints one compiled FirewallFilterSnapshot. The
// `[effective]` tag in the heading distinguishes it from the raw
// `show firewall filter` output.
func renderEffectiveFilterSnapshot(snap *dpuserspace.FirewallFilterSnapshot) {
	fmt.Printf("Filter: %s (family %s) [effective]\n", snap.Name, snap.Family)
	if len(snap.Terms) == 0 {
		fmt.Println("  (no terms — matches nothing)")
		fmt.Println()
		return
	}
	for i := range snap.Terms {
		term := &snap.Terms[i]
		fmt.Printf("  Term: %s\n", term.Name)

		// --- from (match conditions, as lowered for the matcher) ---
		if s := effectiveAddrMatchLine("source", term.SourceAddresses, term.SourceExcept, term.SourceConstrained); s != "" {
			fmt.Print(s)
		}
		if s := effectiveAddrMatchLine("destination", term.DestAddresses, term.DestExcept, term.DestConstrained); s != "" {
			fmt.Print(s)
		}
		for _, p := range term.Protocols {
			fmt.Printf("    from protocol %s\n", p)
		}
		if len(term.SourcePorts) > 0 {
			fmt.Printf("    from source-port %s\n", strings.Join(term.SourcePorts, ", "))
		}
		if len(term.SourcePortsExcept) > 0 {
			fmt.Printf("    from source-port-except %s\n", strings.Join(term.SourcePortsExcept, ", "))
		}
		if len(term.DestPorts) > 0 {
			fmt.Printf("    from destination-port %s\n", strings.Join(term.DestPorts, ", "))
		}
		if len(term.DestPortsExcept) > 0 {
			fmt.Printf("    from destination-port-except %s\n", strings.Join(term.DestPortsExcept, ", "))
		}
		if len(term.DSCPValues) > 0 {
			fmt.Printf("    from dscp %s\n", formatWireUint8List(term.DSCPValues))
		}
		if term.DSCPMatchUnrepresentable {
			fmt.Printf("    from dscp <unrepresentable — snapshot fails closed>\n")
		}
		if len(term.ICMPTypes) > 0 {
			fmt.Printf("    from icmp-type %s\n", formatWireUint8List(term.ICMPTypes))
		}
		if term.ICMPTypeUnrepresentable {
			fmt.Printf("    from icmp-type <unrepresentable — snapshot fails closed>\n")
		}
		if len(term.ICMPCodes) > 0 {
			fmt.Printf("    from icmp-code %s\n", formatWireUint8List(term.ICMPCodes))
		}
		if term.ICMPCodeUnrepresentable {
			fmt.Printf("    from icmp-code <unrepresentable — snapshot fails closed>\n")
		}
		if term.TCPFlags != nil {
			fmt.Printf("    from tcp-flags require 0x%02x\n", *term.TCPFlags)
		}
		if term.TCPFlagsForbidden != nil {
			fmt.Printf("    from tcp-flags forbid 0x%02x\n", *term.TCPFlagsForbidden)
		}
		if term.TCPFlagsUnparseable {
			fmt.Printf("    from tcp-flags <unparseable — snapshot fails closed>\n")
		}
		if term.IsFragment {
			fmt.Printf("    from is-fragment\n")
		}
		if fm := term.FlexMatch; fm != nil {
			base := fm.MatchStart
			if base == "" {
				base = "layer-3"
			}
			fmt.Printf("    from flexible-match-range match-start %s offset %d length %d value 0x%x mask 0x%x\n",
				base, fm.Offset, fm.Length, fm.Value, fm.Mask)
		}

		// --- then (action + modifiers) ---
		if term.RoutingInstance != "" {
			fmt.Printf("    then routing-instance %s\n", term.RoutingInstance)
		}
		if term.ForwardingClass != "" {
			fmt.Printf("    then forwarding-class %s\n", term.ForwardingClass)
		}
		if term.PolicerName != "" {
			fmt.Printf("    then policer %s\n", term.PolicerName)
		}
		if term.DSCPRewrite != nil {
			fmt.Printf("    then dscp %d\n", *term.DSCPRewrite)
		}
		if term.Log {
			fmt.Printf("    then log\n")
		}
		if term.Count != "" {
			fmt.Printf("    then count %s\n", term.Count)
		}
		// NextTerm marks a fall-through term (no terminating action); a
		// non-fall-through term terminates with its action (default accept).
		if term.NextTerm {
			fmt.Printf("    then next term (fall-through)\n")
		} else {
			action := term.Action
			if action == "" {
				action = "accept"
			}
			fmt.Printf("    then %s\n", action)
		}
	}
	fmt.Println()
}

// effectiveAddrMatchLine formats one direction's compiled address match. It
// distinguishes the four post-resolution states the matcher enforces
// (resolvePrefixListAddrs / ResolveFilterPrefixListAddrs): unconstrained
// (matches any — emits nothing), a positive set (empty positive = matches
// nothing, fail-closed), an `except` set (empty except = matches any), and the
// populated forms.
func effectiveAddrMatchLine(dir string, addrs []string, except, constrained bool) string {
	if !constrained {
		return ""
	}
	switch {
	case except && len(addrs) == 0:
		return fmt.Sprintf("    from %s-address except (empty set — matches any)\n", dir)
	case except:
		return fmt.Sprintf("    from %s-address except %s\n", dir, strings.Join(addrs, ", "))
	case len(addrs) == 0:
		return fmt.Sprintf("    from %s-address (empty set — matches nothing)\n", dir)
	default:
		return fmt.Sprintf("    from %s-address %s\n", dir, strings.Join(addrs, ", "))
	}
}

// formatWireUint8List renders a compiled uint8 match set (DSCP code points,
// ICMP type/code bytes) as comma-separated decimals.
func formatWireUint8List(vals dpuserspace.WireUint8List) string {
	parts := make([]string, len(vals))
	for i, v := range vals {
		parts[i] = strconv.Itoa(int(v))
	}
	return strings.Join(parts, ", ")
}
