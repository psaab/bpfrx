package cli

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/nat"
	"github.com/psaab/xpf/pkg/natshow"
)

// warnSessionScan prints a single operator warning to stderr when a
// session enumeration used for a NAT/summary count was truncated by a
// backend iterator error (e.g. a helper restart mid-scan). Without this
// the CLI would print an under-count as if it were the full table —
// the #2469 partial-as-success defect. nil errors are no-ops.
func warnSessionScan(errs ...error) {
	for _, err := range errs {
		if err != nil {
			fmt.Fprintf(os.Stderr,
				"warning: session enumeration incomplete (counts below may be understated): %v\n",
				err)
			return
		}
	}
}

// handleShowNAT dispatches `show security nat ...` subcommands to the
// per-NAT-mode presenters below.
func (c *CLI) handleShowNAT(args []string) error {
	cfg := c.store.ActiveConfig()

	if len(args) == 0 {
		fmt.Println("show security nat:")
		writeCompletionHelp(os.Stdout, treeHelpCandidates(operationalTree["show"].Children["security"].Children["nat"].Children))
		return nil
	}

	switch args[0] {
	case "source":
		if len(args) >= 2 && args[1] == "persistent-nat-table" {
			if len(args) >= 3 && args[2] == "detail" {
				return c.showPersistentNATDetail()
			}
			return c.showPersistentNAT()
		}
		return c.showNATSource(cfg, args[1:])
	case "destination":
		return c.showNATDestination(cfg, args[1:])
	case "static":
		return c.showNATStatic(cfg, args[1:])
	case "nat64":
		return c.showNAT64(cfg)
	case "nptv6":
		return c.showNPTv6(cfg)
	default:
		return fmt.Errorf("unknown show security nat target: %s", args[0])
	}
}

func (c *CLI) showNATSource(cfg *config.Config, args []string) error {
	// Sub-command dispatch: summary, pool <name>, rule-set <name>, rule all
	if len(args) > 0 {
		switch args[0] {
		case "summary":
			return c.showNATSourceSummary(cfg)
		case "pool":
			poolName := ""
			if len(args) > 1 {
				poolName = args[1]
			}
			return c.showNATSourcePool(cfg, poolName)
		case "rule":
			if len(args) > 1 && args[1] == "detail" {
				return c.showNATSourceRuleDetail(cfg)
			}
			return c.showNATSourceRuleAll(cfg)
		case "rule-set":
			if len(args) > 1 {
				return c.showNATSourceRuleSet(cfg, args[1])
			}
			return fmt.Errorf("usage: show security nat source rule-set <name>")
		case "deterministic-nat":
			return c.showNATDeterministic(args[1:])
		}
	}

	// Default: show all pools, rules, and summary
	if cfg != nil && cfg.Security.NAT.AddressPersistent {
		fmt.Println("Address-persistent: enabled")
		fmt.Println()
	}
	// Show configured source NAT pools
	if cfg != nil && len(cfg.Security.NAT.SourcePools) > 0 {
		fmt.Println("Source NAT pools:")
		for name, pool := range cfg.Security.NAT.SourcePools {
			fmt.Printf("  Pool: %s\n", name)
			for _, addr := range pool.Addresses {
				fmt.Printf("    Address: %s\n", addr)
			}
			portLow, portHigh := pool.PortLow, pool.PortHigh
			if portLow == 0 {
				portLow = 1024
			}
			if portHigh == 0 {
				portHigh = 65535
			}
			fmt.Printf("    Port range: %d-%d\n", portLow, portHigh)
		}
		fmt.Println()
	}

	// Show configured source NAT rules
	if cfg != nil {
		for _, rs := range cfg.Security.NAT.Source {
			fmt.Printf("Source NAT rule-set: %s\n", rs.Name)
			fmt.Printf("  From zone: %s, To zone: %s\n", rs.FromZone, rs.ToZone)
			for _, rule := range rs.Rules {
				action := "interface"
				if rule.Then.PoolName != "" {
					action = "pool " + rule.Then.PoolName
				}
				fmt.Printf("  Rule: %s -> %s\n", rule.Name, action)
				if rule.Match.SourceAddress != "" {
					fmt.Printf("    Match source-address: %s\n", rule.Match.SourceAddress)
				}
			}
			fmt.Println()
		}
	}

	// Show summary of active SNAT sessions
	if c.dp == nil || !c.dp.IsLoaded() {
		return nil
	}

	snatCount := 0
	errV4 := c.dp.IterateSessions(func(key dataplane.SessionKey, val dataplane.SessionValue) bool {
		if val.IsReverse != 0 {
			return true
		}
		if val.Flags&dataplane.SessFlagSNAT != 0 {
			snatCount++
		}
		return true
	})
	errV6 := c.dp.IterateSessionsV6(func(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
		if val.IsReverse != 0 {
			return true
		}
		if val.Flags&dataplane.SessFlagSNAT != 0 {
			snatCount++
		}
		return true
	})
	// A truncated scan (e.g. helper restart) under-counts; warn so the
	// operator does not read the count as authoritative (#2469).
	warnSessionScan(errV4, errV6)
	fmt.Printf("Active SNAT sessions: %d\n", snatCount)

	// Show NAT alloc fail counter. #3345: emit an explicit warning on a read
	// failure rather than silently omitting the line — a degraded counter
	// bridge must be distinguishable from "zero allocation failures".
	if allocFails, err := c.dp.ReadGlobalCounter(dataplane.GlobalCtrNATAllocFail); err == nil {
		fmt.Printf("NAT allocation failures: %d\n", allocFails)
	} else {
		fmt.Printf("warning: NAT allocation-failure counter read failed (counter unavailable): %v\n", err)
	}

	return nil
}

// showNATSourceSummary displays a Junos-style summary of all source NAT pools.

func (c *CLI) showNATSourceSummary(cfg *config.Config) error {
	if cfg == nil {
		fmt.Println("No source NAT configured")
		return nil
	}

	// Count pools: named pools + interface-mode rules
	type ruleSetKey struct{ from, to string }
	type poolInfo struct {
		name    string
		address string
		total   int // total ports (0 = N/A for interface)
		used    int
		isIface bool
		key     ruleSetKey
	}
	var pools []poolInfo

	// Named pools
	// #7000: capacity comes from the compiler's verdict, not from a per-consumer
	// re-derivation. `len(pool.Addresses)` reported capacity for a REFUSED pool,
	// under-reported every prefix member, and missed the singular `address`
	// field entirely.
	overBudget := config.SourceNATAggregateOverBudgetPools(cfg)
	for name, pool := range cfg.Security.NAT.SourcePools {
		portLow, portHigh := pool.PortLow, pool.PortHigh
		if portLow == 0 {
			portLow = 1024
		}
		if portHigh == 0 {
			portHigh = 65535
		}
		ports, _ := config.SourceNATPoolReportablePorts(pool, name, portLow, portHigh, overBudget)
		totalPorts := int(ports)
		addr := strings.Join(pool.Addresses, ",")
		pools = append(pools, poolInfo{name: name, address: addr, total: totalPorts})
	}

	// Interface-mode pools (count from rules, deduplicated by zone pair).
	ifacePoolSeen := make(map[ruleSetKey]struct{})
	for _, rs := range cfg.Security.NAT.Source {
		key := ruleSetKey{from: rs.FromZone, to: rs.ToZone}
		for _, rule := range rs.Rules {
			if rule.Then.Interface {
				if _, exists := ifacePoolSeen[key]; exists {
					continue
				}
				ifacePoolSeen[key] = struct{}{}
				pools = append(pools, poolInfo{
					name:    fmt.Sprintf("%s/%s (interface)", rs.FromZone, rs.ToZone),
					address: "interface",
					isIface: true,
					key:     key,
				})
			}
		}
	}

	// Count active SNAT translations and per-rule-set sessions
	totalSNAT := 0
	rsSessions := make(map[ruleSetKey]int)
	if c.dp != nil && c.dp.IsLoaded() {
		cr := c.applyResult()
		// Build reverse zone ID map
		var zoneByID map[uint16]string
		if cr != nil {
			zoneByID = make(map[uint16]string, len(cr.ZoneIDs))
			for name, id := range cr.ZoneIDs {
				zoneByID[id] = name
			}
			for i := range pools {
				if pools[i].isIface {
					continue
				}
				if id, ok := cr.PoolIDs[pools[i].name]; ok {
					cnt, err := c.dp.ReadNATPortCounter(uint32(id))
					if err == nil {
						pools[i].used = int(cnt)
					}
				}
			}
		}
		// Count SNAT sessions per zone pair
		errV4 := c.dp.IterateSessions(func(_ dataplane.SessionKey, val dataplane.SessionValue) bool {
			if val.IsReverse == 0 && val.Flags&dataplane.SessFlagSNAT != 0 {
				totalSNAT++
				if zoneByID != nil {
					rsSessions[ruleSetKey{zoneByID[val.IngressZone], zoneByID[val.EgressZone]}]++
				}
			}
			return true
		})
		// Count IPv6 SNAT sessions
		errV6 := c.dp.IterateSessionsV6(func(_ dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
			if val.IsReverse == 0 && val.Flags&dataplane.SessFlagSNAT != 0 {
				totalSNAT++
				if zoneByID != nil {
					rsSessions[ruleSetKey{zoneByID[val.IngressZone], zoneByID[val.EgressZone]}]++
				}
			}
			return true
		})
		// A truncated scan under-counts the per-pool/zone-pair session
		// figures below; warn so they are not read as authoritative (#2469).
		warnSessionScan(errV4, errV6)
		for i := range pools {
			if pools[i].isIface {
				pools[i].used = rsSessions[pools[i].key]
			}
		}
	}

	fmt.Printf("Total active translations: %d\n", totalSNAT)
	fmt.Printf("Total pools: %d\n", len(pools))
	fmt.Println()
	fmt.Printf("%-20s %-20s %-8s %-8s %-12s %-12s\n",
		"Pool", "Address", "Ports", "Used", "Available", "Utilization")
	for _, p := range pools {
		// #7473: the Ports/Available columns below describe a pool the builder
		// may have refused, where the numbers are configuration rather than
		// live capacity.
		poolDisarm := ""
		if pl, ok := cfg.Security.NAT.SourcePools[p.name]; ok {
			poolDisarm = sourceNATPoolNotInstalled(pl)
		}
		ports := "N/A"
		avail := "N/A"
		util := "N/A"
		if p.total > 0 {
			ports = fmt.Sprintf("%d", p.total)
			a := p.total - p.used
			if a < 0 {
				a = 0
			}
			avail = fmt.Sprintf("%d", a)
			util = fmt.Sprintf("%.1f%%", float64(p.used)/float64(p.total)*100)
		}
		fmt.Printf("%-20s %-20s %-8s %-8d %-12s %-12s\n",
			p.name, p.address, ports, p.used, avail, util)
		if poolDisarm != "" {
			fmt.Println(natNotInstalledLine(poolDisarm, true))
		}
	}

	// Per-rule-set session counts
	if len(rsSessions) > 0 {
		fmt.Println()
		fmt.Printf("%-30s %-12s\n", "Rule-set (from -> to)", "Sessions")
		for _, rs := range cfg.Security.NAT.Source {
			key := ruleSetKey{rs.FromZone, rs.ToZone}
			if cnt, ok := rsSessions[key]; ok {
				fmt.Printf("%-30s %-12d\n",
					fmt.Sprintf("%s -> %s", rs.FromZone, rs.ToZone), cnt)
			}
		}
	}
	return nil
}

// showNATSourcePool displays detailed information about a specific NAT pool.

func (c *CLI) showNATSourcePool(cfg *config.Config, poolName string) error {
	if cfg == nil {
		fmt.Println("No source NAT configured")
		return nil
	}

	// If poolName is empty or "all", show all pools
	showAll := poolName == "" || poolName == "all"
	var cr *dataplane.ApplyResult
	if c.dp != nil && c.dp.IsLoaded() {
		cr = c.applyResult()
	}

	detailOverBudget := config.SourceNATAggregateOverBudgetPools(cfg)
	for name, pool := range cfg.Security.NAT.SourcePools {
		if !showAll && name != poolName {
			continue
		}

		portLow, portHigh := pool.PortLow, pool.PortHigh
		if portLow == 0 {
			portLow = 1024
		}
		if portHigh == 0 {
			portHigh = 65535
		}
		// #7000: see the summary view above.
		ports, unusable := config.SourceNATPoolReportablePorts(pool, name, portLow, portHigh, detailOverBudget)
		totalPorts := int(ports)

		fmt.Printf("Pool name: %s\n", name)
		for _, addr := range pool.Addresses {
			fmt.Printf("  Address: %s\n", addr)
		}
		fmt.Printf("  Port range: %d-%d\n", portLow, portHigh)
		// #7000: a capacity of 0 is ambiguous on its own — no members, a
		// malformed member, or the #6812 aggregate budget all produce it, and
		// they have different remedies. The detail view has room to say which,
		// so it does; the operator is not left inferring it from a bare 0.
		if unusable != "" {
			fmt.Printf("  Unusable: %s\n", config.SourceNATDisarmReasonText(unusable))
		}

		if cr != nil {
			if id, ok := cr.PoolIDs[name]; ok {
				cnt, err := c.dp.ReadNATPortCounter(uint32(id))
				if err == nil {
					avail := totalPorts - int(cnt)
					if avail < 0 {
						avail = 0
					}
					fmt.Printf("  Ports allocated: %d\n", cnt)
					fmt.Printf("  Ports available: %d\n", avail)
					if totalPorts > 0 {
						fmt.Printf("  Utilization: %.1f%%\n",
							float64(cnt)/float64(totalPorts)*100)
					}
				}
			}
		}
		fmt.Println()
	}

	if !showAll {
		if _, ok := cfg.Security.NAT.SourcePools[poolName]; !ok {
			fmt.Printf("Pool %q not found\n", poolName)
		}
	}
	return nil
}

// showNATSourceRuleSet displays a specific source NAT rule-set with hit counters.

func (c *CLI) showNATSourceRuleSet(cfg *config.Config, rsName string) error {
	if cfg == nil {
		fmt.Println("No source NAT configured")
		return nil
	}

	cr := c.applyResult()
	for _, rs := range cfg.Security.NAT.Source {
		if rs.Name != rsName {
			continue
		}
		fmt.Printf("Rule-set: %s\n", rs.Name)
		fmt.Printf("  From zone: %s  To zone: %s\n", rs.FromZone, rs.ToZone)
		for _, rule := range rs.Rules {
			action := "interface"
			if rule.Then.PoolName != "" {
				action = "pool " + rule.Then.PoolName
			}
			fmt.Printf("  Rule: %s\n", rule.Name)
			srcMatch := "0.0.0.0/0"
			if rule.Match.SourceAddress != "" {
				srcMatch = rule.Match.SourceAddress
			}
			dstMatch := "0.0.0.0/0"
			if rule.Match.DestinationAddress != "" {
				dstMatch = rule.Match.DestinationAddress
			}
			fmt.Printf("    Match: source %s destination %s\n", srcMatch, dstMatch)
			// #7473
			if line := natNotInstalledLine(sourceNATRuleNotInstalled(cfg, rule), true); line != "" {
				fmt.Println("  " + line)
			}
			fmt.Printf("    Action: %s\n", action)

			// Show hit counters if dataplane is loaded
			if c.dp != nil && cr != nil {
				ruleKey := dataplane.NATCounterKey(dataplane.NATCounterTypeSource, rs.Name, rule.Name)
				if cid, ok := cr.NATCounterIDs[ruleKey]; ok {
					cnt, err := c.dp.ReadNATRuleCounter(uint32(cid))
					if err == nil {
						fmt.Printf("    Translation hits: %d packets  %d bytes\n",
							cnt.Packets, cnt.Bytes)
					}
				}
			}
		}
		fmt.Println()
		return nil
	}
	fmt.Printf("Rule-set %q not found\n", rsName)
	return nil
}

// showNATSourceRuleAll displays all source NAT rules across all rule-sets with hit counters.

func (c *CLI) showNATSourceRuleAll(cfg *config.Config) error {
	if cfg == nil || len(cfg.Security.NAT.Source) == 0 {
		fmt.Println("No source NAT rules configured")
		return nil
	}

	cr := c.applyResult()
	totalRules := 0
	for _, rs := range cfg.Security.NAT.Source {
		for _, rule := range rs.Rules {
			totalRules++
			action := "interface"
			if rule.Then.PoolName != "" {
				action = "pool " + rule.Then.PoolName
			}
			srcMatch := "0.0.0.0/0"
			if rule.Match.SourceAddress != "" {
				srcMatch = rule.Match.SourceAddress
			}
			dstMatch := "0.0.0.0/0"
			if rule.Match.DestinationAddress != "" {
				dstMatch = rule.Match.DestinationAddress
			}

			fmt.Printf("Rule-set: %-20s Rule: %-12s %s -> %s  Action: %s\n",
				rs.Name, rule.Name, rs.FromZone, rs.ToZone, action)
			fmt.Printf("  Match: source %s destination %s\n", srcMatch, dstMatch)
			// #7473: without this the translation-hit 0 printed below reads as
			// "no traffic matched" for a rule the builder never installed.
			if line := natNotInstalledLine(sourceNATRuleNotInstalled(cfg, rule), true); line != "" {
				fmt.Println(line)
			}

			if c.dp != nil && cr != nil {
				ruleKey := dataplane.NATCounterKey(dataplane.NATCounterTypeSource, rs.Name, rule.Name)
				if cid, ok := cr.NATCounterIDs[ruleKey]; ok {
					cnt, err := c.dp.ReadNATRuleCounter(uint32(cid))
					if err == nil {
						fmt.Printf("  Translation hits: %d packets  %d bytes\n",
							cnt.Packets, cnt.Bytes)
					}
				}
			}
		}
	}
	fmt.Printf("\nTotal source NAT rules: %d\n", totalRules)
	return nil
}

// showNATSourceRuleDetail displays Junos-style detailed source NAT rules.

func (c *CLI) showNATSourceRuleDetail(cfg *config.Config) error {
	// #1687: shared with the gRPC ShowText path via pkg/natshow.
	natshow.RenderSourceRuleDetail(os.Stdout, cfg, c.dp, c.applyResult)
	return nil
}

func (c *CLI) showNATDestination(cfg *config.Config, args []string) error {
	if cfg == nil || cfg.Security.NAT.Destination == nil {
		fmt.Println("No destination NAT rules configured.")
		return nil
	}

	// Sub-command dispatch: summary, pool <name>, rule-set <name>, rule all
	if len(args) > 0 {
		switch args[0] {
		case "summary":
			return c.showNATDestinationSummary(cfg)
		case "pool":
			poolName := ""
			if len(args) > 1 {
				poolName = args[1]
			}
			return c.showNATDestinationPool(cfg, poolName)
		case "rule":
			if len(args) > 1 && args[1] == "detail" {
				return c.showNATDestinationRuleDetail(cfg)
			}
			return c.showNATDestinationRuleAll(cfg)
		case "rule-set":
			if len(args) > 1 {
				return c.showNATDestinationRuleSet(cfg, args[1])
			}
			return fmt.Errorf("usage: show security nat destination rule-set <name>")
		}
	}

	dnat := cfg.Security.NAT.Destination
	cr := c.applyResult()

	// Show destination NAT pools
	if len(dnat.Pools) > 0 {
		fmt.Println("Destination NAT pools:")
		for name, pool := range dnat.Pools {
			fmt.Printf("  Pool: %s\n", name)
			fmt.Printf("    Address: %s\n", pool.Address)
			if pool.Port != 0 {
				fmt.Printf("    Port: %d\n", pool.Port)
			}
		}
		fmt.Println()
	}

	// Show destination NAT rule sets
	for _, rs := range dnat.RuleSets {
		fmt.Printf("Destination NAT rule-set: %s\n", rs.Name)
		fmt.Printf("  From zone: %s, To zone: %s\n", rs.FromZone, rs.ToZone)
		for _, rule := range rs.Rules {
			fmt.Printf("  Rule: %s\n", rule.Name)
			// #7473: annotate before the match/pool lines, so the operator sees
			// the rule is not armed before reading what it claims to translate.
			if line := natNotInstalledLine(destNATRuleNotInstalled(cfg, rule), false); line != "" {
				fmt.Println("  " + line)
			}
			if rule.Match.DestinationAddress != "" {
				fmt.Printf("    Match destination-address: %s\n", rule.Match.DestinationAddress)
			}
			if rule.Match.DestinationPort != 0 {
				fmt.Printf("    Match destination-port: %d\n", rule.Match.DestinationPort)
			}
			if rule.Then.PoolName != "" {
				fmt.Printf("    Then pool: %s\n", rule.Then.PoolName)
			}

			// Show hit counters if dataplane is loaded
			if c.dp != nil && cr != nil {
				ruleKey := dataplane.NATCounterKey(dataplane.NATCounterTypeDest, rs.Name, rule.Name)
				if cid, ok := cr.NATCounterIDs[ruleKey]; ok {
					cnt, err := c.dp.ReadNATRuleCounter(uint32(cid))
					if err == nil {
						fmt.Printf("    Translation hits: %d packets  %d bytes\n",
							cnt.Packets, cnt.Bytes)
					}
				}
			}
		}
		fmt.Println()
	}

	// Show summary of active DNAT sessions
	if c.dp != nil && c.dp.IsLoaded() {
		dnatCount := 0
		errV4 := c.dp.IterateSessions(func(key dataplane.SessionKey, val dataplane.SessionValue) bool {
			if val.IsReverse != 0 {
				return true
			}
			if val.Flags&dataplane.SessFlagDNAT != 0 {
				dnatCount++
			}
			return true
		})
		errV6 := c.dp.IterateSessionsV6(func(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
			if val.IsReverse != 0 {
				return true
			}
			if val.Flags&dataplane.SessFlagDNAT != 0 {
				dnatCount++
			}
			return true
		})
		warnSessionScan(errV4, errV6)
		fmt.Printf("Active DNAT sessions: %d\n", dnatCount)
	}

	return nil
}

// showNATDestinationSummary displays a summary of all destination NAT pools.

func (c *CLI) showNATDestinationSummary(cfg *config.Config) error {
	dnat := cfg.Security.NAT.Destination
	if dnat == nil || len(dnat.Pools) == 0 {
		fmt.Println("No destination NAT pools configured")
		return nil
	}

	// Count active DNAT sessions per pool and per rule-set
	poolHits := make(map[string]int)
	totalDNAT := 0
	type ruleSetKey struct{ from, to string }
	rsSessions := make(map[ruleSetKey]int)

	var cr *dataplane.ApplyResult
	if c.dp != nil && c.dp.IsLoaded() {
		cr = c.applyResult()
	}
	if cr != nil {
		for _, rs := range dnat.RuleSets {
			for _, rule := range rs.Rules {
				if rule.Then.PoolName == "" {
					continue
				}
				ruleKey := dataplane.NATCounterKey(dataplane.NATCounterTypeDest, rs.Name, rule.Name)
				if cid, ok := cr.NATCounterIDs[ruleKey]; ok {
					cnt, err := c.dp.ReadNATRuleCounter(uint32(cid))
					if err == nil {
						poolHits[rule.Then.PoolName] += int(cnt.Packets)
					}
				}
			}
		}

		// Count active DNAT sessions by iterating sessions
		zoneByID := make(map[uint16]string, len(cr.ZoneIDs))
		for name, id := range cr.ZoneIDs {
			zoneByID[id] = name
		}
		errV4 := c.dp.IterateSessions(func(_ dataplane.SessionKey, val dataplane.SessionValue) bool {
			if val.IsReverse == 0 && val.Flags&dataplane.SessFlagDNAT != 0 {
				totalDNAT++
				rsSessions[ruleSetKey{zoneByID[val.IngressZone], zoneByID[val.EgressZone]}]++
			}
			return true
		})
		errV6 := c.dp.IterateSessionsV6(func(_ dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
			if val.IsReverse == 0 && val.Flags&dataplane.SessFlagDNAT != 0 {
				totalDNAT++
				rsSessions[ruleSetKey{zoneByID[val.IngressZone], zoneByID[val.EgressZone]}]++
			}
			return true
		})
		warnSessionScan(errV4, errV6)
	}

	fmt.Printf("Total active translations: %d\n", totalDNAT)
	fmt.Printf("Total pools: %d\n", len(dnat.Pools))
	fmt.Println()
	fmt.Printf("%-20s %-20s %-8s %-12s\n",
		"Pool", "Address", "Port", "Hits")
	for name, pool := range dnat.Pools {
		portStr := "-"
		if pool.Port != 0 {
			portStr = fmt.Sprintf("%d", pool.Port)
		}
		hits := poolHits[name]
		fmt.Printf("%-20s %-20s %-8s %-12d\n",
			name, pool.Address, portStr, hits)
		// #7473: a pool whose every referencing rule is excluded is not
		// translating, and the Hits column above would otherwise read as
		// "no traffic" rather than "not installed".
		if reason := destNATPoolNotInstalled(cfg, name); reason != "" {
			fmt.Println(natNotInstalledLine(reason, false))
		}
	}

	// Per-rule-set session counts
	if len(rsSessions) > 0 {
		fmt.Println()
		fmt.Printf("%-30s %-12s\n", "Rule-set (from -> to)", "Sessions")
		for _, rs := range dnat.RuleSets {
			key := ruleSetKey{rs.FromZone, rs.ToZone}
			if cnt, ok := rsSessions[key]; ok {
				fmt.Printf("%-30s %-12d\n",
					fmt.Sprintf("%s -> %s", rs.FromZone, rs.ToZone), cnt)
			}
		}
	}
	return nil
}

// showNATDestinationPool displays detailed information about a specific DNAT pool.

func (c *CLI) showNATDestinationPool(cfg *config.Config, poolName string) error {
	dnat := cfg.Security.NAT.Destination
	if dnat == nil || len(dnat.Pools) == 0 {
		fmt.Println("No destination NAT pools configured")
		return nil
	}

	showAll := poolName == "" || poolName == "all"
	cr := c.applyResult()

	for name, pool := range dnat.Pools {
		if !showAll && name != poolName {
			continue
		}
		fmt.Printf("Pool name: %s\n", name)
		fmt.Printf("  Address: %s\n", pool.Address)
		if pool.Port != 0 {
			fmt.Printf("  Port: %d\n", pool.Port)
		}

		// Show which rule-sets reference this pool
		for _, rs := range dnat.RuleSets {
			for _, rule := range rs.Rules {
				if rule.Then.PoolName == name {
					fmt.Printf("  Referenced by: %s/%s (from %s)\n",
						rs.Name, rule.Name, rs.FromZone)
					// #7473: a referencing rule the builder excluded does not
					// actually reach this pool; without the annotation the
					// reference reads as a live translation path.
					if line := natNotInstalledLine(destNATRuleNotInstalled(cfg, rule), false); line != "" {
						fmt.Println("  " + line)
					}
				}
			}
		}

		// Show hit counters from all rules referencing this pool
		if c.dp != nil && cr != nil {
			var totalPkts, totalBytes uint64
			for _, rs := range dnat.RuleSets {
				for _, rule := range rs.Rules {
					if rule.Then.PoolName != name {
						continue
					}
					ruleKey := dataplane.NATCounterKey(dataplane.NATCounterTypeDest, rs.Name, rule.Name)
					if cid, ok := cr.NATCounterIDs[ruleKey]; ok {
						cnt, err := c.dp.ReadNATRuleCounter(uint32(cid))
						if err == nil {
							totalPkts += cnt.Packets
							totalBytes += cnt.Bytes
						}
					}
				}
			}
			fmt.Printf("  Total hits: %d packets  %d bytes\n", totalPkts, totalBytes)
		}
		fmt.Println()
	}

	if !showAll {
		if _, ok := dnat.Pools[poolName]; !ok {
			fmt.Printf("Pool %q not found\n", poolName)
		}
	}
	return nil
}

// showNATDestinationRuleSet displays a specific destination NAT rule-set with hit counters.

func (c *CLI) showNATDestinationRuleSet(cfg *config.Config, rsName string) error {
	dnat := cfg.Security.NAT.Destination
	if dnat == nil {
		fmt.Println("No destination NAT configured")
		return nil
	}

	cr := c.applyResult()
	for _, rs := range dnat.RuleSets {
		if rs.Name != rsName {
			continue
		}
		fmt.Printf("Rule-set: %s\n", rs.Name)
		fmt.Printf("  From zone: %s  To zone: %s\n", rs.FromZone, rs.ToZone)
		for _, rule := range rs.Rules {
			fmt.Printf("  Rule: %s\n", rule.Name)
			dstMatch := "0.0.0.0/0"
			if rule.Match.DestinationAddress != "" {
				dstMatch = rule.Match.DestinationAddress
			}
			fmt.Printf("    Match destination-address: %s\n", dstMatch)
			// #7473
			if line := natNotInstalledLine(destNATRuleNotInstalled(cfg, rule), false); line != "" {
				fmt.Println("  " + line)
			}
			if rule.Match.DestinationPort != 0 {
				fmt.Printf("    Match destination-port: %d\n", rule.Match.DestinationPort)
			}
			action := "off"
			if rule.Then.PoolName != "" {
				action = "pool " + rule.Then.PoolName
			}
			fmt.Printf("    Action: %s\n", action)

			// Show hit counters if dataplane is loaded
			if c.dp != nil && cr != nil {
				ruleKey := dataplane.NATCounterKey(dataplane.NATCounterTypeDest, rs.Name, rule.Name)
				if cid, ok := cr.NATCounterIDs[ruleKey]; ok {
					cnt, err := c.dp.ReadNATRuleCounter(uint32(cid))
					if err == nil {
						fmt.Printf("    Translation hits: %d packets  %d bytes\n",
							cnt.Packets, cnt.Bytes)
					}
				}
			}
		}
		fmt.Println()
		return nil
	}
	fmt.Printf("Rule-set %q not found\n", rsName)
	return nil
}

// showNATDestinationRuleAll displays all destination NAT rules with hit counters.

func (c *CLI) showNATDestinationRuleAll(cfg *config.Config) error {
	dnat := cfg.Security.NAT.Destination
	if dnat == nil || len(dnat.RuleSets) == 0 {
		fmt.Println("No destination NAT rules configured")
		return nil
	}

	cr := c.applyResult()
	totalRules := 0
	for _, rs := range dnat.RuleSets {
		for _, rule := range rs.Rules {
			totalRules++
			dstMatch := "0.0.0.0/0"
			if rule.Match.DestinationAddress != "" {
				dstMatch = rule.Match.DestinationAddress
			}
			if rule.Match.DestinationPort != 0 {
				dstMatch += fmt.Sprintf(":%d", rule.Match.DestinationPort)
			}
			action := "off"
			if rule.Then.PoolName != "" {
				action = "pool " + rule.Then.PoolName
			}

			fmt.Printf("Rule-set: %-20s Rule: %-12s from %s  Action: %s\n",
				rs.Name, rule.Name, rs.FromZone, action)
			fmt.Printf("  Match: destination %s\n", dstMatch)
			// #7473: same archetype on the destination family.
			if line := natNotInstalledLine(destNATRuleNotInstalled(cfg, rule), false); line != "" {
				fmt.Println(line)
			}

			if c.dp != nil && cr != nil {
				ruleKey := dataplane.NATCounterKey(dataplane.NATCounterTypeDest, rs.Name, rule.Name)
				if cid, ok := cr.NATCounterIDs[ruleKey]; ok {
					cnt, err := c.dp.ReadNATRuleCounter(uint32(cid))
					if err == nil {
						fmt.Printf("  Translation hits: %d packets  %d bytes\n",
							cnt.Packets, cnt.Bytes)
					}
				}
			}
		}
	}
	fmt.Printf("\nTotal destination NAT rules: %d\n", totalRules)
	return nil
}

// showNATDestinationRuleDetail displays Junos-style detailed destination NAT rules.

func (c *CLI) showNATDestinationRuleDetail(cfg *config.Config) error {
	// #1687: shared with the gRPC ShowText path via pkg/natshow. The
	// shared renderer carries the full nil/empty guard; the
	// showNATDestination dispatcher keeps its own pre-guard.
	natshow.RenderDestRuleDetail(os.Stdout, cfg, c.dp, c.applyResult)
	return nil
}

func (c *CLI) showNATStatic(cfg *config.Config, args []string) error {
	// #1687: shared with the gRPC ShowText path via pkg/natshow.
	// C-1b (#4314): `rule [detail]` drill-down mirrors source/destination NAT.
	if len(args) > 0 && args[0] == "rule" {
		detail := len(args) >= 2 && args[1] == "detail"
		natshow.RenderStaticRule(os.Stdout, cfg, detail)
		return nil
	}
	natshow.RenderStatic(os.Stdout, cfg)
	return nil
}

func (c *CLI) showNAT64(cfg *config.Config) error {
	if cfg == nil || len(cfg.Security.NAT.NAT64) == 0 {
		fmt.Println("No NAT64 rule-sets configured.")
		return nil
	}

	for _, rs := range cfg.Security.NAT.NAT64 {
		fmt.Printf("NAT64 rule-set: %s\n", rs.Name)
		if rs.Prefix != "" {
			fmt.Printf("  Prefix:      %s\n", rs.Prefix)
		}
		if rs.SourcePool != "" {
			fmt.Printf("  Source pool:  %s\n", rs.SourcePool)
		}
		fmt.Println()
	}

	return nil
}

func (c *CLI) showPersistentNAT() error {
	// #1687: shared with the gRPC ShowText path via pkg/natshow.
	natshow.RenderPersistent(os.Stdout, c.dp)
	return nil
}

// showPersistentNATDetail displays detailed persistent NAT bindings with session counts and age.

func (c *CLI) showPersistentNATDetail() error {
	// #1687: shared with the gRPC ShowText path via pkg/natshow.
	natshow.RenderPersistentDetail(os.Stdout, c.dp)
	return nil
}

func (c *CLI) showNPTv6(cfg *config.Config) error {
	// #1687: shared with the gRPC ShowText path via pkg/natshow.
	natshow.RenderNPTv6(os.Stdout, cfg)
	return nil
}

// appliedNATView projects the userspace manager's last-applied NAT snapshot
// into a nat.AppliedView for the deterministic-mapping lookup (#5794). Reads
// only cached in-memory state; returns an unavailable view when the
// dataplane is not the userspace manager, is not running, or has applied
// nothing.
func (c *CLI) appliedNATView() nat.AppliedView {
	if c.dp == nil {
		return nat.AppliedView{Available: false}
	}
	provider, ok := c.dpProbe().(interface {
		AppliedNATView() dpuserspace.AppliedNATView
	})
	if !ok {
		return nat.AppliedView{Available: false}
	}
	v := provider.AppliedNATView()
	if !v.Available || v.Config == nil {
		return nat.AppliedView{Available: false}
	}
	return nat.AppliedView{Config: v.Config, Generation: v.AppliedGeneration, Available: true}
}

// showNATDeterministic resolves a deterministic source-NAT mapping against
// the last-applied NAT generation (#5794). args are the tokens AFTER
// "deterministic-nat":
//
//	internal-host <ip> [pool <name>]           (forward)
//	nat-ip <ip> nat-port <port> [pool <name>]  (reverse)
func (c *CLI) showNATDeterministic(args []string) error {
	usage := "usage: show security nat source deterministic-nat (internal-host <ip> | nat-ip <ip> nat-port <port>) [pool <name>]"
	if len(args) == 0 {
		return fmt.Errorf("%s", usage)
	}
	view := c.appliedNATView()
	switch args[0] {
	case "internal-host":
		if len(args) < 2 {
			return fmt.Errorf("%s", usage)
		}
		res, lerr := nat.LookupForward(view, natPoolArg(args[2:]), args[1])
		if lerr != nil {
			fmt.Printf("No deterministic mapping (%s): %s\n", lerr.Code, lerr.Detail)
			return nil
		}
		res.Render(os.Stdout)
		return nil
	case "nat-ip":
		if len(args) < 4 || args[2] != "nat-port" {
			return fmt.Errorf("%s", usage)
		}
		port, err := strconv.Atoi(args[3])
		if err != nil || port < 1 || port > 65535 {
			return fmt.Errorf("nat-port must be 1-65535")
		}
		res, lerr := nat.LookupReverse(view, natPoolArg(args[4:]), args[1], uint16(port))
		if lerr != nil {
			fmt.Printf("No deterministic mapping (%s): %s\n", lerr.Code, lerr.Detail)
			return nil
		}
		res.Render(os.Stdout)
		return nil
	default:
		return fmt.Errorf("unknown deterministic-nat query %q (want internal-host or nat-ip)", args[0])
	}
}

// natPoolArg extracts an optional trailing `pool <name>` filter.
func natPoolArg(rest []string) string {
	if len(rest) >= 2 && rest[0] == "pool" {
		return rest[1]
	}
	return ""
}
