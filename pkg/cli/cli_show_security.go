package cli

import (
	"fmt"
	"net"
	"strings"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/policymatch"
)

// runtimePolicyIndex returns the span-accumulated runtime/RT_FLOW policy ID for
// the policy at (policySetID, sliceIndex), used as the displayed detail `Index`
// so it matches the numeric policy ID the RT_FLOW/event path logs (#3063). It
// falls back to the raw ordinal policySetID*MaxRulesPerPolicy + sliceIndex when
// the lookup has no entry (e.g. a config the dataplane would reject for
// MaxRulesPerPolicy overflow), which is byte-identical to the pre-#3063 value.
// This is a DISPLAY identity only — it is NOT the counter handle passed to
// ReadPolicyCounters (that stays the raw ordinal; see policyRuleIDForCounter).
func runtimePolicyIndex(ids map[[2]uint32]uint32, policySetID, sliceIndex uint32) uint32 {
	if id, ok := ids[[2]uint32{policySetID, sliceIndex}]; ok {
		return id
	}
	return policySetID*dataplane.MaxRulesPerPolicy + sliceIndex
}

func (c *CLI) showPoliciesHitCount(cfg *config.Config, fromZone, toZone string) error {
	if c.dp == nil || !c.dp.IsLoaded() {
		fmt.Println("dataplane not loaded")
		return nil
	}

	// Honor `set security policy-stats system-wide enable` (#2008 M4 /
	// #2118): per-policy hit counters are maintained and displayed only
	// when policy-stats is enabled system-wide (default off). The
	// Prometheus collector already gates on this knob; gate the CLI
	// hit-count table identically so the CLI, gRPC text, structured
	// gRPC, and Prometheus surfaces all report the SAME values. When the
	// knob is off the "Policy count" column reads 0 (we skip the
	// dataplane read).
	statsEnabled := cfg.Security.PolicyStatsEnabled

	fmt.Println("Logical system: root-logical-system")
	fmt.Printf("%-8s%-17s%-18s%-24s%-14s%s\n",
		"Index", "From zone", "To zone", "Name", "Policy count", "Action")

	// #3408: surface a per-policy counter read failure as a warning AFTER
	// all reads, rather than printing clean-zero hit counts.
	var readErr error
	index := uint32(1)
	policySetID := uint32(0)
	for _, zpp := range cfg.Security.Policies {
		if fromZone != "" && zpp.FromZone != fromZone {
			policySetID++
			continue
		}
		if toZone != "" && zpp.ToZone != toZone {
			policySetID++
			continue
		}
		for i, pol := range zpp.Policies {
			action := "Permit"
			switch pol.Action {
			case 1:
				action = "Deny"
			case 2:
				action = "Reject"
			}
			ruleID := policySetID*dataplane.MaxRulesPerPolicy + uint32(i)
			var count uint64
			if statsEnabled || pol.Count {
				if counters, err := c.dp.ReadPolicyCounters(ruleID); err == nil {
					count = counters.Packets
				} else if readErr == nil {
					readErr = err
				}
			}
			fmt.Printf("%-8d%-17s%-18s%-24s%-14d%s\n",
				index, zpp.FromZone, zpp.ToZone, pol.Name, count, action)
			index++
		}
		policySetID++
	}
	// Global policies
	if len(cfg.Security.GlobalPolicies) > 0 && fromZone == "" && toZone == "" {
		for i, pol := range cfg.Security.GlobalPolicies {
			action := "Permit"
			switch pol.Action {
			case 1:
				action = "Deny"
			case 2:
				action = "Reject"
			}
			ruleID := policySetID*dataplane.MaxRulesPerPolicy + uint32(i)
			var count uint64
			if statsEnabled || pol.Count {
				if counters, err := c.dp.ReadPolicyCounters(ruleID); err == nil {
					count = counters.Packets
				} else if readErr == nil {
					readErr = err
				}
			}
			// #3286: a scoped global (#3148) shows its zone pair in the
			// From/To columns so counter-based validation is unambiguous;
			// an unscoped global keeps junos-global/junos-global.
			hcFrom, hcTo := "junos-global", "junos-global"
			if pol.Match.FromZone != "" {
				hcFrom = pol.Match.FromZone
			}
			if pol.Match.ToZone != "" {
				hcTo = pol.Match.ToZone
			}
			fmt.Printf("%-8d%-17s%-18s%-24s%-14d%s\n",
				index, hcFrom, hcTo, pol.Name, count, action)
			index++
		}
	}
	if readErr != nil {
		fmt.Printf("warning: policy counter read failed (counts may be incomplete): %v\n", readErr)
	}
	return nil
}

// showPoliciesDetail displays an expanded Junos-style detail view of security policies.

func (c *CLI) showPoliciesDetail(cfg *config.Config, fromZone, toZone string) error {
	schedActive, haveSched := c.policySchedulerActiveState()
	// #3063: the displayed Index must equal the runtime/RT_FLOW policy ID,
	// which advances by application-set expansion. RuntimePolicyIDs mirrors the
	// snapshot's PolicyID assignment so an operator cross-referencing a
	// policy-deny log lands on the correct detail row even after a multi-app
	// policy shifts the ID namespace.
	runtimeIDs := dpuserspace.RuntimePolicyIDs(cfg)
	policySetID := uint32(0)
	seqNum := 1
	for _, zpp := range cfg.Security.Policies {
		if fromZone != "" && zpp.FromZone != fromZone {
			policySetID++
			continue
		}
		if toZone != "" && zpp.ToZone != toZone {
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
			ruleID := runtimePolicyIndex(runtimeIDs, policySetID, uint32(i))
			// #3062: reflect runtime scheduler state — a policy bound to a
			// currently-inactive scheduler reports State: inactive (the
			// dataplane is dropping its rule). Active/non-scheduled policies
			// stay bit-identical (State: enabled, no Scheduler line).
			state := policyDetailState(pol.SchedulerName, schedActive, haveSched)
			fmt.Printf("Policy: %s, action-type: %s, State: %s, Index: %d, Scope Policy: 0\n",
				pol.Name, action, state, ruleID)
			fmt.Printf("  Policy Type: Configured\n")
			if state == "inactive" {
				fmt.Printf("  Scheduler: %s (inactive)\n", pol.SchedulerName)
			}
			fmt.Printf("  Sequence number: %d\n", seqNum)
			fmt.Printf("  From zone: %s, To zone: %s\n", zpp.FromZone, zpp.ToZone)
			if pol.Description != "" {
				fmt.Printf("  Description: %s\n", pol.Description)
			}
			fmt.Printf("  Source addresses:\n")
			for _, addr := range pol.Match.SourceAddresses {
				if addr == "any" {
					fmt.Printf("    any-ipv4(global): 0.0.0.0/0\n")
					fmt.Printf("    any-ipv6(global): ::/0\n")
				} else {
					resolved := resolveAddressDetail(cfg, addr)
					fmt.Printf("    %s(global): %s\n", addr, resolved)
				}
			}
			fmt.Printf("  Destination addresses:\n")
			for _, addr := range pol.Match.DestinationAddresses {
				if addr == "any" {
					fmt.Printf("    any-ipv4(global): 0.0.0.0/0\n")
					fmt.Printf("    any-ipv6(global): ::/0\n")
				} else {
					resolved := resolveAddressDetail(cfg, addr)
					fmt.Printf("    %s(global): %s\n", addr, resolved)
				}
			}
			for _, app := range pol.Match.Applications {
				fmt.Printf("  Application: %s\n", app)
				c.printAppDetail(cfg, app)
			}
			if pol.Log != nil {
				parts := []string{}
				if pol.Log.SessionInit {
					parts = append(parts, "at-create")
				}
				if pol.Log.SessionClose {
					parts = append(parts, "at-close")
				}
				if len(parts) > 0 {
					fmt.Printf("  Session log: %s\n", strings.Join(parts, ", "))
				}
			}
			seqNum++
		}
		policySetID++
		fmt.Println()
	}

	// Global policies
	if len(cfg.Security.GlobalPolicies) > 0 && fromZone == "" && toZone == "" {
		for i, pol := range cfg.Security.GlobalPolicies {
			action := "permit"
			switch pol.Action {
			case 1:
				action = "deny"
			case 2:
				action = "reject"
			}
			ruleID := runtimePolicyIndex(runtimeIDs, policySetID, uint32(i))
			// #3062: scheduler-inactive global policy reports State: inactive.
			state := policyDetailState(pol.SchedulerName, schedActive, haveSched)
			fmt.Printf("Policy: %s, action-type: %s, State: %s, Index: %d, Scope Policy: 0\n",
				pol.Name, action, state, ruleID)
			fmt.Printf("  Policy Type: Configured\n")
			if state == "inactive" {
				fmt.Printf("  Scheduler: %s (inactive)\n", pol.SchedulerName)
			}
			fmt.Printf("  Sequence number: %d\n", seqNum)
			// #3286: a scoped global policy (#3148) narrows itself to a
			// zone pair via `match from-zone/to-zone`. Show the configured
			// scope instead of the all-zones "junos-global" placeholder so
			// an operator can tell which zone pair a global rule applies to.
			// An unscoped global keeps junos-global/junos-global.
			globalFromZone, globalToZone := "junos-global", "junos-global"
			if pol.Match.FromZone != "" {
				globalFromZone = pol.Match.FromZone
			}
			if pol.Match.ToZone != "" {
				globalToZone = pol.Match.ToZone
			}
			fmt.Printf("  From zone: %s, To zone: %s\n", globalFromZone, globalToZone)
			if pol.Description != "" {
				fmt.Printf("  Description: %s\n", pol.Description)
			}
			fmt.Printf("  Source addresses:\n")
			for _, addr := range pol.Match.SourceAddresses {
				if addr == "any" {
					fmt.Printf("    any-ipv4(global): 0.0.0.0/0\n")
					fmt.Printf("    any-ipv6(global): ::/0\n")
				} else {
					resolved := resolveAddressDetail(cfg, addr)
					fmt.Printf("    %s(global): %s\n", addr, resolved)
				}
			}
			fmt.Printf("  Destination addresses:\n")
			for _, addr := range pol.Match.DestinationAddresses {
				if addr == "any" {
					fmt.Printf("    any-ipv4(global): 0.0.0.0/0\n")
					fmt.Printf("    any-ipv6(global): ::/0\n")
				} else {
					resolved := resolveAddressDetail(cfg, addr)
					fmt.Printf("    %s(global): %s\n", addr, resolved)
				}
			}
			for _, app := range pol.Match.Applications {
				fmt.Printf("  Application: %s\n", app)
				c.printAppDetail(cfg, app)
			}
			if pol.Log != nil {
				parts := []string{}
				if pol.Log.SessionInit {
					parts = append(parts, "at-create")
				}
				if pol.Log.SessionClose {
					parts = append(parts, "at-close")
				}
				if len(parts) > 0 {
					fmt.Printf("  Session log: %s\n", strings.Join(parts, ", "))
				}
			}
			seqNum++

			_ = ruleID
		}
		fmt.Println()
	}
	return nil
}

// resolveAddressDetail returns the CIDR for an address name, or the name itself if not found.

// showMatchPolicies performs a 5-tuple policy lookup and shows matching rules.

func (c *CLI) showMatchPolicies(cfg *config.Config, args []string) error {
	if cfg == nil {
		fmt.Println("No active configuration")
		return nil
	}

	// Parse arguments: from-zone <z> to-zone <z> source-ip <ip> destination-ip <ip>
	//                   destination-port <p> protocol <proto>
	var fromZone, toZone, srcIP, dstIP, proto string
	var dstPort, srcPort int
	var icmpType, icmpCode *uint8
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "from-zone":
			if i+1 < len(args) {
				i++
				fromZone = args[i]
			}
		case "to-zone":
			if i+1 < len(args) {
				i++
				toZone = args[i]
			}
		case "source-ip":
			if i+1 < len(args) {
				i++
				srcIP = args[i]
			}
		case "destination-ip":
			if i+1 < len(args) {
				i++
				dstIP = args[i]
			}
		case "destination-port":
			if i+1 < len(args) {
				i++
				p, err := policymatch.ParsePort(args[i])
				if err != nil {
					return fmt.Errorf("invalid destination-port: %w", err)
				}
				dstPort = p
			}
		case "source-port":
			if i+1 < len(args) {
				i++
				p, err := policymatch.ParsePort(args[i])
				if err != nil {
					return fmt.Errorf("invalid source-port: %w", err)
				}
				srcPort = p
			}
		case "protocol":
			if i+1 < len(args) {
				i++
				proto = args[i]
			}
		case "icmp-type":
			if i+1 < len(args) {
				i++
				// #3284: honor ICMP/ICMPv6 type-constrained app terms
				// (junos-ping = type 8).
				v, err := policymatch.ParseICMPValue(args[i])
				if err != nil {
					return fmt.Errorf("invalid icmp-type: %w", err)
				}
				icmpType = v
			}
		case "icmp-code":
			if i+1 < len(args) {
				i++
				v, err := policymatch.ParseICMPValue(args[i])
				if err != nil {
					return fmt.Errorf("invalid icmp-code: %w", err)
				}
				icmpCode = v
			}
		}
	}

	if fromZone == "" || toZone == "" {
		fmt.Println("usage: show security match-policies from-zone <zone> to-zone <zone>")
		fmt.Println("       source-ip <ip> destination-ip <ip> destination-port <port> protocol <tcp|udp>")
		return nil
	}

	// A non-empty but malformed source/destination IP would parse to
	// nil and be treated as a wildcard by matchPolicyAddr, yielding a
	// false-positive PERMIT verdict in the simulator (#1711). Reject it
	// explicitly. An empty value still means "unspecified" (match any).
	if srcIP != "" && net.ParseIP(srcIP) == nil {
		return fmt.Errorf("invalid source-ip %q", srcIP)
	}
	if dstIP != "" && net.ParseIP(dstIP) == nil {
		return fmt.Errorf("invalid destination-ip %q", dstIP)
	}

	// #3108: a non-empty but unknown/out-of-range protocol token ("tcpp",
	// "999") must not silently become "any protocol" — matchApp short-circuits
	// to match-any for an unresolvable protocol, yielding a misleading verdict
	// for a policy using `application any`. An empty value still means
	// "unspecified" (match any protocol).
	if err := policymatch.ValidateProtocol(proto); err != nil {
		return err
	}

	parsedSrc := net.ParseIP(srcIP)
	parsedDst := net.ParseIP(dstIP)

	// #3042: delegate to the single shared simulator so the CLI agrees with
	// the runtime evaluator. The pre-#3042 loop scanned only zone-pair
	// policies (never globals), hard-coded "default deny" (ignoring
	// default-policy permit-all), and used a narrow address/app matcher that
	// missed predefined apps, nested application-sets, literal CIDRs,
	// any-ipv4/any-ipv6, and source/destination exclusion.
	// #3105: pass the live dynamic-address feed-prefix overlay so a feed-backed
	// address-name resolves to its live CIDRs on-box, matching the REST/gRPC
	// simulators and the AF_XDP helper. Nil (CLI outside the daemon) keeps the
	// pre-#3105 static-only behavior.
	res := policymatch.Match(cfg, policymatch.Query{
		FromZone:    fromZone,
		ToZone:      toZone,
		SrcIP:       parsedSrc,
		DstIP:       parsedDst,
		Protocol:    proto,
		SrcPort:     srcPort,
		DstPort:     dstPort,
		ICMPType:    icmpType,
		ICMPCode:    icmpCode,
		FeedOverlay: c.feedOverlay(),
		// #3104: skip scheduler-inactive policies like the runtime does, so the
		// simulator falls through to the next active rule / default-policy.
		PolicyInactiveFn: c.policyInactiveFn(),
	})
	if res.HostInboundUnmatched {
		// #3285: host-bound traffic — no transit global/default fallback.
		fmt.Printf("No matching to-zone junos-host policy for %s -> junos-host\n", fromZone)
		fmt.Printf("  host-inbound: local delivery proceeds (transit global/default-policy NOT applied)\n")
		return nil
	}
	if !res.Matched {
		fmt.Printf("No matching policy found for %s -> %s (default %s)\n",
			fromZone, toZone, policymatch.ActionString(res.Action))
		return nil
	}
	if res.Global {
		fmt.Printf("Matching policy (global):\n")
	} else {
		fmt.Printf("Matching policy:\n")
	}
	fmt.Printf("  From zone: %s, To zone: %s\n", fromZone, toZone)
	fmt.Printf("  Policy: %s\n", res.PolicyName)
	// #3331: identify WHICH scoped/global policy matched so a verdict maps back
	// to the runtime policy / session-table ID / audit record when names repeat.
	fmt.Printf("    Policy ID: %d\n", res.PolicyID)
	if res.Global {
		fmt.Printf("    Scope: global (match from-zone: %s, to-zone: %s)\n",
			matchScopeZone(res.FromZone), matchScopeZone(res.ToZone))
	} else {
		fmt.Printf("    Scope: zone-pair (from-zone: %s, to-zone: %s)\n", res.FromZone, res.ToZone)
	}
	if res.Description != "" {
		fmt.Printf("    Description: %s\n", res.Description)
	}
	fmt.Printf("    Source addresses: %v\n", res.SrcAddresses)
	fmt.Printf("    Destination addresses: %v\n", res.DstAddresses)
	fmt.Printf("    Applications: %v\n", res.Applications)
	fmt.Printf("    Action: %s\n", policymatch.ActionString(res.Action))
	return nil
}

// matchScopeZone renders a global policy's match from-zone/to-zone scope for the
// match-policies output (#3331). An empty scope means the global policy applies
// to every zone, shown as "any" to match the Junos / `show policies` convention.
func matchScopeZone(z string) string {
	if z == "" {
		return "any"
	}
	return z
}
