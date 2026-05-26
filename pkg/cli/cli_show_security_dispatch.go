// Dispatcher methods for `show security ...` and `show security screen ...`
// plus the small helpers consumed exclusively by the security presenters.
//
// Worker methods (showZonesDisplay, showPoliciesHitCount, showScreen, etc.)
// live in cli_show_security.go; this file holds only the dispatchers that
// route args to those workers and the helper functions that the workers
// share with the dispatchers.
package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

// enabledStr returns "enabled" or "disabled" for a boolean flag.
func enabledStr(v bool) string {
	if v {
		return "enabled"
	}
	return "disabled"
}

// parsePolicyZoneFilter extracts from-zone/to-zone filters from args.
func parsePolicyZoneFilter(args []string) (fromZone, toZone string) {
	for i := 0; i < len(args)-1; i++ {
		switch args[i] {
		case "from-zone":
			fromZone = args[i+1]
		case "to-zone":
			toZone = args[i+1]
		}
	}
	return
}

// resolveAddressDetail looks up the CIDR for a named address in the global
// address book, falling back to the name itself if not found.
func resolveAddressDetail(cfg *config.Config, name string) string {
	ab := cfg.Security.AddressBook
	if ab != nil {
		if addr, ok := ab.Addresses[name]; ok && addr.Value != "" {
			return addr.Value
		}
	}
	return name
}

// printAppDetail prints Junos-style application detail lines (protocol, ports, timeout).
func (c *CLI) printAppDetail(cfg *config.Config, appName string) {
	if appName == "any" {
		fmt.Printf("    IP protocol: 0, ALG: 0, Inactivity timeout: 0\n")
		fmt.Printf("      Source port range: [0-0]\n")
		fmt.Printf("      Destination ports: [0-0]\n")
		return
	}
	if cfg.Applications.Applications == nil {
		return
	}
	app, ok := cfg.Applications.Applications[appName]
	if !ok {
		return
	}
	proto := app.Protocol
	if proto == "" {
		proto = "0"
	}
	timeout := 0
	if app.InactivityTimeout > 0 {
		timeout = app.InactivityTimeout
	}
	algVal := "0"
	if app.ALG != "" {
		algVal = app.ALG
	}
	fmt.Printf("    IP protocol: %s, ALG: %s, Inactivity timeout: %d\n", proto, algVal, timeout)
	srcPort := "0-0"
	if app.SourcePort != "" {
		srcPort = app.SourcePort
	}
	dstPort := "0-0"
	if app.DestinationPort != "" {
		dstPort = app.DestinationPort
	}
	fmt.Printf("      Source port range: [%s]\n", srcPort)
	fmt.Printf("      Destination ports: [%s]\n", dstPort)
}

func (c *CLI) handleShowSecurity(args []string) error {
	secTree := operationalTree["show"].Children["security"].Children
	if len(args) == 0 {
		fmt.Println("show security:")
		writeCompletionHelp(os.Stdout, treeHelpCandidates(secTree))
		return nil
	}

	resolved, err := resolveCommand(args[0], keysFromTree(secTree))
	if err != nil {
		return err
	}
	args[0] = resolved

	cfg := c.store.ActiveConfig()
	if cfg == nil && args[0] != "statistics" && args[0] != "ipsec" && args[0] != "alarms" {
		fmt.Println("no active configuration")
		return nil
	}

	switch args[0] {
	case "zones":
		detail := false
		filterZone := ""
		if len(args) >= 2 {
			if args[1] == "detail" {
				detail = true
			} else {
				filterZone = args[1]
				if len(args) >= 3 && args[2] == "detail" {
					detail = true
				}
			}
		}
		return c.showZonesDisplay(cfg, detail, filterZone)

	case "policies":
		// Parse optional zone-pair filter: from-zone X to-zone Y
		fromZone, toZone := parsePolicyZoneFilter(args[1:])
		// "show security policies global" — only show global policies
		globalOnly := len(args) >= 2 && args[1] == "global"
		// "show security policies hit-count" — Junos-style hit count table
		if len(args) >= 2 && args[1] == "hit-count" {
			return c.showPoliciesHitCount(cfg, fromZone, toZone)
		}
		// "show security policies detail" — expanded Junos-style detail view
		if len(args) >= 2 && args[1] == "detail" {
			return c.showPoliciesDetail(cfg, fromZone, toZone)
		}
		brief := len(args) >= 2 && args[1] == "brief"
		if brief {
			// Brief tabular summary
			fmt.Printf("%-12s %-12s %-20s %-8s %s\n",
				"From", "To", "Name", "Action", "Hits")
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
					action := "permit"
					switch pol.Action {
					case 1:
						action = "deny"
					case 2:
						action = "reject"
					}
					ruleID := policySetID*dataplane.MaxRulesPerPolicy + uint32(i)
					hits := "-"
					if c.dp != nil && c.dp.IsLoaded() {
						if counters, err := c.dp.ReadPolicyCounters(ruleID); err == nil {
							hits = fmt.Sprintf("%d", counters.Packets)
						}
					}
					fmt.Printf("%-12s %-12s %-20s %-8s %s\n",
						zpp.FromZone, zpp.ToZone, pol.Name, action, hits)
				}
				policySetID++
			}
			// Global policies in brief view
			if len(cfg.Security.GlobalPolicies) > 0 && fromZone == "" && toZone == "" {
				for i, pol := range cfg.Security.GlobalPolicies {
					action := "permit"
					switch pol.Action {
					case 1:
						action = "deny"
					case 2:
						action = "reject"
					}
					ruleID := policySetID*dataplane.MaxRulesPerPolicy + uint32(i)
					hits := "-"
					if c.dp != nil && c.dp.IsLoaded() {
						if counters, err := c.dp.ReadPolicyCounters(ruleID); err == nil {
							hits = fmt.Sprintf("%d", counters.Packets)
						}
					}
					fmt.Printf("%-12s %-12s %-20s %-8s %s\n",
						"*", "*", pol.Name, action, hits)
				}
			}
			return nil
		}

		policySetID := uint32(0)
		if !globalOnly {
			for _, zpp := range cfg.Security.Policies {
				if fromZone != "" && zpp.FromZone != fromZone {
					policySetID++
					continue
				}
				if toZone != "" && zpp.ToZone != toZone {
					policySetID++
					continue
				}
				// Junos format: "From zone: X, To zone: Y" header
				fmt.Printf("From zone: %s, To zone: %s\n", zpp.FromZone, zpp.ToZone)
				for i, pol := range zpp.Policies {
					action := "permit"
					switch pol.Action {
					case 1:
						action = "deny"
					case 2:
						action = "reject"
					}
					ruleID := policySetID*dataplane.MaxRulesPerPolicy + uint32(i)
					// Junos: Policy: <name>, State: enabled, Index: <N>, Scope Policy: 0, Sequence number: <N>
					fmt.Printf("  Policy: %s, State: enabled, Index: %d, Scope Policy: 0, Sequence number: %d\n",
						pol.Name, ruleID, i+1)
					if pol.Description != "" {
						fmt.Printf("    Description: %s\n", pol.Description)
					}
					fmt.Printf("    Source addresses: %s\n",
						strings.Join(pol.Match.SourceAddresses, ", "))
					fmt.Printf("    Destination addresses: %s\n",
						strings.Join(pol.Match.DestinationAddresses, ", "))
					fmt.Printf("    Applications: %s\n",
						strings.Join(pol.Match.Applications, ", "))
					actionStr := action
					if pol.Log != nil {
						actionStr += ", log"
					}
					fmt.Printf("    Action: %s\n", actionStr)
				}
				policySetID++
			}
		} else {
			// When globalOnly, still count zone-pair policy sets to get correct global ruleID base
			policySetID = uint32(len(cfg.Security.Policies))
		}
		// Global policies
		if len(cfg.Security.GlobalPolicies) > 0 && (globalOnly || (fromZone == "" && toZone == "")) {
			fmt.Println("Global policies:")
			for i, pol := range cfg.Security.GlobalPolicies {
				action := "permit"
				switch pol.Action {
				case 1:
					action = "deny"
				case 2:
					action = "reject"
				}
				ruleID := policySetID*dataplane.MaxRulesPerPolicy + uint32(i)
				// Junos global: Policy: <name>, State: enabled, Index: <N>, Scope Policy: 0, Sequence number: <N>
				fmt.Printf("  Policy: %s, State: enabled, Index: %d, Scope Policy: 0, Sequence number: %d\n",
					pol.Name, ruleID, i+1)
				if pol.Description != "" {
					fmt.Printf("    Description: %s\n", pol.Description)
				}
				fmt.Printf("    From zones: any\n")
				fmt.Printf("    To zones: any\n")
				fmt.Printf("    Source addresses: %s\n",
					strings.Join(pol.Match.SourceAddresses, ", "))
				fmt.Printf("    Destination addresses: %s\n",
					strings.Join(pol.Match.DestinationAddresses, ", "))
				fmt.Printf("    Applications: %s\n",
					strings.Join(pol.Match.Applications, ", "))
				actionStr := action
				if pol.Log != nil {
					actionStr += ", log"
				}
				fmt.Printf("    Action: %s\n", actionStr)
			}
		}
		return nil

	case "flow":
		if len(args) >= 2 && args[1] == "session" {
			return c.showFlowSession(args[2:])
		}
		if len(args) >= 2 && args[1] == "traceoptions" {
			return c.showFlowTraceoptions()
		}
		if len(args) >= 2 && args[1] == "statistics" {
			return c.showFlowStatistics()
		}
		if len(args) == 1 {
			return c.showFlowTimeouts()
		}
		return fmt.Errorf("unknown show security flow target")

	case "screen":
		return c.handleShowScreen(args[1:])

	case "nat":
		return c.handleShowNAT(args[1:])

	case "address-book":
		return c.showAddressBook(args[1:])

	case "applications":
		return c.showApplications(args[1:])

	case "log":
		return c.showSecurityLog(args[1:])

	case "statistics":
		detail := len(args) >= 2 && args[1] == "detail"
		return c.showStatistics(detail)

	case "ipsec":
		return c.showIPsec(args[1:])

	case "ike":
		return c.showIKE(args[1:])

	case "alarms":
		return c.showSecurityAlarms(args[1:])

	case "alg":
		// Accept optional "status" subcommand
		return c.showALG()

	case "dynamic-address":
		return c.showDynamicAddress()

	case "match-policies":
		return c.showMatchPolicies(cfg, args[1:])

	case "vrrp":
		return c.showVRRP()

	default:
		return fmt.Errorf("unknown show security target: %s", args[0])
	}
}

func (c *CLI) handleShowScreen(args []string) error {
	if len(args) == 0 {
		return c.showScreen()
	}
	switch args[0] {
	case "ids-option":
		if len(args) < 2 {
			return c.showScreen()
		}
		if len(args) >= 3 && args[2] == "detail" {
			return c.showScreenIdsOptionDetail(args[1])
		}
		return c.showScreenIdsOption(args[1])
	case "statistics":
		if len(args) >= 2 && args[1] == "zone" && len(args) >= 3 {
			return c.showScreenStatistics(args[2])
		}
		return c.showScreenStatisticsAll()
	default:
		return c.showScreen()
	}
}
