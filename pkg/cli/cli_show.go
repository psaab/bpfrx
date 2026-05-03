// #1044c Phase 1: relocate handleShow from cli.go.
// Pure relocation — same methodology as #1043 server_show.go split.
// No behavior change.

package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/psaab/xpf/pkg/cmdtree"
)

func (c *CLI) handleShow(args []string) error {
	showTree := operationalTree["show"].Children
	if len(args) == 0 {
		fmt.Println("show: specify what to show")
		writeCompletionHelp(os.Stdout, treeHelpCandidates(showTree))
		return nil
	}

	resolved, err := resolveCommand(args[0], keysFromTree(showTree))
	if err != nil {
		return err
	}
	args[0] = resolved

	switch args[0] {
	case "version":
		return c.showVersion()

	case "chassis":
		return c.showChassis(args[1:])

	case "configuration":
		rest := strings.Join(args[1:], " ")
		// Build path (everything after "configuration" before "|")
		var cfgPath []string
		for _, a := range args[1:] {
			if a == "|" {
				break
			}
			cfgPath = append(cfgPath, a)
		}
		if strings.Contains(rest, "| display json") {
			if len(cfgPath) > 0 {
				output := c.store.ShowActivePathJSON(cfgPath)
				if output == "" {
					fmt.Printf("configuration path not found: %s\n", strings.Join(cfgPath, " "))
				} else {
					fmt.Print(output)
				}
			} else {
				fmt.Print(c.store.ShowActiveJSON())
			}
		} else if strings.Contains(rest, "| display set") {
			if len(cfgPath) > 0 {
				output := c.store.ShowActivePathSet(cfgPath)
				if output == "" {
					fmt.Printf("configuration path not found: %s\n", strings.Join(cfgPath, " "))
				} else {
					fmt.Print(output)
				}
			} else {
				fmt.Print(c.store.ShowActiveSet())
			}
		} else if strings.Contains(rest, "| display xml") {
			if len(cfgPath) > 0 {
				output := c.store.ShowActivePathXML(cfgPath)
				if output == "" {
					fmt.Printf("configuration path not found: %s\n", strings.Join(cfgPath, " "))
				} else {
					fmt.Print(output)
				}
			} else {
				fmt.Print(c.store.ShowActiveXML())
			}
		} else if strings.Contains(rest, "| display inheritance") {
			if len(cfgPath) > 0 {
				output := c.store.ShowActivePathInheritance(cfgPath)
				if output == "" {
					fmt.Printf("configuration path not found: %s\n", strings.Join(cfgPath, " "))
				} else {
					fmt.Print(output)
				}
			} else {
				fmt.Print(c.store.ShowActiveInheritance())
			}
		} else if idx := strings.Index(rest, "| "); idx >= 0 {
			pipeParts := strings.Fields(strings.TrimSpace(rest[idx+2:]))
			if len(pipeParts) >= 2 && pipeParts[0] == "display" {
				fmt.Printf("syntax error: unknown display option '%s'\n", pipeParts[1])
			} else if len(pipeParts) > 0 {
				fmt.Printf("syntax error: unknown pipe command '%s'\n", pipeParts[0])
			}
		} else if len(cfgPath) > 0 {
			output := c.store.ShowActivePath(cfgPath)
			if output == "" {
				fmt.Printf("configuration path not found: %s\n", strings.Join(cfgPath, " "))
			} else {
				fmt.Print(output)
			}
		} else {
			fmt.Print(c.store.ShowActive())
		}
		return nil

	case "class-of-service":
		return c.handleShowClassOfService(args[1:])

	case "dhcp":
		if len(args) >= 2 {
			switch args[1] {
			case "leases":
				return c.showDHCPLeases()
			case "client-identifier":
				return c.showDHCPClientIdentifier()
			}
		}
		cmdtree.PrintTreeHelp("show dhcp:", operationalTree, "show", "dhcp")
		return nil

	case "firewall":
		if len(args) >= 3 && args[1] == "filter" {
			family := ""
			if len(args) >= 5 && args[3] == "family" {
				family = args[4]
			}
			return c.showFirewallFilter(args[2], family)
		}
		return c.showFirewallFilters()

	case "flow-monitoring":
		return c.showFlowMonitoring()

	case "log":
		return c.showDaemonLog(args[1:])

	case "route":
		return c.handleShowRoute(args[1:])

	case "security":
		return c.handleShowSecurity(args[1:])

	case "services":
		return c.handleShowServices(args[1:])

	case "interfaces":
		return c.showInterfaces(args[1:])

	case "protocols":
		return c.handleShowProtocols(args[1:])

	case "bgp":
		// "show bgp ..." is a shorthand alias for "show protocols bgp ..."
		return c.showBGP(args[1:])

	case "system":
		return c.handleShowSystem(args[1:])

	case "schedulers":
		return c.showSchedulers()

	case "dhcp-relay":
		return c.showDHCPRelay()

	case "dhcp-server":
		detail := len(args) >= 2 && args[1] == "detail"
		return c.showDHCPServer(detail)

	case "snmp":
		if len(args) >= 2 && args[1] == "v3" {
			return c.showSNMPv3()
		}
		return c.showSNMP()

	case "lldp":
		if len(args) >= 2 && args[1] == "neighbors" {
			return c.showLLDPNeighbors()
		}
		return c.showLLDP()

	case "arp":
		return c.showARP(args[1:])

	case "ipv6":
		return c.handleShowIPv6(args[1:])

	case "policy-options":
		return c.showPolicyOptions()

	case "route-map":
		return c.showRouteMap()

	case "event-options":
		return c.showEventOptions()

	case "routing-options":
		return c.showRoutingOptions()

	case "routing-instances":
		detail := len(args) >= 2 && args[1] == "detail"
		return c.showRoutingInstances(detail)

	case "forwarding-options":
		if len(args) >= 2 && args[1] == "port-mirroring" {
			return c.showPortMirroring()
		}
		return c.showForwardingOptions()

	case "vlans":
		return c.showVlans()

	case "task":
		return c.showTask()

	case "monitor":
		if len(args) >= 3 && args[1] == "security" && args[2] == "flow" {
			return c.showMonitorSecurityFlow()
		}
		cmdtree.PrintTreeHelp("show monitor:", operationalTree, "show", "monitor")
		return nil

	default:
		return fmt.Errorf("unknown show target: %s", args[0])
	}
}
