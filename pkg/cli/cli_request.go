package cli

// cli_request.go is the dispatch shell for the operational request /
// diagnostic command families that were historically one 1300-line grab-bag
// (#4653). It keeps only the top-level `request` dispatcher plus the small
// `request dhcp` / `request protocols` handlers that do not warrant their own
// file. The per-family handlers live in sibling files in this package (same
// package, so unexported symbols stay reachable):
//
//	cli_request_ping.go     ping / traceroute (+ diagcmd argv builders)
//	cli_request_testcmd.go  test policy / routing / security-zone
//	monitor_traffic.go      monitor + monitor traffic (tcpdump argv builder)
//	cli_request_chassis.go  request chassis cluster failover / data-plane
//	cli_request_system.go   request system reboot/halt/zeroize/software/...
//	cli_request_security.go request security ipsec / policies / wireguard
//
// The split is pure code motion — no behavior change. The security-sensitive
// diagcmd/tcpdump argv construction with its `--` end-of-options separators
// (#4527 / #2084 / #4524) moved verbatim.

import (
	"fmt"
	"os"
)

func (c *CLI) handleRequest(args []string) error {
	if len(args) == 0 {
		fmt.Println("request:")
		writeCompletionHelp(os.Stdout, treeHelpCandidates(operationalTree["request"].Children))
		return nil
	}

	switch args[0] {
	case "chassis":
		return c.handleRequestChassis(args[1:])
	case "dhcp":
		return c.handleRequestDHCP(args[1:])
	case "protocols":
		return c.handleRequestProtocols(args[1:])
	case "security":
		return c.handleRequestSecurity(args[1:])
	case "system":
		return c.handleRequestSystem(args[1:])
	default:
		return fmt.Errorf("unknown request target: %s", args[0])
	}
}

func (c *CLI) handleRequestDHCP(args []string) error {
	if len(args) == 0 || args[0] != "renew" {
		fmt.Println("request dhcp:")
		writeCompletionHelp(os.Stdout, treeHelpCandidates(operationalTree["request"].Children["dhcp"].Children))
		return nil
	}
	if len(args) < 2 {
		return fmt.Errorf("usage: request dhcp renew <interface>")
	}
	if c.dhcp == nil {
		return fmt.Errorf("DHCP manager not available")
	}
	if err := c.dhcp.Renew(args[1]); err != nil {
		return err
	}
	fmt.Printf("DHCP renewal initiated on %s\n", args[1])
	return nil
}

func (c *CLI) handleRequestProtocols(args []string) error {
	if len(args) == 0 {
		fmt.Println("request protocols:")
		writeCompletionHelp(os.Stdout, treeHelpCandidates(operationalTree["request"].Children["protocols"].Children))
		return nil
	}
	if c.frr == nil {
		return fmt.Errorf("FRR manager not available")
	}
	switch args[0] {
	case "ospf":
		if len(args) < 2 || args[1] != "clear" {
			fmt.Println("request protocols ospf:")
			writeCompletionHelp(os.Stdout, treeHelpCandidates(operationalTree["request"].Children["protocols"].Children["ospf"].Children))
			return nil
		}
		output, err := c.frr.ExecVtysh("clear ip ospf process")
		if err != nil {
			return fmt.Errorf("clear OSPF: %w", err)
		}
		if output != "" {
			fmt.Print(output)
		}
		fmt.Println("OSPF process cleared")
		return nil
	case "bgp":
		if len(args) < 2 || args[1] != "clear" {
			fmt.Println("request protocols bgp:")
			writeCompletionHelp(os.Stdout, treeHelpCandidates(operationalTree["request"].Children["protocols"].Children["bgp"].Children))
			return nil
		}
		output, err := c.frr.ExecVtysh("clear bgp * soft")
		if err != nil {
			return fmt.Errorf("clear BGP: %w", err)
		}
		if output != "" {
			fmt.Print(output)
		}
		fmt.Println("BGP sessions cleared (soft reset)")
		return nil
	default:
		return fmt.Errorf("unknown request protocols target: %s", args[0])
	}
}
