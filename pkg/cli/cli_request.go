package cli

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/routing"
)

func (c *CLI) handlePing(args []string) error {
	if len(args) == 0 {
		fmt.Println("usage: ping <target> [count <N>] [source <IP>] [size <N>] [routing-instance <name>]")
		return nil
	}

	target := args[0]
	count := "5"
	source := ""
	size := ""
	vrfName := ""

	for i := 1; i < len(args)-1; i++ {
		switch args[i] {
		case "count":
			count = args[i+1]
			i++
		case "source":
			source = args[i+1]
			i++
		case "size":
			size = args[i+1]
			i++
		case "routing-instance":
			vrfName = args[i+1]
			i++
		}
	}

	var cmdArgs []string
	if vrfName != "" {
		cmdArgs = append(cmdArgs, "ip", "vrf", "exec", "vrf-"+vrfName, "ping")
	} else {
		cmdArgs = append(cmdArgs, "ping")
	}

	cmdArgs = append(cmdArgs, "-c", count)
	if source != "" {
		cmdArgs = append(cmdArgs, "-I", source)
	}
	if size != "" {
		cmdArgs = append(cmdArgs, "-s", size)
	}
	cmdArgs = append(cmdArgs, target)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	c.cmdMu.Lock()
	c.cmdCancel = cancel
	c.cmdMu.Unlock()
	defer func() {
		c.cmdMu.Lock()
		c.cmdCancel = nil
		c.cmdMu.Unlock()
	}()

	cmd := exec.CommandContext(ctx, cmdArgs[0], cmdArgs[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if ctx.Err() != nil {
		return nil // cancelled by Ctrl-C or timeout
	}
	return err
}

func (c *CLI) handleTraceroute(args []string) error {
	if len(args) == 0 {
		fmt.Println("usage: traceroute <target> [source <IP>] [routing-instance <name>]")
		return nil
	}

	target := args[0]
	source := ""
	vrfName := ""

	for i := 1; i < len(args)-1; i++ {
		switch args[i] {
		case "source":
			source = args[i+1]
			i++
		case "routing-instance":
			vrfName = args[i+1]
			i++
		}
	}

	var cmdArgs []string
	if vrfName != "" {
		cmdArgs = append(cmdArgs, "ip", "vrf", "exec", "vrf-"+vrfName, "traceroute")
	} else {
		cmdArgs = append(cmdArgs, "traceroute")
	}

	if source != "" {
		cmdArgs = append(cmdArgs, "-s", source)
	}
	cmdArgs = append(cmdArgs, target)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	c.cmdMu.Lock()
	c.cmdCancel = cancel
	c.cmdMu.Unlock()
	defer func() {
		c.cmdMu.Lock()
		c.cmdCancel = nil
		c.cmdMu.Unlock()
	}()

	cmd := exec.CommandContext(ctx, cmdArgs[0], cmdArgs[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if ctx.Err() != nil {
		return nil // cancelled by Ctrl-C or timeout
	}
	return err
}

// handleTest dispatches test sub-commands (policy, routing, security-zone).
func (c *CLI) handleTest(args []string) error {
	if len(args) == 0 {
		fmt.Println("test: specify a test command")
		writeCompletionHelp(os.Stdout, treeHelpCandidates(operationalTree["test"].Children))
		return nil
	}

	resolved, err := resolveCommand(args[0], keysFromTree(operationalTree["test"].Children))
	if err != nil {
		return err
	}

	switch resolved {
	case "policy":
		return c.testPolicy(args[1:])
	case "routing":
		return c.testRouting(args[1:])
	case "security-zone":
		return c.testSecurityZone(args[1:])
	default:
		return fmt.Errorf("unknown test command: %s", resolved)
	}
}

// testPolicy performs a 5-tuple policy lookup similar to Junos "test policy".
func (c *CLI) testPolicy(args []string) error {
	cfg := c.store.ActiveConfig()
	if cfg == nil {
		fmt.Println("No active configuration")
		return nil
	}

	var fromZone, toZone, srcIP, dstIP, proto string
	var dstPort int
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
				dstPort, _ = strconv.Atoi(args[i])
			}
		case "protocol":
			if i+1 < len(args) {
				i++
				proto = args[i]
			}
		}
	}

	if fromZone == "" || toZone == "" {
		fmt.Println("usage: test policy from-zone <zone> to-zone <zone>")
		fmt.Println("       source-ip <ip> destination-ip <ip> destination-port <port> protocol <tcp|udp>")
		return nil
	}

	parsedSrc := net.ParseIP(srcIP)
	parsedDst := net.ParseIP(dstIP)

	// Check zone-pair policies
	for _, zpp := range cfg.Security.Policies {
		if zpp.FromZone != fromZone || zpp.ToZone != toZone {
			continue
		}
		for _, pol := range zpp.Policies {
			if !matchPolicyAddr(pol.Match.SourceAddresses, parsedSrc, cfg) {
				continue
			}
			if !matchPolicyAddr(pol.Match.DestinationAddresses, parsedDst, cfg) {
				continue
			}
			if !matchPolicyApp(pol.Match.Applications, proto, dstPort, cfg) {
				continue
			}
			action := "permit"
			switch pol.Action {
			case 1:
				action = "deny"
			case 2:
				action = "reject"
			}
			fmt.Printf("Policy match:\n")
			fmt.Printf("  From zone: %s\n  To zone:   %s\n", fromZone, toZone)
			fmt.Printf("  Policy:    %s\n", pol.Name)
			fmt.Printf("  Action:    %s\n", action)
			if srcIP != "" {
				fmt.Printf("  Source:    %s -> ", srcIP)
			} else {
				fmt.Printf("  Source:    any -> ")
			}
			if dstIP != "" {
				fmt.Printf("%s", dstIP)
			} else {
				fmt.Printf("any")
			}
			if dstPort > 0 {
				fmt.Printf(":%d", dstPort)
			}
			if proto != "" {
				fmt.Printf(" [%s]", proto)
			}
			fmt.Println()
			return nil
		}
	}

	// Check global policies
	for _, pol := range cfg.Security.GlobalPolicies {
		if !matchPolicyAddr(pol.Match.SourceAddresses, parsedSrc, cfg) {
			continue
		}
		if !matchPolicyAddr(pol.Match.DestinationAddresses, parsedDst, cfg) {
			continue
		}
		if !matchPolicyApp(pol.Match.Applications, proto, dstPort, cfg) {
			continue
		}
		action := "permit"
		switch pol.Action {
		case 1:
			action = "deny"
		case 2:
			action = "reject"
		}
		fmt.Printf("Policy match (global):\n")
		fmt.Printf("  Policy:    %s\n", pol.Name)
		fmt.Printf("  Action:    %s\n", action)
		return nil
	}

	fmt.Printf("Default deny (no matching policy for %s -> %s)\n", fromZone, toZone)
	return nil
}

// testRouting looks up a destination in the routing table.
func (c *CLI) testRouting(args []string) error {
	if c.routing == nil {
		fmt.Println("Routing manager not available")
		return nil
	}

	var dest, instance string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "destination":
			if i+1 < len(args) {
				i++
				dest = args[i]
			}
		case "instance":
			if i+1 < len(args) {
				i++
				instance = args[i]
			}
		}
	}

	if dest == "" {
		fmt.Println("usage: test routing destination <ip-or-prefix> [instance <name>]")
		return nil
	}

	var entries []routing.RouteEntry
	var err error
	if instance != "" {
		entries, err = c.routing.GetVRFRoutes(instance)
	} else {
		entries, err = c.routing.GetRoutes()
	}
	if err != nil {
		return fmt.Errorf("get routes: %w", err)
	}

	// Normalize dest to CIDR for matching
	filterCIDR := dest
	if !strings.Contains(filterCIDR, "/") {
		if strings.Contains(filterCIDR, ":") {
			filterCIDR += "/128"
		} else {
			filterCIDR += "/32"
		}
	}
	filterIP, _, filterErr := net.ParseCIDR(filterCIDR)
	if filterErr != nil {
		filterIP = net.ParseIP(dest)
	}

	// Find the best (longest prefix) match
	var best *routing.RouteEntry
	bestLen := -1
	for i := range entries {
		_, rNet, err := net.ParseCIDR(entries[i].Destination)
		if err != nil {
			continue
		}
		if filterIP != nil && rNet.Contains(filterIP) {
			ones, _ := rNet.Mask.Size()
			if ones > bestLen {
				bestLen = ones
				best = &entries[i]
			}
		}
	}

	if instance != "" {
		fmt.Printf("Routing lookup in instance %s for %s:\n", instance, dest)
	} else {
		fmt.Printf("Routing lookup for %s:\n", dest)
	}
	if best == nil {
		fmt.Println("  No matching route found")
	} else {
		fmt.Printf("  Destination: %s\n", best.Destination)
		fmt.Printf("  Next-hop:    %s\n", best.NextHop)
		fmt.Printf("  Interface:   %s\n", best.Interface)
		fmt.Printf("  Protocol:    %s\n", best.Protocol)
		fmt.Printf("  Preference:  %d\n", best.Preference)
	}
	return nil
}

// testSecurityZone looks up which zone an interface belongs to.
func (c *CLI) testSecurityZone(args []string) error {
	cfg := c.store.ActiveConfig()
	if cfg == nil {
		fmt.Println("No active configuration")
		return nil
	}

	var ifName string
	for i := 0; i < len(args); i++ {
		if args[i] == "interface" && i+1 < len(args) {
			i++
			ifName = args[i]
		}
	}

	if ifName == "" {
		fmt.Println("usage: test security-zone interface <name>")
		return nil
	}

	for zoneName, zone := range cfg.Security.Zones {
		for _, iface := range zone.Interfaces {
			if iface == ifName {
				fmt.Printf("Interface %s belongs to zone: %s\n", ifName, zoneName)
				if zone.Description != "" {
					fmt.Printf("  Description: %s\n", zone.Description)
				}
				if zone.ScreenProfile != "" {
					fmt.Printf("  Screen:      %s\n", zone.ScreenProfile)
				}
				if zone.HostInboundTraffic != nil {
					if len(zone.HostInboundTraffic.SystemServices) > 0 {
						fmt.Printf("  Host-inbound services: %s\n", strings.Join(zone.HostInboundTraffic.SystemServices, ", "))
					}
					if len(zone.HostInboundTraffic.Protocols) > 0 {
						fmt.Printf("  Host-inbound protocols: %s\n", strings.Join(zone.HostInboundTraffic.Protocols, ", "))
					}
				}
				return nil
			}
		}
	}

	fmt.Printf("Interface %s is not assigned to any security zone\n", ifName)
	return nil
}

// handleMonitor dispatches monitor sub-commands.
func (c *CLI) handleMonitor(args []string) error {
	monTree := operationalTree["monitor"].Children
	if len(args) == 0 {
		fmt.Println("monitor:")
		writeCompletionHelp(os.Stdout, treeHelpCandidates(monTree))
		return nil
	}

	resolved, err := resolveCommand(args[0], keysFromTree(monTree))
	if err != nil {
		return err
	}

	switch resolved {
	case "traffic":
		return c.handleMonitorTraffic(args[1:])
	case "interface":
		return c.handleMonitorInterface(args[1:])
	case "security":
		return c.handleMonitorSecurity(args[1:])
	default:
		return fmt.Errorf("unknown monitor target: %s", resolved)
	}
}

// handleMonitorTraffic wraps tcpdump for live packet capture.
func (c *CLI) handleMonitorTraffic(args []string) error {
	var iface, filter string
	count := "0" // 0 = unlimited

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "interface":
			if i+1 < len(args) {
				i++
				iface = args[i]
			}
		case "matching":
			if i+1 < len(args) {
				i++
				filter = args[i]
			}
		case "count":
			if i+1 < len(args) {
				i++
				count = args[i]
			}
		}
	}

	if iface == "" {
		fmt.Println("usage: monitor traffic interface <name> [matching <filter>] [count <N>]")
		return nil
	}

	// Resolve fabric IPVLAN overlays to physical parent (#136).
	origName := iface
	iface = resolveFabricParent(iface)

	// Warn about XDP redirect visibility on fabric interfaces (#138).
	if strings.HasPrefix(origName, "fab") || strings.HasPrefix(origName, "em") {
		fmt.Println("WARNING: XDP-redirected packets bypass AF_PACKET and will not appear in tcpdump.")
		fmt.Println("For fabric redirect telemetry, use: show chassis cluster fabric statistics")
		fmt.Println()
	}

	cmdArgs := []string{"tcpdump", "-i", iface, "-n", "-l"}
	if count != "0" {
		cmdArgs = append(cmdArgs, "-c", count)
	}
	if filter != "" {
		cmdArgs = append(cmdArgs, filter)
	}

	fmt.Printf("Monitoring traffic on %s (Ctrl+C to stop)...\n", iface)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c.cmdMu.Lock()
	c.cmdCancel = cancel
	c.cmdMu.Unlock()
	defer func() {
		c.cmdMu.Lock()
		c.cmdCancel = nil
		c.cmdMu.Unlock()
	}()

	cmd := exec.CommandContext(ctx, cmdArgs[0], cmdArgs[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if ctx.Err() != nil {
		fmt.Println() // newline after ^C
		return nil
	}
	return err
}

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

func (c *CLI) handleRequestChassis(args []string) error {
	if len(args) == 0 || args[0] != "cluster" {
		fmt.Println("request chassis:")
		writeCompletionHelp(os.Stdout, treeHelpCandidates(operationalTree["request"].Children["chassis"].Children))
		return nil
	}
	args = args[1:] // consume "cluster"
	if len(args) == 0 {
		fmt.Println("request chassis cluster:")
		writeCompletionHelp(os.Stdout, treeHelpCandidates(operationalTree["request"].Children["chassis"].Children["cluster"].Children))
		return nil
	}
	switch args[0] {
	case "failover":
		return c.handleRequestChassisClusterFailover(args[1:])
	case "data-plane":
		return c.handleRequestChassisClusterDataPlane(args[1:])
	default:
		fmt.Println("request chassis cluster:")
		writeCompletionHelp(os.Stdout, treeHelpCandidates(operationalTree["request"].Children["chassis"].Children["cluster"].Children))
		return nil
	}
}

func (c *CLI) handleRequestChassisClusterFailover(args []string) error {
	if c.cluster == nil {
		return fmt.Errorf("cluster not configured")
	}
	// "request chassis cluster failover reset redundancy-group <N>"
	if len(args) >= 1 && args[0] == "reset" {
		if len(args) < 3 || args[1] != "redundancy-group" {
			return fmt.Errorf("usage: request chassis cluster failover reset redundancy-group <N>")
		}
		rgID, err := strconv.Atoi(args[2])
		if err != nil {
			return fmt.Errorf("invalid redundancy-group ID: %s", args[2])
		}
		if err := c.cluster.ResetFailover(rgID); err != nil {
			return err
		}
		fmt.Printf("Failover reset for redundancy group %d\n", rgID)
		return nil
	}

	// "request chassis cluster failover data node <N>"
	if len(args) >= 3 && args[0] == "data" && args[1] == "node" {
		targetNode, err := strconv.Atoi(args[2])
		if err != nil {
			return fmt.Errorf("invalid node ID: %s", args[2])
		}
		if !cluster.IsSupportedClusterNodeID(targetNode) {
			return fmt.Errorf("unsupported cluster failover target node %d", targetNode)
		}
		localNode := c.cluster.NodeID()
		if targetNode != localNode {
			message, err := c.requestPeerSystemAction(
				context.Background(),
				fmt.Sprintf("cluster-failover-data:node%d", targetNode),
			)
			if err != nil {
				return err
			}
			fmt.Println(message)
			return nil
		}

		dataRGs := c.cluster.DataGroupIDs()
		if len(dataRGs) == 0 {
			return fmt.Errorf("no data redundancy groups configured")
		}
		moveRGs := make([]int, 0, len(dataRGs))
		for _, rgID := range dataRGs {
			if !c.cluster.IsLocalPrimary(rgID) {
				moveRGs = append(moveRGs, rgID)
			}
		}
		if len(moveRGs) == 0 {
			fmt.Printf("All data redundancy groups are already primary on node %d\n", targetNode)
			return nil
		}
		if len(moveRGs) == 1 {
			if err := c.cluster.RequestPeerFailover(moveRGs[0]); err != nil {
				return err
			}
		} else {
			if err := c.cluster.RequestPeerFailoverBatch(moveRGs); err != nil {
				return err
			}
		}
		fmt.Printf("Manual failover completed for data redundancy groups %v (transfer committed)\n", moveRGs)
		return nil
	}

	// "request chassis cluster failover redundancy-group <N> [node <N>]"
	if len(args) >= 2 && args[0] == "redundancy-group" {
		rgID, err := strconv.Atoi(args[1])
		if err != nil {
			return fmt.Errorf("invalid redundancy-group ID: %s", args[1])
		}

		// If "node <N>" is specified, route to the correct node.
		if len(args) >= 4 && args[2] == "node" {
			targetNode, err := strconv.Atoi(args[3])
			if err != nil {
				return fmt.Errorf("invalid node ID: %s", args[3])
			}
			localNode := c.cluster.NodeID()
			if targetNode == localNode {
				if err := c.cluster.RequestPeerFailover(rgID); err != nil {
					return err
				}
				fmt.Printf("Manual failover completed for redundancy group %d (transfer committed)\n", rgID)
				return nil
			}
			message, err := c.requestPeerSystemAction(
				context.Background(),
				fmt.Sprintf("cluster-failover:%d:node%d", rgID, targetNode),
			)
			if err != nil {
				return err
			}
			fmt.Println(message)
			return nil
		}

		if err := c.cluster.ManualFailover(rgID); err != nil {
			return err
		}
		fmt.Printf("Manual failover triggered for redundancy group %d\n", rgID)
		return nil
	}

	return fmt.Errorf("usage: request chassis cluster failover {redundancy-group <N> [node <N>] | data node <N>}")
}

func (c *CLI) handleRequestChassisClusterDataPlane(args []string) error {
	if len(args) == 0 || args[0] != "userspace" {
		fmt.Println("request chassis cluster data-plane:")
		writeCompletionHelp(os.Stdout, treeHelpCandidates(operationalTree["request"].Children["chassis"].Children["cluster"].Children["data-plane"].Children))
		return nil
	}
	provider, err := c.userspaceDataplaneControl()
	if err != nil {
		return err
	}
	args = args[1:]

	var status dpuserspace.ProcessStatus
	switch {
	case len(args) > 0 && args[0] == "inject-packet":
		slot, mode, extra, err := dpuserspace.ParseInjectPacketCommand(args)
		if err != nil {
			return err
		}
		status, err = provider.Status()
		if err != nil {
			return err
		}
		req, err := dpuserspace.BuildInjectPacketRequest(slot, mode, extra, status)
		if err != nil {
			return err
		}
		status, err = provider.InjectPacket(req)
		if err != nil {
			return err
		}
	case len(args) > 0 && args[0] == "forwarding":
		armed, err := dpuserspace.ParseForwardingCommand(args)
		if err != nil {
			return err
		}
		status, err = provider.SetForwardingArmed(armed)
		if err != nil {
			return err
		}
	case len(args) > 0 && args[0] == "queue":
		queueID, registered, armed, err := dpuserspace.ParseQueueCommand(args)
		if err != nil {
			return err
		}
		status, err = provider.SetQueueState(queueID, registered, armed)
		if err != nil {
			return err
		}
	case len(args) > 0 && args[0] == "binding":
		slot, registered, armed, err := dpuserspace.ParseBindingCommand(args)
		if err != nil {
			return err
		}
		status, err = provider.SetBindingState(slot, registered, armed)
		if err != nil {
			return err
		}
	default:
		fmt.Println("request chassis cluster data-plane userspace:")
		writeCompletionHelp(os.Stdout, treeHelpCandidates(operationalTree["request"].Children["chassis"].Children["cluster"].Children["data-plane"].Children["userspace"].Children))
		return nil
	}
	fmt.Print(dpuserspace.FormatStatusSummary(status))
	fmt.Println()
	fmt.Print(dpuserspace.FormatBindings(status))
	return nil
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

func (c *CLI) handleRequestSystem(args []string) error {
	if len(args) == 0 {
		fmt.Println("request system:")
		writeCompletionHelp(os.Stdout, treeHelpCandidates(operationalTree["request"].Children["system"].Children))
		return nil
	}

	switch args[0] {
	case "reboot":
		fmt.Print("Reboot the system? [yes,no] (no) ")
		c.rl.SetPrompt("")
		line, err := c.rl.Readline()
		c.rl.SetPrompt(c.operationalPrompt())
		if err != nil || strings.TrimSpace(strings.ToLower(line)) != "yes" {
			fmt.Println("Reboot cancelled")
			return nil
		}
		fmt.Println("System going down for reboot NOW!")
		cmd := exec.Command("systemctl", "reboot")
		return cmd.Run()

	case "halt":
		fmt.Print("Halt the system? [yes,no] (no) ")
		c.rl.SetPrompt("")
		line, err := c.rl.Readline()
		c.rl.SetPrompt(c.operationalPrompt())
		if err != nil || strings.TrimSpace(strings.ToLower(line)) != "yes" {
			fmt.Println("Halt cancelled")
			return nil
		}
		fmt.Println("System halting NOW!")
		cmd := exec.Command("systemctl", "halt")
		return cmd.Run()

	case "power-off":
		fmt.Print("Power off the system? [yes,no] (no) ")
		c.rl.SetPrompt("")
		line, err := c.rl.Readline()
		c.rl.SetPrompt(c.operationalPrompt())
		if err != nil || strings.TrimSpace(strings.ToLower(line)) != "yes" {
			fmt.Println("Power-off cancelled")
			return nil
		}
		fmt.Println("System powering off NOW!")
		cmd := exec.Command("systemctl", "poweroff")
		return cmd.Run()

	case "zeroize":
		fmt.Println("WARNING: This will erase all configuration and return to factory defaults.")
		fmt.Print("Zeroize the system? [yes,no] (no) ")
		c.rl.SetPrompt("")
		line, err := c.rl.Readline()
		c.rl.SetPrompt(c.operationalPrompt())
		if err != nil || strings.TrimSpace(strings.ToLower(line)) != "yes" {
			fmt.Println("Zeroize cancelled")
			return nil
		}

		// Remove active and candidate configs, rollback history
		configDir := "/etc/xpf"
		files, _ := os.ReadDir(configDir)
		for _, f := range files {
			if strings.HasSuffix(f.Name(), ".conf") || strings.HasPrefix(f.Name(), "rollback") {
				os.Remove(configDir + "/" + f.Name())
			}
		}

		// Remove BPF pins
		os.RemoveAll("/sys/fs/bpf/xpf")

		// Remove managed networkd files
		ndFiles, _ := os.ReadDir("/etc/systemd/network")
		for _, f := range ndFiles {
			if strings.HasPrefix(f.Name(), "10-xpf-") {
				os.Remove("/etc/systemd/network/" + f.Name())
			}
		}

		// Remove FRR managed section
		exec.Command("systemctl", "stop", "xpfd").Run()

		fmt.Println("System zeroized. Configuration erased.")
		fmt.Println("Reboot to complete factory reset.")
		return nil

	case "configuration":
		return c.handleRequestSystemConfiguration(args[1:])

	case "software":
		return c.handleRequestSystemSoftware(args[1:])

	default:
		return fmt.Errorf("unknown request system command: %s", args[0])
	}
}

func (c *CLI) handleRequestSystemSoftware(args []string) error {
	if len(args) == 0 {
		fmt.Println("request system software:")
		writeCompletionHelp(os.Stdout, treeHelpCandidates(operationalTree["request"].Children["system"].Children["software"].Children))
		return nil
	}

	if args[0] != "in-service-upgrade" {
		return fmt.Errorf("unknown request system software command: %s", args[0])
	}

	if c.cluster == nil {
		fmt.Println("Cluster not configured")
		return nil
	}

	fmt.Println("WARNING: This will force this node to secondary for all redundancy groups.")
	fmt.Print("Proceed with in-service upgrade? [yes,no] (no) ")
	c.rl.SetPrompt("")
	line, err := c.rl.Readline()
	c.rl.SetPrompt(c.operationalPrompt())
	if err != nil || strings.TrimSpace(strings.ToLower(line)) != "yes" {
		fmt.Println("ISSU cancelled")
		return nil
	}

	if err := c.cluster.ForceSecondary(); err != nil {
		return fmt.Errorf("ISSU: %v", err)
	}

	fmt.Println("Node is now secondary for all redundancy groups.")
	fmt.Println("Traffic has been drained to peer.")
	fmt.Println("You may now replace the binary and restart the service:")
	fmt.Println("  systemctl stop xpfd && <replace binary> && systemctl start xpfd")
	return nil
}

func (c *CLI) handleRequestSystemConfiguration(args []string) error {
	if len(args) == 0 {
		fmt.Println("request system configuration:")
		writeCompletionHelp(os.Stdout, treeHelpCandidates(operationalTree["request"].Children["system"].Children["configuration"].Children))
		return nil
	}

	if args[0] != "rescue" {
		return fmt.Errorf("unknown request system configuration command: %s", args[0])
	}

	if len(args) < 2 {
		fmt.Println("request system configuration rescue:")
		writeCompletionHelp(os.Stdout, treeHelpCandidates(operationalTree["request"].Children["system"].Children["configuration"].Children["rescue"].Children))
		return nil
	}

	switch args[1] {
	case "save":
		if err := c.store.SaveRescueConfig(); err != nil {
			return err
		}
		fmt.Println("Rescue configuration saved")
		return nil

	case "delete":
		if err := c.store.DeleteRescueConfig(); err != nil {
			return err
		}
		fmt.Println("Rescue configuration deleted")
		return nil

	default:
		return fmt.Errorf("unknown request system configuration rescue command: %s", args[1])
	}
}

func (c *CLI) handleRequestSecurity(args []string) error {
	if len(args) == 0 {
		fmt.Println("request security:")
		writeCompletionHelp(os.Stdout, treeHelpCandidates(operationalTree["request"].Children["security"].Children))
		return nil
	}
	if args[0] != "ipsec" {
		return fmt.Errorf("unknown request security target: %s", args[0])
	}
	if len(args) < 3 || args[1] != "sa" || args[2] != "clear" {
		fmt.Println("request security ipsec sa:")
		writeCompletionHelp(os.Stdout, treeHelpCandidates(operationalTree["request"].Children["security"].Children["ipsec"].Children["sa"].Children))
		return nil
	}
	if c.ipsec == nil {
		return fmt.Errorf("IPsec manager not available")
	}
	count, err := c.ipsec.TerminateAllSAs()
	if err != nil {
		return err
	}
	fmt.Printf("Cleared %d IPsec SA(s)\n", count)
	return nil
}
