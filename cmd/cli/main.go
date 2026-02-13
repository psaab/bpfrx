// cli is the remote CLI client for bpfrxd.
//
// It connects to the bpfrxd gRPC API and provides the same Junos-style
// interactive CLI as the embedded console.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/chzyer/readline"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "github.com/psaab/bpfrx/pkg/grpcapi/bpfrxv1"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:50051", "bpfrxd gRPC address")
	flag.Parse()

	conn, err := grpc.NewClient(*addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		fmt.Fprintf(os.Stderr, "cli: connect: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	client := pb.NewBpfrxServiceClient(conn)

	// Verify connectivity
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	resp, err := client.GetStatus(ctx, &pb.GetStatusRequest{})
	cancel()
	if err != nil {
		fmt.Fprintf(os.Stderr, "cli: cannot reach bpfrxd at %s: %v\n", *addr, err)
		os.Exit(1)
	}

	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "bpfrx"
	}
	username := os.Getenv("USER")
	if username == "" {
		username = "remote"
	}

	c := &ctl{
		client:     client,
		hostname:   hostname,
		username:   username,
		configMode: false,
	}

	rl, err := readline.NewEx(&readline.Config{
		Prompt:          c.operationalPrompt(),
		HistoryFile:     "/tmp/cli_history",
		InterruptPrompt: "^C",
		EOFPrompt:       "exit",
		AutoComplete:    &remoteCompleter{ctl: c},
		Stdin:           os.Stdin,
		Stdout:          os.Stdout,
		Stderr:          os.Stderr,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "cli: readline: %v\n", err)
		os.Exit(1)
	}
	defer rl.Close()
	c.rl = rl

	fmt.Printf("cli — connected to bpfrxd (uptime: %s)\n", resp.Uptime)
	fmt.Println("Type '?' for help")
	fmt.Println()

	for {
		// Show commit confirmed reminder
		if c.configMode {
			st, err := client.GetConfigModeStatus(context.Background(), &pb.GetConfigModeStatusRequest{})
			if err == nil && st.ConfirmPending {
				fmt.Println("[commit confirmed pending - issue 'commit' to confirm]")
			}
		}

		line, err := rl.Readline()
		if err != nil {
			if err == readline.ErrInterrupt {
				continue
			}
			if err == io.EOF {
				break
			}
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			break
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if err := c.dispatch(line); err != nil {
			if err == errExit {
				break
			}
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
		}
	}

	// Clean exit: leave config mode if active
	if c.configMode {
		_, _ = client.ExitConfigure(context.Background(), &pb.ExitConfigureRequest{})
	}
}

var errExit = fmt.Errorf("exit")

type ctl struct {
	client     pb.BpfrxServiceClient
	rl         *readline.Instance
	hostname   string
	username   string
	configMode bool
}

func (c *ctl) dispatch(line string) error {
	if strings.HasSuffix(line, "?") {
		c.showContextHelp(strings.TrimSuffix(line, "?"))
		return nil
	}

	// Extract pipe filter (| match, | except, | count, | last, | no-more).
	// Skip | display set and | compare.
	if cmd, pipeType, pipeArg, ok := extractPipe(line); ok {
		return c.dispatchWithPipe(cmd, pipeType, pipeArg)
	}

	if c.configMode {
		return c.dispatchConfig(line)
	}
	return c.dispatchOperational(line)
}

// extractPipe splits a line at the last "| <filter>" expression.
func extractPipe(line string) (string, string, string, bool) {
	idx := strings.LastIndex(line, " | ")
	if idx < 0 {
		return line, "", "", false
	}
	cmd := strings.TrimSpace(line[:idx])
	pipe := strings.TrimSpace(line[idx+3:])
	parts := strings.SplitN(pipe, " ", 2)
	pipeType := parts[0]
	var pipeArg string
	if len(parts) > 1 {
		pipeArg = parts[1]
	}
	switch pipeType {
	case "match", "grep", "except", "count", "last", "no-more":
		return cmd, pipeType, pipeArg, true
	default:
		return line, "", "", false
	}
}

// dispatchWithPipe runs the command and applies the pipe filter.
func (c *ctl) dispatchWithPipe(cmd, pipeType, pipeArg string) error {
	origStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("pipe: %w", err)
	}
	os.Stdout = w

	var cmdErr error
	done := make(chan struct{})
	go func() {
		defer close(done)
		cmdErr = c.dispatch(cmd)
	}()
	<-done
	w.Close()
	os.Stdout = origStdout

	output, _ := io.ReadAll(r)
	r.Close()

	lines := strings.Split(string(output), "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}

	switch pipeType {
	case "match", "grep":
		lp := strings.ToLower(pipeArg)
		for _, line := range lines {
			if strings.Contains(strings.ToLower(line), lp) {
				fmt.Fprintln(origStdout, line)
			}
		}
	case "except":
		lp := strings.ToLower(pipeArg)
		for _, line := range lines {
			if !strings.Contains(strings.ToLower(line), lp) {
				fmt.Fprintln(origStdout, line)
			}
		}
	case "count":
		fmt.Fprintf(origStdout, "Count: %d lines\n", len(lines))
	case "last":
		n := 10
		if pipeArg != "" {
			if v, err := strconv.Atoi(pipeArg); err == nil && v > 0 {
				n = v
			}
		}
		start := len(lines) - n
		if start < 0 {
			start = 0
		}
		for _, line := range lines[start:] {
			fmt.Fprintln(origStdout, line)
		}
	case "no-more":
		for _, line := range lines {
			fmt.Fprintln(origStdout, line)
		}
	}
	return cmdErr
}

func (c *ctl) dispatchOperational(line string) error {
	parts := strings.Fields(line)
	if len(parts) == 0 {
		return nil
	}

	switch parts[0] {
	case "configure":
		_, err := c.client.EnterConfigure(context.Background(), &pb.EnterConfigureRequest{})
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		c.configMode = true
		c.rl.SetPrompt(c.configPrompt())
		fmt.Println("Entering configuration mode")
		fmt.Println("[edit]")
		return nil

	case "show":
		if len(parts) >= 2 && parts[1] == "version" {
			return c.showText("version")
		}
		return c.handleShow(parts[1:])

	case "clear":
		return c.handleClear(parts[1:])

	case "ping":
		return c.handlePing(parts[1:])

	case "traceroute":
		return c.handleTraceroute(parts[1:])

	case "request":
		return c.handleRequest(parts[1:])

	case "quit", "exit":
		return errExit

	case "?", "help":
		c.showOperationalHelp()
		return nil

	default:
		return fmt.Errorf("unknown command: %s", parts[0])
	}
}

func (c *ctl) dispatchConfig(line string) error {
	parts := strings.Fields(line)
	if len(parts) == 0 {
		return nil
	}

	switch parts[0] {
	case "set":
		if len(parts) < 2 {
			return fmt.Errorf("set: missing path")
		}
		_, err := c.client.Set(context.Background(), &pb.SetRequest{
			Input: strings.Join(parts[1:], " "),
		})
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		return nil

	case "delete":
		if len(parts) < 2 {
			return fmt.Errorf("delete: missing path")
		}
		_, err := c.client.Delete(context.Background(), &pb.DeleteRequest{
			Input: strings.Join(parts[1:], " "),
		})
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		return nil

	case "show":
		return c.handleConfigShow(parts[1:])

	case "commit":
		return c.handleCommit(parts[1:])

	case "rollback":
		n := int32(0)
		if len(parts) >= 2 {
			if v, err := strconv.Atoi(parts[1]); err == nil {
				n = int32(v)
			}
		}
		_, err := c.client.Rollback(context.Background(), &pb.RollbackRequest{N: n})
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		fmt.Println("configuration rolled back")
		return nil

	case "load":
		return c.handleLoad(parts[1:])

	case "run":
		if len(parts) < 2 {
			return fmt.Errorf("run: missing command")
		}
		return c.dispatchOperational(strings.Join(parts[1:], " "))

	case "exit", "quit":
		_, _ = c.client.ExitConfigure(context.Background(), &pb.ExitConfigureRequest{})
		c.configMode = false
		c.rl.SetPrompt(c.operationalPrompt())
		fmt.Println("Exiting configuration mode")
		return nil

	case "?", "help":
		c.showConfigHelp()
		return nil

	default:
		return fmt.Errorf("unknown command: %s (in configuration mode)", parts[0])
	}
}

func (c *ctl) handleShow(args []string) error {
	if len(args) == 0 {
		fmt.Println("show: specify what to show")
		fmt.Println("  chassis          Show hardware information")
		fmt.Println("  configuration    Show active configuration")
		fmt.Println("  dhcp             Show DHCP information")
		fmt.Println("  dhcp-relay       Show DHCP relay status")
		fmt.Println("  dhcp-server      Show DHCP server leases")
		fmt.Println("  firewall         Show firewall filters")
		fmt.Println("  flow-monitoring  Show flow monitoring/NetFlow configuration")
		fmt.Println("  log              Show daemon log entries")
		fmt.Println("  route            Show routing table")
		fmt.Println("  schedulers       Show policy schedulers")
		fmt.Println("  security         Show security information")
		fmt.Println("  services         Show services information")
		fmt.Println("  snmp             Show SNMP statistics")
		fmt.Println("  interfaces       Show interface status")
		fmt.Println("  protocols        Show protocol information")
		fmt.Println("  system           Show system information")
		fmt.Println("  policy-options   Show prefix-lists and policy-statements")
		fmt.Println("  event-options    Show event-driven policies")
		fmt.Println("  routing-instances Show VRF/virtual-router instances")
		fmt.Println("  routing-options  Show static routes and routing config")
		fmt.Println("  forwarding-options Show forwarding/sampling config")
		fmt.Println("  version          Show software version")
		return nil
	}

	switch args[0] {
	case "chassis":
		if len(args) >= 2 {
			switch args[1] {
			case "cluster":
				return c.showText("chassis-cluster")
			case "environment":
				return c.showText("chassis-environment")
			}
		}
		return c.showText("chassis")

	case "configuration":
		format := pb.ConfigFormat_HIERARCHICAL
		rest := strings.Join(args[1:], " ")
		if strings.Contains(rest, "| display json") {
			format = pb.ConfigFormat_JSON
		} else if strings.Contains(rest, "| display set") {
			format = pb.ConfigFormat_SET
		}
		// Extract path components (everything after "configuration" before "|")
		var path []string
		for _, a := range args[1:] {
			if a == "|" {
				break
			}
			path = append(path, a)
		}
		resp, err := c.client.ShowConfig(context.Background(), &pb.ShowConfigRequest{
			Format: format,
			Target: pb.ConfigTarget_ACTIVE,
			Path:   path,
		})
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		if resp.Output == "" && len(path) > 0 {
			fmt.Printf("configuration path not found: %s\n", strings.Join(path, " "))
		} else {
			fmt.Print(resp.Output)
		}
		return nil

	case "dhcp":
		if len(args) >= 2 {
			switch args[1] {
			case "leases":
				return c.showDHCPLeases()
			case "client-identifier":
				return c.showDHCPClientIdentifier()
			}
		}
		fmt.Println("show dhcp:")
		fmt.Println("  leases              Show DHCP leases")
		fmt.Println("  client-identifier   Show DHCPv6 DUID(s)")
		return nil

	case "route":
		if len(args) >= 2 && args[1] == "summary" {
			return c.showText("route-summary")
		}
		if len(args) >= 3 && args[1] == "instance" {
			return c.showTextFiltered("route-instance", args[2])
		}
		if len(args) >= 3 && args[1] == "table" {
			return c.showText("route-table:" + args[2])
		}
		if len(args) >= 3 && args[1] == "protocol" {
			return c.showText("route-protocol:" + args[2])
		}
		// Single arg: treat as prefix filter (e.g. "show route 10.0.1.0/24")
		if len(args) >= 2 && (strings.Contains(args[1], "/") || strings.Contains(args[1], ".") || strings.Contains(args[1], ":")) {
			return c.showText("route-prefix:" + args[1])
		}
		return c.showRoutes()

	case "security":
		return c.handleShowSecurity(args[1:])

	case "interfaces":
		return c.showInterfaces(args[1:])

	case "protocols":
		return c.handleShowProtocols(args[1:])

	case "system":
		return c.handleShowSystem(args[1:])

	case "schedulers":
		return c.showText("schedulers")

	case "snmp":
		return c.showText("snmp")

	case "dhcp-relay":
		return c.showText("dhcp-relay")

	case "dhcp-server":
		return c.showText("dhcp-server")

	case "firewall":
		return c.showText("firewall")

	case "flow-monitoring":
		return c.showText("flow-monitoring")

	case "log":
		if len(args) > 1 {
			// show log <filename> [count]
			return c.showText("log:" + strings.Join(args[1:], ":"))
		}
		return c.showText("log")

	case "services":
		return c.handleShowServices(args[1:])

	case "version":
		return c.showText("version")

	case "arp":
		return c.showSystemInfo("arp")

	case "ipv6":
		if len(args) >= 2 && args[1] == "neighbors" {
			return c.showSystemInfo("ipv6-neighbors")
		}
		fmt.Println("show ipv6:")
		fmt.Println("  neighbors        Show IPv6 neighbor cache")
		return nil

	case "policy-options":
		return c.showText("policy-options")

	case "event-options":
		return c.showText("event-options")

	case "routing-options":
		return c.showText("routing-options")

	case "routing-instances":
		return c.showText("routing-instances")

	case "forwarding-options":
		return c.showText("forwarding-options")

	default:
		return fmt.Errorf("unknown show target: %s", args[0])
	}
}

func (c *ctl) handleShowServices(args []string) error {
	if len(args) == 0 {
		fmt.Println("show services:")
		fmt.Println("  rpm              Show RPM probe results")
		return nil
	}
	switch args[0] {
	case "rpm":
		return c.showText("rpm")
	default:
		return fmt.Errorf("unknown services target: %s", args[0])
	}
}

func (c *ctl) handleShowSecurity(args []string) error {
	if len(args) == 0 {
		fmt.Println("show security:")
		fmt.Println("  zones            Show security zones")
		fmt.Println("  policies         Show security policies")
		fmt.Println("  policies brief   Show brief policy summary")
		fmt.Println("  policies hit-count  Show policy hit counters")
		fmt.Println("  screen           Show screen/IDS profiles")
		fmt.Println("  flow             Show flow timeouts")
		fmt.Println("  flow session     Show active sessions")
		fmt.Println("  flow traceoptions Show flow trace configuration")
		fmt.Println("  nat              Show NAT information")
		fmt.Println("  address-book     Show address book entries")
		fmt.Println("  applications     Show application definitions")
		fmt.Println("  alg              Show ALG status")
		fmt.Println("  dynamic-address  Show dynamic address feeds")
		fmt.Println("  match-policies   Match 5-tuple against policies")
		fmt.Println("  log              Show recent security events")
		fmt.Println("  statistics       Show global statistics")
		fmt.Println("  ipsec            Show IPsec VPN status")
		fmt.Println("  vrrp             Show VRRP status")
		return nil
	}

	switch args[0] {
	case "zones":
		return c.showZones()
	case "policies":
		if len(args) >= 2 && args[1] == "brief" {
			return c.showPoliciesBrief()
		}
		if len(args) >= 2 && args[1] == "hit-count" {
			// Parse optional from-zone/to-zone filters
			var filterParts []string
			for i := 2; i+1 < len(args); i++ {
				if args[i] == "from-zone" || args[i] == "to-zone" {
					filterParts = append(filterParts, args[i], args[i+1])
					i++
				}
			}
			return c.showTextFiltered("policies-hit-count", strings.Join(filterParts, " "))
		}
		// Parse from-zone/to-zone filter for regular policy display
		var fromZone, toZone string
		for i := 1; i+1 < len(args); i++ {
			switch args[i] {
			case "from-zone":
				i++
				fromZone = args[i]
			case "to-zone":
				i++
				toZone = args[i]
			}
		}
		return c.showPoliciesFiltered(fromZone, toZone)
	case "screen":
		return c.showScreen()
	case "flow":
		if len(args) >= 2 && args[1] == "session" {
			return c.showFlowSession(args[2:])
		}
		if len(args) >= 2 && args[1] == "traceoptions" {
			return c.showText("flow-traceoptions")
		}
		if len(args) >= 2 && args[1] == "statistics" {
			return c.showText("flow-statistics")
		}
		if len(args) == 1 {
			return c.showText("flow-timeouts")
		}
		return fmt.Errorf("usage: show security flow {session|statistics|traceoptions}")
	case "nat":
		return c.handleShowNAT(args[1:])
	case "log":
		return c.showEvents(args[1:])
	case "statistics":
		return c.showStatistics()
	case "ipsec":
		return c.showIPsec(args[1:])
	case "ike":
		return c.showIKE(args[1:])
	case "match-policies":
		return c.showMatchPolicies(args[1:])
	case "vrrp":
		return c.showVRRP()
	case "alg":
		return c.showText("alg")
	case "dynamic-address":
		return c.showText("dynamic-address")
	case "address-book":
		return c.showText("address-book")
	case "applications":
		return c.showText("applications")
	default:
		return fmt.Errorf("unknown show security target: %s", args[0])
	}
}

func (c *ctl) showZones() error {
	resp, err := c.client.GetZones(context.Background(), &pb.GetZonesRequest{})
	if err != nil {
		return fmt.Errorf("%v", err)
	}

	// Fetch policies for cross-reference
	polResp, _ := c.client.GetPolicies(context.Background(), &pb.GetPoliciesRequest{})

	for _, z := range resp.Zones {
		if z.Id > 0 {
			fmt.Printf("Zone: %s (id: %d)\n", z.Name, z.Id)
		} else {
			fmt.Printf("Zone: %s\n", z.Name)
		}
		if z.Description != "" {
			fmt.Printf("  Description: %s\n", z.Description)
		}
		fmt.Printf("  Interfaces: %s\n", strings.Join(z.Interfaces, ", "))
		if z.TcpRst {
			fmt.Println("  TCP RST: enabled")
		}
		if z.ScreenProfile != "" {
			fmt.Printf("  Screen: %s\n", z.ScreenProfile)
		}
		if len(z.HostInboundServices) > 0 {
			fmt.Printf("  Host-inbound services: %s\n", strings.Join(z.HostInboundServices, ", "))
		}
		if z.IngressPackets > 0 || z.EgressPackets > 0 {
			fmt.Println("  Traffic statistics:")
			fmt.Printf("    Input:  %d packets, %d bytes\n", z.IngressPackets, z.IngressBytes)
			fmt.Printf("    Output: %d packets, %d bytes\n", z.EgressPackets, z.EgressBytes)
		}

		// Show policies referencing this zone
		if polResp != nil {
			var refs []string
			for _, pi := range polResp.Policies {
				if pi.FromZone == z.Name || pi.ToZone == z.Name {
					dir := "from"
					peer := pi.ToZone
					if pi.ToZone == z.Name {
						dir = "to"
						peer = pi.FromZone
					}
					refs = append(refs, fmt.Sprintf("%s %s (%d rules)", dir, peer, len(pi.Rules)))
				}
			}
			if len(refs) > 0 {
				fmt.Printf("  Policies: %s\n", strings.Join(refs, ", "))
			}
		}

		fmt.Println()
	}
	return nil
}

func (c *ctl) showPoliciesFiltered(fromZone, toZone string) error {
	resp, err := c.client.GetPolicies(context.Background(), &pb.GetPoliciesRequest{})
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	for _, pi := range resp.Policies {
		if fromZone != "" && pi.FromZone != fromZone {
			continue
		}
		if toZone != "" && pi.ToZone != toZone {
			continue
		}
		fmt.Printf("From zone: %s, To zone: %s\n", pi.FromZone, pi.ToZone)
		for _, rule := range pi.Rules {
			fmt.Printf("  Rule: %s\n", rule.Name)
			if rule.Description != "" {
				fmt.Printf("    Description: %s\n", rule.Description)
			}
			fmt.Printf("    Match: src=%v dst=%v app=%v\n",
				rule.SrcAddresses, rule.DstAddresses, rule.Applications)
			fmt.Printf("    Action: %s\n", rule.Action)
			if rule.HitPackets > 0 || rule.HitBytes > 0 {
				fmt.Printf("    Hit count: %d packets, %d bytes\n", rule.HitPackets, rule.HitBytes)
			}
		}
		fmt.Println()
	}
	return nil
}

func (c *ctl) showScreen() error {
	return c.showText("screen")
}

func (c *ctl) showFlowSession(args []string) error {
	req := &pb.GetSessionsRequest{Limit: 100}
	// Parse filter arguments (matches local CLI's session filter syntax)
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "zone":
			if i+1 < len(args) {
				i++
				if v, err := strconv.ParseUint(args[i], 10, 32); err == nil {
					req.Zone = uint32(v)
				}
			}
		case "protocol":
			if i+1 < len(args) {
				i++
				req.Protocol = strings.ToUpper(args[i])
			}
		case "source-prefix":
			if i+1 < len(args) {
				i++
				req.SourcePrefix = args[i]
			}
		case "destination-prefix":
			if i+1 < len(args) {
				i++
				req.DestinationPrefix = args[i]
			}
		case "source-port":
			if i+1 < len(args) {
				i++
				if v, err := strconv.ParseUint(args[i], 10, 32); err == nil {
					req.SourcePort = uint32(v)
				}
			}
		case "destination-port":
			if i+1 < len(args) {
				i++
				if v, err := strconv.ParseUint(args[i], 10, 32); err == nil {
					req.DestinationPort = uint32(v)
				}
			}
		case "nat":
			req.NatOnly = true
		case "limit":
			if i+1 < len(args) {
				i++
				if v, err := strconv.Atoi(args[i]); err == nil {
					req.Limit = int32(v)
				}
			}
		case "summary":
			return c.showSessionSummary()
		}
	}

	resp, err := c.client.GetSessions(context.Background(), req)
	if err != nil {
		return fmt.Errorf("%v", err)
	}

	for i, se := range resp.Sessions {
		fmt.Printf("Session ID: %d, Policy: %d, State: %s, Timeout: %ds, Age: %ds, Idle: %ds\n",
			i+1, se.PolicyId, se.State, se.TimeoutSeconds, se.AgeSeconds, se.IdleSeconds)
		inZone := se.IngressZoneName
		if inZone == "" {
			inZone = fmt.Sprintf("%d", se.IngressZone)
		}
		outZone := se.EgressZoneName
		if outZone == "" {
			outZone = fmt.Sprintf("%d", se.EgressZone)
		}
		fmt.Printf("  In: %s:%d --> %s:%d;%s, Zone: %s -> %s\n",
			se.SrcAddr, se.SrcPort, se.DstAddr, se.DstPort,
			se.Protocol, inZone, outZone)
		if se.Nat != "" {
			fmt.Printf("  NAT: %s\n", se.Nat)
		}
		fmt.Printf("  Packets: %d/%d, Bytes: %d/%d\n",
			se.FwdPackets, se.RevPackets, se.FwdBytes, se.RevBytes)
	}
	fmt.Printf("Total sessions: %d\n", resp.Total)
	return nil
}

func (c *ctl) showSessionSummary() error {
	resp, err := c.client.GetSessionSummary(context.Background(), &pb.GetSessionSummaryRequest{})
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	fmt.Printf("Session summary:\n")
	fmt.Printf("  Total entries:    %d\n", resp.TotalEntries)
	fmt.Printf("  Forward only:    %d\n", resp.ForwardOnly)
	fmt.Printf("  Established:     %d\n", resp.Established)
	fmt.Printf("  IPv4 sessions:   %d\n", resp.Ipv4Sessions)
	fmt.Printf("  IPv6 sessions:   %d\n", resp.Ipv6Sessions)
	fmt.Printf("  SNAT sessions:   %d\n", resp.SnatSessions)
	fmt.Printf("  DNAT sessions:   %d\n", resp.DnatSessions)
	return nil
}

func (c *ctl) handleShowNAT(args []string) error {
	if len(args) == 0 {
		fmt.Println("show security nat:")
		fmt.Println("  source           Show source NAT rules")
		fmt.Println("  destination                  Show destination NAT rules")
		fmt.Println("  destination summary          Show destination NAT pool summary")
		fmt.Println("  destination pool <name|all>  Show destination NAT pool details")
		fmt.Println("  destination rule-set <name>  Show destination NAT rule-set details")
		fmt.Println("  static           Show static NAT rules")
		fmt.Println("  nat64            Show NAT64 rule-sets")
		return nil
	}
	switch args[0] {
	case "static":
		return c.showText("nat-static")
	case "source":
		if len(args) >= 2 && args[1] == "summary" {
			return c.showNATSourceSummary()
		}
		if len(args) >= 2 && args[1] == "pool" {
			return c.showNATPoolStats()
		}
		if len(args) >= 2 && args[1] == "persistent-nat-table" {
			return c.showText("persistent-nat")
		}
		if len(args) >= 2 && args[1] == "rule" {
			return c.showNATRuleStats("")
		}
		if len(args) >= 3 && args[1] == "rule-set" {
			return c.showNATRuleStats(args[2])
		}
		if len(args) >= 2 && args[1] == "rule-set" {
			return c.showNATRuleStats("")
		}
		resp, err := c.client.GetNATSource(context.Background(), &pb.GetNATSourceRequest{})
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		for _, r := range resp.Rules {
			fmt.Printf("  %s -> %s: %s", r.FromZone, r.ToZone, r.Type)
			if r.Pool != "" {
				fmt.Printf(" (pool: %s)", r.Pool)
			}
			fmt.Println()
		}
		return nil
	case "destination":
		if len(args) >= 2 && args[1] == "summary" {
			return c.showNATDestinationSummary()
		}
		if len(args) >= 2 && args[1] == "pool" {
			return c.showNATDestinationPool()
		}
		if len(args) >= 2 && args[1] == "rule" {
			return c.showNATDNATRuleStats("")
		}
		if len(args) >= 3 && args[1] == "rule-set" {
			return c.showNATDNATRuleStats(args[2])
		}
		if len(args) >= 2 && args[1] == "rule-set" {
			return c.showNATDNATRuleStats("")
		}
		resp, err := c.client.GetNATDestination(context.Background(), &pb.GetNATDestinationRequest{})
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		for _, r := range resp.Rules {
			fmt.Printf("  Rule: %s  dst=%s", r.Name, r.DstAddr)
			if r.DstPort > 0 {
				fmt.Printf(":%d", r.DstPort)
			}
			fmt.Printf(" -> %s", r.TranslateIp)
			if r.TranslatePort > 0 {
				fmt.Printf(":%d", r.TranslatePort)
			}
			fmt.Println()
		}
		return nil
	case "nat64":
		return c.showText("nat64")
	default:
		return fmt.Errorf("unknown show security nat target: %s", args[0])
	}
}

func (c *ctl) showMatchPolicies(args []string) error {
	req := &pb.MatchPoliciesRequest{}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "from-zone":
			if i+1 < len(args) {
				i++
				req.FromZone = args[i]
			}
		case "to-zone":
			if i+1 < len(args) {
				i++
				req.ToZone = args[i]
			}
		case "source-ip":
			if i+1 < len(args) {
				i++
				req.SourceIp = args[i]
			}
		case "destination-ip":
			if i+1 < len(args) {
				i++
				req.DestinationIp = args[i]
			}
		case "destination-port":
			if i+1 < len(args) {
				i++
				if v, err := strconv.Atoi(args[i]); err == nil {
					req.DestinationPort = int32(v)
				}
			}
		case "protocol":
			if i+1 < len(args) {
				i++
				req.Protocol = args[i]
			}
		}
	}

	if req.FromZone == "" || req.ToZone == "" {
		fmt.Println("usage: show security match-policies from-zone <zone> to-zone <zone>")
		fmt.Println("       source-ip <ip> destination-ip <ip> destination-port <port> protocol <tcp|udp>")
		return nil
	}

	resp, err := c.client.MatchPolicies(context.Background(), req)
	if err != nil {
		return fmt.Errorf("%v", err)
	}

	if resp.Matched {
		fmt.Printf("Matching policy:\n")
		fmt.Printf("  From zone: %s, To zone: %s\n", req.FromZone, req.ToZone)
		fmt.Printf("  Policy: %s\n", resp.PolicyName)
		fmt.Printf("    Source addresses: %v\n", resp.SrcAddresses)
		fmt.Printf("    Destination addresses: %v\n", resp.DstAddresses)
		fmt.Printf("    Applications: %v\n", resp.Applications)
		fmt.Printf("    Action: %s\n", resp.Action)
	} else {
		fmt.Printf("No matching policy found for %s -> %s (default deny)\n", req.FromZone, req.ToZone)
	}
	return nil
}

func (c *ctl) showVRRP() error {
	resp, err := c.client.GetVRRPStatus(context.Background(), &pb.GetVRRPStatusRequest{})
	if err != nil {
		return fmt.Errorf("%v", err)
	}

	if len(resp.Instances) == 0 {
		fmt.Println("No VRRP groups configured")
		return nil
	}

	if resp.ServiceStatus != "" {
		fmt.Println(resp.ServiceStatus)
	}

	fmt.Printf("%-14s %-6s %-8s %-10s %-16s %-8s\n",
		"Interface", "Group", "State", "Priority", "VIP", "Preempt")
	for _, inst := range resp.Instances {
		preempt := "no"
		if inst.Preempt {
			preempt = "yes"
		}
		vip := strings.Join(inst.VirtualAddresses, ",")
		fmt.Printf("%-14s %-6d %-8s %-10d %-16s %-8s\n",
			inst.Interface, inst.GroupId, inst.State, inst.Priority, vip, preempt)
	}
	return nil
}

func (c *ctl) showNATSourceSummary() error {
	resp, err := c.client.GetNATPoolStats(context.Background(), &pb.GetNATPoolStatsRequest{})
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	fmt.Printf("Total pools: %d\n", len(resp.Pools))
	fmt.Printf("%-20s %-20s %-8s %-8s %-12s %-12s\n",
		"Pool", "Address", "Ports", "Used", "Available", "Utilization")
	for _, p := range resp.Pools {
		ports := "N/A"
		avail := "N/A"
		util := "N/A"
		if !p.IsInterface {
			ports = fmt.Sprintf("%d", p.TotalPorts)
			avail = fmt.Sprintf("%d", p.AvailablePorts)
			util = p.Utilization
		}
		fmt.Printf("%-20s %-20s %-8s %-8d %-12s %-12s\n",
			p.Name, p.Address, ports, p.UsedPorts, avail, util)
	}
	return nil
}

func (c *ctl) showNATPoolStats() error {
	resp, err := c.client.GetNATPoolStats(context.Background(), &pb.GetNATPoolStatsRequest{})
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	for _, p := range resp.Pools {
		fmt.Printf("Pool name: %s\n", p.Name)
		fmt.Printf("  Address: %s\n", p.Address)
		if !p.IsInterface {
			fmt.Printf("  Ports allocated: %d\n", p.UsedPorts)
			fmt.Printf("  Ports available: %d\n", p.AvailablePorts)
			fmt.Printf("  Utilization: %s\n", p.Utilization)
		} else {
			fmt.Printf("  Active sessions: %d\n", p.UsedPorts)
		}
		fmt.Println()
	}
	return nil
}

func (c *ctl) showNATRuleStats(ruleSet string) error {
	resp, err := c.client.GetNATRuleStats(context.Background(), &pb.GetNATRuleStatsRequest{
		RuleSet: ruleSet,
	})
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	if len(resp.Rules) == 0 {
		if ruleSet != "" {
			fmt.Printf("Rule-set %q not found\n", ruleSet)
		} else {
			fmt.Println("No source NAT rules configured")
		}
		return nil
	}

	curRS := ""
	for _, r := range resp.Rules {
		if r.RuleSet != curRS {
			if curRS != "" {
				fmt.Println()
			}
			curRS = r.RuleSet
			fmt.Printf("Rule-set: %s\n", r.RuleSet)
			fmt.Printf("  From zone: %s  To zone: %s\n", r.FromZone, r.ToZone)
		}
		fmt.Printf("  Rule: %s\n", r.RuleName)
		fmt.Printf("    Match: source %s destination %s\n", r.SourceMatch, r.DestinationMatch)
		fmt.Printf("    Action: %s\n", r.Action)
		fmt.Printf("    Translation hits: %d packets  %d bytes\n", r.HitPackets, r.HitBytes)
	}
	fmt.Println()
	return nil
}

func (c *ctl) showNATDestinationSummary() error {
	resp, err := c.client.GetNATDestination(context.Background(), &pb.GetNATDestinationRequest{})
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	if len(resp.Rules) == 0 {
		fmt.Println("No destination NAT pools configured")
		return nil
	}

	// Build pool info from rules
	type poolInfo struct {
		addr string
		port uint32
	}
	pools := make(map[string]poolInfo)
	for _, r := range resp.Rules {
		if _, ok := pools[r.TranslateIp]; !ok {
			pools[r.TranslateIp] = poolInfo{addr: r.TranslateIp, port: r.TranslatePort}
		}
	}

	// Get hit counters via rule stats
	statsResp, err := c.client.GetNATRuleStats(context.Background(), &pb.GetNATRuleStatsRequest{
		NatType: "destination",
	})
	poolHits := make(map[string]uint64)
	if err == nil {
		for _, r := range statsResp.Rules {
			poolHits[r.Action] += r.HitPackets
		}
	}

	fmt.Printf("Total pools: %d\n", len(pools))
	fmt.Printf("%-20s %-20s %-8s %-12s\n", "Pool", "Address", "Port", "Hits")
	for addr, p := range pools {
		portStr := "-"
		if p.port > 0 {
			portStr = fmt.Sprintf("%d", p.port)
		}
		fmt.Printf("%-20s %-20s %-8s %-12d\n", addr, addr, portStr, poolHits["pool "+addr])
	}
	return nil
}

func (c *ctl) showNATDestinationPool() error {
	resp, err := c.client.GetNATDestination(context.Background(), &pb.GetNATDestinationRequest{})
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	if len(resp.Rules) == 0 {
		fmt.Println("No destination NAT pools configured")
		return nil
	}
	for _, r := range resp.Rules {
		fmt.Printf("Pool: %s\n", r.TranslateIp)
		fmt.Printf("  Address: %s\n", r.TranslateIp)
		if r.TranslatePort > 0 {
			fmt.Printf("  Port: %d\n", r.TranslatePort)
		}
		fmt.Printf("  Rule: %s (dst %s", r.Name, r.DstAddr)
		if r.DstPort > 0 {
			fmt.Printf(":%d", r.DstPort)
		}
		fmt.Println(")")
		fmt.Println()
	}
	return nil
}

func (c *ctl) showNATDNATRuleStats(ruleSet string) error {
	resp, err := c.client.GetNATRuleStats(context.Background(), &pb.GetNATRuleStatsRequest{
		RuleSet: ruleSet,
		NatType: "destination",
	})
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	if len(resp.Rules) == 0 {
		if ruleSet != "" {
			fmt.Printf("Rule-set %q not found\n", ruleSet)
		} else {
			fmt.Println("No destination NAT rules configured")
		}
		return nil
	}

	curRS := ""
	for _, r := range resp.Rules {
		if r.RuleSet != curRS {
			if curRS != "" {
				fmt.Println()
			}
			curRS = r.RuleSet
			fmt.Printf("Rule-set: %s\n", r.RuleSet)
			fmt.Printf("  From zone: %s  To zone: %s\n", r.FromZone, r.ToZone)
		}
		fmt.Printf("  Rule: %s\n", r.RuleName)
		fmt.Printf("    Match destination: %s\n", r.DestinationMatch)
		fmt.Printf("    Action: %s\n", r.Action)
		fmt.Printf("    Translation hits: %d packets  %d bytes\n", r.HitPackets, r.HitBytes)
	}
	fmt.Println()
	return nil
}

func (c *ctl) showEvents(args []string) error {
	req := &pb.GetEventsRequest{Limit: 50}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "zone":
			if i+1 < len(args) {
				i++
				if v, err := strconv.ParseUint(args[i], 10, 32); err == nil {
					req.Zone = uint32(v)
				}
			}
		case "protocol":
			if i+1 < len(args) {
				i++
				req.Protocol = args[i]
			}
		case "action":
			if i+1 < len(args) {
				i++
				req.Action = args[i]
			}
		default:
			if v, err := strconv.Atoi(args[i]); err == nil {
				req.Limit = int32(v)
			}
		}
	}

	resp, err := c.client.GetEvents(context.Background(), req)
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	if len(resp.Events) == 0 {
		fmt.Println("no events recorded")
		return nil
	}
	for _, e := range resp.Events {
		inZone := e.IngressZoneName
		if inZone == "" {
			inZone = fmt.Sprintf("%d", e.IngressZone)
		}
		outZone := e.EgressZoneName
		if outZone == "" {
			outZone = fmt.Sprintf("%d", e.EgressZone)
		}
		fmt.Printf("%s %-14s %s -> %s %s action=%-6s policy=%d zone=%s->%s\n",
			e.Time, e.Type, e.SrcAddr, e.DstAddr, e.Protocol, e.Action,
			e.PolicyId, inZone, outZone)
	}
	fmt.Printf("(%d events shown)\n", len(resp.Events))
	return nil
}

func (c *ctl) showStatistics() error {
	resp, err := c.client.GetGlobalStats(context.Background(), &pb.GetGlobalStatsRequest{})
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	fmt.Println("Global statistics:")
	fmt.Printf("  %-25s %d\n", "RX packets:", resp.RxPackets)
	fmt.Printf("  %-25s %d\n", "TX packets:", resp.TxPackets)
	fmt.Printf("  %-25s %d\n", "Drops:", resp.Drops)
	fmt.Printf("  %-25s %d\n", "Sessions created:", resp.SessionsCreated)
	fmt.Printf("  %-25s %d\n", "Sessions closed:", resp.SessionsClosed)
	fmt.Printf("  %-25s %d\n", "Screen drops:", resp.ScreenDrops)
	fmt.Printf("  %-25s %d\n", "Policy denies:", resp.PolicyDenies)
	fmt.Printf("  %-25s %d\n", "NAT alloc failures:", resp.NatAllocFailures)
	fmt.Printf("  %-25s %d\n", "Host-inbound denies:", resp.HostInboundDenies)
	fmt.Printf("  %-25s %d\n", "Host-inbound allowed:", resp.HostInboundAllowed)
	fmt.Printf("  %-25s %d\n", "TC egress packets:", resp.TcEgressPackets)
	fmt.Printf("  %-25s %d\n", "NAT64 translations:", resp.Nat64Translations)
	return nil
}

func (c *ctl) showFlowStatistics() error {
	resp, err := c.client.GetGlobalStats(context.Background(), &pb.GetGlobalStatsRequest{})
	if err != nil {
		return fmt.Errorf("%v", err)
	}

	fmt.Println("Flow statistics:")
	fmt.Printf("  %-30s %d\n", "Current sessions:", resp.SessionsCreated-resp.SessionsClosed)
	fmt.Printf("  %-30s %d\n", "Sessions created:", resp.SessionsCreated)
	fmt.Printf("  %-30s %d\n", "Sessions closed:", resp.SessionsClosed)
	fmt.Println()
	fmt.Printf("  %-30s %d\n", "Packets received:", resp.RxPackets)
	fmt.Printf("  %-30s %d\n", "Packets transmitted:", resp.TxPackets)
	fmt.Printf("  %-30s %d\n", "Packets dropped:", resp.Drops)
	fmt.Printf("  %-30s %d\n", "TC egress packets:", resp.TcEgressPackets)
	fmt.Println()
	fmt.Printf("  %-30s %d\n", "Policy deny:", resp.PolicyDenies)
	fmt.Printf("  %-30s %d\n", "NAT allocation failures:", resp.NatAllocFailures)
	fmt.Printf("  %-30s %d\n", "NAT64 translations:", resp.Nat64Translations)
	fmt.Println()
	fmt.Printf("  %-30s %d\n", "Host-inbound allowed:", resp.HostInboundAllowed)
	fmt.Printf("  %-30s %d\n", "Host-inbound denied:", resp.HostInboundDenies)

	if resp.ScreenDrops > 0 {
		fmt.Println()
		fmt.Printf("  %-30s %d\n", "Screen drops (total):", resp.ScreenDrops)
		for name, count := range resp.ScreenDropDetails {
			fmt.Printf("    %-28s %d\n", name+":", count)
		}
	}

	return nil
}

func (c *ctl) showIKE(args []string) error {
	if len(args) > 0 && args[0] == "security-associations" {
		resp, err := c.client.GetIPsecSA(context.Background(), &pb.GetIPsecSARequest{})
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		if resp.Output == "" {
			fmt.Println("No IKE security associations")
		} else {
			fmt.Print(resp.Output)
		}
		return nil
	}
	// Show IKE configuration
	return c.showText("ike")
}

func (c *ctl) showIPsec(args []string) error {
	if len(args) > 0 && args[0] == "security-associations" {
		resp, err := c.client.GetIPsecSA(context.Background(), &pb.GetIPsecSARequest{})
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		fmt.Print(resp.Output)
		return nil
	}
	fmt.Println("show security ipsec:")
	fmt.Println("  security-associations  Show IPsec SAs")
	return nil
}

func (c *ctl) showInterfaces(args []string) error {
	if len(args) > 0 && args[0] == "tunnel" {
		return c.showText("tunnels")
	}
	if len(args) > 0 && args[0] == "extensive" {
		return c.showText("interfaces-extensive")
	}
	req := &pb.ShowInterfacesDetailRequest{}
	for _, a := range args {
		if a == "terse" {
			req.Terse = true
		} else {
			req.Filter = a
		}
	}
	resp, err := c.client.ShowInterfacesDetail(context.Background(), req)
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	fmt.Print(resp.Output)
	return nil
}

func (c *ctl) showDHCPLeases() error {
	resp, err := c.client.GetDHCPLeases(context.Background(), &pb.GetDHCPLeasesRequest{})
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	if len(resp.Leases) == 0 {
		fmt.Println("No active DHCP leases")
		return nil
	}
	fmt.Println("DHCP leases:")
	for _, l := range resp.Leases {
		fmt.Printf("  Interface: %s, Family: %s\n", l.Interface, l.Family)
		fmt.Printf("    Address:   %s\n", l.Address)
		if l.Gateway != "" {
			fmt.Printf("    Gateway:   %s\n", l.Gateway)
		}
		if len(l.Dns) > 0 {
			fmt.Printf("    DNS:       %s\n", strings.Join(l.Dns, ", "))
		}
		fmt.Printf("    Lease:     %s\n", l.LeaseTime)
		fmt.Printf("    Obtained:  %s\n", l.Obtained)
		fmt.Println()
	}
	return nil
}

func (c *ctl) showDHCPClientIdentifier() error {
	resp, err := c.client.GetDHCPClientIdentifiers(context.Background(), &pb.GetDHCPClientIdentifiersRequest{})
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	if len(resp.Identifiers) == 0 {
		fmt.Println("No DHCPv6 DUIDs configured")
		return nil
	}
	fmt.Println("DHCPv6 client identifiers:")
	for _, d := range resp.Identifiers {
		fmt.Printf("  Interface: %s\n", d.Interface)
		fmt.Printf("    Type:    %s\n", d.Type)
		fmt.Printf("    DUID:    %s\n", d.Display)
		fmt.Printf("    Hex:     %s\n", d.Hex)
		fmt.Println()
	}
	return nil
}

func (c *ctl) showRoutes() error {
	resp, err := c.client.GetRoutes(context.Background(), &pb.GetRoutesRequest{})
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	if len(resp.Routes) == 0 {
		fmt.Println("No routes")
		return nil
	}
	fmt.Println("Routing table:")
	fmt.Printf("  %-24s %-20s %-14s %-12s %s\n", "Destination", "Next-hop", "Interface", "Proto", "Pref")
	for _, r := range resp.Routes {
		fmt.Printf("  %-24s %-20s %-14s %-12s %d\n", r.Destination, r.NextHop, r.Interface, r.Protocol, r.Preference)
	}
	return nil
}

func (c *ctl) handleShowProtocols(args []string) error {
	if len(args) == 0 {
		fmt.Println("show protocols:")
		fmt.Println("  ospf             Show OSPF information")
		fmt.Println("  bgp              Show BGP information")
		fmt.Println("  rip              Show RIP routes")
		fmt.Println("  isis             Show IS-IS information")
		return nil
	}
	switch args[0] {
	case "ospf":
		typ := "neighbor"
		if len(args) >= 2 {
			typ = args[1]
		}
		resp, err := c.client.GetOSPFStatus(context.Background(), &pb.GetOSPFStatusRequest{Type: typ})
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		fmt.Print(resp.Output)
		return nil
	case "bgp":
		typ := "summary"
		if len(args) >= 2 {
			typ = args[1]
		}
		resp, err := c.client.GetBGPStatus(context.Background(), &pb.GetBGPStatusRequest{Type: typ})
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		fmt.Print(resp.Output)
		return nil
	case "rip":
		resp, err := c.client.GetRIPStatus(context.Background(), &pb.GetRIPStatusRequest{})
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		fmt.Print(resp.Output)
		return nil
	case "isis":
		typ := "adjacency"
		if len(args) >= 2 {
			typ = args[1]
		}
		resp, err := c.client.GetISISStatus(context.Background(), &pb.GetISISStatusRequest{Type: typ})
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		fmt.Print(resp.Output)
		return nil
	default:
		return fmt.Errorf("unknown show protocols target: %s", args[0])
	}
}

func (c *ctl) handleShowSystem(args []string) error {
	if len(args) == 0 {
		fmt.Println("show system:")
		fmt.Println("  alarms             Show system alarms")
		fmt.Println("  backup-router      Show backup router configuration")
		fmt.Println("  buffers            Show BPF map utilization")
		fmt.Println("  internet-options   Show internet options")
		fmt.Println("  license            Show system license")
		fmt.Println("  login              Show configured login users")
		fmt.Println("  memory             Show memory usage")
		fmt.Println("  ntp                Show NTP server status")
		fmt.Println("  processes          Show running processes")
		fmt.Println("  rollback           Show rollback history")
		fmt.Println("  root-authentication Show root authentication")
		fmt.Println("  services           Show configured system services")
		fmt.Println("  storage            Show filesystem usage")
		fmt.Println("  syslog             Show system syslog configuration")
		fmt.Println("  uptime             Show system uptime")
		return nil
	}

	switch args[0] {
	case "rollback":
		if len(args) >= 2 {
			// "show system rollback compare N"
			if args[1] == "compare" && len(args) >= 3 {
				n, err := strconv.Atoi(args[2])
				if err != nil || n < 1 {
					return fmt.Errorf("usage: show system rollback compare <N>")
				}
				resp, err := c.client.ShowCompare(context.Background(), &pb.ShowCompareRequest{
					RollbackN: int32(n),
				})
				if err != nil {
					return fmt.Errorf("%v", err)
				}
				if resp.Output == "" {
					fmt.Println("No differences found")
				} else {
					fmt.Print(resp.Output)
				}
				return nil
			}

			n, err := strconv.Atoi(args[1])
			if err != nil || n < 1 {
				return fmt.Errorf("usage: show system rollback <N>")
			}
			format := pb.ConfigFormat_HIERARCHICAL
			rest := strings.Join(args[2:], " ")
			if strings.Contains(rest, "| display set") {
				format = pb.ConfigFormat_SET
			} else if strings.Contains(rest, "compare") {
				// "show system rollback N compare"
				resp, err := c.client.ShowCompare(context.Background(), &pb.ShowCompareRequest{
					RollbackN: int32(n),
				})
				if err != nil {
					return fmt.Errorf("%v", err)
				}
				if resp.Output == "" {
					fmt.Println("No differences found")
				} else {
					fmt.Print(resp.Output)
				}
				return nil
			}
			resp, err := c.client.ShowRollback(context.Background(), &pb.ShowRollbackRequest{
				N:      int32(n),
				Format: format,
			})
			if err != nil {
				return fmt.Errorf("%v", err)
			}
			fmt.Print(resp.Output)
			return nil
		}

		resp, err := c.client.ListHistory(context.Background(), &pb.ListHistoryRequest{})
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		if len(resp.Entries) == 0 {
			fmt.Println("No rollback history available")
			return nil
		}
		for _, e := range resp.Entries {
			fmt.Printf("  rollback %d: %s\n", e.Index, e.Timestamp)
		}
		return nil

	case "uptime":
		return c.showSystemInfo("uptime")

	case "memory":
		return c.showSystemInfo("memory")

	case "storage":
		return c.showText("storage")

	case "processes":
		return c.showSystemInfo("processes")

	case "alarms":
		return c.showText("alarms")

	case "users":
		return c.showSystemInfo("users")

	case "connections":
		return c.showSystemInfo("connections")

	case "license":
		fmt.Println("License: open-source (no license required)")
		return nil

	case "services":
		return c.showText("system-services")

	case "ntp":
		return c.showText("ntp")

	case "login":
		return c.showText("login")

	case "syslog":
		return c.showText("system-syslog")

	case "internet-options":
		return c.showText("internet-options")

	case "root-authentication":
		return c.showText("root-authentication")

	case "backup-router":
		return c.showText("backup-router")

	case "buffers":
		return c.showText("buffers")

	default:
		return fmt.Errorf("unknown show system target: %s", args[0])
	}
}

func (c *ctl) handleConfigShow(args []string) error {
	line := strings.Join(args, " ")

	if strings.Contains(line, "| compare") {
		if idx := strings.Index(line, "| compare rollback"); idx >= 0 {
			rest := strings.TrimSpace(line[idx+len("| compare rollback"):])
			n, err := strconv.Atoi(rest)
			if err != nil || n < 1 {
				return fmt.Errorf("usage: show | compare rollback <N>")
			}
			resp, err := c.client.ShowCompare(context.Background(), &pb.ShowCompareRequest{RollbackN: int32(n)})
			if err != nil {
				return fmt.Errorf("%v", err)
			}
			fmt.Print(resp.Output)
			return nil
		}
		resp, err := c.client.ShowCompare(context.Background(), &pb.ShowCompareRequest{})
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		fmt.Print(resp.Output)
		return nil
	}

	format := pb.ConfigFormat_HIERARCHICAL
	if strings.Contains(line, "| display json") {
		format = pb.ConfigFormat_JSON
	} else if strings.Contains(line, "| display set") {
		format = pb.ConfigFormat_SET
	}
	resp, err := c.client.ShowConfig(context.Background(), &pb.ShowConfigRequest{
		Format: format,
		Target: pb.ConfigTarget_CANDIDATE,
	})
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	fmt.Print(resp.Output)
	return nil
}

func (c *ctl) handleCommit(args []string) error {
	if len(args) > 0 && args[0] == "check" {
		_, err := c.client.CommitCheck(context.Background(), &pb.CommitCheckRequest{})
		if err != nil {
			return fmt.Errorf("commit check failed: %v", err)
		}
		fmt.Println("configuration check succeeds")
		return nil
	}

	if len(args) > 0 && args[0] == "confirmed" {
		minutes := int32(10)
		if len(args) >= 2 {
			if v, err := strconv.Atoi(args[1]); err == nil && v > 0 {
				minutes = int32(v)
			}
		}
		_, err := c.client.CommitConfirmed(context.Background(), &pb.CommitConfirmedRequest{Minutes: minutes})
		if err != nil {
			return fmt.Errorf("commit confirmed failed: %v", err)
		}
		fmt.Printf("commit confirmed will be automatically rolled back in %d minutes unless confirmed\n", minutes)
		return nil
	}

	_, err := c.client.Commit(context.Background(), &pb.CommitRequest{})
	if err != nil {
		return fmt.Errorf("commit failed: %v", err)
	}
	fmt.Println("commit complete")
	return nil
}

func (c *ctl) handleClear(args []string) error {
	if len(args) < 1 {
		fmt.Println("clear:")
		fmt.Println("  security flow session          Clear all sessions")
		fmt.Println("  security counters              Clear all counters")
		fmt.Println("  firewall all                   Clear firewall filter counters")
		fmt.Println("  dhcp client-identifier         Clear DHCPv6 DUID(s)")
		return nil
	}

	switch args[0] {
	case "security":
		return c.handleClearSecurity(args[1:])
	case "firewall":
		return c.handleClearFirewall(args[1:])
	case "dhcp":
		return c.handleClearDHCP(args[1:])
	default:
		fmt.Println("clear:")
		fmt.Println("  security flow session          Clear all sessions")
		fmt.Println("  security counters              Clear all counters")
		fmt.Println("  firewall all                   Clear firewall filter counters")
		fmt.Println("  dhcp client-identifier         Clear DHCPv6 DUID(s)")
		return nil
	}
}

func (c *ctl) handleClearSecurity(args []string) error {
	if len(args) < 1 {
		fmt.Println("clear security:")
		fmt.Println("  flow session                         Clear all sessions")
		fmt.Println("  policies hit-count                   Clear policy hit counters")
		fmt.Println("  counters                             Clear all counters")
		fmt.Println("  nat source persistent-nat-table      Clear persistent NAT bindings")
		return nil
	}

	switch args[0] {
	case "nat":
		if len(args) >= 3 && args[1] == "source" && args[2] == "persistent-nat-table" {
			resp, err := c.client.SystemAction(context.Background(), &pb.SystemActionRequest{
				Action: "clear-persistent-nat",
			})
			if err != nil {
				return fmt.Errorf("%v", err)
			}
			fmt.Println(resp.Message)
			return nil
		}
		return fmt.Errorf("usage: clear security nat source persistent-nat-table")

	case "flow":
		if len(args) < 2 || args[1] != "session" {
			return fmt.Errorf("usage: clear security flow session [filters...]")
		}
		req := &pb.ClearSessionsRequest{}
		for i := 2; i < len(args); i++ {
			if i+1 >= len(args) {
				break
			}
			switch args[i] {
			case "source-prefix":
				i++
				req.SourcePrefix = args[i]
			case "destination-prefix":
				i++
				req.DestinationPrefix = args[i]
			case "protocol":
				i++
				req.Protocol = args[i]
			case "zone":
				i++
				req.Zone = args[i]
			case "source-port":
				i++
				if v, err := strconv.Atoi(args[i]); err == nil {
					req.SourcePort = uint32(v)
				}
			case "destination-port":
				i++
				if v, err := strconv.Atoi(args[i]); err == nil {
					req.DestinationPort = uint32(v)
				}
			}
		}
		resp, err := c.client.ClearSessions(context.Background(), req)
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		fmt.Printf("%d IPv4 and %d IPv6 session entries cleared\n", resp.Ipv4Cleared, resp.Ipv6Cleared)
		return nil

	case "policies":
		if len(args) >= 2 && args[1] == "hit-count" {
			resp, err := c.client.SystemAction(context.Background(), &pb.SystemActionRequest{
				Action: "clear-policy-counters",
			})
			if err != nil {
				return fmt.Errorf("%v", err)
			}
			fmt.Println(resp.Message)
			return nil
		}
		return fmt.Errorf("usage: clear security policies hit-count")

	case "counters":
		_, err := c.client.ClearCounters(context.Background(), &pb.ClearCountersRequest{})
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		fmt.Println("all counters cleared")
		return nil

	default:
		fmt.Println("clear security:")
		fmt.Println("  flow session                         Clear all sessions")
		fmt.Println("  policies hit-count                   Clear policy hit counters")
		fmt.Println("  counters                             Clear all counters")
		fmt.Println("  nat source persistent-nat-table      Clear persistent NAT bindings")
		return nil
	}
}

func (c *ctl) handleClearFirewall(args []string) error {
	if len(args) < 1 || args[0] != "all" {
		fmt.Println("clear firewall:")
		fmt.Println("  all    Clear all firewall filter counters")
		return nil
	}
	resp, err := c.client.SystemAction(context.Background(), &pb.SystemActionRequest{
		Action: "clear-firewall-counters",
	})
	if err != nil {
		return fmt.Errorf("clear firewall counters: %w", err)
	}
	fmt.Println(resp.Message)
	return nil
}

func (c *ctl) handleClearDHCP(args []string) error {
	if len(args) < 1 || args[0] != "client-identifier" {
		fmt.Println("clear dhcp:")
		fmt.Println("  client-identifier [interface <name>]    Clear DHCPv6 DUID(s)")
		return nil
	}

	req := &pb.ClearDHCPClientIdentifierRequest{}
	if len(args) >= 3 && args[1] == "interface" {
		req.Interface = args[2]
	}

	resp, err := c.client.ClearDHCPClientIdentifier(context.Background(), req)
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	fmt.Println(resp.Message)
	return nil
}

// --- Generic show helpers ---

func (c *ctl) showText(topic string) error {
	return c.showTextFiltered(topic, "")
}

func (c *ctl) showTextFiltered(topic, filter string) error {
	resp, err := c.client.ShowText(context.Background(), &pb.ShowTextRequest{
		Topic:  topic,
		Filter: filter,
	})
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	fmt.Print(resp.Output)
	return nil
}

func (c *ctl) showSystemInfo(typ string) error {
	resp, err := c.client.GetSystemInfo(context.Background(), &pb.GetSystemInfoRequest{Type: typ})
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	fmt.Print(resp.Output)
	return nil
}

func (c *ctl) showPoliciesBrief() error {
	resp, err := c.client.GetPolicies(context.Background(), &pb.GetPoliciesRequest{})
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	fmt.Printf("%-12s %-12s %-20s %-8s %s\n",
		"From", "To", "Name", "Action", "Hits")
	for _, pi := range resp.Policies {
		for _, rule := range pi.Rules {
			hits := "-"
			if rule.HitPackets > 0 {
				hits = fmt.Sprintf("%d", rule.HitPackets)
			}
			fmt.Printf("%-12s %-12s %-20s %-8s %s\n",
				pi.FromZone, pi.ToZone, rule.Name, rule.Action, hits)
		}
	}
	return nil
}

func (c *ctl) handleRequest(args []string) error {
	if len(args) == 0 {
		fmt.Println("request:")
		fmt.Println("  dhcp renew       Renew DHCP lease on an interface")
		fmt.Println("  system reboot    Reboot the system")
		fmt.Println("  system halt      Halt the system")
		fmt.Println("  system zeroize   Factory reset (erase all config)")
		return nil
	}
	switch args[0] {
	case "dhcp":
		return c.handleRequestDHCP(args[1:])
	case "system":
		// fall through to existing logic below
	default:
		return fmt.Errorf("unknown request target: %s", args[0])
	}
	if len(args) < 2 {
		fmt.Println("request system:")
		fmt.Println("  reboot    Reboot the system")
		fmt.Println("  halt      Halt the system")
		fmt.Println("  zeroize   Factory reset (erase all config)")
		return nil
	}

	switch args[1] {
	case "reboot", "halt":
		fmt.Printf("%s the system? [yes,no] (no) ", strings.Title(args[1]))
		c.rl.SetPrompt("")
		line, err := c.rl.Readline()
		c.rl.SetPrompt(c.operationalPrompt())
		if err != nil || strings.TrimSpace(strings.ToLower(line)) != "yes" {
			fmt.Printf("%s cancelled\n", strings.Title(args[1]))
			return nil
		}
		resp, err := c.client.SystemAction(context.Background(), &pb.SystemActionRequest{
			Action: args[1],
		})
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		fmt.Println(resp.Message)
		return nil
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
		resp, err := c.client.SystemAction(context.Background(), &pb.SystemActionRequest{
			Action: "zeroize",
		})
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		fmt.Println(resp.Message)
		return nil
	default:
		return fmt.Errorf("unknown request system command: %s", args[1])
	}
}

func (c *ctl) handleRequestDHCP(args []string) error {
	if len(args) == 0 || args[0] != "renew" {
		fmt.Println("request dhcp:")
		fmt.Println("  renew <interface>  Renew DHCP lease on an interface")
		return nil
	}
	if len(args) < 2 {
		return fmt.Errorf("usage: request dhcp renew <interface>")
	}
	resp, err := c.client.SystemAction(context.Background(), &pb.SystemActionRequest{
		Action: "dhcp-renew",
		Target: args[1],
	})
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	fmt.Println(resp.Message)
	return nil
}

// --- Tab completion ---

type remoteCompleter struct {
	ctl *ctl
}

func (rc *remoteCompleter) Do(line []rune, pos int) ([][]rune, int) {
	text := string(line[:pos])

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	resp, err := rc.ctl.client.Complete(ctx, &pb.CompleteRequest{
		Line:       text,
		Pos:        int32(pos),
		ConfigMode: rc.ctl.configMode,
	})
	if err != nil || len(resp.Candidates) == 0 {
		return nil, 0
	}

	// Determine partial word for replacement length
	words := strings.Fields(text)
	trailingSpace := len(text) > 0 && text[len(text)-1] == ' '
	var partial string
	if !trailingSpace && len(words) > 0 {
		partial = words[len(words)-1]
	}

	var result [][]rune
	for _, c := range resp.Candidates {
		suffix := c[len(partial):]
		result = append(result, []rune(suffix+" "))
	}
	return result, len(partial)
}

// --- Context help ---

func (c *ctl) showContextHelp(prefix string) {
	prefix = strings.TrimSpace(prefix)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Request completions for the prefix + trailing space (as if ready for next word)
	resp, err := c.client.Complete(ctx, &pb.CompleteRequest{
		Line:       prefix + " ",
		Pos:        int32(len(prefix) + 1),
		ConfigMode: c.configMode,
	})
	if err != nil || len(resp.Candidates) == 0 {
		fmt.Println("  (no help available)")
		return
	}

	sort.Strings(resp.Candidates)
	fmt.Println("Possible completions:")
	for _, cand := range resp.Candidates {
		fmt.Printf("  %s\n", cand)
	}
}

// --- Prompts ---

func (c *ctl) operationalPrompt() string {
	return fmt.Sprintf("%s@%s> ", c.username, c.hostname)
}

func (c *ctl) configPrompt() string {
	return fmt.Sprintf("%s@%s# ", c.username, c.hostname)
}

// --- Help ---

func (c *ctl) showOperationalHelp() {
	fmt.Println("Operational mode commands:")
	fmt.Println("  configure                          Enter configuration mode")
	fmt.Println("  show configuration                 Show running configuration")
	fmt.Println("  show configuration | display set   Show as flat set commands")
	fmt.Println("  show configuration | display json  Show as JSON")
	fmt.Println("  show dhcp leases                   Show DHCP leases")
	fmt.Println("  show dhcp client-identifier        Show DHCPv6 DUID(s)")
	fmt.Println("  show dhcp-relay                    Show DHCP relay status")
	fmt.Println("  show dhcp-server                   Show DHCP server leases")
	fmt.Println("  show firewall                      Show firewall filters")
	fmt.Println("  show flow-monitoring               Show NetFlow v9 configuration")
	fmt.Println("  show route                         Show routing table")
	fmt.Println("  show schedulers                    Show policy schedulers")
	fmt.Println("  show security                      Show security information")
	fmt.Println("  show security policies brief       Show brief policy summary")
	fmt.Println("  show security ike security-assoc.   Show IKE SAs (live)")
	fmt.Println("  show security ipsec                Show IPsec VPN status")
	fmt.Println("  show security log [N]              Show recent security events")
	fmt.Println("  show snmp                          Show SNMP configuration")
	fmt.Println("  show interfaces                    Show interface status")
	fmt.Println("  show protocols ospf neighbor       Show OSPF neighbors")
	fmt.Println("  show protocols bgp summary         Show BGP peer summary")
	fmt.Println("  show system rollback               Show rollback history")
	fmt.Println("  show system uptime                 Show system uptime")
	fmt.Println("  show system memory                 Show memory usage")
	fmt.Println("  show version                       Show software version")
	fmt.Println("  clear security flow session        Clear all sessions")
	fmt.Println("  clear security counters            Clear all counters")
	fmt.Println("  clear security nat source pers...  Clear persistent NAT bindings")
	fmt.Println("  clear dhcp client-identifier       Clear DHCPv6 DUID(s)")
	fmt.Println("  request system reboot              Reboot the system")
	fmt.Println("  request system halt                Halt the system")
	fmt.Println("  quit                               Exit CLI")
}

func (c *ctl) handlePing(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: ping <host> [count N] [source IP] [size N] [routing-instance NAME]")
	}
	req := &pb.PingRequest{Target: args[0], Count: 5}
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "count":
			if i+1 < len(args) {
				i++
				if v, err := strconv.Atoi(args[i]); err == nil {
					req.Count = int32(v)
				}
			}
		case "source":
			if i+1 < len(args) {
				i++
				req.Source = args[i]
			}
		case "size":
			if i+1 < len(args) {
				i++
				if v, err := strconv.Atoi(args[i]); err == nil {
					req.Size = int32(v)
				}
			}
		case "routing-instance":
			if i+1 < len(args) {
				i++
				req.RoutingInstance = args[i]
			}
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	resp, err := c.client.Ping(ctx, req)
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	fmt.Print(resp.Output)
	return nil
}

func (c *ctl) handleTraceroute(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: traceroute <host> [source IP] [routing-instance NAME]")
	}
	req := &pb.TracerouteRequest{Target: args[0]}
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "source":
			if i+1 < len(args) {
				i++
				req.Source = args[i]
			}
		case "routing-instance":
			if i+1 < len(args) {
				i++
				req.RoutingInstance = args[i]
			}
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	resp, err := c.client.Traceroute(ctx, req)
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	fmt.Print(resp.Output)
	return nil
}

func (c *ctl) handleLoad(args []string) error {
	if len(args) < 2 {
		fmt.Println("load:")
		fmt.Println("  override terminal    Replace candidate with pasted config")
		fmt.Println("  merge terminal       Merge pasted config into candidate")
		fmt.Println("  override <file>      Replace candidate with file contents")
		fmt.Println("  merge <file>         Merge file contents into candidate")
		return nil
	}

	mode := args[0]
	if mode != "override" && mode != "merge" {
		return fmt.Errorf("load: unknown mode %q (use 'override' or 'merge')", mode)
	}

	source := args[1]
	var content string

	if source == "terminal" {
		fmt.Println("[Type or paste configuration, then press Ctrl-D on an empty line]")
		var lines []string
		for {
			line, err := c.rl.Readline()
			if err != nil {
				break
			}
			lines = append(lines, line)
		}
		content = strings.Join(lines, "\n")
	} else {
		data, err := os.ReadFile(source)
		if err != nil {
			return fmt.Errorf("load: %v", err)
		}
		content = string(data)
	}

	if strings.TrimSpace(content) == "" {
		return fmt.Errorf("load: empty input")
	}

	_, err := c.client.Load(context.Background(), &pb.LoadRequest{
		Mode:    mode,
		Content: content,
	})
	if err != nil {
		return fmt.Errorf("load %s: %v", mode, err)
	}
	fmt.Printf("load %s complete\n", mode)
	return nil
}

func (c *ctl) showConfigHelp() {
	fmt.Println("Configuration mode commands:")
	fmt.Println("  set <path>                   Set a configuration value")
	fmt.Println("  delete <path>                Delete a configuration element")
	fmt.Println("  load override terminal       Replace config from terminal input")
	fmt.Println("  load merge terminal          Merge config from terminal input")
	fmt.Println("  load override <file>         Replace config from file")
	fmt.Println("  load merge <file>            Merge config from file")
	fmt.Println("  show                         Show candidate configuration")
	fmt.Println("  show | compare               Show pending changes vs active")
	fmt.Println("  show | compare rollback N    Show changes vs rollback N")
	fmt.Println("  show | display set           Show as flat set commands")
	fmt.Println("  show | display json          Show as JSON")
	fmt.Println("  commit                       Validate and apply configuration")
	fmt.Println("  commit check                 Validate without applying")
	fmt.Println("  commit confirmed [minutes]   Auto-rollback unless confirmed")
	fmt.Println("  rollback [n]                 Revert to previous configuration")
	fmt.Println("  run <cmd>                    Run operational command")
	fmt.Println("  exit                         Exit configuration mode")
}
