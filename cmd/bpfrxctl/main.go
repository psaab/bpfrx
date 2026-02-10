// bpfrxctl is the remote CLI client for bpfrxd.
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
		fmt.Fprintf(os.Stderr, "bpfrxctl: connect: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	client := pb.NewBpfrxServiceClient(conn)

	// Verify connectivity
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	resp, err := client.GetStatus(ctx, &pb.GetStatusRequest{})
	cancel()
	if err != nil {
		fmt.Fprintf(os.Stderr, "bpfrxctl: cannot reach bpfrxd at %s: %v\n", *addr, err)
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
		HistoryFile:     "/tmp/bpfrxctl_history",
		InterruptPrompt: "^C",
		EOFPrompt:       "exit",
		AutoComplete:    &remoteCompleter{ctl: c},
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "bpfrxctl: readline: %v\n", err)
		os.Exit(1)
	}
	defer rl.Close()
	c.rl = rl

	fmt.Printf("bpfrxctl — connected to bpfrxd (uptime: %s)\n", resp.Uptime)
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

	if c.configMode {
		return c.dispatchConfig(line)
	}
	return c.dispatchOperational(line)
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
		return nil

	case "show":
		return c.handleShow(parts[1:])

	case "clear":
		return c.handleClear(parts[1:])

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
		fmt.Println("  configuration    Show active configuration")
		fmt.Println("  dhcp             Show DHCP information")
		fmt.Println("  route            Show routing table")
		fmt.Println("  security         Show security information")
		fmt.Println("  interfaces       Show interface status")
		fmt.Println("  protocols        Show protocol information")
		fmt.Println("  system           Show system information")
		return nil
	}

	switch args[0] {
	case "configuration":
		format := pb.ConfigFormat_HIERARCHICAL
		rest := strings.Join(args[1:], " ")
		if strings.Contains(rest, "| display set") {
			format = pb.ConfigFormat_SET
		}
		resp, err := c.client.ShowConfig(context.Background(), &pb.ShowConfigRequest{
			Format: format,
			Target: pb.ConfigTarget_ACTIVE,
		})
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		fmt.Print(resp.Output)
		return nil

	case "dhcp":
		if len(args) >= 2 && args[1] == "leases" {
			return c.showDHCPLeases()
		}
		fmt.Println("show dhcp:")
		fmt.Println("  leases           Show DHCP leases")
		return nil

	case "route":
		return c.showRoutes()

	case "security":
		return c.handleShowSecurity(args[1:])

	case "interfaces":
		return c.showInterfaces()

	case "protocols":
		return c.handleShowProtocols(args[1:])

	case "system":
		return c.handleShowSystem(args[1:])

	default:
		return fmt.Errorf("unknown show target: %s", args[0])
	}
}

func (c *ctl) handleShowSecurity(args []string) error {
	if len(args) == 0 {
		fmt.Println("show security:")
		fmt.Println("  zones            Show security zones")
		fmt.Println("  policies         Show security policies")
		fmt.Println("  screen           Show screen/IDS profiles")
		fmt.Println("  flow session     Show active sessions")
		fmt.Println("  nat              Show NAT information")
		fmt.Println("  log              Show recent security events")
		fmt.Println("  statistics       Show global statistics")
		fmt.Println("  ipsec            Show IPsec VPN status")
		return nil
	}

	switch args[0] {
	case "zones":
		return c.showZones()
	case "policies":
		return c.showPolicies()
	case "screen":
		return c.showScreen()
	case "flow":
		if len(args) >= 2 && args[1] == "session" {
			return c.showFlowSession(args[2:])
		}
		return fmt.Errorf("usage: show security flow session")
	case "nat":
		return c.handleShowNAT(args[1:])
	case "log":
		return c.showEvents(args[1:])
	case "statistics":
		return c.showStatistics()
	case "ipsec":
		return c.showIPsec(args[1:])
	default:
		return fmt.Errorf("unknown show security target: %s", args[0])
	}
}

func (c *ctl) showZones() error {
	resp, err := c.client.GetZones(context.Background(), &pb.GetZonesRequest{})
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	for _, z := range resp.Zones {
		if z.Id > 0 {
			fmt.Printf("Zone: %s (id: %d)\n", z.Name, z.Id)
		} else {
			fmt.Printf("Zone: %s\n", z.Name)
		}
		fmt.Printf("  Interfaces: %s\n", strings.Join(z.Interfaces, ", "))
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
		fmt.Println()
	}
	return nil
}

func (c *ctl) showPolicies() error {
	resp, err := c.client.GetPolicies(context.Background(), &pb.GetPoliciesRequest{})
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	for _, pi := range resp.Policies {
		fmt.Printf("From zone: %s, To zone: %s\n", pi.FromZone, pi.ToZone)
		for _, rule := range pi.Rules {
			fmt.Printf("  Rule: %s\n", rule.Name)
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
	resp, err := c.client.GetScreen(context.Background(), &pb.GetScreenRequest{})
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	if len(resp.Screens) == 0 {
		fmt.Println("No screen profiles configured")
		return nil
	}
	for _, si := range resp.Screens {
		fmt.Printf("Screen profile: %s\n", si.Name)
		for _, check := range si.Checks {
			fmt.Printf("  %s\n", check)
		}
		fmt.Println()
	}
	return nil
}

func (c *ctl) showFlowSession(args []string) error {
	req := &pb.GetSessionsRequest{Limit: 100}
	// Parse simple filters from args
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "zone":
			if i+1 < len(args) {
				i++
				// Zone filter requires numeric ID; try to parse
				if v, err := strconv.ParseUint(args[i], 10, 32); err == nil {
					req.Zone = uint32(v)
				}
			}
		case "protocol":
			if i+1 < len(args) {
				i++
				req.Protocol = args[i]
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
		fmt.Printf("Session ID: %d, Policy: %d, State: %s, Timeout: %ds\n",
			i+1, se.PolicyId, se.State, se.TimeoutSeconds)
		fmt.Printf("  In: %s:%d --> %s:%d;%s, Zone: %d -> %d\n",
			se.SrcAddr, se.SrcPort, se.DstAddr, se.DstPort,
			se.Protocol, se.IngressZone, se.EgressZone)
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
		fmt.Println("  destination      Show destination NAT rules")
		return nil
	}
	switch args[0] {
	case "source":
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
	default:
		return fmt.Errorf("unknown show security nat target: %s", args[0])
	}
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
		fmt.Printf("%s %-14s %s -> %s %s action=%-6s policy=%d zone=%d->%d\n",
			e.Time, e.Type, e.SrcAddr, e.DstAddr, e.Protocol, e.Action,
			e.PolicyId, e.IngressZone, e.EgressZone)
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
	fmt.Printf("  %-25s %d\n", "TC egress packets:", resp.TcEgressPackets)
	return nil
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

func (c *ctl) showInterfaces() error {
	resp, err := c.client.GetInterfaces(context.Background(), &pb.GetInterfacesRequest{})
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	fmt.Printf("  %-16s %-8s %-12s %12s %12s %12s %12s\n",
		"Interface", "Ifindex", "Zone", "RxPackets", "RxBytes", "TxPackets", "TxBytes")
	for _, ii := range resp.Interfaces {
		fmt.Printf("  %-16s %-8d %-12s %12d %12d %12d %12d\n",
			ii.Name, ii.Ifindex, ii.Zone,
			ii.RxPackets, ii.RxBytes, ii.TxPackets, ii.TxBytes)
	}
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

func (c *ctl) showRoutes() error {
	resp, err := c.client.GetRoutes(context.Background(), &pb.GetRoutesRequest{})
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	if len(resp.Routes) == 0 {
		fmt.Println("No static routes configured")
		return nil
	}
	fmt.Printf("  %-24s %-20s %-14s %s\n", "Destination", "Next-hop", "Interface", "Pref")
	for _, r := range resp.Routes {
		fmt.Printf("  %-24s %-20s %-14s %d\n", r.Destination, r.NextHop, r.Interface, r.Preference)
	}
	return nil
}

func (c *ctl) handleShowProtocols(args []string) error {
	if len(args) == 0 {
		fmt.Println("show protocols:")
		fmt.Println("  ospf             Show OSPF information")
		fmt.Println("  bgp              Show BGP information")
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
	default:
		return fmt.Errorf("unknown show protocols target: %s", args[0])
	}
}

func (c *ctl) handleShowSystem(args []string) error {
	if len(args) == 0 || args[0] != "rollback" {
		fmt.Println("show system:")
		fmt.Println("  rollback         Show rollback history")
		return nil
	}

	if len(args) >= 2 {
		n, err := strconv.Atoi(args[1])
		if err != nil || n < 1 {
			return fmt.Errorf("usage: show system rollback <N>")
		}
		format := pb.ConfigFormat_HIERARCHICAL
		rest := strings.Join(args[2:], " ")
		if strings.Contains(rest, "| display set") {
			format = pb.ConfigFormat_SET
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
	if strings.Contains(line, "| display set") {
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
	if len(args) < 2 || args[0] != "security" {
		fmt.Println("clear:")
		fmt.Println("  security flow session    Clear all sessions")
		fmt.Println("  security counters        Clear all counters")
		return nil
	}

	switch args[1] {
	case "flow":
		if len(args) < 3 || args[2] != "session" {
			return fmt.Errorf("usage: clear security flow session")
		}
		resp, err := c.client.ClearSessions(context.Background(), &pb.ClearSessionsRequest{})
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		fmt.Printf("%d IPv4 and %d IPv6 session entries cleared\n", resp.Ipv4Cleared, resp.Ipv6Cleared)
		return nil

	case "counters":
		_, err := c.client.ClearCounters(context.Background(), &pb.ClearCountersRequest{})
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		fmt.Println("all counters cleared")
		return nil

	default:
		fmt.Println("clear security:")
		fmt.Println("  flow session    Clear all sessions")
		fmt.Println("  counters        Clear all counters")
		return nil
	}
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
	for _, cand := range resp.Candidates {
		fmt.Printf("  %s\n", cand)
	}
}

// --- Prompts ---

func (c *ctl) operationalPrompt() string {
	return fmt.Sprintf("%s@%s> ", c.username, c.hostname)
}

func (c *ctl) configPrompt() string {
	return fmt.Sprintf("[edit]\n%s@%s# ", c.username, c.hostname)
}

// --- Help ---

func (c *ctl) showOperationalHelp() {
	fmt.Println("Operational mode commands:")
	fmt.Println("  configure                          Enter configuration mode")
	fmt.Println("  show configuration                 Show running configuration")
	fmt.Println("  show configuration | display set   Show as flat set commands")
	fmt.Println("  show dhcp leases                   Show DHCP leases")
	fmt.Println("  show route                         Show routing table")
	fmt.Println("  show security                      Show security information")
	fmt.Println("  show security ipsec                Show IPsec VPN status")
	fmt.Println("  show security log [N]              Show recent security events")
	fmt.Println("  show interfaces                    Show interface status")
	fmt.Println("  show protocols ospf neighbor       Show OSPF neighbors")
	fmt.Println("  show protocols bgp summary         Show BGP peer summary")
	fmt.Println("  show system rollback               Show rollback history")
	fmt.Println("  clear security flow session        Clear all sessions")
	fmt.Println("  clear security counters            Clear all counters")
	fmt.Println("  quit                               Exit CLI")
}

func (c *ctl) showConfigHelp() {
	fmt.Println("Configuration mode commands:")
	fmt.Println("  set <path>                   Set a configuration value")
	fmt.Println("  delete <path>                Delete a configuration element")
	fmt.Println("  show                         Show candidate configuration")
	fmt.Println("  show | compare               Show pending changes vs active")
	fmt.Println("  show | compare rollback N    Show changes vs rollback N")
	fmt.Println("  show | display set           Show as flat set commands")
	fmt.Println("  commit                       Validate and apply configuration")
	fmt.Println("  commit check                 Validate without applying")
	fmt.Println("  commit confirmed [minutes]   Auto-rollback unless confirmed")
	fmt.Println("  rollback [n]                 Revert to previous configuration")
	fmt.Println("  run <cmd>                    Run operational command")
	fmt.Println("  exit                         Exit configuration mode")
}
