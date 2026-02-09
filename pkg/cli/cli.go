// Package cli implements the Junos-style interactive CLI for bpfrx.
package cli

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	"github.com/chzyer/readline"
	"github.com/psviderski/bpfrx/pkg/config"
	"github.com/psviderski/bpfrx/pkg/configstore"
	"github.com/psviderski/bpfrx/pkg/dataplane"
)

// CLI is the interactive command-line interface.
type CLI struct {
	rl       *readline.Instance
	store    *configstore.Store
	dp       *dataplane.Manager
	hostname string
	username string
}

// New creates a new CLI.
func New(store *configstore.Store, dp *dataplane.Manager) *CLI {
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "bpfrx"
	}
	username := os.Getenv("USER")
	if username == "" {
		username = "root"
	}

	return &CLI{
		store:    store,
		dp:       dp,
		hostname: hostname,
		username: username,
	}
}

// Run starts the interactive CLI loop.
func (c *CLI) Run() error {
	var err error
	c.rl, err = readline.NewEx(&readline.Config{
		Prompt:          c.operationalPrompt(),
		HistoryFile:     "/tmp/bpfrx_history",
		InterruptPrompt: "^C",
		EOFPrompt:       "exit",
	})
	if err != nil {
		return fmt.Errorf("readline init: %w", err)
	}
	defer c.rl.Close()

	fmt.Println("bpfrx firewall - Junos-style eBPF firewall")
	fmt.Println("Type '?' for help")
	fmt.Println()

	for {
		line, err := c.rl.Readline()
		if err != nil {
			if err == readline.ErrInterrupt {
				continue
			}
			if err == io.EOF {
				break
			}
			return err
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if err := c.dispatch(line); err != nil {
			if err == errExit {
				return nil
			}
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
		}
	}
	return nil
}

var errExit = fmt.Errorf("exit")

func (c *CLI) dispatch(line string) error {
	if c.store.InConfigMode() {
		return c.dispatchConfig(line)
	}
	return c.dispatchOperational(line)
}

func (c *CLI) dispatchOperational(line string) error {
	parts := strings.Fields(line)
	if len(parts) == 0 {
		return nil
	}

	switch parts[0] {
	case "configure":
		c.store.EnterConfigure()
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

func (c *CLI) dispatchConfig(line string) error {
	parts := strings.Fields(line)
	if len(parts) == 0 {
		return nil
	}

	switch parts[0] {
	case "set":
		if len(parts) < 2 {
			return fmt.Errorf("set: missing path")
		}
		return c.store.SetFromInput(strings.Join(parts[1:], " "))

	case "delete":
		if len(parts) < 2 {
			return fmt.Errorf("delete: missing path")
		}
		return c.store.DeleteFromInput(strings.Join(parts[1:], " "))

	case "show":
		return c.handleConfigShow(parts[1:])

	case "commit":
		return c.handleCommit(parts[1:])

	case "rollback":
		n := 0
		if len(parts) >= 2 {
			fmt.Sscanf(parts[1], "%d", &n)
		}
		if err := c.store.Rollback(n); err != nil {
			return err
		}
		fmt.Println("configuration rolled back")
		return nil

	case "run":
		if len(parts) < 2 {
			return fmt.Errorf("run: missing command")
		}
		return c.dispatchOperational(strings.Join(parts[1:], " "))

	case "exit", "quit":
		if c.store.IsDirty() {
			fmt.Println("warning: uncommitted changes will be discarded")
		}
		c.store.ExitConfigure()
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

func (c *CLI) handleShow(args []string) error {
	if len(args) == 0 {
		fmt.Println("show: specify what to show")
		fmt.Println("  configuration    Show active configuration")
		fmt.Println("  security         Show security information")
		fmt.Println("  interfaces       Show interface status")
		return nil
	}

	switch args[0] {
	case "configuration":
		fmt.Print(c.store.ShowActive())
		return nil

	case "security":
		return c.handleShowSecurity(args[1:])

	case "interfaces":
		return c.showInterfaces(args[1:])

	default:
		return fmt.Errorf("unknown show target: %s", args[0])
	}
}

func (c *CLI) handleShowSecurity(args []string) error {
	if len(args) == 0 {
		fmt.Println("show security:")
		fmt.Println("  zones            Show security zones")
		fmt.Println("  policies         Show security policies")
		fmt.Println("  screen           Show screen/IDS profiles")
		fmt.Println("  flow session     Show active sessions")
		fmt.Println("  nat source       Show source NAT information")
		fmt.Println("  nat destination  Show destination NAT information")
		fmt.Println("  statistics       Show global statistics")
		return nil
	}

	cfg := c.store.ActiveConfig()
	if cfg == nil && args[0] != "statistics" {
		fmt.Println("no active configuration")
		return nil
	}

	switch args[0] {
	case "zones":
		for name, zone := range cfg.Security.Zones {
			// Resolve zone ID for counter lookup
			var zoneID uint16
			if c.dp != nil {
				if cr := c.dp.LastCompileResult(); cr != nil {
					zoneID = cr.ZoneIDs[name]
				}
			}

			if zoneID > 0 {
				fmt.Printf("Zone: %s (id: %d)\n", name, zoneID)
			} else {
				fmt.Printf("Zone: %s\n", name)
			}
			fmt.Printf("  Interfaces: %s\n", strings.Join(zone.Interfaces, ", "))
			if zone.ScreenProfile != "" {
				fmt.Printf("  Screen: %s\n", zone.ScreenProfile)
			}
			if zone.HostInboundTraffic != nil {
				if len(zone.HostInboundTraffic.SystemServices) > 0 {
					fmt.Printf("  Host-inbound system-services: %s\n",
						strings.Join(zone.HostInboundTraffic.SystemServices, ", "))
				}
				if len(zone.HostInboundTraffic.Protocols) > 0 {
					fmt.Printf("  Host-inbound protocols: %s\n",
						strings.Join(zone.HostInboundTraffic.Protocols, ", "))
				}
			}

			// Per-zone traffic counters
			if c.dp != nil && c.dp.IsLoaded() && zoneID > 0 {
				ingress, errIn := c.dp.ReadZoneCounters(zoneID, 0)
				egress, errOut := c.dp.ReadZoneCounters(zoneID, 1)
				if errIn == nil && errOut == nil {
					fmt.Println("  Traffic statistics:")
					fmt.Printf("    Input:  %d packets, %d bytes\n",
						ingress.Packets, ingress.Bytes)
					fmt.Printf("    Output: %d packets, %d bytes\n",
						egress.Packets, egress.Bytes)
				}
			}

			fmt.Println()
		}
		return nil

	case "policies":
		policySetID := uint32(0)
		for _, zpp := range cfg.Security.Policies {
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
				fmt.Printf("  Rule: %s (id: %d)\n", pol.Name, ruleID)
				fmt.Printf("    Match: src=%v dst=%v app=%v\n",
					pol.Match.SourceAddresses,
					pol.Match.DestinationAddresses,
					pol.Match.Applications)
				fmt.Printf("    Action: %s\n", action)

				// Per-rule hit counts from BPF
				if c.dp != nil && c.dp.IsLoaded() {
					counters, err := c.dp.ReadPolicyCounters(ruleID)
					if err == nil {
						fmt.Printf("    Hit count: %d packets, %d bytes\n",
							counters.Packets, counters.Bytes)
					}
				}
			}
			policySetID++
			fmt.Println()
		}
		return nil

	case "flow":
		if len(args) >= 2 && args[1] == "session" {
			return c.showFlowSession()
		}
		return fmt.Errorf("unknown show security flow target")

	case "screen":
		return c.showScreen()

	case "nat":
		return c.handleShowNAT(args[1:])

	case "statistics":
		return c.showStatistics()

	default:
		return fmt.Errorf("unknown show security target: %s", args[0])
	}
}

func (c *CLI) showScreen() error {
	cfg := c.store.ActiveConfig()
	if cfg == nil {
		fmt.Println("no active configuration")
		return nil
	}

	if len(cfg.Security.Screen) == 0 {
		fmt.Println("No screen profiles configured")
		return nil
	}

	// Build reverse map: profile name -> zones using it
	zonesByProfile := make(map[string][]string)
	for name, zone := range cfg.Security.Zones {
		if zone.ScreenProfile != "" {
			zonesByProfile[zone.ScreenProfile] = append(
				zonesByProfile[zone.ScreenProfile], name)
		}
	}

	for name, profile := range cfg.Security.Screen {
		fmt.Printf("Screen profile: %s\n", name)

		// TCP checks
		if profile.TCP.Land {
			fmt.Println("  TCP LAND attack detection: enabled")
		}
		if profile.TCP.SynFin {
			fmt.Println("  TCP SYN+FIN detection: enabled")
		}
		if profile.TCP.NoFlag {
			fmt.Println("  TCP no-flag detection: enabled")
		}
		if profile.TCP.FinNoAck {
			fmt.Println("  TCP FIN-no-ACK detection: enabled")
		}
		if profile.TCP.WinNuke {
			fmt.Println("  TCP WinNuke detection: enabled")
		}
		if profile.TCP.SynFlood != nil {
			fmt.Printf("  TCP SYN flood protection: attack-threshold %d\n",
				profile.TCP.SynFlood.AttackThreshold)
		}

		// ICMP checks
		if profile.ICMP.PingDeath {
			fmt.Println("  ICMP ping-of-death detection: enabled")
		}
		if profile.ICMP.FloodThreshold > 0 {
			fmt.Printf("  ICMP flood protection: threshold %d\n",
				profile.ICMP.FloodThreshold)
		}

		// IP checks
		if profile.IP.SourceRouteOption {
			fmt.Println("  IP source-route option detection: enabled")
		}

		// UDP checks
		if profile.UDP.FloodThreshold > 0 {
			fmt.Printf("  UDP flood protection: threshold %d\n",
				profile.UDP.FloodThreshold)
		}

		// Zones using this profile
		if zones, ok := zonesByProfile[name]; ok {
			fmt.Printf("  Applied to zones: %s\n", strings.Join(zones, ", "))
		} else {
			fmt.Println("  Applied to zones: (none)")
		}

		fmt.Println()
	}

	// Show screen drop counter
	if c.dp != nil && c.dp.IsLoaded() {
		ctrMap := c.dp.Map("global_counters")
		if ctrMap != nil {
			var perCPU []uint64
			if err := ctrMap.Lookup(uint32(dataplane.GlobalCtrScreenDrops), &perCPU); err == nil {
				var total uint64
				for _, v := range perCPU {
					total += v
				}
				fmt.Printf("Total screen drops: %d\n", total)
			}
		}
	}

	return nil
}

func (c *CLI) showStatistics() error {
	if c.dp == nil || !c.dp.IsLoaded() {
		fmt.Println("Statistics: dataplane not loaded")
		return nil
	}

	ctrMap := c.dp.Map("global_counters")
	if ctrMap == nil {
		fmt.Println("Statistics: global_counters map not found")
		return nil
	}

	// Read per-CPU values and sum across CPUs for each counter index.
	names := []struct {
		idx  uint32
		name string
	}{
		{dataplane.GlobalCtrRxPackets, "RX packets"},
		{dataplane.GlobalCtrTxPackets, "TX packets"},
		{dataplane.GlobalCtrDrops, "Drops"},
		{dataplane.GlobalCtrSessionsNew, "Sessions created"},
		{dataplane.GlobalCtrSessionsClosed, "Sessions closed"},
		{dataplane.GlobalCtrScreenDrops, "Screen drops"},
		{dataplane.GlobalCtrPolicyDeny, "Policy denies"},
		{dataplane.GlobalCtrNATAllocFail, "NAT alloc failures"},
		{dataplane.GlobalCtrHostInboundDeny, "Host-inbound denies"},
		{dataplane.GlobalCtrTCEgressPackets, "TC egress packets"},
	}

	fmt.Println("Global statistics:")
	for _, n := range names {
		var perCPU []uint64
		if err := ctrMap.Lookup(n.idx, &perCPU); err != nil {
			fmt.Printf("  %-25s (error: %v)\n", n.name+":", err)
			continue
		}
		var total uint64
		for _, v := range perCPU {
			total += v
		}
		fmt.Printf("  %-25s %d\n", n.name+":", total)
	}
	return nil
}

func (c *CLI) handleConfigShow(args []string) error {
	// Check for pipe commands
	line := strings.Join(args, " ")

	if strings.Contains(line, "| compare") {
		fmt.Print(c.store.ShowCompare())
		return nil
	}

	if strings.Contains(line, "| display set") {
		fmt.Print(c.store.ShowCandidateSet())
		return nil
	}

	fmt.Print(c.store.ShowCandidate())
	return nil
}

func (c *CLI) handleCommit(args []string) error {
	if len(args) > 0 && args[0] == "check" {
		_, err := c.store.CommitCheck()
		if err != nil {
			return fmt.Errorf("commit check failed: %w", err)
		}
		fmt.Println("configuration check succeeds")
		return nil
	}

	compiled, err := c.store.Commit()
	if err != nil {
		return fmt.Errorf("commit failed: %w", err)
	}

	// Apply to dataplane
	if c.dp != nil {
		if err := c.applyToDataplane(compiled); err != nil {
			fmt.Fprintf(os.Stderr, "warning: dataplane apply failed: %v\n", err)
		}
	}

	fmt.Println("commit complete")
	return nil
}

func (c *CLI) applyToDataplane(cfg *config.Config) error {
	if c.dp == nil || !c.dp.IsLoaded() {
		return nil
	}

	_, err := c.dp.Compile(cfg)
	return err
}

func (c *CLI) showFlowSession() error {
	if c.dp == nil || !c.dp.IsLoaded() {
		fmt.Println("Session table: dataplane not loaded")
		return nil
	}

	count := 0

	// IPv4 sessions
	err := c.dp.IterateSessions(func(key dataplane.SessionKey, val dataplane.SessionValue) bool {
		if val.IsReverse != 0 {
			return true
		}
		count++

		srcIP := net.IP(key.SrcIP[:])
		dstIP := net.IP(key.DstIP[:])
		srcPort := ntohs(key.SrcPort)
		dstPort := ntohs(key.DstPort)
		protoName := protoNameFromNum(key.Protocol)
		stateName := sessionStateName(val.State)

		fmt.Printf("Session ID: %d, Policy: %d, State: %s, Timeout: %ds\n",
			count, val.PolicyID, stateName, val.Timeout)
		fmt.Printf("  In: %s:%d --> %s:%d;%s,",
			srcIP, srcPort, dstIP, dstPort, protoName)
		fmt.Printf(" Zone: %d -> %d\n", val.IngressZone, val.EgressZone)

		if val.Flags&dataplane.SessFlagSNAT != 0 {
			natIP := uint32ToIP(val.NATSrcIP)
			natPort := ntohs(val.NATSrcPort)
			fmt.Printf("  NAT: src %s:%d -> %s:%d\n",
				srcIP, srcPort, natIP, natPort)
		}
		if val.Flags&dataplane.SessFlagDNAT != 0 {
			natIP := uint32ToIP(val.NATDstIP)
			natPort := ntohs(val.NATDstPort)
			fmt.Printf("  NAT: dst %s:%d -> %s:%d\n",
				natIP, natPort, dstIP, dstPort)
		}

		fmt.Printf("  Packets: %d/%d, Bytes: %d/%d\n",
			val.FwdPackets, val.RevPackets, val.FwdBytes, val.RevBytes)
		return true
	})
	if err != nil {
		return fmt.Errorf("iterate sessions: %w", err)
	}

	// IPv6 sessions
	err = c.dp.IterateSessionsV6(func(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
		if val.IsReverse != 0 {
			return true
		}
		count++

		srcIP := net.IP(key.SrcIP[:])
		dstIP := net.IP(key.DstIP[:])
		srcPort := ntohs(key.SrcPort)
		dstPort := ntohs(key.DstPort)
		protoName := protoNameFromNum(key.Protocol)
		stateName := sessionStateName(val.State)

		fmt.Printf("Session ID: %d, Policy: %d, State: %s, Timeout: %ds\n",
			count, val.PolicyID, stateName, val.Timeout)
		fmt.Printf("  In: [%s]:%d --> [%s]:%d;%s,",
			srcIP, srcPort, dstIP, dstPort, protoName)
		fmt.Printf(" Zone: %d -> %d\n", val.IngressZone, val.EgressZone)

		if val.Flags&dataplane.SessFlagSNAT != 0 {
			natIP := net.IP(val.NATSrcIP[:])
			natPort := ntohs(val.NATSrcPort)
			fmt.Printf("  NAT: src [%s]:%d -> [%s]:%d\n",
				srcIP, srcPort, natIP, natPort)
		}
		if val.Flags&dataplane.SessFlagDNAT != 0 {
			natIP := net.IP(val.NATDstIP[:])
			natPort := ntohs(val.NATDstPort)
			fmt.Printf("  NAT: dst [%s]:%d -> [%s]:%d\n",
				natIP, natPort, dstIP, dstPort)
		}

		fmt.Printf("  Packets: %d/%d, Bytes: %d/%d\n",
			val.FwdPackets, val.RevPackets, val.FwdBytes, val.RevBytes)
		return true
	})
	if err != nil {
		return fmt.Errorf("iterate sessions_v6: %w", err)
	}

	fmt.Printf("Total sessions: %d\n", count)
	return nil
}

func (c *CLI) handleClear(args []string) error {
	if len(args) < 3 || args[0] != "security" || args[1] != "flow" || args[2] != "session" {
		fmt.Println("clear:")
		fmt.Println("  security flow session    Clear all sessions")
		return nil
	}

	if c.dp == nil || !c.dp.IsLoaded() {
		fmt.Println("dataplane not loaded")
		return nil
	}

	v4, v6, err := c.dp.ClearAllSessions()
	if err != nil {
		return fmt.Errorf("clear sessions: %w", err)
	}
	fmt.Printf("%d IPv4 and %d IPv6 session entries cleared\n", v4, v6)
	return nil
}

func (c *CLI) handleShowNAT(args []string) error {
	cfg := c.store.ActiveConfig()

	if len(args) == 0 {
		fmt.Println("show security nat:")
		fmt.Println("  source           Show source NAT rules and sessions")
		fmt.Println("  destination      Show destination NAT rules")
		fmt.Println("  static           Show static 1:1 NAT rules")
		return nil
	}

	switch args[0] {
	case "source":
		return c.showNATSource(cfg, args[1:])
	case "destination":
		return c.showNATDestination(cfg)
	case "static":
		return c.showNATStatic(cfg)
	default:
		return fmt.Errorf("unknown show security nat target: %s", args[0])
	}
}

func (c *CLI) showNATSource(cfg *config.Config, args []string) error {
	// Show configured source NAT pools
	if cfg != nil && len(cfg.Security.NAT.SourcePools) > 0 {
		fmt.Println("Source NAT pools:")
		for name, pool := range cfg.Security.NAT.SourcePools {
			fmt.Printf("  Pool: %s\n", name)
			for _, addr := range pool.Addresses {
				fmt.Printf("    Address: %s\n", addr)
			}
			fmt.Printf("    Port range: %d-%d\n", pool.PortLow, pool.PortHigh)
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
	_ = c.dp.IterateSessions(func(key dataplane.SessionKey, val dataplane.SessionValue) bool {
		if val.IsReverse != 0 {
			return true
		}
		if val.Flags&dataplane.SessFlagSNAT != 0 {
			snatCount++
		}
		return true
	})
	_ = c.dp.IterateSessionsV6(func(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
		if val.IsReverse != 0 {
			return true
		}
		if val.Flags&dataplane.SessFlagSNAT != 0 {
			snatCount++
		}
		return true
	})
	fmt.Printf("Active SNAT sessions: %d\n", snatCount)

	// Show NAT alloc fail counter
	ctrMap := c.dp.Map("global_counters")
	if ctrMap != nil {
		var perCPU []uint64
		if err := ctrMap.Lookup(uint32(dataplane.GlobalCtrNATAllocFail), &perCPU); err == nil {
			var total uint64
			for _, v := range perCPU {
				total += v
			}
			fmt.Printf("NAT allocation failures: %d\n", total)
		}
	}

	return nil
}

func (c *CLI) showNATDestination(cfg *config.Config) error {
	if cfg == nil || cfg.Security.NAT.Destination == nil {
		fmt.Println("No destination NAT rules configured.")
		return nil
	}

	dnat := cfg.Security.NAT.Destination

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
			if rule.Match.DestinationAddress != "" {
				fmt.Printf("    Match destination-address: %s\n", rule.Match.DestinationAddress)
			}
			if rule.Match.DestinationPort != 0 {
				fmt.Printf("    Match destination-port: %d\n", rule.Match.DestinationPort)
			}
			if rule.Then.PoolName != "" {
				fmt.Printf("    Then pool: %s\n", rule.Then.PoolName)
			}
		}
		fmt.Println()
	}

	// Show summary of active DNAT sessions
	if c.dp != nil && c.dp.IsLoaded() {
		dnatCount := 0
		_ = c.dp.IterateSessions(func(key dataplane.SessionKey, val dataplane.SessionValue) bool {
			if val.IsReverse != 0 {
				return true
			}
			if val.Flags&dataplane.SessFlagDNAT != 0 {
				dnatCount++
			}
			return true
		})
		_ = c.dp.IterateSessionsV6(func(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
			if val.IsReverse != 0 {
				return true
			}
			if val.Flags&dataplane.SessFlagDNAT != 0 {
				dnatCount++
			}
			return true
		})
		fmt.Printf("Active DNAT sessions: %d\n", dnatCount)
	}

	return nil
}

func (c *CLI) showNATStatic(cfg *config.Config) error {
	if cfg == nil || len(cfg.Security.NAT.Static) == 0 {
		fmt.Println("No static NAT rules configured.")
		return nil
	}

	for _, rs := range cfg.Security.NAT.Static {
		fmt.Printf("Static NAT rule-set: %s\n", rs.Name)
		fmt.Printf("  From zone: %s\n", rs.FromZone)
		for _, rule := range rs.Rules {
			fmt.Printf("  Rule: %s\n", rule.Name)
			fmt.Printf("    Match destination-address: %s\n", rule.Match)
			fmt.Printf("    Then static-nat prefix:    %s\n", rule.Then)
		}
		fmt.Println()
	}

	return nil
}

func (c *CLI) showInterfaces(args []string) error {
	cfg := c.store.ActiveConfig()
	if cfg == nil {
		fmt.Println("no active configuration")
		return nil
	}

	// Optional filter by interface name
	var filterName string
	if len(args) > 0 {
		filterName = args[0]
	}

	// Build interface -> zone name mapping from config
	ifaceZone := make(map[string]string)
	for name, zone := range cfg.Security.Zones {
		for _, ifaceName := range zone.Interfaces {
			ifaceZone[ifaceName] = name
		}
	}

	// Collect unique interface names from all zones
	var ifaceNames []string
	for ifaceName := range ifaceZone {
		if filterName != "" && ifaceName != filterName {
			continue
		}
		ifaceNames = append(ifaceNames, ifaceName)
	}

	if len(ifaceNames) == 0 && filterName != "" {
		return fmt.Errorf("interface %s not found in configuration", filterName)
	}

	for _, ifaceName := range ifaceNames {
		zoneName := ifaceZone[ifaceName]

		// Query live system for link info
		iface, err := net.InterfaceByName(ifaceName)
		if err != nil {
			fmt.Printf("Physical interface: %s, Not present\n", ifaceName)
			fmt.Printf("  Security zone: %s\n", zoneName)
			fmt.Println()
			continue
		}

		upDown := "Down"
		if iface.Flags&net.FlagUp != 0 {
			upDown = "Up"
		}
		enabled := "Enabled"
		if iface.Flags&net.FlagUp == 0 {
			enabled = "Disabled"
		}

		fmt.Printf("Physical interface: %s, %s, Physical link is %s\n",
			ifaceName, enabled, upDown)
		fmt.Printf("  Link-level type: Ethernet, MTU: %d, MAC: %s\n",
			iface.MTU, iface.HardwareAddr)
		fmt.Printf("  Security zone: %s\n", zoneName)

		// Traffic counters from BPF map
		if c.dp != nil && c.dp.IsLoaded() {
			counters, err := c.dp.ReadInterfaceCounters(iface.Index)
			if err == nil {
				fmt.Println("  Traffic statistics:")
				fmt.Printf("    Input:  %d packets, %d bytes\n",
					counters.RxPackets, counters.RxBytes)
				fmt.Printf("    Output: %d packets, %d bytes\n",
					counters.TxPackets, counters.TxBytes)
			}
		}

		// Addresses
		addrs, err := iface.Addrs()
		if err == nil && len(addrs) > 0 {
			fmt.Printf("\n  Logical interface %s.0\n", ifaceName)
			fmt.Println("    Addresses:")
			for _, addr := range addrs {
				ipNet, ok := addr.(*net.IPNet)
				if !ok {
					continue
				}
				ones, _ := ipNet.Mask.Size()
				if ipNet.IP.To4() != nil {
					fmt.Printf("      inet  %s/%d\n", ipNet.IP, ones)
				} else {
					fmt.Printf("      inet6 %s/%d\n", ipNet.IP, ones)
				}
			}
		}

		fmt.Println()
	}

	return nil
}

func protoNameFromNum(p uint8) string {
	switch p {
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 1:
		return "ICMP"
	case dataplane.ProtoICMPv6:
		return "ICMPv6"
	default:
		return fmt.Sprintf("%d", p)
	}
}

// uint32ToIP converts a network byte order uint32 to net.IP.
func uint32ToIP(v uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, v)
	return ip
}

func sessionStateName(state uint8) string {
	switch state {
	case dataplane.SessStateNone:
		return "None"
	case dataplane.SessStateNew:
		return "New"
	case dataplane.SessStateSynSent:
		return "SYN_SENT"
	case dataplane.SessStateSynRecv:
		return "SYN_RECV"
	case dataplane.SessStateEstablished:
		return "Established"
	case dataplane.SessStateFINWait:
		return "FIN_WAIT"
	case dataplane.SessStateCloseWait:
		return "CLOSE_WAIT"
	case dataplane.SessStateTimeWait:
		return "TIME_WAIT"
	case dataplane.SessStateClosed:
		return "Closed"
	default:
		return fmt.Sprintf("Unknown(%d)", state)
	}
}

// ntohs converts a uint16 from network to host byte order.
func ntohs(v uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	return binary.NativeEndian.Uint16(b[:])
}

func (c *CLI) operationalPrompt() string {
	return fmt.Sprintf("%s@%s> ", c.username, c.hostname)
}

func (c *CLI) configPrompt() string {
	return fmt.Sprintf("[edit]\n%s@%s# ", c.username, c.hostname)
}

func (c *CLI) showOperationalHelp() {
	fmt.Println("Operational mode commands:")
	fmt.Println("  configure                    Enter configuration mode")
	fmt.Println("  show configuration           Show running configuration")
	fmt.Println("  show security                Show security information")
	fmt.Println("  clear security flow session  Clear all sessions")
	fmt.Println("  quit                         Exit CLI")
}

func (c *CLI) showConfigHelp() {
	fmt.Println("Configuration mode commands:")
	fmt.Println("  set <path>         Set a configuration value")
	fmt.Println("  delete <path>      Delete a configuration element")
	fmt.Println("  show               Show candidate configuration")
	fmt.Println("  show | compare     Show pending changes")
	fmt.Println("  show | display set Show as flat set commands")
	fmt.Println("  commit             Validate and apply configuration")
	fmt.Println("  commit check       Validate without applying")
	fmt.Println("  rollback [n]       Revert to previous configuration")
	fmt.Println("  run <cmd>          Run operational command")
	fmt.Println("  exit               Exit configuration mode")
}
