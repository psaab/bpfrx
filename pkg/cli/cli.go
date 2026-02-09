// Package cli implements the Junos-style interactive CLI for bpfrx.
package cli

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/chzyer/readline"
	"github.com/psaab/bpfrx/pkg/config"
	"github.com/psaab/bpfrx/pkg/configstore"
	"github.com/psaab/bpfrx/pkg/dataplane"
	"github.com/psaab/bpfrx/pkg/frr"
	"github.com/psaab/bpfrx/pkg/ipsec"
	"github.com/psaab/bpfrx/pkg/logging"
	"github.com/psaab/bpfrx/pkg/routing"
)

// CLI is the interactive command-line interface.
type CLI struct {
	rl          *readline.Instance
	store       *configstore.Store
	dp          *dataplane.Manager
	eventBuf    *logging.EventBuffer
	eventReader *logging.EventReader
	routing     *routing.Manager
	frr         *frr.Manager
	ipsec       *ipsec.Manager
	hostname    string
	username    string
}

// New creates a new CLI.
func New(store *configstore.Store, dp *dataplane.Manager, eventBuf *logging.EventBuffer, eventReader *logging.EventReader, rm *routing.Manager, fm *frr.Manager, im *ipsec.Manager) *CLI {
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "bpfrx"
	}
	username := os.Getenv("USER")
	if username == "" {
		username = "root"
	}

	return &CLI{
		store:       store,
		dp:          dp,
		eventBuf:    eventBuf,
		eventReader: eventReader,
		routing:     rm,
		frr:         fm,
		ipsec:       im,
		hostname:    hostname,
		username:    username,
	}
}

// completionNode is a static command completion tree node.
type completionNode struct {
	desc     string
	children map[string]*completionNode
}

// operationalTree defines tab completion for operational mode.
var operationalTree = map[string]*completionNode{
	"configure": {desc: "Enter configuration mode"},
	"show": {desc: "Show information", children: map[string]*completionNode{
		"configuration": {desc: "Show active configuration"},
		"route":         {desc: "Show routing table"},
		"security": {desc: "Show security information", children: map[string]*completionNode{
			"zones":    {desc: "Show security zones"},
			"policies": {desc: "Show security policies"},
			"screen":   {desc: "Show screen/IDS profiles"},
			"flow": {desc: "Show flow information", children: map[string]*completionNode{
				"session": {desc: "Show active sessions"},
			}},
			"nat": {desc: "Show NAT information", children: map[string]*completionNode{
				"source":      {desc: "Show source NAT"},
				"destination": {desc: "Show destination NAT"},
				"static":      {desc: "Show static NAT"},
			}},
			"address-book": {desc: "Show address book entries"},
			"applications": {desc: "Show application definitions"},
			"log":          {desc: "Show recent security events [N] [zone <z>] [protocol <p>] [action <a>]"},
			"statistics":   {desc: "Show global statistics"},
			"ipsec": {desc: "Show IPsec status", children: map[string]*completionNode{
				"security-associations": {desc: "Show IPsec SAs"},
			}},
		}},
		"interfaces": {desc: "Show interface status", children: map[string]*completionNode{
			"tunnel": {desc: "Show tunnel interfaces"},
		}},
		"protocols": {desc: "Show protocol information", children: map[string]*completionNode{
			"ospf": {desc: "Show OSPF information", children: map[string]*completionNode{
				"neighbor": {desc: "Show OSPF neighbors"},
				"database": {desc: "Show OSPF database"},
			}},
			"bgp": {desc: "Show BGP information", children: map[string]*completionNode{
				"summary": {desc: "Show BGP peer summary"},
				"routes":  {desc: "Show BGP routes"},
			}},
		}},
		"system": {desc: "Show system information", children: map[string]*completionNode{
			"rollback": {desc: "Show rollback history"},
		}},
	}},
	"clear": {desc: "Clear information", children: map[string]*completionNode{
		"security": {desc: "Clear security information", children: map[string]*completionNode{
			"flow": {desc: "Clear flow information", children: map[string]*completionNode{
				"session": {desc: "Clear all sessions"},
			}},
			"counters": {desc: "Clear all counters"},
		}},
	}},
	"quit": {desc: "Exit CLI"},
	"exit": {desc: "Exit CLI"},
}

// configTopLevel defines tab completion for config mode top-level commands.
var configTopLevel = map[string]*completionNode{
	"set":      {desc: "Set a configuration value"},
	"delete":   {desc: "Delete a configuration element"},
	"show":     {desc: "Show candidate configuration"},
	"commit":   {desc: "Commit configuration", children: map[string]*completionNode{
		"check":     {desc: "Validate without applying"},
		"confirmed": {desc: "Auto-rollback if not confirmed [minutes]"},
	}},
	"rollback": {desc: "Revert to previous configuration"},
	"run":      {desc: "Run operational command"},
	"exit":     {desc: "Exit configuration mode"},
	"quit":     {desc: "Exit configuration mode"},
}

// cliCompleter implements readline.AutoCompleter.
type cliCompleter struct {
	cli *CLI
}

func (cc *cliCompleter) Do(line []rune, pos int) ([][]rune, int) {
	// Only complete up to cursor position.
	text := string(line[:pos])
	words := strings.Fields(text)

	// Detect if cursor is at a space after the last word (ready for new word).
	trailingSpace := len(text) > 0 && text[len(text)-1] == ' '

	var partial string
	if !trailingSpace && len(words) > 0 {
		partial = words[len(words)-1]
		words = words[:len(words)-1]
	}

	var candidates []string

	if cc.cli.store.InConfigMode() {
		candidates = cc.completeConfig(words, partial)
	} else {
		candidates = cc.completeOperational(words, partial)
	}

	if len(candidates) == 0 {
		return nil, 0
	}

	sort.Strings(candidates)

	var result [][]rune
	for _, c := range candidates {
		suffix := c[len(partial):]
		result = append(result, []rune(suffix+" "))
	}
	return result, len(partial)
}

func (cc *cliCompleter) completeOperational(words []string, partial string) []string {
	return completeFromTree(operationalTree, words, partial)
}

func (cc *cliCompleter) completeConfig(words []string, partial string) []string {
	if len(words) == 0 {
		// Complete top-level config commands.
		return filterPrefix(keysOf(configTopLevel), partial)
	}

	switch words[0] {
	case "set", "delete":
		// Use schema-driven completion for the path after set/delete.
		schemaCompletions := config.CompleteSetPathWithValues(words[1:], cc.cli.valueProvider)
		if schemaCompletions == nil {
			return nil
		}
		return filterPrefix(schemaCompletions, partial)

	case "run":
		// Delegate to operational completions for the rest.
		return completeFromTree(operationalTree, words[1:], partial)

	case "commit":
		if len(words) == 1 {
			return filterPrefix([]string{"check", "confirmed"}, partial)
		}
		return nil

	default:
		return nil
	}
}

func completeFromTree(tree map[string]*completionNode, words []string, partial string) []string {
	current := tree
	for _, w := range words {
		node, ok := current[w]
		if !ok {
			return nil
		}
		if node.children == nil {
			return nil
		}
		current = node.children
	}
	return filterPrefix(keysOf(current), partial)
}

func keysOf(m map[string]*completionNode) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func filterPrefix(items []string, prefix string) []string {
	if prefix == "" {
		return items
	}
	var result []string
	for _, item := range items {
		if strings.HasPrefix(item, prefix) {
			result = append(result, item)
		}
	}
	return result
}

// Run starts the interactive CLI loop.
func (c *CLI) Run() error {
	var err error
	c.rl, err = readline.NewEx(&readline.Config{
		Prompt:          c.operationalPrompt(),
		HistoryFile:     "/tmp/bpfrx_history",
		InterruptPrompt: "^C",
		EOFPrompt:       "exit",
		AutoComplete:    &cliCompleter{cli: c},
	})
	if err != nil {
		return fmt.Errorf("readline init: %w", err)
	}
	defer c.rl.Close()

	// Register auto-rollback handler for commit confirmed
	c.store.SetAutoRollbackHandler(func(cfg *config.Config) {
		if c.dp != nil {
			if err := c.applyToDataplane(cfg); err != nil {
				fmt.Fprintf(os.Stderr, "\nwarning: auto-rollback dataplane apply failed: %v\n", err)
			}
		}
		c.reloadSyslog(cfg)
		fmt.Fprintf(os.Stderr, "\ncommit confirmed timed out, configuration has been rolled back\n")
	})

	fmt.Println("bpfrx firewall - Junos-style eBPF firewall")
	fmt.Println("Type '?' for help")
	fmt.Println()

	for {
		if c.store.IsConfirmPending() {
			fmt.Println("[commit confirmed pending - issue 'commit' to confirm]")
		}
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
	// Context-sensitive help: trailing ? shows available completions.
	if strings.HasSuffix(line, "?") {
		c.showContextHelp(strings.TrimSuffix(line, "?"))
		return nil
	}

	// Extract | match pipe (but not | display set or | compare).
	if cmd, pattern, ok := extractMatchPipe(line); ok && pattern != "" {
		return c.dispatchWithMatchPipe(cmd, pattern)
	}

	if c.store.InConfigMode() {
		return c.dispatchConfig(line)
	}
	return c.dispatchOperational(line)
}

// extractMatchPipe splits a line at "| match <pattern>".
// Returns the command part, the pattern, and whether a match pipe was found.
func extractMatchPipe(line string) (string, string, bool) {
	idx := strings.Index(line, "| match ")
	if idx < 0 {
		return line, "", false
	}
	cmd := strings.TrimSpace(line[:idx])
	pattern := strings.TrimSpace(line[idx+len("| match "):])
	return cmd, pattern, true
}

// dispatchWithMatchPipe runs the command and filters output lines by pattern.
func (c *CLI) dispatchWithMatchPipe(cmd, pattern string) error {
	// Capture stdout.
	origStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("pipe: %w", err)
	}
	os.Stdout = w

	// Run the inner command.
	var cmdErr error
	done := make(chan struct{})
	go func() {
		defer close(done)
		cmdErr = c.dispatch(cmd)
	}()
	<-done
	w.Close()
	os.Stdout = origStdout

	// Read captured output and filter.
	output, _ := io.ReadAll(r)
	r.Close()

	lowerPattern := strings.ToLower(pattern)
	for _, line := range strings.Split(string(output), "\n") {
		if strings.Contains(strings.ToLower(line), lowerPattern) {
			fmt.Fprintln(origStdout, line)
		}
	}

	return cmdErr
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
		fmt.Println("  route            Show routing table")
		fmt.Println("  security         Show security information")
		fmt.Println("  interfaces       Show interface status")
		fmt.Println("  protocols        Show protocol information")
		fmt.Println("  system           Show system information")
		return nil
	}

	switch args[0] {
	case "configuration":
		rest := strings.Join(args[1:], " ")
		if strings.Contains(rest, "| display set") {
			fmt.Print(c.store.ShowActiveSet())
		} else {
			fmt.Print(c.store.ShowActive())
		}
		return nil

	case "route":
		return c.showRoutes()

	case "security":
		return c.handleShowSecurity(args[1:])

	case "interfaces":
		return c.showInterfaces(args[1:])

	case "protocols":
		return c.handleShowProtocols(args[1:])

	case "system":
		return c.handleShowSystem(args[1:])

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
		fmt.Println("  flow             Show flow timeouts")
		fmt.Println("  flow session     Show active sessions [zone <n>] [protocol <p>] [source-prefix <cidr>] [destination-prefix <cidr>] [summary]")
		fmt.Println("  nat source       Show source NAT information")
		fmt.Println("  nat destination  Show destination NAT information")
		fmt.Println("  address-book     Show address book entries")
		fmt.Println("  applications     Show application definitions")
		fmt.Println("  ipsec            Show IPsec VPN status")
		fmt.Println("  log [N] [zone <name>] [protocol <proto>] [action <act>]")
		fmt.Println("  statistics       Show global statistics")
		return nil
	}

	cfg := c.store.ActiveConfig()
	if cfg == nil && args[0] != "statistics" && args[0] != "ipsec" {
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
			return c.showFlowSession(args[2:])
		}
		if len(args) == 1 {
			return c.showFlowTimeouts()
		}
		return fmt.Errorf("unknown show security flow target")

	case "screen":
		return c.showScreen()

	case "nat":
		return c.handleShowNAT(args[1:])

	case "address-book":
		return c.showAddressBook()

	case "applications":
		return c.showApplications()

	case "log":
		return c.showSecurityLog(args[1:])

	case "statistics":
		return c.showStatistics()

	case "ipsec":
		return c.showIPsec(args[1:])

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
		if profile.TCP.SynFrag {
			fmt.Println("  TCP SYN fragment detection: enabled")
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
		// Check for "| compare rollback N"
		if idx := strings.Index(line, "| compare rollback"); idx >= 0 {
			rest := strings.TrimSpace(line[idx+len("| compare rollback"):])
			n, err := strconv.Atoi(rest)
			if err != nil || n < 1 {
				return fmt.Errorf("usage: show | compare rollback <N>")
			}
			diff, err := c.store.ShowCompareRollback(n)
			if err != nil {
				return err
			}
			fmt.Print(diff)
			return nil
		}
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

	if len(args) > 0 && args[0] == "confirmed" {
		minutes := 10
		if len(args) >= 2 {
			if v, err := strconv.Atoi(args[1]); err == nil && v > 0 {
				minutes = v
			}
		}

		compiled, err := c.store.CommitConfirmed(minutes)
		if err != nil {
			return fmt.Errorf("commit confirmed failed: %w", err)
		}

		// Apply to dataplane
		if c.dp != nil {
			if err := c.applyToDataplane(compiled); err != nil {
				fmt.Fprintf(os.Stderr, "warning: dataplane apply failed: %v\n", err)
			}
		}
		c.reloadSyslog(compiled)

		fmt.Printf("commit confirmed will be automatically rolled back in %d minutes unless confirmed\n", minutes)
		return nil
	}

	// Bare commit: if a confirmed commit is pending, confirm it
	if c.store.IsConfirmPending() {
		if err := c.store.ConfirmCommit(); err != nil {
			return fmt.Errorf("confirm commit: %w", err)
		}
		fmt.Println("commit confirmed")
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

	// Hot-reload syslog clients
	c.reloadSyslog(compiled)

	fmt.Println("commit complete")
	return nil
}

func (c *CLI) reloadSyslog(cfg *config.Config) {
	if c.eventReader == nil {
		return
	}
	var clients []*logging.SyslogClient
	for name, stream := range cfg.Security.Log.Streams {
		client, err := logging.NewSyslogClient(stream.Host, stream.Port)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: syslog stream %s: %v\n", name, err)
			continue
		}
		clients = append(clients, client)
	}
	c.eventReader.ReplaceSyslogClients(clients)
}

func (c *CLI) applyToDataplane(cfg *config.Config) error {
	// 1. Create tunnel interfaces first
	if c.routing != nil {
		var tunnels []*config.TunnelConfig
		for _, ifc := range cfg.Interfaces.Interfaces {
			if ifc.Tunnel != nil {
				tunnels = append(tunnels, ifc.Tunnel)
			}
		}
		if len(tunnels) > 0 {
			if err := c.routing.ApplyTunnels(tunnels); err != nil {
				fmt.Fprintf(os.Stderr, "warning: tunnel apply failed: %v\n", err)
			}
		}
	}

	// 2. Compile eBPF dataplane
	if c.dp != nil && c.dp.IsLoaded() {
		if _, err := c.dp.Compile(cfg); err != nil {
			return err
		}
	}

	// 3. Install static routes
	if c.routing != nil && len(cfg.RoutingOptions.StaticRoutes) > 0 {
		if err := c.routing.ApplyStaticRoutes(cfg.RoutingOptions.StaticRoutes); err != nil {
			fmt.Fprintf(os.Stderr, "warning: static routes apply failed: %v\n", err)
		}
	}

	// 4. Apply FRR config
	if c.frr != nil && (cfg.Protocols.OSPF != nil || cfg.Protocols.BGP != nil) {
		if err := c.frr.Apply(cfg.Protocols.OSPF, cfg.Protocols.BGP); err != nil {
			fmt.Fprintf(os.Stderr, "warning: FRR apply failed: %v\n", err)
		}
	}

	// 5. Apply IPsec config
	if c.ipsec != nil && len(cfg.Security.IPsec.VPNs) > 0 {
		if err := c.ipsec.Apply(&cfg.Security.IPsec); err != nil {
			fmt.Fprintf(os.Stderr, "warning: IPsec apply failed: %v\n", err)
		}
	}

	return nil
}

// sessionFilter holds parsed filter criteria for session display.
type sessionFilter struct {
	zoneID  uint16   // 0 = any
	proto   uint8    // 0 = any
	srcNet  *net.IPNet
	dstNet  *net.IPNet
	summary bool     // only show count
}

func (c *CLI) parseSessionFilter(args []string) sessionFilter {
	var f sessionFilter
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "zone":
			if i+1 < len(args) {
				i++
				if c.dp != nil {
					if cr := c.dp.LastCompileResult(); cr != nil {
						f.zoneID = cr.ZoneIDs[args[i]]
					}
				}
			}
		case "protocol":
			if i+1 < len(args) {
				i++
				switch strings.ToLower(args[i]) {
				case "tcp":
					f.proto = 6
				case "udp":
					f.proto = 17
				case "icmp":
					f.proto = 1
				case "icmpv6":
					f.proto = dataplane.ProtoICMPv6
				}
			}
		case "source-prefix":
			if i+1 < len(args) {
				i++
				cidr := args[i]
				if !strings.Contains(cidr, "/") {
					if strings.Contains(cidr, ":") {
						cidr += "/128"
					} else {
						cidr += "/32"
					}
				}
				_, ipNet, err := net.ParseCIDR(cidr)
				if err == nil {
					f.srcNet = ipNet
				}
			}
		case "destination-prefix":
			if i+1 < len(args) {
				i++
				cidr := args[i]
				if !strings.Contains(cidr, "/") {
					if strings.Contains(cidr, ":") {
						cidr += "/128"
					} else {
						cidr += "/32"
					}
				}
				_, ipNet, err := net.ParseCIDR(cidr)
				if err == nil {
					f.dstNet = ipNet
				}
			}
		case "summary":
			f.summary = true
		}
	}
	return f
}

func (f *sessionFilter) matchesV4(key dataplane.SessionKey, val dataplane.SessionValue) bool {
	if f.zoneID != 0 && val.IngressZone != f.zoneID && val.EgressZone != f.zoneID {
		return false
	}
	if f.proto != 0 && key.Protocol != f.proto {
		return false
	}
	if f.srcNet != nil && !f.srcNet.Contains(net.IP(key.SrcIP[:])) {
		return false
	}
	if f.dstNet != nil && !f.dstNet.Contains(net.IP(key.DstIP[:])) {
		return false
	}
	return true
}

func (f *sessionFilter) matchesV6(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
	if f.zoneID != 0 && val.IngressZone != f.zoneID && val.EgressZone != f.zoneID {
		return false
	}
	if f.proto != 0 && key.Protocol != f.proto {
		return false
	}
	if f.srcNet != nil && !f.srcNet.Contains(net.IP(key.SrcIP[:])) {
		return false
	}
	if f.dstNet != nil && !f.dstNet.Contains(net.IP(key.DstIP[:])) {
		return false
	}
	return true
}

func (f *sessionFilter) hasFilter() bool {
	return f.zoneID != 0 || f.proto != 0 || f.srcNet != nil || f.dstNet != nil
}

func (c *CLI) showFlowSession(args []string) error {
	if c.dp == nil || !c.dp.IsLoaded() {
		fmt.Println("Session table: dataplane not loaded")
		return nil
	}

	f := c.parseSessionFilter(args)
	count := 0

	// IPv4 sessions
	err := c.dp.IterateSessions(func(key dataplane.SessionKey, val dataplane.SessionValue) bool {
		if val.IsReverse != 0 {
			return true
		}
		if f.hasFilter() && !f.matchesV4(key, val) {
			return true
		}
		count++

		if f.summary {
			return true
		}

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
		if f.hasFilter() && !f.matchesV6(key, val) {
			return true
		}
		count++

		if f.summary {
			return true
		}

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

func (c *CLI) showFlowTimeouts() error {
	cfg := c.store.ActiveConfig()
	if cfg == nil {
		fmt.Println("no active configuration")
		return nil
	}

	flow := &cfg.Security.Flow

	fmt.Println("Flow session timeouts:")

	// TCP
	if flow.TCPSession != nil {
		tcp := flow.TCPSession
		printTimeout := func(name string, val, def int) {
			if val > 0 {
				fmt.Printf("  %-30s %ds\n", name+":", val)
			} else {
				fmt.Printf("  %-30s %ds (default)\n", name+":", def)
			}
		}
		printTimeout("TCP established timeout", tcp.EstablishedTimeout, 1800)
		printTimeout("TCP initial timeout", tcp.InitialTimeout, 30)
		printTimeout("TCP closing timeout", tcp.ClosingTimeout, 30)
		printTimeout("TCP time-wait timeout", tcp.TimeWaitTimeout, 120)
	} else {
		fmt.Println("  TCP established timeout:       1800s (default)")
		fmt.Println("  TCP initial timeout:           30s (default)")
		fmt.Println("  TCP closing timeout:           30s (default)")
		fmt.Println("  TCP time-wait timeout:         120s (default)")
	}

	// UDP
	if flow.UDPSessionTimeout > 0 {
		fmt.Printf("  %-30s %ds\n", "UDP session timeout:", flow.UDPSessionTimeout)
	} else {
		fmt.Println("  UDP session timeout:           60s (default)")
	}

	// ICMP
	if flow.ICMPSessionTimeout > 0 {
		fmt.Printf("  %-30s %ds\n", "ICMP session timeout:", flow.ICMPSessionTimeout)
	} else {
		fmt.Println("  ICMP session timeout:          30s (default)")
	}

	return nil
}

func (c *CLI) handleClear(args []string) error {
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

	case "counters":
		if c.dp == nil || !c.dp.IsLoaded() {
			fmt.Println("dataplane not loaded")
			return nil
		}
		if err := c.dp.ClearAllCounters(); err != nil {
			return fmt.Errorf("clear counters: %w", err)
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

func (c *CLI) showAddressBook() error {
	cfg := c.store.ActiveConfig()
	if cfg == nil || cfg.Security.AddressBook == nil {
		fmt.Println("No address book configured")
		return nil
	}
	ab := cfg.Security.AddressBook

	if len(ab.Addresses) > 0 {
		fmt.Println("Addresses:")
		for _, addr := range ab.Addresses {
			fmt.Printf("  %-24s %s\n", addr.Name, addr.Value)
		}
	}

	if len(ab.AddressSets) > 0 {
		fmt.Println("Address sets:")
		for _, as := range ab.AddressSets {
			fmt.Printf("  %-24s members: %s\n", as.Name, strings.Join(as.Addresses, ", "))
		}
	}

	if len(ab.Addresses) == 0 && len(ab.AddressSets) == 0 {
		fmt.Println("Address book is empty")
	}

	return nil
}

func (c *CLI) showApplications() error {
	cfg := c.store.ActiveConfig()

	// User-defined applications
	if cfg != nil && len(cfg.Applications.Applications) > 0 {
		fmt.Println("User-defined applications:")
		for _, app := range cfg.Applications.Applications {
			port := app.DestinationPort
			if port == "" {
				port = "-"
			}
			fmt.Printf("  %-24s protocol: %-6s port: %s\n", app.Name, app.Protocol, port)
		}
		fmt.Println()
	}

	// User-defined application-sets
	if cfg != nil && len(cfg.Applications.ApplicationSets) > 0 {
		fmt.Println("Application sets:")
		for _, as := range cfg.Applications.ApplicationSets {
			fmt.Printf("  %-24s members: %s\n", as.Name, strings.Join(as.Applications, ", "))
		}
		fmt.Println()
	}

	// Predefined applications
	fmt.Println("Predefined applications:")
	for _, app := range config.PredefinedApplications {
		port := app.DestinationPort
		if port == "" {
			port = "-"
		}
		fmt.Printf("  %-24s protocol: %-6s port: %s\n", app.Name, app.Protocol, port)
	}

	return nil
}

func (c *CLI) showRoutes() error {
	if c.routing == nil {
		fmt.Println("Routing manager not available")
		return nil
	}

	entries, err := c.routing.GetRoutes()
	if err != nil {
		return fmt.Errorf("get routes: %w", err)
	}

	fmt.Println("Routing table:")
	fmt.Printf("  %-24s %-20s %-14s %-12s %s\n",
		"Destination", "Next-hop", "Interface", "Proto", "Pref")
	for _, e := range entries {
		fmt.Printf("  %-24s %-20s %-14s %-12s %d\n",
			e.Destination, e.NextHop, e.Interface, e.Protocol, e.Preference)
	}
	return nil
}

func (c *CLI) handleShowProtocols(args []string) error {
	if len(args) == 0 {
		fmt.Println("show protocols:")
		fmt.Println("  ospf             Show OSPF information")
		fmt.Println("  bgp              Show BGP information")
		return nil
	}

	switch args[0] {
	case "ospf":
		return c.showOSPF(args[1:])
	case "bgp":
		return c.showBGP(args[1:])
	default:
		return fmt.Errorf("unknown show protocols target: %s", args[0])
	}
}

func (c *CLI) showOSPF(args []string) error {
	if c.frr == nil {
		fmt.Println("FRR manager not available")
		return nil
	}

	if len(args) == 0 {
		fmt.Println("show protocols ospf:")
		fmt.Println("  neighbor         Show OSPF neighbors")
		fmt.Println("  database         Show OSPF database")
		return nil
	}

	switch args[0] {
	case "neighbor":
		neighbors, err := c.frr.GetOSPFNeighbors()
		if err != nil {
			return fmt.Errorf("OSPF neighbors: %w", err)
		}
		if len(neighbors) == 0 {
			fmt.Println("No OSPF neighbors")
			return nil
		}
		fmt.Printf("  %-18s %-10s %-16s %-18s %s\n",
			"Neighbor ID", "Priority", "State", "Address", "Interface")
		for _, n := range neighbors {
			fmt.Printf("  %-18s %-10s %-16s %-18s %s\n",
				n.NeighborID, n.Priority, n.State, n.Address, n.Interface)
		}
		return nil

	case "database":
		output, err := c.frr.GetOSPFDatabase()
		if err != nil {
			return fmt.Errorf("OSPF database: %w", err)
		}
		fmt.Print(output)
		return nil

	default:
		return fmt.Errorf("unknown show protocols ospf target: %s", args[0])
	}
}

func (c *CLI) showBGP(args []string) error {
	if c.frr == nil {
		fmt.Println("FRR manager not available")
		return nil
	}

	if len(args) == 0 {
		fmt.Println("show protocols bgp:")
		fmt.Println("  summary          Show BGP peer summary")
		fmt.Println("  routes           Show BGP routes")
		return nil
	}

	switch args[0] {
	case "summary":
		peers, err := c.frr.GetBGPSummary()
		if err != nil {
			return fmt.Errorf("BGP summary: %w", err)
		}
		if len(peers) == 0 {
			fmt.Println("No BGP peers")
			return nil
		}
		fmt.Printf("  %-20s %-8s %-10s %-10s %-12s %s\n",
			"Neighbor", "AS", "MsgRcvd", "MsgSent", "Up/Down", "State")
		for _, p := range peers {
			fmt.Printf("  %-20s %-8s %-10s %-10s %-12s %s\n",
				p.Neighbor, p.AS, p.MsgRcvd, p.MsgSent, p.UpDown, p.State)
		}
		return nil

	case "routes":
		routes, err := c.frr.GetBGPRoutes()
		if err != nil {
			return fmt.Errorf("BGP routes: %w", err)
		}
		if len(routes) == 0 {
			fmt.Println("No BGP routes")
			return nil
		}
		fmt.Printf("  %-24s %-20s %s\n", "Network", "Next-hop", "Path")
		for _, r := range routes {
			fmt.Printf("  %-24s %-20s %s\n", r.Network, r.NextHop, r.Path)
		}
		return nil

	default:
		return fmt.Errorf("unknown show protocols bgp target: %s", args[0])
	}
}

func (c *CLI) showIPsec(args []string) error {
	if c.ipsec == nil {
		fmt.Println("IPsec manager not available")
		return nil
	}

	if len(args) > 0 && args[0] == "security-associations" {
		sas, err := c.ipsec.GetSAStatus()
		if err != nil {
			return fmt.Errorf("IPsec SA status: %w", err)
		}
		if len(sas) == 0 {
			fmt.Println("No IPsec security associations")
			return nil
		}
		for _, sa := range sas {
			fmt.Printf("SA: %s\n", sa.Name)
			fmt.Printf("  State: %s\n", sa.State)
			if sa.LocalAddr != "" {
				fmt.Printf("  Local: %s\n", sa.LocalAddr)
			}
			if sa.RemoteAddr != "" {
				fmt.Printf("  Remote: %s\n", sa.RemoteAddr)
			}
			if sa.LocalTS != "" {
				fmt.Printf("  Local TS: %s\n", sa.LocalTS)
			}
			if sa.RemoteTS != "" {
				fmt.Printf("  Remote TS: %s\n", sa.RemoteTS)
			}
			fmt.Println()
		}
		return nil
	}

	// Default: show configured VPNs
	cfg := c.store.ActiveConfig()
	if cfg == nil {
		fmt.Println("no active configuration")
		return nil
	}

	if len(cfg.Security.IPsec.VPNs) == 0 {
		fmt.Println("No IPsec VPNs configured")
		return nil
	}

	for name, vpn := range cfg.Security.IPsec.VPNs {
		fmt.Printf("VPN: %s\n", name)
		fmt.Printf("  Gateway: %s\n", vpn.Gateway)
		if vpn.LocalAddr != "" {
			fmt.Printf("  Local address: %s\n", vpn.LocalAddr)
		}
		if vpn.IPsecPolicy != "" {
			fmt.Printf("  IPsec policy: %s\n", vpn.IPsecPolicy)
		}
		if vpn.LocalID != "" {
			fmt.Printf("  Local identity: %s\n", vpn.LocalID)
		}
		if vpn.RemoteID != "" {
			fmt.Printf("  Remote identity: %s\n", vpn.RemoteID)
		}
		fmt.Println()
	}
	return nil
}

func (c *CLI) showTunnelInterfaces() error {
	if c.routing == nil {
		fmt.Println("Routing manager not available")
		return nil
	}

	tunnels, err := c.routing.GetTunnelStatus()
	if err != nil {
		return fmt.Errorf("tunnel status: %w", err)
	}

	if len(tunnels) == 0 {
		fmt.Println("No tunnel interfaces")
		return nil
	}

	for _, t := range tunnels {
		fmt.Printf("Tunnel interface: %s\n", t.Name)
		fmt.Printf("  State: %s\n", t.State)
		if t.Source != "" {
			fmt.Printf("  Source: %s\n", t.Source)
		}
		if t.Destination != "" {
			fmt.Printf("  Destination: %s\n", t.Destination)
		}
		for _, addr := range t.Addresses {
			fmt.Printf("  Address: %s\n", addr)
		}
		fmt.Println()
	}
	return nil
}

func (c *CLI) showSecurityLog(args []string) error {
	if c.eventBuf == nil {
		fmt.Println("no events (event buffer not initialized)")
		return nil
	}

	n := 50
	var filter logging.EventFilter

	// Parse arguments: [N] [zone <name>] [protocol <proto>] [action <act>]
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "zone":
			if i+1 < len(args) {
				i++
				zoneName := args[i]
				if c.dp != nil {
					if cr := c.dp.LastCompileResult(); cr != nil {
						if zid, ok := cr.ZoneIDs[zoneName]; ok {
							filter.Zone = zid
						} else {
							return fmt.Errorf("zone %q not found", zoneName)
						}
					}
				}
			}
		case "protocol":
			if i+1 < len(args) {
				i++
				filter.Protocol = args[i]
			}
		case "action":
			if i+1 < len(args) {
				i++
				filter.Action = args[i]
			}
		default:
			// Try parsing as count.
			if v, err := strconv.Atoi(args[i]); err == nil {
				n = v
			}
		}
	}

	var events []logging.EventRecord
	if !filter.IsEmpty() {
		events = c.eventBuf.LatestFiltered(n, filter)
	} else {
		events = c.eventBuf.Latest(n)
	}
	if len(events) == 0 {
		fmt.Println("no events recorded")
		return nil
	}

	for _, e := range events {
		ts := e.Time.Format("15:04:05")
		if e.Type == "SCREEN_DROP" {
			fmt.Printf("%s %-14s screen=%-16s %s -> %s %s action=%s zone=%d\n",
				ts, e.Type, e.ScreenCheck, e.SrcAddr, e.DstAddr, e.Protocol, e.Action, e.InZone)
		} else if e.Type == "SESSION_CLOSE" {
			fmt.Printf("%s %-14s %s -> %s %s action=%-6s policy=%d zone=%d->%d pkts=%d bytes=%d\n",
				ts, e.Type, e.SrcAddr, e.DstAddr, e.Protocol, e.Action,
				e.PolicyID, e.InZone, e.OutZone, e.SessionPkts, e.SessionBytes)
		} else {
			fmt.Printf("%s %-14s %s -> %s %s action=%-6s policy=%d zone=%d->%d\n",
				ts, e.Type, e.SrcAddr, e.DstAddr, e.Protocol, e.Action,
				e.PolicyID, e.InZone, e.OutZone)
		}
	}
	fmt.Printf("(%d events shown)\n", len(events))
	return nil
}

func (c *CLI) showInterfaces(args []string) error {
	// Handle "show interfaces tunnel" sub-command
	if len(args) > 0 && args[0] == "tunnel" {
		return c.showTunnelInterfaces()
	}

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

func (c *CLI) handleShowSystem(args []string) error {
	if len(args) == 0 {
		fmt.Println("show system:")
		fmt.Println("  rollback         Show rollback history")
		return nil
	}

	switch args[0] {
	case "rollback":
		if len(args) >= 2 {
			// "show system rollback N" — show specific rollback content.
			n, err := strconv.Atoi(args[1])
			if err != nil || n < 1 {
				return fmt.Errorf("usage: show system rollback <N>")
			}
			rest := strings.Join(args[2:], " ")
			if strings.Contains(rest, "| display set") {
				content, err := c.store.ShowRollbackSet(n)
				if err != nil {
					return err
				}
				fmt.Print(content)
			} else {
				content, err := c.store.ShowRollback(n)
				if err != nil {
					return err
				}
				fmt.Print(content)
			}
			return nil
		}

		// List all rollback entries with timestamps.
		entries := c.store.ListHistory()
		if len(entries) == 0 {
			fmt.Println("No rollback history available")
			return nil
		}
		for i, entry := range entries {
			fmt.Printf("  rollback %d: %s\n", i+1, entry.Timestamp.Format("2006-01-02 15:04:05"))
		}
		return nil
	default:
		return fmt.Errorf("unknown show system target: %s", args[0])
	}
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

func (c *CLI) showContextHelp(prefix string) {
	prefix = strings.TrimSpace(prefix)
	words := strings.Fields(prefix)

	if c.store.InConfigMode() {
		c.showConfigContextHelp(words)
	} else {
		c.showOperationalContextHelp(words)
	}
}

func (c *CLI) showOperationalContextHelp(words []string) {
	// Navigate to the appropriate tree level.
	current := operationalTree
	for _, w := range words {
		node, ok := current[w]
		if !ok {
			fmt.Println("  (no help available)")
			return
		}
		if node.children == nil {
			fmt.Printf("  %-20s %s\n", w, node.desc)
			return
		}
		current = node.children
	}

	// Show children with descriptions.
	items := make([]string, 0, len(current))
	for name := range current {
		items = append(items, name)
	}
	sort.Strings(items)
	for _, name := range items {
		fmt.Printf("  %-20s %s\n", name, current[name].desc)
	}
}

func (c *CLI) showConfigContextHelp(words []string) {
	if len(words) == 0 {
		// Show top-level config commands.
		items := make([]string, 0, len(configTopLevel))
		for name := range configTopLevel {
			items = append(items, name)
		}
		sort.Strings(items)
		for _, name := range items {
			fmt.Printf("  %-20s %s\n", name, configTopLevel[name].desc)
		}
		return
	}

	switch words[0] {
	case "set", "delete":
		completions := config.CompleteSetPathWithValues(words[1:], c.valueProvider)
		if completions == nil {
			fmt.Println("  (value expected)")
			return
		}
		sort.Strings(completions)
		for _, name := range completions {
			fmt.Printf("  %s\n", name)
		}

	case "run":
		c.showOperationalContextHelp(words[1:])

	default:
		fmt.Println("  (no help available)")
	}
}

func (c *CLI) valueProvider(hint config.ValueHint) []string {
	cfg := c.store.ActiveConfig()
	if cfg == nil {
		return nil
	}
	switch hint {
	case config.ValueHintZoneName:
		names := make([]string, 0, len(cfg.Security.Zones))
		for name := range cfg.Security.Zones {
			names = append(names, name)
		}
		return names
	case config.ValueHintAddressName:
		var names []string
		if cfg.Security.AddressBook != nil {
			for _, addr := range cfg.Security.AddressBook.Addresses {
				names = append(names, addr.Name)
			}
			for _, as := range cfg.Security.AddressBook.AddressSets {
				names = append(names, as.Name)
			}
		}
		return names
	case config.ValueHintAppName:
		var names []string
		for _, app := range cfg.Applications.Applications {
			names = append(names, app.Name)
		}
		for _, as := range cfg.Applications.ApplicationSets {
			names = append(names, as.Name)
		}
		for name := range config.PredefinedApplications {
			names = append(names, name)
		}
		return names
	case config.ValueHintAppSetName:
		var names []string
		for _, as := range cfg.Applications.ApplicationSets {
			names = append(names, as.Name)
		}
		return names
	case config.ValueHintPoolName:
		var names []string
		for name := range cfg.Security.NAT.SourcePools {
			names = append(names, name)
		}
		if cfg.Security.NAT.Destination != nil {
			for name := range cfg.Security.NAT.Destination.Pools {
				names = append(names, name)
			}
		}
		return names
	case config.ValueHintScreenProfile:
		names := make([]string, 0, len(cfg.Security.Screen))
		for name := range cfg.Security.Screen {
			names = append(names, name)
		}
		return names
	case config.ValueHintStreamName:
		names := make([]string, 0, len(cfg.Security.Log.Streams))
		for name := range cfg.Security.Log.Streams {
			names = append(names, name)
		}
		return names
	case config.ValueHintInterfaceName:
		var names []string
		for _, zone := range cfg.Security.Zones {
			names = append(names, zone.Interfaces...)
		}
		return names
	}
	return nil
}

func (c *CLI) operationalPrompt() string {
	return fmt.Sprintf("%s@%s> ", c.username, c.hostname)
}

func (c *CLI) configPrompt() string {
	return fmt.Sprintf("[edit]\n%s@%s# ", c.username, c.hostname)
}

func (c *CLI) showOperationalHelp() {
	fmt.Println("Operational mode commands:")
	fmt.Println("  configure                          Enter configuration mode")
	fmt.Println("  show configuration                 Show running configuration")
	fmt.Println("  show configuration | display set   Show as flat set commands")
	fmt.Println("  show route                         Show routing table")
	fmt.Println("  show security                      Show security information")
	fmt.Println("  show security ipsec                Show IPsec VPN status")
	fmt.Println("  show security log [N]              Show recent security events")
	fmt.Println("  show interfaces tunnel             Show tunnel interfaces")
	fmt.Println("  show protocols ospf neighbor       Show OSPF neighbors")
	fmt.Println("  show protocols bgp summary         Show BGP peer summary")
	fmt.Println("  show system rollback               Show rollback history")
	fmt.Println("  clear security flow session        Clear all sessions")
	fmt.Println("  clear security counters            Clear all counters")
	fmt.Println("  quit                               Exit CLI")
	fmt.Println()
	fmt.Println("  <command> | match <pattern>         Filter output by pattern")
	fmt.Println("  Use <TAB> for command completion, ? for context help")
}

func (c *CLI) showConfigHelp() {
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
	fmt.Println()
	fmt.Println("  Use <TAB> for command completion, ? for context help")
}
