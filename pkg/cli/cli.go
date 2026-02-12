// Package cli implements the Junos-style interactive CLI for bpfrx.
package cli

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/chzyer/readline"
	"github.com/psaab/bpfrx/pkg/config"
	"github.com/psaab/bpfrx/pkg/configstore"
	"github.com/psaab/bpfrx/pkg/dataplane"
	"github.com/psaab/bpfrx/pkg/dhcp"
	"github.com/psaab/bpfrx/pkg/frr"
	"github.com/psaab/bpfrx/pkg/ipsec"
	"github.com/psaab/bpfrx/pkg/logging"
	"github.com/psaab/bpfrx/pkg/routing"
	"github.com/psaab/bpfrx/pkg/vrrp"
	"github.com/vishvananda/netlink"
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
	dhcp        *dhcp.Manager
	hostname    string
	username    string
}

// New creates a new CLI.
func New(store *configstore.Store, dp *dataplane.Manager, eventBuf *logging.EventBuffer, eventReader *logging.EventReader, rm *routing.Manager, fm *frr.Manager, im *ipsec.Manager, dm *dhcp.Manager) *CLI {
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
		dhcp:        dm,
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
		"dhcp": {desc: "Show DHCP information", children: map[string]*completionNode{
			"leases":            {desc: "Show DHCP leases"},
			"client-identifier": {desc: "Show DHCPv6 DUID(s)"},
		}},
		"flow-monitoring": {desc: "Show flow monitoring/NetFlow configuration"},
		"route": {desc: "Show routing table [instance <name>]", children: map[string]*completionNode{
			"instance": {desc: "Show routes for a routing instance"},
		}},
		"security": {desc: "Show security information", children: map[string]*completionNode{
			"zones":           {desc: "Show security zones"},
			"policies":        {desc: "Show security policies"},
			"screen":          {desc: "Show screen/IDS profiles"},
			"alg":             {desc: "Show ALG status"},
			"dynamic-address": {desc: "Show dynamic address feeds"},
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
		"services": {desc: "Show services information", children: map[string]*completionNode{
			"rpm": {desc: "Show RPM probe results", children: map[string]*completionNode{
				"probe-results": {desc: "Show RPM probe results"},
			}},
		}},
		"interfaces": {desc: "Show interface status", children: map[string]*completionNode{
			"terse":  {desc: "Show interface summary"},
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
			"rip":  {desc: "Show RIP information"},
			"isis": {desc: "Show IS-IS information", children: map[string]*completionNode{
				"adjacency": {desc: "Show IS-IS adjacencies"},
				"routes":    {desc: "Show IS-IS routes"},
			}},
		}},
		"schedulers":  {desc: "Show policy schedulers"},
		"dhcp-relay":  {desc: "Show DHCP relay status"},
		"snmp":        {desc: "Show SNMP statistics"},
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
		"dhcp": {desc: "Clear DHCP information", children: map[string]*completionNode{
			"client-identifier": {desc: "Clear DHCPv6 DUID(s)"},
		}},
	}},
	"ping":       {desc: "Ping remote host"},
	"traceroute": {desc: "Trace route to remote host"},
	"quit":       {desc: "Exit CLI"},
	"exit":       {desc: "Exit CLI"},
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
		Stdin:           os.Stdin,
		Stdout:          os.Stdout,
		Stderr:          os.Stderr,
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

	// Extract pipe filter (| match, | except, | count, | last, | no-more).
	// Skip | display set and | compare (handled separately).
	if cmd, pipeType, pipeArg, ok := extractPipe(line); ok {
		return c.dispatchWithPipe(cmd, pipeType, pipeArg)
	}

	if c.store.InConfigMode() {
		return c.dispatchConfig(line)
	}

	// For show commands, auto-page output when it exceeds terminal height.
	if strings.HasPrefix(strings.TrimSpace(line), "show ") {
		return c.dispatchWithPager(line)
	}

	return c.dispatchOperational(line)
}

// extractPipe splits a line at the last "| <filter>" expression.
// Recognized filters: match, except, count, last, no-more.
// Returns the command part, pipe type, pipe argument, and whether a pipe was found.
// Skips "| display set" and "| compare" which are handled separately.
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
		// Not a recognized pipe filter (e.g. "| display set", "| compare")
		return line, "", "", false
	}
}

// dispatchWithPipe runs the command and applies the pipe filter to the output.
func (c *CLI) dispatchWithPipe(cmd, pipeType, pipeArg string) error {
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

	// Read captured output.
	output, _ := io.ReadAll(r)
	r.Close()

	lines := strings.Split(string(output), "\n")
	// Remove trailing empty line from split
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}

	switch pipeType {
	case "match", "grep":
		lowerPattern := strings.ToLower(pipeArg)
		for _, line := range lines {
			if strings.Contains(strings.ToLower(line), lowerPattern) {
				fmt.Fprintln(origStdout, line)
			}
		}
	case "except":
		lowerPattern := strings.ToLower(pipeArg)
		for _, line := range lines {
			if !strings.Contains(strings.ToLower(line), lowerPattern) {
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
		// Output without paging (we don't page by default, so just pass through)
		for _, line := range lines {
			fmt.Fprintln(origStdout, line)
		}
	}

	return cmdErr
}

// dispatchWithPager runs a show command and pages the output if it exceeds
// the terminal height. Press space for next page, enter for next line, q to quit.
func (c *CLI) dispatchWithPager(line string) error {
	origStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		return c.dispatchOperational(line)
	}
	os.Stdout = w

	var cmdErr error
	done := make(chan struct{})
	go func() {
		defer close(done)
		cmdErr = c.dispatchOperational(line)
	}()
	<-done
	w.Close()
	os.Stdout = origStdout

	output, _ := io.ReadAll(r)
	r.Close()

	lines := strings.Split(string(output), "\n")
	// Remove trailing empty line from split
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}

	// Get terminal height
	termHeight := 24
	ws, err := unix.IoctlGetWinsize(int(origStdout.Fd()), unix.TIOCGWINSZ)
	if err == nil && ws.Row > 0 {
		termHeight = int(ws.Row)
	}
	pageSize := termHeight - 1 // leave one line for the --More-- prompt

	// If output fits on screen, just print it
	if len(lines) <= pageSize {
		for _, line := range lines {
			fmt.Fprintln(origStdout, line)
		}
		return cmdErr
	}

	// Page output
	lineIdx := 0
	for lineIdx < len(lines) {
		// Print a page
		end := lineIdx + pageSize
		if end > len(lines) {
			end = len(lines)
		}
		for _, line := range lines[lineIdx:end] {
			fmt.Fprintln(origStdout, line)
		}
		lineIdx = end

		if lineIdx >= len(lines) {
			break
		}

		// Show --More-- prompt and wait for input
		fmt.Fprint(origStdout, "\033[7m--More--\033[0m") // inverse video
		buf := make([]byte, 1)
		os.Stdin.Read(buf)
		fmt.Fprint(origStdout, "\r        \r") // clear --More--

		switch buf[0] {
		case 'q', 'Q':
			return cmdErr
		case '\n', '\r':
			// Show one more line
			if lineIdx < len(lines) {
				fmt.Fprintln(origStdout, lines[lineIdx])
				lineIdx++
			}
			// Don't advance by pageSize, just continue the loop which will
			// show the prompt again immediately
			continue
		default:
			// space or any other key: show next page
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
		if err := c.store.EnterConfigure(); err != nil {
			return err
		}
		c.rl.SetPrompt(c.configPrompt())
		fmt.Println("Entering configuration mode")
		fmt.Println("[edit]")
		return nil

	case "show":
		return c.handleShow(parts[1:])

	case "clear":
		return c.handleClear(parts[1:])

	case "ping":
		return c.handlePing(parts[1:])

	case "traceroute":
		return c.handleTraceroute(parts[1:])

	case "monitor":
		return c.handleMonitor(parts[1:])

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
		fmt.Println("  dhcp             Show DHCP information")
		fmt.Println("  dhcp-relay       Show DHCP relay status")
		fmt.Println("  firewall         Show firewall filters")
		fmt.Println("  flow-monitoring  Show flow monitoring/NetFlow configuration")
		fmt.Println("  route            Show routing table")
		fmt.Println("  schedulers       Show policy schedulers")
		fmt.Println("  security         Show security information")
		fmt.Println("  services         Show services information")
		fmt.Println("  snmp             Show SNMP statistics")
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

	case "firewall":
		return c.showFirewallFilters()

	case "flow-monitoring":
		return c.showFlowMonitoring()

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

	case "system":
		return c.handleShowSystem(args[1:])

	case "schedulers":
		return c.showSchedulers()

	case "dhcp-relay":
		return c.showDHCPRelay()

	case "snmp":
		return c.showSNMP()

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
		fmt.Println("  flow session     Show active sessions [zone <n>] [protocol <p>] [source-prefix <cidr>]")
	fmt.Println("                   [destination-prefix <cidr>] [source-port <p>] [destination-port <p>]")
	fmt.Println("                   [nat] [interface <name>] [summary]")
		fmt.Println("  nat source       Show source NAT information")
		fmt.Println("  nat destination  Show destination NAT information")
		fmt.Println("  address-book     Show address book entries")
		fmt.Println("  applications     Show application definitions")
		fmt.Println("  alg              Show ALG (Application Layer Gateway) status")
		fmt.Println("  ipsec            Show IPsec VPN status")
		fmt.Println("  dynamic-address  Show dynamic address feeds")
		fmt.Println("  match-policies   Match 5-tuple against policies")
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

	case "alg":
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
		{dataplane.GlobalCtrHostInbound, "Host-inbound allowed"},
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

	// 3. Apply all routes + dynamic protocols via FRR
	if c.frr != nil {
		fc := &frr.FullConfig{
			OSPF:         cfg.Protocols.OSPF,
			BGP:          cfg.Protocols.BGP,
			StaticRoutes: cfg.RoutingOptions.StaticRoutes,
		}
		if c.dhcp != nil {
			for _, lease := range c.dhcp.Leases() {
				if !lease.Gateway.IsValid() {
					continue
				}
				fc.DHCPRoutes = append(fc.DHCPRoutes, frr.DHCPRoute{
					Gateway:   lease.Gateway.String(),
					Interface: lease.Interface,
					IsIPv6:    lease.Family == dhcp.AFInet6,
				})
			}
		}
		for _, ri := range cfg.RoutingInstances {
			fc.Instances = append(fc.Instances, frr.InstanceConfig{
				VRFName:      "vrf-" + ri.Name,
				OSPF:         ri.OSPF,
				BGP:          ri.BGP,
				StaticRoutes: ri.StaticRoutes,
			})
		}
		if err := c.frr.ApplyFull(fc); err != nil {
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
	srcPort uint16   // 0 = any
	dstPort uint16   // 0 = any
	natOnly bool     // show only NAT sessions
	iface   string   // ingress interface name filter
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
		case "source-port":
			if i+1 < len(args) {
				i++
				if v, err := strconv.Atoi(args[i]); err == nil {
					f.srcPort = uint16(v)
				}
			}
		case "destination-port":
			if i+1 < len(args) {
				i++
				if v, err := strconv.Atoi(args[i]); err == nil {
					f.dstPort = uint16(v)
				}
			}
		case "nat":
			f.natOnly = true
		case "interface":
			if i+1 < len(args) {
				i++
				f.iface = args[i]
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
	if f.srcPort != 0 && key.SrcPort != f.srcPort {
		return false
	}
	if f.dstPort != 0 && key.DstPort != f.dstPort {
		return false
	}
	if f.natOnly && val.Flags&(dataplane.SessFlagSNAT|dataplane.SessFlagDNAT) == 0 {
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
	if f.srcPort != 0 && key.SrcPort != f.srcPort {
		return false
	}
	if f.dstPort != 0 && key.DstPort != f.dstPort {
		return false
	}
	if f.natOnly && val.Flags&(dataplane.SessFlagSNAT|dataplane.SessFlagDNAT) == 0 {
		return false
	}
	return true
}

func (f *sessionFilter) hasFilter() bool {
	return f.zoneID != 0 || f.proto != 0 || f.srcNet != nil || f.dstNet != nil ||
		f.srcPort != 0 || f.dstPort != 0 || f.natOnly || f.iface != ""
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

	// TCP MSS clamping
	if flow.TCPMSSIPsecVPN > 0 || flow.TCPMSSGre > 0 {
		fmt.Println()
		fmt.Println("TCP MSS clamping:")
		if flow.TCPMSSIPsecVPN > 0 {
			fmt.Printf("  %-30s %d\n", "IPsec VPN MSS:", flow.TCPMSSIPsecVPN)
		}
		if flow.TCPMSSGre > 0 {
			fmt.Printf("  %-30s %d\n", "GRE tunnel MSS:", flow.TCPMSSGre)
		}
	}

	// Flow options
	if flow.AllowDNSReply || flow.AllowEmbeddedICMP {
		fmt.Println()
		fmt.Println("Flow options:")
		if flow.AllowDNSReply {
			fmt.Println("  allow-dns-reply:               enabled")
		}
		if flow.AllowEmbeddedICMP {
			fmt.Println("  allow-embedded-icmp:           enabled")
		}
	}

	return nil
}

func (c *CLI) handleClear(args []string) error {
	if len(args) < 1 {
		fmt.Println("clear:")
		fmt.Println("  security flow session          Clear all sessions")
		fmt.Println("  security counters              Clear all counters")
		fmt.Println("  dhcp client-identifier         Clear DHCPv6 DUID(s)")
		return nil
	}

	switch args[0] {
	case "security":
		return c.handleClearSecurity(args[1:])
	case "dhcp":
		return c.handleClearDHCP(args[1:])
	default:
		fmt.Println("clear:")
		fmt.Println("  security flow session          Clear all sessions")
		fmt.Println("  security counters              Clear all counters")
		fmt.Println("  dhcp client-identifier         Clear DHCPv6 DUID(s)")
		return nil
	}
}

func (c *CLI) handleClearSecurity(args []string) error {
	if len(args) < 1 {
		fmt.Println("clear security:")
		fmt.Println("  flow session                         Clear all sessions")
		fmt.Println("  counters                             Clear all counters")
		fmt.Println("  nat source persistent-nat-table      Clear persistent NAT bindings")
		return nil
	}

	switch args[0] {
	case "nat":
		if len(args) >= 3 && args[1] == "source" && args[2] == "persistent-nat-table" {
			return c.clearPersistentNAT()
		}
		return fmt.Errorf("usage: clear security nat source persistent-nat-table")
	case "flow":
		if len(args) < 2 || args[1] != "session" {
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

func (c *CLI) handleClearDHCP(args []string) error {
	if len(args) < 1 || args[0] != "client-identifier" {
		fmt.Println("clear dhcp:")
		fmt.Println("  client-identifier [interface <name>]    Clear DHCPv6 DUID(s)")
		return nil
	}

	if c.dhcp == nil {
		fmt.Println("No DHCP clients running")
		return nil
	}

	// Optional interface filter: clear dhcp client-identifier interface <name>
	if len(args) >= 3 && args[1] == "interface" {
		ifName := args[2]
		if err := c.dhcp.ClearDUID(ifName); err != nil {
			return fmt.Errorf("clear DUID: %w", err)
		}
		fmt.Printf("DHCPv6 DUID cleared for %s\n", ifName)
		return nil
	}

	c.dhcp.ClearAllDUIDs()
	fmt.Println("All DHCPv6 DUIDs cleared")
	return nil
}

func (c *CLI) handleShowNAT(args []string) error {
	cfg := c.store.ActiveConfig()

	if len(args) == 0 {
		fmt.Println("show security nat:")
		fmt.Println("  source                       Show source NAT rules and sessions")
		fmt.Println("  source summary               Show source NAT pool utilization summary")
		fmt.Println("  source pool <name|all>       Show source NAT pool details")
		fmt.Println("  source rule-set <name>       Show source NAT rule-set details")
		fmt.Println("  source persistent-nat-table  Show persistent NAT bindings")
		fmt.Println("  destination                  Show destination NAT rules")
		fmt.Println("  static                       Show static 1:1 NAT rules")
		return nil
	}

	switch args[0] {
	case "source":
		if len(args) >= 2 && args[1] == "persistent-nat-table" {
			return c.showPersistentNAT()
		}
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
	// Sub-command dispatch: summary, pool <name>, rule-set <name>
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
		case "rule-set":
			if len(args) > 1 {
				return c.showNATSourceRuleSet(cfg, args[1])
			}
			return fmt.Errorf("usage: show security nat source rule-set <name>")
		}
	}

	// Default: show all pools, rules, and summary
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

// showNATSourceSummary displays a Junos-style summary of all source NAT pools.
func (c *CLI) showNATSourceSummary(cfg *config.Config) error {
	if cfg == nil {
		fmt.Println("No source NAT configured")
		return nil
	}

	// Count pools: named pools + interface-mode rules
	type poolInfo struct {
		name    string
		address string
		total   int // total ports (0 = N/A for interface)
		used    int
		isIface bool
	}
	var pools []poolInfo

	// Named pools
	for name, pool := range cfg.Security.NAT.SourcePools {
		portLow, portHigh := pool.PortLow, pool.PortHigh
		if portLow == 0 {
			portLow = 1024
		}
		if portHigh == 0 {
			portHigh = 65535
		}
		totalPorts := (portHigh - portLow + 1) * len(pool.Addresses)
		addr := strings.Join(pool.Addresses, ",")
		pools = append(pools, poolInfo{name: name, address: addr, total: totalPorts})
	}

	// Interface-mode pools (count from rules)
	for _, rs := range cfg.Security.NAT.Source {
		for _, rule := range rs.Rules {
			if rule.Then.Interface {
				pools = append(pools, poolInfo{
					name: fmt.Sprintf("%s/%s (interface)", rs.FromZone, rs.ToZone),
					address: "interface", isIface: true,
				})
			}
		}
	}

	// Read per-pool port counters from BPF
	if c.dp != nil && c.dp.IsLoaded() {
		if cr := c.dp.LastCompileResult(); cr != nil {
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
		// Count interface NAT sessions
		ifaceSNAT := 0
		_ = c.dp.IterateSessions(func(_ dataplane.SessionKey, val dataplane.SessionValue) bool {
			if val.IsReverse == 0 && val.Flags&dataplane.SessFlagSNAT != 0 {
				ifaceSNAT++
			}
			return true
		})
		for i := range pools {
			if pools[i].isIface {
				pools[i].used = ifaceSNAT
			}
		}
	}

	fmt.Printf("Total pools: %d\n", len(pools))
	fmt.Printf("%-20s %-20s %-8s %-8s %-12s %-12s\n",
		"Pool", "Address", "Ports", "Used", "Available", "Utilization")
	for _, p := range pools {
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
		totalPorts := (portHigh - portLow + 1) * len(pool.Addresses)

		fmt.Printf("Pool name: %s\n", name)
		for _, addr := range pool.Addresses {
			fmt.Printf("  Address: %s\n", addr)
		}
		fmt.Printf("  Port range: %d-%d\n", portLow, portHigh)

		if c.dp != nil && c.dp.IsLoaded() {
			if cr := c.dp.LastCompileResult(); cr != nil {
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
			fmt.Printf("    Action: %s\n", action)

			// Show hit counters if dataplane is loaded
			if c.dp != nil && c.dp.LastCompileResult() != nil {
				ruleKey := rs.Name + "/" + rule.Name
				if cid, ok := c.dp.LastCompileResult().NATCounterIDs[ruleKey]; ok {
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
			var parts []string
			for _, a := range as.Addresses {
				parts = append(parts, a)
			}
			for _, s := range as.AddressSets {
				parts = append(parts, "set:"+s)
			}
			fmt.Printf("  %-24s members: %s\n", as.Name, strings.Join(parts, ", "))
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

func (c *CLI) handleShowRoute(args []string) error {
	if len(args) >= 2 && args[0] == "instance" {
		return c.showRoutesForInstance(args[1])
	}
	return c.showRoutes()
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

func (c *CLI) showRoutesForInstance(instanceName string) error {
	if c.routing == nil {
		fmt.Println("Routing manager not available")
		return nil
	}

	cfg := c.store.ActiveConfig()
	if cfg == nil {
		fmt.Println("No active configuration")
		return nil
	}

	var tableID int
	found := false
	for _, ri := range cfg.RoutingInstances {
		if ri.Name == instanceName {
			tableID = ri.TableID
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("routing instance %q not found", instanceName)
	}

	entries, err := c.routing.GetRoutesForTable(tableID)
	if err != nil {
		return fmt.Errorf("get routes for instance %s: %w", instanceName, err)
	}

	fmt.Printf("Routing table for instance %s (table %d):\n", instanceName, tableID)
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
		fmt.Println("  rip              Show RIP information")
		fmt.Println("  isis             Show IS-IS information")
		return nil
	}

	switch args[0] {
	case "ospf":
		return c.showOSPF(args[1:])
	case "bgp":
		return c.showBGP(args[1:])
	case "rip":
		return c.showRIP()
	case "isis":
		return c.showISIS(args[1:])
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

	// Handle "show interfaces terse" sub-command
	if len(args) > 0 && args[0] == "terse" {
		return c.showInterfacesTerse()
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

	// Build interface -> zone mapping
	ifaceZone := make(map[string]*config.ZoneConfig)
	ifaceZoneName := make(map[string]string)
	for name, zone := range cfg.Security.Zones {
		for _, ifaceName := range zone.Interfaces {
			ifaceZone[ifaceName] = zone
			ifaceZoneName[ifaceName] = name
		}
	}

	// Collect logical interfaces
	type logicalIface struct {
		zoneName string
		zone     *config.ZoneConfig
		physName string
		unitNum  int
		vlanID   int
	}
	var logicals []logicalIface

	for ifaceName, zone := range ifaceZone {
		if filterName != "" && !strings.HasPrefix(ifaceName, filterName) {
			continue
		}
		parts := strings.SplitN(ifaceName, ".", 2)
		physName := parts[0]
		unitNum := 0
		if len(parts) == 2 {
			unitNum, _ = strconv.Atoi(parts[1])
		}
		vlanID := 0
		if ifCfg, ok := cfg.Interfaces.Interfaces[physName]; ok {
			if unit, ok := ifCfg.Units[unitNum]; ok {
				vlanID = unit.VlanID
			}
		}
		logicals = append(logicals, logicalIface{
			zoneName: ifaceZoneName[ifaceName],
			zone:     zone,
			physName: physName,
			unitNum:  unitNum,
			vlanID:   vlanID,
		})
	}

	if len(logicals) == 0 && filterName != "" {
		return fmt.Errorf("interface %s not found in configuration", filterName)
	}

	// Group by physical interface
	physGroups := make(map[string][]logicalIface)
	var physOrder []string
	for _, li := range logicals {
		if _, seen := physGroups[li.physName]; !seen {
			physOrder = append(physOrder, li.physName)
		}
		physGroups[li.physName] = append(physGroups[li.physName], li)
	}
	sort.Strings(physOrder)

	for _, physName := range physOrder {
		group := physGroups[physName]

		// Get netlink link for richer info
		link, nlErr := netlink.LinkByName(physName)

		// Fallback to net.InterfaceByName if netlink fails
		iface, stdErr := net.InterfaceByName(physName)
		if stdErr != nil && nlErr != nil {
			fmt.Printf("Physical interface: %s, Not present\n\n", physName)
			continue
		}

		// Determine link state
		linkUp := "Down"
		enabled := "Enabled"
		if nlErr == nil {
			attrs := link.Attrs()
			if attrs.OperState == netlink.OperUp {
				linkUp = "Up"
			}
			if attrs.Flags&net.FlagUp == 0 {
				enabled = "Disabled"
			}
		} else if iface != nil {
			if iface.Flags&net.FlagUp != 0 {
				linkUp = "Up"
			}
		}

		fmt.Printf("Physical interface: %s, %s, Physical link is %s\n",
			physName, enabled, linkUp)

		// Link-level details
		mtu := 0
		var hwAddr net.HardwareAddr
		if nlErr == nil {
			attrs := link.Attrs()
			mtu = attrs.MTU
			hwAddr = attrs.HardwareAddr
		} else if iface != nil {
			mtu = iface.MTU
			hwAddr = iface.HardwareAddr
		}

		linkType := "Ethernet"
		speedStr := ""
		if speed := readLinkSpeed(physName); speed > 0 {
			speedStr = fmt.Sprintf(", Speed: %s", formatSpeed(speed))
		}

		fmt.Printf("  Link-level type: %s, MTU: %d%s\n", linkType, mtu, speedStr)

		if len(hwAddr) > 0 {
			fmt.Printf("  Current address: %s, Hardware address: %s\n", hwAddr, hwAddr)
		}

		// Device flags
		if nlErr == nil {
			attrs := link.Attrs()
			var flags []string
			flags = append(flags, "Present")
			if attrs.OperState == netlink.OperUp {
				flags = append(flags, "Running")
			}
			if linkUp == "Down" {
				flags = append(flags, "Down")
			}
			fmt.Printf("  Device flags   : %s\n", strings.Join(flags, " "))
		}

		// VLAN tagging
		if ifCfg, ok := cfg.Interfaces.Interfaces[physName]; ok && ifCfg.VlanTagging {
			fmt.Println("  VLAN tagging: Enabled")
		}

		// Kernel link statistics
		if nlErr == nil {
			attrs := link.Attrs()
			if s := attrs.Statistics; s != nil {
				fmt.Printf("  Input rate     : %d packets, %d bytes\n",
					s.RxPackets, s.RxBytes)
				fmt.Printf("  Output rate    : %d packets, %d bytes\n",
					s.TxPackets, s.TxBytes)
				if s.RxErrors > 0 || s.TxErrors > 0 {
					fmt.Printf("  Errors         : %d input, %d output\n",
						s.RxErrors, s.TxErrors)
				}
				if s.RxDropped > 0 || s.TxDropped > 0 {
					fmt.Printf("  Drops          : %d input, %d output\n",
						s.RxDropped, s.TxDropped)
				}
			}
		}

		// BPF traffic counters (XDP/TC level)
		if c.dp != nil && c.dp.IsLoaded() && iface != nil {
			counters, err := c.dp.ReadInterfaceCounters(iface.Index)
			if err == nil && (counters.RxPackets > 0 || counters.TxPackets > 0) {
				fmt.Println("  BPF statistics:")
				fmt.Printf("    Input:  %d packets, %d bytes\n",
					counters.RxPackets, counters.RxBytes)
				fmt.Printf("    Output: %d packets, %d bytes\n",
					counters.TxPackets, counters.TxBytes)
			}
		}

		// Show each logical unit
		for _, li := range group {
			lookupName := physName
			if li.vlanID > 0 {
				lookupName = fmt.Sprintf("%s.%d", physName, li.vlanID)
			}

			fmt.Printf("\n  Logical interface %s.%d", physName, li.unitNum)
			if li.vlanID > 0 {
				fmt.Printf(" VLAN-Tag [ 0x8100.%d ]", li.vlanID)
			}
			fmt.Println()

			fmt.Printf("    Security: Zone: %s\n", li.zoneName)

			// Host-inbound traffic services
			if li.zone != nil && li.zone.HostInboundTraffic != nil {
				hit := li.zone.HostInboundTraffic
				if len(hit.SystemServices) > 0 {
					fmt.Printf("    Allowed host-inbound traffic : %s\n",
						strings.Join(hit.SystemServices, " "))
				}
				if len(hit.Protocols) > 0 {
					fmt.Printf("    Allowed host-inbound protocols: %s\n",
						strings.Join(hit.Protocols, " "))
				}
			}

			// DHCP annotations
			var unit *config.InterfaceUnit
			if ifCfg, ok := cfg.Interfaces.Interfaces[physName]; ok {
				if u, ok := ifCfg.Units[li.unitNum]; ok {
					unit = u
				}
			}
			if unit != nil {
				if unit.DHCP {
					fmt.Println("    DHCPv4: enabled")
					if lease := c.dhcpLease(physName, dhcp.AFInet); lease != nil {
						fmt.Printf("      Address: %s, Gateway: %s\n",
							lease.Address, lease.Gateway)
					}
				}
				if unit.DHCPv6 {
					duidInfo := ""
					if unit.DHCPv6Client != nil && unit.DHCPv6Client.DUIDType != "" {
						duidInfo = fmt.Sprintf(" (DUID type: %s)", unit.DHCPv6Client.DUIDType)
					}
					fmt.Printf("    DHCPv6: enabled%s\n", duidInfo)
					if lease := c.dhcpLease(physName, dhcp.AFInet6); lease != nil {
						fmt.Printf("      Address: %s, Gateway: %s\n",
							lease.Address, lease.Gateway)
					}
				}
			}

			// Addresses grouped by protocol
			liface, err := net.InterfaceByName(lookupName)
			if err != nil && iface != nil {
				liface = iface
			}
			if liface != nil {
				addrs, err := liface.Addrs()
				if err == nil && len(addrs) > 0 {
					var v4Addrs, v6Addrs []string
					for _, addr := range addrs {
						ipNet, ok := addr.(*net.IPNet)
						if !ok {
							continue
						}
						ones, _ := ipNet.Mask.Size()
						if ipNet.IP.To4() != nil {
							v4Addrs = append(v4Addrs, fmt.Sprintf("%s/%d", ipNet.IP, ones))
						} else {
							v6Addrs = append(v6Addrs, fmt.Sprintf("%s/%d", ipNet.IP, ones))
						}
					}
					if len(v4Addrs) > 0 {
						fmt.Printf("    Protocol inet, MTU: %d\n", mtu)
						for _, a := range v4Addrs {
							fmt.Printf("      Addresses, Flags: Is-Preferred Is-Primary\n")
							fmt.Printf("        Local: %s\n", a)
						}
					}
					if len(v6Addrs) > 0 {
						fmt.Printf("    Protocol inet6, MTU: %d\n", mtu)
						for _, a := range v6Addrs {
							flags := "Is-Preferred Is-Primary"
							if strings.HasPrefix(a, "fe80:") {
								flags = "Is-Preferred"
							}
							fmt.Printf("      Addresses, Flags: %s\n", flags)
							fmt.Printf("        Local: %s\n", a)
						}
					}
				}
			}
		}

		fmt.Println()
	}

	return nil
}

// dhcpLease returns the DHCP lease for an interface/family, or nil.
func (c *CLI) dhcpLease(ifaceName string, af dhcp.AddressFamily) *dhcp.Lease {
	if c.dhcp == nil {
		return nil
	}
	return c.dhcp.LeaseFor(ifaceName, af)
}

func (c *CLI) showInterfacesTerse() error {
	cfg := c.store.ActiveConfig()
	if cfg == nil {
		fmt.Println("no active configuration")
		return nil
	}

	type ifUnit struct {
		physName string
		unitNum  int
		vlanID   int
	}
	var units []ifUnit

	for physName, ifCfg := range cfg.Interfaces.Interfaces {
		for unitNum, unit := range ifCfg.Units {
			units = append(units, ifUnit{physName: physName, unitNum: unitNum, vlanID: unit.VlanID})
		}
	}

	sort.Slice(units, func(i, j int) bool {
		if units[i].physName != units[j].physName {
			return units[i].physName < units[j].physName
		}
		return units[i].unitNum < units[j].unitNum
	})

	fmt.Printf("%-24s%-6s%-6s%-9s%-22s\n", "Interface", "Admin", "Link", "Proto", "Local")

	printedPhys := make(map[string]bool)

	for _, u := range units {
		if !printedPhys[u.physName] {
			printedPhys[u.physName] = true
			admin := "up"
			link := "up"
			iface, err := net.InterfaceByName(u.physName)
			if err != nil {
				link = "down"
			} else {
				if iface.Flags&net.FlagUp == 0 {
					admin = "down"
				}
				data, err := os.ReadFile("/sys/class/net/" + u.physName + "/operstate")
				if err == nil && strings.TrimSpace(string(data)) != "up" {
					link = "down"
				}
			}
			fmt.Printf("%-24s%-6s%-6s\n", u.physName, admin, link)
		}

		logicalName := fmt.Sprintf("%s.%d", u.physName, u.unitNum)
		lookupName := u.physName
		if u.vlanID > 0 {
			lookupName = fmt.Sprintf("%s.%d", u.physName, u.vlanID)
		}

		var v4Addrs, v6Addrs []string
		liface, err := net.InterfaceByName(lookupName)
		if err != nil {
			liface, err = net.InterfaceByName(u.physName)
		}
		if err == nil {
			addrs, _ := liface.Addrs()
			for _, addr := range addrs {
				ipNet, ok := addr.(*net.IPNet)
				if !ok {
					continue
				}
				ones, _ := ipNet.Mask.Size()
				addrStr := fmt.Sprintf("%s/%d", ipNet.IP, ones)
				if ipNet.IP.To4() != nil {
					v4Addrs = append(v4Addrs, addrStr)
				} else {
					v6Addrs = append(v6Addrs, addrStr)
				}
			}
		}

		admin := "up"
		link := "up"
		if liface == nil {
			link = "down"
		} else if liface.Flags&net.FlagUp == 0 {
			admin = "down"
		}

		firstProto := ""
		firstAddr := ""
		if len(v4Addrs) > 0 {
			firstProto = "inet"
			firstAddr = v4Addrs[0]
		} else if len(v6Addrs) > 0 {
			firstProto = "inet6"
			firstAddr = v6Addrs[0]
		}

		fmt.Printf("%-24s%-6s%-6s%-9s%-22s\n", logicalName, admin, link, firstProto, firstAddr)

		for i := 1; i < len(v4Addrs); i++ {
			fmt.Printf("%-36s%-9s%-22s\n", "", "inet", v4Addrs[i])
		}
		startIdx := 0
		if firstProto == "inet6" {
			startIdx = 1
		}
		for i := startIdx; i < len(v6Addrs); i++ {
			fmt.Printf("%-36s%-9s%-22s\n", "", "inet6", v6Addrs[i])
		}
	}

	return nil
}

// readLinkSpeed reads the link speed in Mbps from sysfs. Returns 0 on error.
func readLinkSpeed(ifaceName string) int {
	data, err := os.ReadFile("/sys/class/net/" + ifaceName + "/speed")
	if err != nil {
		return 0
	}
	speed, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || speed <= 0 {
		return 0
	}
	return speed
}

// formatSpeed formats a link speed in Mbps to a human-readable string.
func formatSpeed(mbps int) string {
	if mbps >= 1000 {
		return fmt.Sprintf("%dGbps", mbps/1000)
	}
	return fmt.Sprintf("%dMbps", mbps)
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
	return fmt.Sprintf("%s@%s# ", c.username, c.hostname)
}

func (c *CLI) showOperationalHelp() {
	fmt.Println("Operational mode commands:")
	fmt.Println("  configure                          Enter configuration mode")
	fmt.Println("  show configuration                 Show running configuration")
	fmt.Println("  show configuration | display set   Show as flat set commands")
	fmt.Println("  show dhcp leases                   Show DHCP leases")
	fmt.Println("  show route                         Show routing table")
	fmt.Println("  show security                      Show security information")
	fmt.Println("  show security ipsec                Show IPsec VPN status")
	fmt.Println("  show security log [N]              Show recent security events")
	fmt.Println("  show interfaces [name]             Show interfaces (VLAN support)")
	fmt.Println("  show interfaces tunnel             Show tunnel interfaces")
	fmt.Println("  show protocols ospf neighbor       Show OSPF neighbors")
	fmt.Println("  show protocols bgp summary         Show BGP peer summary")
	fmt.Println("  show system rollback               Show rollback history")
	fmt.Println("  show security match-policies       Match a 5-tuple against policies")
	fmt.Println("  monitor traffic interface <name>   Capture traffic (tcpdump)")
	fmt.Println("  clear security flow session        Clear all sessions")
	fmt.Println("  clear security counters            Clear all counters")
	fmt.Println("  quit                               Exit CLI")
	fmt.Println()
	fmt.Println("  <command> | match/grep <pattern>    Filter output by pattern")
	fmt.Println("  <command> | except <pattern>        Exclude lines matching pattern")
	fmt.Println("  <command> | count                   Count output lines")
	fmt.Println("  <command> | last [N]                Show last N lines (default 10)")
	fmt.Println("  <command> | no-more                 Disable paging")
	fmt.Println("  Use <TAB> for command completion, ? for context help")
}

func (c *CLI) showDHCPLeases() error {
	if c.dhcp == nil {
		fmt.Println("No DHCP clients running")
		return nil
	}

	leases := c.dhcp.Leases()
	if len(leases) == 0 {
		fmt.Println("No active DHCP leases")
		return nil
	}

	fmt.Println("DHCP leases:")
	for _, l := range leases {
		family := "inet"
		if l.Family == dhcp.AFInet6 {
			family = "inet6"
		}
		elapsed := time.Since(l.Obtained).Round(time.Second)
		remaining := l.LeaseTime - elapsed
		if remaining < 0 {
			remaining = 0
		}
		fmt.Printf("  Interface: %s, Family: %s\n", l.Interface, family)
		fmt.Printf("    Address:   %s\n", l.Address)
		if l.Gateway.IsValid() {
			fmt.Printf("    Gateway:   %s\n", l.Gateway)
		}
		if len(l.DNS) > 0 {
			dnsStrs := make([]string, len(l.DNS))
			for i, d := range l.DNS {
				dnsStrs[i] = d.String()
			}
			fmt.Printf("    DNS:       %s\n", strings.Join(dnsStrs, ", "))
		}
		fmt.Printf("    Lease:     %s (remaining: %s)\n", l.LeaseTime.Round(time.Second), remaining.Round(time.Second))
		fmt.Printf("    Obtained:  %s\n", l.Obtained.Format("2006-01-02 15:04:05"))
		fmt.Println()
	}
	return nil
}

func (c *CLI) showDHCPClientIdentifier() error {
	if c.dhcp == nil {
		fmt.Println("No DHCP clients running")
		return nil
	}

	duids := c.dhcp.DUIDs()
	if len(duids) == 0 {
		fmt.Println("No DHCPv6 DUIDs configured")
		return nil
	}

	fmt.Println("DHCPv6 client identifiers:")
	for _, d := range duids {
		fmt.Printf("  Interface: %s\n", d.Interface)
		fmt.Printf("    Type:    %s\n", d.Type)
		fmt.Printf("    DUID:    %s\n", d.Display)
		fmt.Printf("    Hex:     %s\n", d.HexBytes)
		fmt.Println()
	}
	return nil
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

func (c *CLI) showFirewallFilters() error {
	cfg := c.store.ActiveConfig()
	if cfg == nil {
		fmt.Println("No active configuration")
		return nil
	}

	showFilters := func(family string, filters map[string]*config.FirewallFilter) {
		for name, f := range filters {
			fmt.Printf("Filter: %s (family %s)\n", name, family)
			for _, term := range f.Terms {
				fmt.Printf("  Term: %s\n", term.Name)
				if term.DSCP != "" {
					fmt.Printf("    from dscp %s\n", term.DSCP)
				}
				if term.Protocol != "" {
					fmt.Printf("    from protocol %s\n", term.Protocol)
				}
				for _, addr := range term.SourceAddresses {
					fmt.Printf("    from source-address %s\n", addr)
				}
				for _, addr := range term.DestAddresses {
					fmt.Printf("    from destination-address %s\n", addr)
				}
				for _, port := range term.DestinationPorts {
					fmt.Printf("    from destination-port %s\n", port)
				}
				if term.ICMPType >= 0 {
					fmt.Printf("    from icmp-type %d\n", term.ICMPType)
				}
				if term.ICMPCode >= 0 {
					fmt.Printf("    from icmp-code %d\n", term.ICMPCode)
				}
				action := term.Action
				if action == "" {
					action = "accept"
				}
				if term.RoutingInstance != "" {
					fmt.Printf("    then routing-instance %s\n", term.RoutingInstance)
				}
				if term.Log {
					fmt.Printf("    then log\n")
				}
				fmt.Printf("    then %s\n", action)
			}
			fmt.Println()
		}
	}

	if len(cfg.Firewall.FiltersInet) == 0 && len(cfg.Firewall.FiltersInet6) == 0 {
		fmt.Println("No firewall filters configured")
		return nil
	}

	showFilters("inet", cfg.Firewall.FiltersInet)
	showFilters("inet6", cfg.Firewall.FiltersInet6)
	return nil
}

func (c *CLI) showFlowMonitoring() error {
	cfg := c.store.ActiveConfig()
	if cfg == nil {
		fmt.Println("No active configuration")
		return nil
	}

	hasConfig := false

	if cfg.Services.FlowMonitoring != nil && cfg.Services.FlowMonitoring.Version9 != nil {
		v9 := cfg.Services.FlowMonitoring.Version9
		if len(v9.Templates) > 0 {
			hasConfig = true
			fmt.Println("Flow Monitoring Version 9 Templates:")
			for name, tmpl := range v9.Templates {
				activeTimeout := tmpl.FlowActiveTimeout
				if activeTimeout == 0 {
					activeTimeout = 60
				}
				inactiveTimeout := tmpl.FlowInactiveTimeout
				if inactiveTimeout == 0 {
					inactiveTimeout = 15
				}
				refreshRate := tmpl.TemplateRefreshRate
				if refreshRate == 0 {
					refreshRate = 60
				}
				fmt.Printf("  Template: %s\n", name)
				fmt.Printf("    Flow active timeout:   %d seconds\n", activeTimeout)
				fmt.Printf("    Flow inactive timeout: %d seconds\n", inactiveTimeout)
				fmt.Printf("    Template refresh rate: %d seconds\n", refreshRate)
			}
			fmt.Println()
		}
	}

	if cfg.ForwardingOptions.Sampling != nil {
		for name, inst := range cfg.ForwardingOptions.Sampling.Instances {
			hasConfig = true
			fmt.Printf("Sampling Instance: %s\n", name)
			if inst.InputRate > 0 {
				fmt.Printf("  Input rate: 1/%d\n", inst.InputRate)
			}
			showSamplingFamily := func(af string, fam *config.SamplingFamily) {
				if fam == nil {
					return
				}
				fmt.Printf("  Family %s:\n", af)
				if fam.InlineJflow {
					fmt.Printf("    Inline jflow: enabled\n")
				}
				if fam.SourceAddress != "" {
					fmt.Printf("    Source address: %s\n", fam.SourceAddress)
				}
				for _, fs := range fam.FlowServers {
					portStr := ""
					if fs.Port > 0 {
						portStr = fmt.Sprintf(":%d", fs.Port)
					}
					tmplStr := ""
					if fs.Version9Template != "" {
						tmplStr = fmt.Sprintf(" (template: %s)", fs.Version9Template)
					}
					fmt.Printf("    Collector: %s%s%s\n", fs.Address, portStr, tmplStr)
				}
			}
			showSamplingFamily("inet", inst.FamilyInet)
			showSamplingFamily("inet6", inst.FamilyInet6)
			fmt.Println()
		}
	}

	if !hasConfig {
		fmt.Println("No flow monitoring configured")
	}

	return nil
}

func (c *CLI) showDynamicAddress() error {
	cfg := c.store.ActiveConfig()
	if cfg == nil {
		fmt.Println("No active configuration")
		return nil
	}

	if len(cfg.Security.DynamicAddress.FeedServers) == 0 {
		fmt.Println("No dynamic address feeds configured")
		return nil
	}

	fmt.Println("Dynamic Address Feed Servers:")
	for name, fs := range cfg.Security.DynamicAddress.FeedServers {
		updateInt := fs.UpdateInterval
		if updateInt == 0 {
			updateInt = 3600
		}
		holdInt := fs.HoldInterval
		if holdInt == 0 {
			holdInt = 7200
		}
		fmt.Printf("  Feed Server: %s\n", name)
		if fs.URL != "" {
			fmt.Printf("    URL: %s\n", fs.URL)
		}
		if fs.FeedName != "" {
			fmt.Printf("    Feed name: %s\n", fs.FeedName)
		}
		fmt.Printf("    Update interval: %d seconds\n", updateInt)
		fmt.Printf("    Hold interval:   %d seconds\n", holdInt)
	}

	return nil
}

func (c *CLI) showALG() error {
	cfg := c.store.ActiveConfig()
	if cfg == nil {
		fmt.Println("No active configuration")
		return nil
	}

	alg := &cfg.Security.ALG
	fmt.Println("ALG (Application Layer Gateway) status:")

	printALG := func(name string, disabled bool) {
		if disabled {
			fmt.Printf("  %-10s disabled\n", name+":")
		} else {
			fmt.Printf("  %-10s enabled\n", name+":")
		}
	}

	printALG("DNS", alg.DNSDisable)
	printALG("FTP", alg.FTPDisable)
	printALG("SIP", alg.SIPDisable)
	printALG("TFTP", alg.TFTPDisable)

	return nil
}

func (c *CLI) handleShowServices(args []string) error {
	if len(args) == 0 {
		fmt.Println("show services:")
		fmt.Println("  rpm    Show RPM probe information")
		return nil
	}
	switch args[0] {
	case "rpm":
		rest := args[1:]
		if len(rest) > 0 && rest[0] == "probe-results" {
			return c.showRPMProbeResults()
		}
		return c.showRPMProbeResults()
	default:
		return fmt.Errorf("unknown services target: %s", args[0])
	}
}

func (c *CLI) showRPMProbeResults() error {
	cfg := c.store.ActiveConfig()
	if cfg == nil || cfg.Services.RPM == nil || len(cfg.Services.RPM.Probes) == 0 {
		fmt.Println("No RPM probes configured")
		return nil
	}

	fmt.Println("RPM Probe Results:")
	for probeName, probe := range cfg.Services.RPM.Probes {
		for testName, test := range probe.Tests {
			probeInt := test.ProbeInterval
			if probeInt == 0 {
				probeInt = 5
			}
			testInt := test.TestInterval
			if testInt == 0 {
				testInt = 60
			}
			thresh := test.ThresholdSuccessive
			if thresh == 0 {
				thresh = 3
			}
			fmt.Printf("  Probe: %s, Test: %s\n", probeName, testName)
			fmt.Printf("    Type: %s, Target: %s\n", test.ProbeType, test.Target)
			if test.SourceAddress != "" {
				fmt.Printf("    Source: %s\n", test.SourceAddress)
			}
			if test.RoutingInstance != "" {
				fmt.Printf("    Routing instance: %s\n", test.RoutingInstance)
			}
			fmt.Printf("    Probe interval: %ds, Test interval: %ds\n", probeInt, testInt)
			fmt.Printf("    Threshold successive-loss: %d\n", thresh)
			if test.DestPort > 0 {
				fmt.Printf("    Destination port: %d\n", test.DestPort)
			}
		}
	}
	return nil
}

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

	cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
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

	cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func (c *CLI) showRIP() error {
	if c.frr == nil {
		fmt.Println("FRR manager not available")
		return nil
	}

	routes, err := c.frr.GetRIPRoutes()
	if err != nil {
		return fmt.Errorf("RIP routes: %w", err)
	}
	if len(routes) == 0 {
		fmt.Println("No RIP routes")
		return nil
	}
	fmt.Printf("  %-20s %-18s %-8s %s\n", "Network", "Next Hop", "Metric", "Interface")
	for _, r := range routes {
		fmt.Printf("  %-20s %-18s %-8s %s\n", r.Network, r.NextHop, r.Metric, r.Interface)
	}
	return nil
}

func (c *CLI) showISIS(args []string) error {
	if c.frr == nil {
		fmt.Println("FRR manager not available")
		return nil
	}

	if len(args) == 0 {
		fmt.Println("show protocols isis:")
		fmt.Println("  adjacency        Show IS-IS adjacencies")
		fmt.Println("  routes           Show IS-IS routes")
		return nil
	}

	switch args[0] {
	case "adjacency":
		adjs, err := c.frr.GetISISAdjacency()
		if err != nil {
			return fmt.Errorf("IS-IS adjacency: %w", err)
		}
		if len(adjs) == 0 {
			fmt.Println("No IS-IS adjacencies")
			return nil
		}
		fmt.Printf("  %-20s %-14s %-10s %-10s %s\n",
			"System ID", "Interface", "Level", "State", "Hold Time")
		for _, a := range adjs {
			fmt.Printf("  %-20s %-14s %-10s %-10s %s\n",
				a.SystemID, a.Interface, a.Level, a.State, a.HoldTime)
		}
		return nil

	case "routes":
		output, err := c.frr.GetISISRoutes()
		if err != nil {
			return fmt.Errorf("IS-IS routes: %w", err)
		}
		fmt.Print(output)
		return nil

	default:
		return fmt.Errorf("unknown show protocols isis target: %s", args[0])
	}
}

func (c *CLI) showSchedulers() error {
	cfg := c.store.ActiveConfig()
	if cfg == nil || len(cfg.Schedulers) == 0 {
		fmt.Println("No schedulers configured")
		return nil
	}

	for name, sched := range cfg.Schedulers {
		fmt.Printf("Scheduler: %s\n", name)
		if sched.StartTime != "" {
			fmt.Printf("  Start time: %s\n", sched.StartTime)
		}
		if sched.StopTime != "" {
			fmt.Printf("  Stop time:  %s\n", sched.StopTime)
		}
		if sched.StartDate != "" {
			fmt.Printf("  Start date: %s\n", sched.StartDate)
		}
		if sched.StopDate != "" {
			fmt.Printf("  Stop date:  %s\n", sched.StopDate)
		}
		if sched.Daily {
			fmt.Println("  Recurrence: daily")
		}
		fmt.Println()
	}
	return nil
}

func (c *CLI) showDHCPRelay() error {
	cfg := c.store.ActiveConfig()
	if cfg == nil || cfg.ForwardingOptions.DHCPRelay == nil {
		fmt.Println("No DHCP relay configured")
		return nil
	}
	relay := cfg.ForwardingOptions.DHCPRelay

	if len(relay.ServerGroups) > 0 {
		fmt.Println("Server groups:")
		for name, sg := range relay.ServerGroups {
			fmt.Printf("  %s: %s\n", name, strings.Join(sg.Servers, ", "))
		}
	}

	if len(relay.Groups) > 0 {
		fmt.Println("Relay groups:")
		for name, g := range relay.Groups {
			fmt.Printf("  %s:\n", name)
			fmt.Printf("    Interfaces: %s\n", strings.Join(g.Interfaces, ", "))
			fmt.Printf("    Active server group: %s\n", g.ActiveServerGroup)
		}
	}
	return nil
}

func (c *CLI) showSNMP() error {
	cfg := c.store.ActiveConfig()
	if cfg == nil || cfg.System.SNMP == nil {
		fmt.Println("No SNMP configured")
		return nil
	}
	snmpCfg := cfg.System.SNMP

	if snmpCfg.Location != "" {
		fmt.Printf("Location:    %s\n", snmpCfg.Location)
	}
	if snmpCfg.Contact != "" {
		fmt.Printf("Contact:     %s\n", snmpCfg.Contact)
	}
	if snmpCfg.Description != "" {
		fmt.Printf("Description: %s\n", snmpCfg.Description)
	}

	if len(snmpCfg.Communities) > 0 {
		fmt.Println("Communities:")
		for name, comm := range snmpCfg.Communities {
			fmt.Printf("  %s: %s\n", name, comm.Authorization)
		}
	}

	if len(snmpCfg.TrapGroups) > 0 {
		fmt.Println("Trap groups:")
		for name, tg := range snmpCfg.TrapGroups {
			fmt.Printf("  %s: %s\n", name, strings.Join(tg.Targets, ", "))
		}
	}
	return nil
}

func (c *CLI) showPersistentNAT() error {
	if c.dp == nil || c.dp.PersistentNAT == nil {
		fmt.Println("Persistent NAT table not available")
		return nil
	}
	bindings := c.dp.PersistentNAT.All()
	if len(bindings) == 0 {
		fmt.Println("No persistent NAT bindings")
		return nil
	}
	fmt.Printf("Total persistent NAT bindings: %d\n\n", len(bindings))
	fmt.Printf("%-20s %-8s %-20s %-8s %-15s %-10s\n",
		"Source IP", "SrcPort", "NAT IP", "NATPort", "Pool", "Timeout")
	for _, b := range bindings {
		remaining := time.Until(b.LastSeen.Add(b.Timeout))
		if remaining < 0 {
			remaining = 0
		}
		fmt.Printf("%-20s %-8d %-20s %-8d %-15s %-10s\n",
			b.SrcIP, b.SrcPort, b.NatIP, b.NatPort, b.PoolName,
			remaining.Truncate(time.Second))
	}
	return nil
}

func (c *CLI) clearPersistentNAT() error {
	if c.dp == nil || c.dp.PersistentNAT == nil {
		fmt.Println("Persistent NAT table not available")
		return nil
	}
	count := c.dp.PersistentNAT.Len()
	c.dp.PersistentNAT.Clear()
	fmt.Printf("Cleared %d persistent NAT bindings\n", count)
	return nil
}

// showVRRP displays VRRP/keepalived status.
func (c *CLI) showVRRP() error {
	cfg := c.store.ActiveConfig()
	if cfg == nil {
		fmt.Println("No active configuration")
		return nil
	}

	// Collect VRRP instances from config
	instances := vrrp.CollectInstances(cfg)
	if len(instances) == 0 {
		fmt.Println("No VRRP groups configured")
		return nil
	}

	// Try to read runtime state
	status, _ := vrrp.Status()
	if status != "" {
		fmt.Println(status)
	}

	// Show configured instances
	fmt.Printf("%-14s %-6s %-8s %-10s %-16s %-8s\n",
		"Interface", "Group", "State", "Priority", "VIP", "Preempt")
	for _, inst := range instances {
		state := "BACKUP"
		preempt := "no"
		if inst.Preempt {
			preempt = "yes"
		}
		vip := strings.Join(inst.VirtualAddresses, ",")
		fmt.Printf("%-14s %-6d %-8s %-10d %-16s %-8s\n",
			inst.Interface, inst.GroupID, state, inst.Priority, vip, preempt)
	}
	return nil
}

// showMatchPolicies performs a 5-tuple policy lookup and shows matching rules.
func (c *CLI) showMatchPolicies(cfg *config.Config, args []string) error {
	if cfg == nil {
		fmt.Println("No active configuration")
		return nil
	}

	// Parse arguments: from-zone <z> to-zone <z> source-ip <ip> destination-ip <ip>
	//                   destination-port <p> protocol <proto>
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
		fmt.Println("usage: show security match-policies from-zone <zone> to-zone <zone>")
		fmt.Println("       source-ip <ip> destination-ip <ip> destination-port <port> protocol <tcp|udp>")
		return nil
	}

	parsedSrc := net.ParseIP(srcIP)
	parsedDst := net.ParseIP(dstIP)

	// Find the zone-pair policy
	for _, zpp := range cfg.Security.Policies {
		if zpp.FromZone != fromZone || zpp.ToZone != toZone {
			continue
		}

		for _, pol := range zpp.Policies {
			// Check source address match
			if !matchPolicyAddr(pol.Match.SourceAddresses, parsedSrc, cfg) {
				continue
			}
			// Check destination address match
			if !matchPolicyAddr(pol.Match.DestinationAddresses, parsedDst, cfg) {
				continue
			}
			// Check application match
			if !matchPolicyApp(pol.Match.Applications, proto, dstPort, cfg) {
				continue
			}

			// Found a match
			action := "permit"
			switch pol.Action {
			case 1:
				action = "deny"
			case 2:
				action = "reject"
			}
			fmt.Printf("Matching policy:\n")
			fmt.Printf("  From zone: %s, To zone: %s\n", fromZone, toZone)
			fmt.Printf("  Policy: %s\n", pol.Name)
			fmt.Printf("    Source addresses: %v\n", pol.Match.SourceAddresses)
			fmt.Printf("    Destination addresses: %v\n", pol.Match.DestinationAddresses)
			fmt.Printf("    Applications: %v\n", pol.Match.Applications)
			fmt.Printf("    Action: %s\n", action)
			return nil
		}
	}

	fmt.Printf("No matching policy found for %s -> %s (default deny)\n", fromZone, toZone)
	return nil
}

// matchPolicyAddr checks if an IP matches a list of address-book references.
func matchPolicyAddr(addrs []string, ip net.IP, cfg *config.Config) bool {
	if len(addrs) == 0 || ip == nil {
		return true // no filter = match all
	}
	for _, a := range addrs {
		if a == "any" {
			return true
		}
		if cfg.Security.AddressBook == nil {
			continue
		}
		// Check address entries
		if addr, ok := cfg.Security.AddressBook.Addresses[a]; ok {
			_, cidr, err := net.ParseCIDR(addr.Value)
			if err == nil && cidr.Contains(ip) {
				return true
			}
		}
		// Check address-set entries (recursive)
		if matchPolicyAddrSet(a, ip, cfg, 0) {
			return true
		}
	}
	return false
}

func matchPolicyAddrSet(setName string, ip net.IP, cfg *config.Config, depth int) bool {
	if depth > 5 || cfg.Security.AddressBook == nil {
		return false
	}
	as, ok := cfg.Security.AddressBook.AddressSets[setName]
	if !ok {
		return false
	}
	for _, addrName := range as.Addresses {
		if addr, ok := cfg.Security.AddressBook.Addresses[addrName]; ok {
			_, cidr, err := net.ParseCIDR(addr.Value)
			if err == nil && cidr.Contains(ip) {
				return true
			}
		}
	}
	for _, nested := range as.AddressSets {
		if matchPolicyAddrSet(nested, ip, cfg, depth+1) {
			return true
		}
	}
	return false
}

// matchPolicyApp checks if a protocol/port matches a list of application references.
func matchPolicyApp(apps []string, proto string, dstPort int, cfg *config.Config) bool {
	if len(apps) == 0 || proto == "" {
		return true // no filter = match all
	}
	for _, a := range apps {
		if a == "any" {
			return true
		}
		// Check predefined and custom applications
		if matchSingleApp(a, proto, dstPort, cfg) {
			return true
		}
		// Check application sets
		if cfg.Applications.ApplicationSets != nil {
			if as, ok := cfg.Applications.ApplicationSets[a]; ok {
				for _, appRef := range as.Applications {
					if matchSingleApp(appRef, proto, dstPort, cfg) {
						return true
					}
				}
			}
		}
	}
	return false
}

func matchSingleApp(appName, proto string, dstPort int, cfg *config.Config) bool {
	if cfg.Applications.Applications == nil {
		return false
	}
	app, ok := cfg.Applications.Applications[appName]
	if !ok {
		return false
	}
	if app.Protocol != "" && !strings.EqualFold(app.Protocol, proto) {
		return false
	}
	if app.DestinationPort != "" && dstPort > 0 {
		// Simple port match (handle single port or range)
		if strings.Contains(app.DestinationPort, "-") {
			parts := strings.SplitN(app.DestinationPort, "-", 2)
			lo, _ := strconv.Atoi(parts[0])
			hi, _ := strconv.Atoi(parts[1])
			if dstPort < lo || dstPort > hi {
				return false
			}
		} else {
			p, _ := strconv.Atoi(app.DestinationPort)
			if p != dstPort {
				return false
			}
		}
	}
	return true
}

// handleMonitor dispatches monitor sub-commands.
func (c *CLI) handleMonitor(args []string) error {
	if len(args) == 0 {
		fmt.Println("monitor:")
		fmt.Println("  traffic interface <name> [matching <filter>] [count <N>]")
		return nil
	}
	if args[0] == "traffic" {
		return c.handleMonitorTraffic(args[1:])
	}
	return fmt.Errorf("unknown monitor target: %s", args[0])
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

	cmdArgs := []string{"tcpdump", "-i", iface, "-n", "-l"}
	if count != "0" {
		cmdArgs = append(cmdArgs, "-c", count)
	}
	if filter != "" {
		cmdArgs = append(cmdArgs, filter)
	}

	fmt.Printf("Monitoring traffic on %s (Ctrl+C to stop)...\n", iface)
	cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
