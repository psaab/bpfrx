// Package cli implements the Junos-style interactive CLI for bpfrx.
package cli

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
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
	"github.com/psaab/bpfrx/pkg/dhcprelay"
	"github.com/psaab/bpfrx/pkg/dhcpserver"
	"github.com/psaab/bpfrx/pkg/frr"
	"github.com/psaab/bpfrx/pkg/ipsec"
	"github.com/psaab/bpfrx/pkg/logging"
	"github.com/psaab/bpfrx/pkg/routing"
	"github.com/psaab/bpfrx/pkg/rpm"
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
	dhcp         *dhcp.Manager
	dhcpRelay    *dhcprelay.Manager
	rpmResultsFn func() []*rpm.ProbeResult
	hostname     string
	username     string
	version      string
}

// New creates a new CLI.
func New(store *configstore.Store, dp *dataplane.Manager, eventBuf *logging.EventBuffer, eventReader *logging.EventReader, rm *routing.Manager, fm *frr.Manager, im *ipsec.Manager, dm *dhcp.Manager, dr *dhcprelay.Manager) *CLI {
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
		dhcpRelay:   dr,
		hostname:    hostname,
		username:    username,
	}
}

// SetRPMResultsFn sets a callback for retrieving live RPM probe results.
func (c *CLI) SetRPMResultsFn(fn func() []*rpm.ProbeResult) {
	c.rpmResultsFn = fn
}

// SetVersion sets the software version string for show version.
func (c *CLI) SetVersion(v string) {
	c.version = v
}

// completionNode is a static command completion tree node.
type completionNode struct {
	desc      string
	children  map[string]*completionNode
	dynamicFn func(cfg *config.Config) []string
}

// operationalTree defines tab completion for operational mode.
var operationalTree = map[string]*completionNode{
	"configure": {desc: "Enter configuration mode"},
	"show": {desc: "Show information", children: map[string]*completionNode{
		"chassis": {desc: "Show hardware information", children: map[string]*completionNode{
			"cluster":     {desc: "Show cluster/HA status"},
			"environment": {desc: "Show temperature and power"},
			"hardware":    {desc: "Show hardware details"},
		}},
		"configuration": {desc: "Show active configuration"},
		"dhcp": {desc: "Show DHCP information", children: map[string]*completionNode{
			"leases":            {desc: "Show DHCP leases"},
			"client-identifier": {desc: "Show DHCPv6 DUID(s)"},
		}},
		"flow-monitoring": {desc: "Show flow monitoring/NetFlow configuration"},
		"log":             {desc: "Show daemon log entries [N]"},
		"route": {desc: "Show routing table [instance <name>]", children: map[string]*completionNode{
			"summary":  {desc: "Show route summary by protocol"},
			"table":    {desc: "Show routes for a VRF table"},
			"protocol": {desc: "Show routes by protocol (static, connected, bgp, ospf, dhcp)"},
			"instance": {desc: "Show routes for a routing instance", dynamicFn: func(cfg *config.Config) []string {
				if cfg == nil {
					return nil
				}
				names := make([]string, 0, len(cfg.RoutingInstances))
				for _, ri := range cfg.RoutingInstances {
					names = append(names, ri.Name)
				}
				return names
			}},
		}},
		"security": {desc: "Show security information", children: map[string]*completionNode{
			"zones": {desc: "Show security zones", dynamicFn: func(cfg *config.Config) []string {
				if cfg == nil {
					return nil
				}
				names := make([]string, 0, len(cfg.Security.Zones))
				for name := range cfg.Security.Zones {
					names = append(names, name)
				}
				return names
			}},
			"policies": {desc: "Show security policies", children: map[string]*completionNode{
				"brief":     {desc: "Show brief policy summary"},
				"hit-count": {desc: "Show policy hit counters [from-zone X to-zone Y]"},
				"from-zone": {desc: "Filter by source zone", dynamicFn: func(cfg *config.Config) []string {
					if cfg == nil {
						return nil
					}
					names := make([]string, 0, len(cfg.Security.Zones))
					for name := range cfg.Security.Zones {
						names = append(names, name)
					}
					return names
				}},
				"to-zone": {desc: "Filter by destination zone"},
			}},
			"screen":          {desc: "Show screen/IDS profiles"},
			"alg":             {desc: "Show ALG status"},
			"dynamic-address": {desc: "Show dynamic address feeds"},
			"flow": {desc: "Show flow information", children: map[string]*completionNode{
				"session":      {desc: "Show active sessions"},
				"statistics":   {desc: "Show flow statistics"},
				"traceoptions": {desc: "Show flow trace configuration"},
			}},
			"nat": {desc: "Show NAT information", children: map[string]*completionNode{
				"source":      {desc: "Show source NAT"},
				"destination": {desc: "Show destination NAT"},
				"static":      {desc: "Show static NAT"},
				"nat64":       {desc: "Show NAT64 rules"},
			}},
			"address-book": {desc: "Show address book entries"},
			"applications": {desc: "Show application definitions"},
			"log":          {desc: "Show recent security events [N] [zone <z>] [protocol <p>] [action <a>]"},
			"statistics":   {desc: "Show global statistics"},
			"ike": {desc: "Show IKE status", children: map[string]*completionNode{
				"security-associations": {desc: "Show IKE SAs"},
			}},
			"ipsec": {desc: "Show IPsec status", children: map[string]*completionNode{
				"security-associations": {desc: "Show IPsec SAs"},
			}},
			"vrrp":           {desc: "Show VRRP high availability status"},
			"match-policies": {desc: "Match 5-tuple against policies"},
		}},
		"services": {desc: "Show services information", children: map[string]*completionNode{
			"rpm": {desc: "Show RPM probe results", children: map[string]*completionNode{
				"probe-results": {desc: "Show RPM probe results"},
			}},
		}},
		"interfaces": {desc: "Show interface status", dynamicFn: func(cfg *config.Config) []string {
			if cfg == nil || cfg.Interfaces.Interfaces == nil {
				return nil
			}
			names := make([]string, 0, len(cfg.Interfaces.Interfaces))
			for name := range cfg.Interfaces.Interfaces {
				names = append(names, name)
			}
			return names
		}, children: map[string]*completionNode{
			"terse":     {desc: "Show interface summary"},
			"extensive": {desc: "Show detailed interface statistics"},
			"tunnel":    {desc: "Show tunnel interfaces"},
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
		"arp":         {desc: "Show ARP table"},
		"ipv6": {desc: "Show IPv6 information", children: map[string]*completionNode{
			"neighbors": {desc: "Show IPv6 neighbor cache"},
		}},
		"schedulers":  {desc: "Show policy schedulers"},
		"dhcp-relay":   {desc: "Show DHCP relay status"},
		"dhcp-server": {desc: "Show DHCP server leases"},
		"snmp":        {desc: "Show SNMP statistics"},
		"system": {desc: "Show system information", children: map[string]*completionNode{
			"alarms":      {desc: "Show system alarms"},
			"connections": {desc: "Show system TCP connections"},
			"rollback": {desc: "Show rollback history", children: map[string]*completionNode{
				"compare": {desc: "Compare rollback with active config"},
			}},
			"backup-router": {desc: "Show backup router configuration"},
			"buffers":       {desc: "Show BPF map utilization"},
			"license":       {desc: "Show system license"},
			"memory":        {desc: "Show memory usage"},
			"ntp":           {desc: "Show NTP server status"},
			"processes":     {desc: "Show running processes"},
			"services":      {desc: "Show configured system services"},
			"storage":       {desc: "Show filesystem usage"},
			"syslog":        {desc: "Show system syslog configuration"},
			"uptime":        {desc: "Show system uptime"},
			"users":         {desc: "Show configured login users"},
		}},
		"routing-options":    {desc: "Show routing options"},
		"routing-instances":  {desc: "Show routing instances"},
		"policy-options":     {desc: "Show policy options"},
		"event-options":      {desc: "Show event policies"},
		"forwarding-options": {desc: "Show forwarding options"},
		"version":            {desc: "Show software version"},
	}},
	"monitor": {desc: "Capture traffic", children: map[string]*completionNode{
		"traffic": {desc: "Capture traffic on interface", children: map[string]*completionNode{
			"interface": {desc: "Interface name to capture on"},
		}},
	}},
	"clear": {desc: "Clear information", children: map[string]*completionNode{
		"security": {desc: "Clear security information", children: map[string]*completionNode{
			"flow": {desc: "Clear flow information", children: map[string]*completionNode{
				"session": {desc: "Clear sessions [source-prefix|destination-prefix|protocol|zone]"},
			}},
			"counters": {desc: "Clear all counters"},
			"policies": {desc: "Clear policy information", children: map[string]*completionNode{
				"hit-count": {desc: "Clear policy hit counters"},
			}},
			"nat": {desc: "Clear NAT information", children: map[string]*completionNode{
				"source": {desc: "Clear source NAT", children: map[string]*completionNode{
					"persistent-nat-table": {desc: "Clear persistent NAT bindings"},
				}},
			}},
		}},
		"firewall": {desc: "Clear firewall counters", children: map[string]*completionNode{
			"all": {desc: "Clear all firewall filter counters"},
		}},
		"dhcp": {desc: "Clear DHCP information", children: map[string]*completionNode{
			"client-identifier": {desc: "Clear DHCPv6 DUID(s)"},
		}},
	}},
	"request": {desc: "Perform system operations", children: map[string]*completionNode{
		"dhcp": {desc: "DHCP operations", children: map[string]*completionNode{
			"renew": {desc: "Renew DHCP lease on an interface"},
		}},
		"system": {desc: "System operations", children: map[string]*completionNode{
			"reboot":  {desc: "Reboot the system"},
			"halt":    {desc: "Halt the system"},
			"zeroize": {desc: "Factory reset (erase all config)"},
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
	"commit": {desc: "Commit configuration", children: map[string]*completionNode{
		"check":     {desc: "Validate without applying"},
		"confirmed": {desc: "Auto-rollback if not confirmed [minutes]"},
	}},
	"load": {desc: "Load configuration from file or terminal", children: map[string]*completionNode{
		"override": {desc: "Replace candidate with file or terminal input"},
		"merge":    {desc: "Merge into candidate from file or terminal"},
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
	text := string(line[:pos])
	words := strings.Fields(text)
	trailingSpace := len(text) > 0 && text[len(text)-1] == ' '

	var partial string
	if !trailingSpace && len(words) > 0 {
		partial = words[len(words)-1]
		words = words[:len(words)-1]
	}

	var candidates []completionCandidate
	if cc.cli.store.InConfigMode() {
		candidates = cc.cli.completeConfigWithDesc(words, partial)
	} else {
		candidates = completeFromTreeWithDesc(operationalTree, words, partial, cc.cli.store.ActiveConfig())
	}
	if len(candidates) == 0 {
		return nil, 0
	}

	sort.Slice(candidates, func(i, j int) bool { return candidates[i].name < candidates[j].name })

	if len(candidates) == 1 {
		suffix := candidates[0].name[len(partial):]
		return [][]rune{[]rune(suffix + " ")}, len(partial)
	}

	// Multiple matches: show descriptions above prompt.
	writeCompletionHelp(cc.cli.rl.Stdout(), candidates)

	// Complete common prefix.
	names := make([]string, len(candidates))
	for i, c := range candidates {
		names[i] = c.name
	}
	cp := commonPrefix(names)
	suffix := cp[len(partial):]
	if suffix == "" {
		return nil, 0
	}
	return [][]rune{[]rune(suffix)}, len(partial)
}

func (c *CLI) completeConfigWithDesc(words []string, partial string) []completionCandidate {
	if len(words) == 0 {
		var candidates []completionCandidate
		for name, node := range configTopLevel {
			if strings.HasPrefix(name, partial) {
				candidates = append(candidates, completionCandidate{name: name, desc: node.desc})
			}
		}
		return candidates
	}

	switch words[0] {
	case "set", "delete":
		schemaCompletions := config.CompleteSetPathWithValues(words[1:], c.valueProvider)
		if schemaCompletions == nil {
			return nil
		}
		var candidates []completionCandidate
		for _, name := range schemaCompletions {
			if strings.HasPrefix(name, partial) {
				candidates = append(candidates, completionCandidate{name: name})
			}
		}
		return candidates

	case "run":
		return completeFromTreeWithDesc(operationalTree, words[1:], partial, c.store.ActiveConfig())

	case "commit", "load":
		if len(words) == 1 {
			node := configTopLevel[words[0]]
			if node == nil || node.children == nil {
				return nil
			}
			var candidates []completionCandidate
			for name, child := range node.children {
				if strings.HasPrefix(name, partial) {
					candidates = append(candidates, completionCandidate{name: name, desc: child.desc})
				}
			}
			return candidates
		}
		return nil

	default:
		return nil
	}
}

// resolveCommand performs Junos-style prefix matching.
// Given a partial input and a list of valid commands, it returns:
// - The full command name if exactly one match
// - "" and an error if ambiguous (multiple matches)
// - "" and an error if no match
func resolveCommand(input string, validCommands []string) (string, error) {
	if input == "" {
		return "", fmt.Errorf("missing command")
	}
	// Exact match first
	for _, cmd := range validCommands {
		if cmd == input {
			return cmd, nil
		}
	}
	// Prefix match
	var matches []string
	for _, cmd := range validCommands {
		if strings.HasPrefix(cmd, input) {
			matches = append(matches, cmd)
		}
	}
	switch len(matches) {
	case 0:
		return "", fmt.Errorf("unknown command: %s", input)
	case 1:
		return matches[0], nil
	default:
		sort.Strings(matches)
		return "", fmt.Errorf("'%s' is ambiguous.\nPossible completions:\n%s",
			input, formatAmbiguousMatches(matches))
	}
}

func formatAmbiguousMatches(matches []string) string {
	var sb strings.Builder
	maxWidth := 0
	for _, m := range matches {
		if len(m) > maxWidth {
			maxWidth = len(m)
		}
	}
	for _, m := range matches {
		sb.WriteString(fmt.Sprintf("  %s\n", m))
	}
	return sb.String()
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
		Listener: readline.FuncListener(func(line []rune, pos int, key rune) ([]rune, int, bool) {
			if key != '?' || pos < 1 {
				return line, pos, false
			}
			// Strip the '?' that readline already inserted.
			cleanLine := make([]rune, 0, len(line)-1)
			cleanLine = append(cleanLine, line[:pos-1]...)
			cleanLine = append(cleanLine, line[pos:]...)
			// Parse words from text before cursor.
			text := string(cleanLine[:pos-1])
			words := strings.Fields(text)
			trailingSpace := len(text) > 0 && text[len(text)-1] == ' '
			var partial string
			if !trailingSpace && len(words) > 0 {
				partial = words[len(words)-1]
				words = words[:len(words)-1]
			}
			var candidates []completionCandidate
			if c.store.InConfigMode() {
				candidates = c.completeConfigWithDesc(words, partial)
			} else {
				candidates = completeFromTreeWithDesc(operationalTree, words, partial, c.store.ActiveConfig())
			}
			if len(candidates) > 0 {
				writeCompletionHelp(c.rl.Stdout(), candidates)
			}
			return cleanLine, pos - 1, true
		}),
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

var operationalCommands = []string{
	"configure", "show", "clear", "ping", "traceroute",
	"monitor", "request", "quit", "exit",
}

func (c *CLI) dispatchOperational(line string) error {
	parts := strings.Fields(line)
	if len(parts) == 0 {
		return nil
	}

	if parts[0] == "?" || parts[0] == "help" {
		c.showOperationalHelp()
		return nil
	}

	resolved, err := resolveCommand(parts[0], operationalCommands)
	if err != nil {
		return err
	}
	parts[0] = resolved

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

	case "request":
		return c.handleRequest(parts[1:])

	case "quit", "exit":
		return errExit

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

	case "load":
		return c.handleLoad(parts[1:])

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
	showTree := operationalTree["show"].children
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
		if strings.Contains(rest, "| display json") {
			fmt.Print(c.store.ShowActiveJSON())
		} else if strings.Contains(rest, "| display set") {
			fmt.Print(c.store.ShowActiveSet())
		} else if len(args) > 1 {
			// Filter out pipe commands from the path
			var path []string
			for _, a := range args[1:] {
				if a == "|" {
					break
				}
				path = append(path, a)
			}
			output := c.store.ShowActivePath(path)
			if output == "" {
				fmt.Printf("configuration path not found: %s\n", strings.Join(path, " "))
			} else {
				fmt.Print(output)
			}
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

	case "system":
		return c.handleShowSystem(args[1:])

	case "schedulers":
		return c.showSchedulers()

	case "dhcp-relay":
		return c.showDHCPRelay()

	case "dhcp-server":
		return c.showDHCPServer()

	case "snmp":
		return c.showSNMP()

	case "arp":
		return c.showARP()

	case "ipv6":
		return c.handleShowIPv6(args[1:])

	case "policy-options":
		return c.showPolicyOptions()

	case "event-options":
		return c.showEventOptions()

	case "routing-options":
		return c.showRoutingOptions()

	case "routing-instances":
		return c.showRoutingInstances()

	case "forwarding-options":
		return c.showForwardingOptions()

	default:
		return fmt.Errorf("unknown show target: %s", args[0])
	}
}

func (c *CLI) handleShowSecurity(args []string) error {
	secTree := operationalTree["show"].children["security"].children
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
			if zone.Description != "" {
				fmt.Printf("  Description: %s\n", zone.Description)
			}
			fmt.Printf("  Interfaces: %s\n", strings.Join(zone.Interfaces, ", "))
			if zone.TCPRst {
				fmt.Println("  TCP RST: enabled")
			}
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

			// Show policies that reference this zone
			var policyRefs []string
			for _, zpp := range cfg.Security.Policies {
				if zpp.FromZone == name || zpp.ToZone == name {
					dir := "from"
					peer := zpp.ToZone
					if zpp.ToZone == name {
						dir = "to"
						peer = zpp.FromZone
					}
					policyRefs = append(policyRefs, fmt.Sprintf("%s %s (%d rules)", dir, peer, len(zpp.Policies)))
				}
			}
			if len(policyRefs) > 0 {
				fmt.Printf("  Policies: %s\n", strings.Join(policyRefs, ", "))
			}

			// Show address book entries (global)
			if ab := cfg.Security.AddressBook; ab != nil && len(ab.Addresses) > 0 {
				addrNames := make([]string, 0, len(ab.Addresses))
				for an := range ab.Addresses {
					addrNames = append(addrNames, an)
				}
				sort.Strings(addrNames)
				fmt.Printf("  Address book: %s\n", strings.Join(addrNames, ", "))
			}

			fmt.Println()
		}
		return nil

	case "policies":
		// Parse optional zone-pair filter: from-zone X to-zone Y
		fromZone, toZone := parsePolicyZoneFilter(args[1:])
		// "show security policies hit-count" — Junos-style hit count table
		if len(args) >= 2 && args[1] == "hit-count" {
			return c.showPoliciesHitCount(cfg, fromZone, toZone)
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
		for _, zpp := range cfg.Security.Policies {
			if fromZone != "" && zpp.FromZone != fromZone {
				policySetID++
				continue
			}
			if toZone != "" && zpp.ToZone != toZone {
				policySetID++
				continue
			}
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
				if pol.Description != "" {
					fmt.Printf("    Description: %s\n", pol.Description)
				}
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
		// Global policies
		if len(cfg.Security.GlobalPolicies) > 0 && fromZone == "" && toZone == "" {
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
				fmt.Printf("  Rule: %s (id: %d)\n", pol.Name, ruleID)
				if pol.Description != "" {
					fmt.Printf("    Description: %s\n", pol.Description)
				}
				fmt.Printf("    Match: src=%v dst=%v app=%v\n",
					pol.Match.SourceAddresses,
					pol.Match.DestinationAddresses,
					pol.Match.Applications)
				fmt.Printf("    Action: %s\n", action)
				if c.dp != nil && c.dp.IsLoaded() {
					counters, err := c.dp.ReadPolicyCounters(ruleID)
					if err == nil {
						fmt.Printf("    Hit count: %d packets, %d bytes\n",
							counters.Packets, counters.Bytes)
					}
				}
			}
			fmt.Println()
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
		return c.showScreen()

	case "nat":
		return c.handleShowNAT(args[1:])

	case "address-book":
		return c.showAddressBook(args[1:])

	case "applications":
		return c.showApplications(args[1:])

	case "log":
		return c.showSecurityLog(args[1:])

	case "statistics":
		return c.showStatistics()

	case "ipsec":
		return c.showIPsec(args[1:])

	case "ike":
		return c.showIKE(args[1:])

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

// showPoliciesHitCount displays a Junos-style policy hit count table.
func (c *CLI) showPoliciesHitCount(cfg *config.Config, fromZone, toZone string) error {
	if c.dp == nil || !c.dp.IsLoaded() {
		fmt.Println("dataplane not loaded")
		return nil
	}

	fmt.Printf("%-12s %-12s %-24s %-8s %12s %16s\n",
		"From zone", "To zone", "Policy", "Action", "Packets", "Bytes")
	fmt.Println(strings.Repeat("-", 88))

	policySetID := uint32(0)
	var totalPkts, totalBytes uint64
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
			var pkts, bytes uint64
			if counters, err := c.dp.ReadPolicyCounters(ruleID); err == nil {
				pkts = counters.Packets
				bytes = counters.Bytes
			}
			totalPkts += pkts
			totalBytes += bytes
			fmt.Printf("%-12s %-12s %-24s %-8s %12d %16d\n",
				zpp.FromZone, zpp.ToZone, pol.Name, action, pkts, bytes)
		}
		policySetID++
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
			ruleID := policySetID*dataplane.MaxRulesPerPolicy + uint32(i)
			var pkts, bytes uint64
			if counters, err := c.dp.ReadPolicyCounters(ruleID); err == nil {
				pkts = counters.Packets
				bytes = counters.Bytes
			}
			totalPkts += pkts
			totalBytes += bytes
			fmt.Printf("%-12s %-12s %-24s %-8s %12d %16d\n",
				"*", "*", pol.Name, action, pkts, bytes)
		}
	}
	fmt.Println(strings.Repeat("-", 88))
	fmt.Printf("%-48s %8s %12d %16d\n", "Total", "", totalPkts, totalBytes)
	return nil
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

	// Show screen drop counters (total + per-type)
	if c.dp != nil && c.dp.IsLoaded() {
		ctrMap := c.dp.Map("global_counters")
		if ctrMap != nil {
			readCtr := func(idx uint32) uint64 {
				var perCPU []uint64
				if err := ctrMap.Lookup(idx, &perCPU); err == nil {
					var total uint64
					for _, v := range perCPU {
						total += v
					}
					return total
				}
				return 0
			}

			totalDrops := readCtr(dataplane.GlobalCtrScreenDrops)
			fmt.Printf("Total screen drops: %d\n", totalDrops)

			if totalDrops > 0 {
				screenCounters := []struct {
					idx  uint32
					name string
				}{
					{dataplane.GlobalCtrScreenSynFlood, "SYN flood"},
					{dataplane.GlobalCtrScreenICMPFlood, "ICMP flood"},
					{dataplane.GlobalCtrScreenUDPFlood, "UDP flood"},
					{dataplane.GlobalCtrScreenLandAttack, "LAND attack"},
					{dataplane.GlobalCtrScreenPingOfDeath, "Ping of death"},
					{dataplane.GlobalCtrScreenTearDrop, "Teardrop"},
					{dataplane.GlobalCtrScreenTCPSynFin, "TCP SYN+FIN"},
					{dataplane.GlobalCtrScreenTCPNoFlag, "TCP no flag"},
					{dataplane.GlobalCtrScreenTCPFinNoAck, "TCP FIN no ACK"},
					{dataplane.GlobalCtrScreenWinNuke, "WinNuke"},
					{dataplane.GlobalCtrScreenIPSrcRoute, "IP source route"},
					{dataplane.GlobalCtrScreenSynFrag, "SYN fragment"},
				}
				for _, sc := range screenCounters {
					v := readCtr(sc.idx)
					if v > 0 {
						fmt.Printf("  %-25s %d\n", sc.name+":", v)
					}
				}
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
		{dataplane.GlobalCtrNAT64Xlate, "NAT64 translations"},
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

	if strings.Contains(line, "| display json") {
		fmt.Print(c.store.ShowCandidateJSON())
		return nil
	}

	if strings.Contains(line, "| display set") {
		fmt.Print(c.store.ShowCandidateSet())
		return nil
	}

	fmt.Print(c.store.ShowCandidate())
	return nil
}

func (c *CLI) handleLoad(args []string) error {
	if len(args) < 2 {
		fmt.Println("load:")
		fmt.Println("  override terminal    Replace candidate with pasted config")
		fmt.Println("  merge terminal       Merge pasted config into candidate")
		fmt.Println("  override <file>      Replace candidate with file contents")
		fmt.Println("  merge <file>         Merge file contents into candidate")
		return nil
	}

	mode := args[0] // "override" or "merge"
	if mode != "override" && mode != "merge" {
		return fmt.Errorf("load: unknown mode %q (use 'override' or 'merge')", mode)
	}

	source := args[1]
	var content string

	if source == "terminal" {
		// Read from terminal until a line containing only a single Ctrl-D marker
		fmt.Println("[Type or paste configuration, then press Ctrl-D on an empty line]")
		var lines []string
		for {
			line, err := c.rl.Readline()
			if err != nil {
				// EOF (Ctrl-D)
				break
			}
			lines = append(lines, line)
		}
		content = strings.Join(lines, "\n")
	} else {
		// Read from file
		data, err := os.ReadFile(source)
		if err != nil {
			return fmt.Errorf("load: %w", err)
		}
		content = string(data)
	}

	if strings.TrimSpace(content) == "" {
		return fmt.Errorf("load: empty input")
	}

	var err error
	switch mode {
	case "override":
		err = c.store.LoadOverride(content)
	case "merge":
		err = c.store.LoadMerge(content)
	}
	if err != nil {
		return fmt.Errorf("load %s: %w", mode, err)
	}

	fmt.Printf("load %s complete\n", mode)
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
		if stream.Severity != "" {
			client.MinSeverity = logging.ParseSeverity(stream.Severity)
		}
		if stream.Category != "" {
			client.Categories = logging.ParseCategory(stream.Category)
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

	// Summary counters for protocol/zone/NAT breakdown
	var byProto map[uint8]int
	var byZonePair map[string]int
	var v4Count, v6Count, natCount int
	if f.summary {
		byProto = make(map[uint8]int)
		byZonePair = make(map[string]int)
	}

	// Build reverse zone ID → name map
	zoneNames := make(map[uint16]string)
	if cr := c.dp.LastCompileResult(); cr != nil {
		for name, id := range cr.ZoneIDs {
			zoneNames[id] = name
		}
	}

	now := monotonicSeconds()

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
			v4Count++
			byProto[key.Protocol]++
			inZ := zoneNames[val.IngressZone]
			outZ := zoneNames[val.EgressZone]
			if inZ == "" {
				inZ = fmt.Sprintf("zone-%d", val.IngressZone)
			}
			if outZ == "" {
				outZ = fmt.Sprintf("zone-%d", val.EgressZone)
			}
			byZonePair[inZ+"->"+outZ]++
			if val.Flags&(dataplane.SessFlagSNAT|dataplane.SessFlagDNAT) != 0 {
				natCount++
			}
			return true
		}

		srcIP := net.IP(key.SrcIP[:])
		dstIP := net.IP(key.DstIP[:])
		srcPort := ntohs(key.SrcPort)
		dstPort := ntohs(key.DstPort)
		protoName := protoNameFromNum(key.Protocol)
		stateName := sessionStateName(val.State)

		var age, idle uint64
		if now > val.Created {
			age = now - val.Created
		}
		if now > val.LastSeen {
			idle = now - val.LastSeen
		}
		fmt.Printf("Session ID: %d, Policy: %d, State: %s, Timeout: %ds, Age: %ds, Idle: %ds\n",
			count, val.PolicyID, stateName, val.Timeout, age, idle)
		fmt.Printf("  In: %s:%d --> %s:%d;%s,",
			srcIP, srcPort, dstIP, dstPort, protoName)
		inZone := zoneNames[val.IngressZone]
		outZone := zoneNames[val.EgressZone]
		if inZone == "" {
			inZone = fmt.Sprintf("%d", val.IngressZone)
		}
		if outZone == "" {
			outZone = fmt.Sprintf("%d", val.EgressZone)
		}
		fmt.Printf(" Zone: %s -> %s\n", inZone, outZone)

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
			v6Count++
			byProto[key.Protocol]++
			inZ := zoneNames[val.IngressZone]
			outZ := zoneNames[val.EgressZone]
			if inZ == "" {
				inZ = fmt.Sprintf("zone-%d", val.IngressZone)
			}
			if outZ == "" {
				outZ = fmt.Sprintf("zone-%d", val.EgressZone)
			}
			byZonePair[inZ+"->"+outZ]++
			if val.Flags&(dataplane.SessFlagSNAT|dataplane.SessFlagDNAT) != 0 {
				natCount++
			}
			return true
		}

		srcIP := net.IP(key.SrcIP[:])
		dstIP := net.IP(key.DstIP[:])
		srcPort := ntohs(key.SrcPort)
		dstPort := ntohs(key.DstPort)
		protoName := protoNameFromNum(key.Protocol)
		stateName := sessionStateName(val.State)

		var age, idle uint64
		if now > val.Created {
			age = now - val.Created
		}
		if now > val.LastSeen {
			idle = now - val.LastSeen
		}
		fmt.Printf("Session ID: %d, Policy: %d, State: %s, Timeout: %ds, Age: %ds, Idle: %ds\n",
			count, val.PolicyID, stateName, val.Timeout, age, idle)
		fmt.Printf("  In: [%s]:%d --> [%s]:%d;%s,",
			srcIP, srcPort, dstIP, dstPort, protoName)
		inZone := zoneNames[val.IngressZone]
		outZone := zoneNames[val.EgressZone]
		if inZone == "" {
			inZone = fmt.Sprintf("%d", val.IngressZone)
		}
		if outZone == "" {
			outZone = fmt.Sprintf("%d", val.EgressZone)
		}
		fmt.Printf(" Zone: %s -> %s\n", inZone, outZone)

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

	if f.summary && count > 0 {
		fmt.Printf("Session summary:\n")
		fmt.Printf("  IPv4 sessions: %d\n", v4Count)
		fmt.Printf("  IPv6 sessions: %d\n", v6Count)
		fmt.Printf("  NAT sessions:  %d\n\n", natCount)

		fmt.Printf("  By protocol:\n")
		protoKeys := make([]uint8, 0, len(byProto))
		for k := range byProto {
			protoKeys = append(protoKeys, k)
		}
		sort.Slice(protoKeys, func(i, j int) bool { return protoKeys[i] < protoKeys[j] })
		for _, p := range protoKeys {
			fmt.Printf("    %-8s %d\n", protoNameFromNum(p), byProto[p])
		}

		fmt.Printf("\n  By zone pair:\n")
		zpKeys := make([]string, 0, len(byZonePair))
		for k := range byZonePair {
			zpKeys = append(zpKeys, k)
		}
		sort.Strings(zpKeys)
		for _, zp := range zpKeys {
			fmt.Printf("    %-30s %d\n", zp, byZonePair[zp])
		}
		fmt.Println()
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
	if flow.AllowDNSReply || flow.AllowEmbeddedICMP || flow.GREPerformanceAcceleration || flow.PowerModeDisable {
		fmt.Println()
		fmt.Println("Flow options:")
		if flow.AllowDNSReply {
			fmt.Println("  allow-dns-reply:               enabled")
		}
		if flow.AllowEmbeddedICMP {
			fmt.Println("  allow-embedded-icmp:           enabled")
		}
		if flow.GREPerformanceAcceleration {
			fmt.Println("  gre-performance-acceleration:  enabled")
		}
		if flow.PowerModeDisable {
			fmt.Println("  power-mode-disable:            yes")
		}
	}

	return nil
}

// showFlowStatistics displays flow statistics from BPF global counters.
func (c *CLI) showFlowStatistics() error {
	if c.dp == nil || !c.dp.IsLoaded() {
		fmt.Println("Flow statistics: dataplane not loaded")
		return nil
	}

	ctrMap := c.dp.Map("global_counters")
	if ctrMap == nil {
		fmt.Println("Flow statistics: global_counters map not found")
		return nil
	}

	readCounter := func(idx uint32) uint64 {
		var perCPU []uint64
		if err := ctrMap.Lookup(idx, &perCPU); err != nil {
			return 0
		}
		var total uint64
		for _, v := range perCPU {
			total += v
		}
		return total
	}

	rxPkts := readCounter(dataplane.GlobalCtrRxPackets)
	txPkts := readCounter(dataplane.GlobalCtrTxPackets)
	drops := readCounter(dataplane.GlobalCtrDrops)
	sessNew := readCounter(dataplane.GlobalCtrSessionsNew)
	sessClosed := readCounter(dataplane.GlobalCtrSessionsClosed)
	screenDrops := readCounter(dataplane.GlobalCtrScreenDrops)
	policyDeny := readCounter(dataplane.GlobalCtrPolicyDeny)
	natFail := readCounter(dataplane.GlobalCtrNATAllocFail)
	hostDeny := readCounter(dataplane.GlobalCtrHostInboundDeny)
	hostAllow := readCounter(dataplane.GlobalCtrHostInbound)
	tcEgress := readCounter(dataplane.GlobalCtrTCEgressPackets)
	nat64 := readCounter(dataplane.GlobalCtrNAT64Xlate)

	fmt.Println("Flow statistics:")
	fmt.Printf("  %-30s %d\n", "Current sessions:", sessNew-sessClosed)
	fmt.Printf("  %-30s %d\n", "Sessions created:", sessNew)
	fmt.Printf("  %-30s %d\n", "Sessions closed:", sessClosed)
	fmt.Println()
	fmt.Printf("  %-30s %d\n", "Packets received:", rxPkts)
	fmt.Printf("  %-30s %d\n", "Packets transmitted:", txPkts)
	fmt.Printf("  %-30s %d\n", "Packets dropped:", drops)
	fmt.Printf("  %-30s %d\n", "TC egress packets:", tcEgress)
	fmt.Println()
	fmt.Printf("  %-30s %d\n", "Policy deny:", policyDeny)
	fmt.Printf("  %-30s %d\n", "NAT allocation failures:", natFail)
	fmt.Printf("  %-30s %d\n", "NAT64 translations:", nat64)
	fmt.Println()
	fmt.Printf("  %-30s %d\n", "Host-inbound allowed:", hostAllow)
	fmt.Printf("  %-30s %d\n", "Host-inbound denied:", hostDeny)

	// Screen drops breakdown
	if screenDrops > 0 {
		fmt.Println()
		fmt.Printf("  %-30s %d\n", "Screen drops (total):", screenDrops)

		screenCounters := []struct {
			idx  uint32
			name string
		}{
			{dataplane.GlobalCtrScreenSynFlood, "SYN flood"},
			{dataplane.GlobalCtrScreenICMPFlood, "ICMP flood"},
			{dataplane.GlobalCtrScreenUDPFlood, "UDP flood"},
			{dataplane.GlobalCtrScreenPortScan, "Port scan"},
			{dataplane.GlobalCtrScreenIPSweep, "IP sweep"},
			{dataplane.GlobalCtrScreenLandAttack, "Land attack"},
			{dataplane.GlobalCtrScreenPingOfDeath, "Ping of death"},
			{dataplane.GlobalCtrScreenTearDrop, "Tear drop"},
			{dataplane.GlobalCtrScreenTCPSynFin, "TCP SYN-FIN"},
			{dataplane.GlobalCtrScreenTCPNoFlag, "TCP no flag"},
			{dataplane.GlobalCtrScreenTCPFinNoAck, "TCP FIN no ACK"},
			{dataplane.GlobalCtrScreenWinNuke, "WinNuke"},
			{dataplane.GlobalCtrScreenIPSrcRoute, "IP source route"},
			{dataplane.GlobalCtrScreenSynFrag, "SYN fragment"},
		}
		for _, sc := range screenCounters {
			v := readCounter(sc.idx)
			if v > 0 {
				fmt.Printf("    %-28s %d\n", sc.name+":", v)
			}
		}
	}

	return nil
}

// showFlowTraceoptions displays flow traceoptions config.
func (c *CLI) showFlowTraceoptions() error {
	cfg := c.store.ActiveConfig()
	if cfg == nil {
		fmt.Println("no active configuration")
		return nil
	}

	opts := cfg.Security.Flow.Traceoptions
	if opts == nil || opts.File == "" {
		fmt.Println("Flow traceoptions: not configured")
		return nil
	}

	fmt.Println("Flow traceoptions:")
	fmt.Printf("  File:           %s\n", opts.File)
	if opts.FileSize > 0 {
		fmt.Printf("  Max size:       %d bytes\n", opts.FileSize)
	}
	if opts.FileCount > 0 {
		fmt.Printf("  File count:     %d\n", opts.FileCount)
	}
	if len(opts.Flags) > 0 {
		fmt.Printf("  Flags:          %s\n", strings.Join(opts.Flags, ", "))
	}
	if len(opts.PacketFilters) > 0 {
		fmt.Println("  Packet filters:")
		for _, pf := range opts.PacketFilters {
			fmt.Printf("    %s:", pf.Name)
			if pf.SourcePrefix != "" {
				fmt.Printf(" src=%s", pf.SourcePrefix)
			}
			if pf.DestinationPrefix != "" {
				fmt.Printf(" dst=%s", pf.DestinationPrefix)
			}
			fmt.Println()
		}
	}

	return nil
}

func (c *CLI) handleClear(args []string) error {
	clearTree := operationalTree["clear"].children
	showHelp := func() {
		fmt.Println("clear:")
		writeCompletionHelp(os.Stdout, treeHelpCandidates(clearTree))
	}
	if len(args) < 1 {
		showHelp()
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
		showHelp()
		return nil
	}
}

func (c *CLI) handleClearSecurity(args []string) error {
	if len(args) < 1 {
		fmt.Println("clear security:")
		writeCompletionHelp(os.Stdout, treeHelpCandidates(operationalTree["clear"].children["security"].children))
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
			return fmt.Errorf("usage: clear security flow session [filters...]")
		}
		if c.dp == nil || !c.dp.IsLoaded() {
			fmt.Println("dataplane not loaded")
			return nil
		}
		f := c.parseSessionFilter(args[2:])
		if f.hasFilter() {
			return c.clearFilteredSessions(f)
		}
		v4, v6, err := c.dp.ClearAllSessions()
		if err != nil {
			return fmt.Errorf("clear sessions: %w", err)
		}
		fmt.Printf("%d IPv4 and %d IPv6 session entries cleared\n", v4, v6)
		return nil

	case "policies":
		if len(args) >= 2 && args[1] == "hit-count" {
			if c.dp == nil || !c.dp.IsLoaded() {
				fmt.Println("dataplane not loaded")
				return nil
			}
			if err := c.dp.ClearPolicyCounters(); err != nil {
				return fmt.Errorf("clear policy counters: %w", err)
			}
			fmt.Println("policy hit counters cleared")
			return nil
		}
		return fmt.Errorf("usage: clear security policies hit-count")

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
		fmt.Println("  flow session                         Clear all sessions")
		fmt.Println("  counters                             Clear all counters")
		fmt.Println("  policies hit-count                   Clear policy hit counters")
		fmt.Println("  nat source persistent-nat-table      Clear persistent NAT bindings")
		return nil
	}
}

// clearFilteredSessions deletes sessions matching the given filter.
func (c *CLI) clearFilteredSessions(f sessionFilter) error {
	v4Deleted := 0
	v6Deleted := 0

	// IPv4: collect matching forward keys and derive reverse keys
	var v4Keys []dataplane.SessionKey
	var v4RevKeys []dataplane.SessionKey
	var snatDNATKeys []dataplane.DNATKey
	_ = c.dp.IterateSessions(func(key dataplane.SessionKey, val dataplane.SessionValue) bool {
		if val.IsReverse != 0 {
			return true // skip reverse entries; they'll be cleaned via forward
		}
		if !f.matchesV4(key, val) {
			return true
		}
		v4Keys = append(v4Keys, key)
		// Reverse key for cleanup
		v4RevKeys = append(v4RevKeys, dataplane.SessionKey{
			Protocol: key.Protocol,
			SrcIP:    key.DstIP,
			DstIP:    key.SrcIP,
			SrcPort:  key.DstPort,
			DstPort:  key.SrcPort,
		})
		// Track SNAT DNAT entries for cleanup
		if val.Flags&dataplane.SessFlagSNAT != 0 &&
			val.Flags&dataplane.SessFlagStaticNAT == 0 {
			snatDNATKeys = append(snatDNATKeys, dataplane.DNATKey{
				Protocol: key.Protocol,
				DstIP:    val.NATSrcIP,
				DstPort:  val.NATSrcPort,
			})
		}
		return true
	})

	for _, key := range v4Keys {
		if err := c.dp.DeleteSession(key); err == nil {
			v4Deleted++
		}
	}
	for _, key := range v4RevKeys {
		c.dp.DeleteSession(key)
	}
	for _, dk := range snatDNATKeys {
		c.dp.DeleteDNATEntry(dk)
	}

	// IPv6: collect matching forward keys
	var v6Keys []dataplane.SessionKeyV6
	var v6RevKeys []dataplane.SessionKeyV6
	var snatDNATKeysV6 []dataplane.DNATKeyV6
	_ = c.dp.IterateSessionsV6(func(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
		if val.IsReverse != 0 {
			return true
		}
		if !f.matchesV6(key, val) {
			return true
		}
		v6Keys = append(v6Keys, key)
		v6RevKeys = append(v6RevKeys, dataplane.SessionKeyV6{
			Protocol: key.Protocol,
			SrcIP:    key.DstIP,
			DstIP:    key.SrcIP,
			SrcPort:  key.DstPort,
			DstPort:  key.SrcPort,
		})
		if val.Flags&dataplane.SessFlagSNAT != 0 &&
			val.Flags&dataplane.SessFlagStaticNAT == 0 {
			snatDNATKeysV6 = append(snatDNATKeysV6, dataplane.DNATKeyV6{
				Protocol: key.Protocol,
				DstIP:    val.NATSrcIP,
				DstPort:  val.NATSrcPort,
			})
		}
		return true
	})

	for _, key := range v6Keys {
		if err := c.dp.DeleteSessionV6(key); err == nil {
			v6Deleted++
		}
	}
	for _, key := range v6RevKeys {
		c.dp.DeleteSessionV6(key)
	}
	for _, dk := range snatDNATKeysV6 {
		c.dp.DeleteDNATEntryV6(dk)
	}

	fmt.Printf("%d IPv4 and %d IPv6 matching sessions cleared\n", v4Deleted, v6Deleted)
	return nil
}

func (c *CLI) handleClearFirewall(args []string) error {
	if len(args) < 1 || args[0] != "all" {
		fmt.Println("clear firewall:")
		fmt.Println("  all    Clear all firewall filter counters")
		return nil
	}
	if c.dp == nil || !c.dp.IsLoaded() {
		fmt.Println("Dataplane not loaded")
		return nil
	}
	if err := c.dp.ClearFilterCounters(); err != nil {
		return fmt.Errorf("clear filter counters: %w", err)
	}
	fmt.Println("Firewall filter counters cleared")
	return nil
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
		writeCompletionHelp(os.Stdout, treeHelpCandidates(operationalTree["show"].children["security"].children["nat"].children))
		return nil
	}

	switch args[0] {
	case "source":
		if len(args) >= 2 && args[1] == "persistent-nat-table" {
			return c.showPersistentNAT()
		}
		return c.showNATSource(cfg, args[1:])
	case "destination":
		return c.showNATDestination(cfg, args[1:])
	case "static":
		return c.showNATStatic(cfg)
	case "nat64":
		return c.showNAT64(cfg)
	default:
		return fmt.Errorf("unknown show security nat target: %s", args[0])
	}
}

func (c *CLI) showNATSource(cfg *config.Config, args []string) error {
	// Sub-command dispatch: summary, pool <name>, rule-set <name>, rule all
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
		case "rule":
			// "rule all" — show all rules across all rule-sets
			return c.showNATSourceRuleAll(cfg)
		case "rule-set":
			if len(args) > 1 {
				return c.showNATSourceRuleSet(cfg, args[1])
			}
			return fmt.Errorf("usage: show security nat source rule-set <name>")
		}
	}

	// Default: show all pools, rules, and summary
	if cfg != nil && cfg.Security.NAT.AddressPersistent {
		fmt.Println("Address-persistent: enabled")
		fmt.Println()
	}
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

// showNATSourceRuleAll displays all source NAT rules across all rule-sets with hit counters.
func (c *CLI) showNATSourceRuleAll(cfg *config.Config) error {
	if cfg == nil || len(cfg.Security.NAT.Source) == 0 {
		fmt.Println("No source NAT rules configured")
		return nil
	}

	totalRules := 0
	for _, rs := range cfg.Security.NAT.Source {
		for _, rule := range rs.Rules {
			totalRules++
			action := "interface"
			if rule.Then.PoolName != "" {
				action = "pool " + rule.Then.PoolName
			}
			srcMatch := "0.0.0.0/0"
			if rule.Match.SourceAddress != "" {
				srcMatch = rule.Match.SourceAddress
			}
			dstMatch := "0.0.0.0/0"
			if rule.Match.DestinationAddress != "" {
				dstMatch = rule.Match.DestinationAddress
			}

			fmt.Printf("Rule-set: %-20s Rule: %-12s %s -> %s  Action: %s\n",
				rs.Name, rule.Name, rs.FromZone, rs.ToZone, action)
			fmt.Printf("  Match: source %s destination %s\n", srcMatch, dstMatch)

			if c.dp != nil && c.dp.LastCompileResult() != nil {
				ruleKey := rs.Name + "/" + rule.Name
				if cid, ok := c.dp.LastCompileResult().NATCounterIDs[ruleKey]; ok {
					cnt, err := c.dp.ReadNATRuleCounter(uint32(cid))
					if err == nil {
						fmt.Printf("  Translation hits: %d packets  %d bytes\n",
							cnt.Packets, cnt.Bytes)
					}
				}
			}
		}
	}
	fmt.Printf("\nTotal source NAT rules: %d\n", totalRules)
	return nil
}

func (c *CLI) showNATDestination(cfg *config.Config, args []string) error {
	if cfg == nil || cfg.Security.NAT.Destination == nil {
		fmt.Println("No destination NAT rules configured.")
		return nil
	}

	// Sub-command dispatch: summary, pool <name>, rule-set <name>, rule all
	if len(args) > 0 {
		switch args[0] {
		case "summary":
			return c.showNATDestinationSummary(cfg)
		case "pool":
			poolName := ""
			if len(args) > 1 {
				poolName = args[1]
			}
			return c.showNATDestinationPool(cfg, poolName)
		case "rule":
			return c.showNATDestinationRuleAll(cfg)
		case "rule-set":
			if len(args) > 1 {
				return c.showNATDestinationRuleSet(cfg, args[1])
			}
			return fmt.Errorf("usage: show security nat destination rule-set <name>")
		}
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

// showNATDestinationSummary displays a summary of all destination NAT pools.
func (c *CLI) showNATDestinationSummary(cfg *config.Config) error {
	dnat := cfg.Security.NAT.Destination
	if dnat == nil || len(dnat.Pools) == 0 {
		fmt.Println("No destination NAT pools configured")
		return nil
	}

	// Count active DNAT sessions per pool
	poolSessions := make(map[string]int)
	if c.dp != nil && c.dp.IsLoaded() && c.dp.LastCompileResult() != nil {
		cr := c.dp.LastCompileResult()
		for _, rs := range dnat.RuleSets {
			for _, rule := range rs.Rules {
				if rule.Then.PoolName == "" {
					continue
				}
				ruleKey := rs.Name + "/" + rule.Name
				if cid, ok := cr.NATCounterIDs[ruleKey]; ok {
					cnt, err := c.dp.ReadNATRuleCounter(uint32(cid))
					if err == nil {
						poolSessions[rule.Then.PoolName] += int(cnt.Packets)
					}
				}
			}
		}
	}

	fmt.Printf("Total pools: %d\n", len(dnat.Pools))
	fmt.Printf("%-20s %-20s %-8s %-12s\n",
		"Pool", "Address", "Port", "Hits")
	for name, pool := range dnat.Pools {
		portStr := "-"
		if pool.Port != 0 {
			portStr = fmt.Sprintf("%d", pool.Port)
		}
		hits := poolSessions[name]
		fmt.Printf("%-20s %-20s %-8s %-12d\n",
			name, pool.Address, portStr, hits)
	}
	return nil
}

// showNATDestinationPool displays detailed information about a specific DNAT pool.
func (c *CLI) showNATDestinationPool(cfg *config.Config, poolName string) error {
	dnat := cfg.Security.NAT.Destination
	if dnat == nil || len(dnat.Pools) == 0 {
		fmt.Println("No destination NAT pools configured")
		return nil
	}

	showAll := poolName == "" || poolName == "all"

	for name, pool := range dnat.Pools {
		if !showAll && name != poolName {
			continue
		}
		fmt.Printf("Pool name: %s\n", name)
		fmt.Printf("  Address: %s\n", pool.Address)
		if pool.Port != 0 {
			fmt.Printf("  Port: %d\n", pool.Port)
		}

		// Show which rule-sets reference this pool
		for _, rs := range dnat.RuleSets {
			for _, rule := range rs.Rules {
				if rule.Then.PoolName == name {
					fmt.Printf("  Referenced by: %s/%s (from %s)\n",
						rs.Name, rule.Name, rs.FromZone)
				}
			}
		}

		// Show hit counters from all rules referencing this pool
		if c.dp != nil && c.dp.LastCompileResult() != nil {
			cr := c.dp.LastCompileResult()
			var totalPkts, totalBytes uint64
			for _, rs := range dnat.RuleSets {
				for _, rule := range rs.Rules {
					if rule.Then.PoolName != name {
						continue
					}
					ruleKey := rs.Name + "/" + rule.Name
					if cid, ok := cr.NATCounterIDs[ruleKey]; ok {
						cnt, err := c.dp.ReadNATRuleCounter(uint32(cid))
						if err == nil {
							totalPkts += cnt.Packets
							totalBytes += cnt.Bytes
						}
					}
				}
			}
			fmt.Printf("  Total hits: %d packets  %d bytes\n", totalPkts, totalBytes)
		}
		fmt.Println()
	}

	if !showAll {
		if _, ok := dnat.Pools[poolName]; !ok {
			fmt.Printf("Pool %q not found\n", poolName)
		}
	}
	return nil
}

// showNATDestinationRuleSet displays a specific destination NAT rule-set with hit counters.
func (c *CLI) showNATDestinationRuleSet(cfg *config.Config, rsName string) error {
	dnat := cfg.Security.NAT.Destination
	if dnat == nil {
		fmt.Println("No destination NAT configured")
		return nil
	}

	for _, rs := range dnat.RuleSets {
		if rs.Name != rsName {
			continue
		}
		fmt.Printf("Rule-set: %s\n", rs.Name)
		fmt.Printf("  From zone: %s  To zone: %s\n", rs.FromZone, rs.ToZone)
		for _, rule := range rs.Rules {
			fmt.Printf("  Rule: %s\n", rule.Name)
			dstMatch := "0.0.0.0/0"
			if rule.Match.DestinationAddress != "" {
				dstMatch = rule.Match.DestinationAddress
			}
			fmt.Printf("    Match destination-address: %s\n", dstMatch)
			if rule.Match.DestinationPort != 0 {
				fmt.Printf("    Match destination-port: %d\n", rule.Match.DestinationPort)
			}
			action := "off"
			if rule.Then.PoolName != "" {
				action = "pool " + rule.Then.PoolName
			}
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

// showNATDestinationRuleAll displays all destination NAT rules with hit counters.
func (c *CLI) showNATDestinationRuleAll(cfg *config.Config) error {
	dnat := cfg.Security.NAT.Destination
	if dnat == nil || len(dnat.RuleSets) == 0 {
		fmt.Println("No destination NAT rules configured")
		return nil
	}

	totalRules := 0
	for _, rs := range dnat.RuleSets {
		for _, rule := range rs.Rules {
			totalRules++
			dstMatch := "0.0.0.0/0"
			if rule.Match.DestinationAddress != "" {
				dstMatch = rule.Match.DestinationAddress
			}
			if rule.Match.DestinationPort != 0 {
				dstMatch += fmt.Sprintf(":%d", rule.Match.DestinationPort)
			}
			action := "off"
			if rule.Then.PoolName != "" {
				action = "pool " + rule.Then.PoolName
			}

			fmt.Printf("Rule-set: %-20s Rule: %-12s from %s  Action: %s\n",
				rs.Name, rule.Name, rs.FromZone, action)
			fmt.Printf("  Match: destination %s\n", dstMatch)

			if c.dp != nil && c.dp.LastCompileResult() != nil {
				ruleKey := rs.Name + "/" + rule.Name
				if cid, ok := c.dp.LastCompileResult().NATCounterIDs[ruleKey]; ok {
					cnt, err := c.dp.ReadNATRuleCounter(uint32(cid))
					if err == nil {
						fmt.Printf("  Translation hits: %d packets  %d bytes\n",
							cnt.Packets, cnt.Bytes)
					}
				}
			}
		}
	}
	fmt.Printf("\nTotal destination NAT rules: %d\n", totalRules)
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

func (c *CLI) showNAT64(cfg *config.Config) error {
	if cfg == nil || len(cfg.Security.NAT.NAT64) == 0 {
		fmt.Println("No NAT64 rule-sets configured.")
		return nil
	}

	for _, rs := range cfg.Security.NAT.NAT64 {
		fmt.Printf("NAT64 rule-set: %s\n", rs.Name)
		if rs.Prefix != "" {
			fmt.Printf("  Prefix:      %s\n", rs.Prefix)
		}
		if rs.SourcePool != "" {
			fmt.Printf("  Source pool:  %s\n", rs.SourcePool)
		}
		fmt.Println()
	}

	return nil
}

func (c *CLI) showAddressBook(args []string) error {
	cfg := c.store.ActiveConfig()
	if cfg == nil || cfg.Security.AddressBook == nil {
		fmt.Println("No address book configured")
		return nil
	}
	ab := cfg.Security.AddressBook

	// Optional filter by name
	filterName := ""
	if len(args) > 0 {
		filterName = args[0]
	}

	if len(ab.Addresses) > 0 {
		if filterName == "" {
			fmt.Println("Addresses:")
		}
		for _, addr := range ab.Addresses {
			if filterName != "" && addr.Name != filterName {
				continue
			}
			fmt.Printf("  %-24s %s\n", addr.Name, addr.Value)
		}
	}

	if len(ab.AddressSets) > 0 {
		if filterName == "" {
			fmt.Println("Address sets:")
		}
		for _, as := range ab.AddressSets {
			if filterName != "" && as.Name != filterName {
				continue
			}
			var parts []string
			for _, a := range as.Addresses {
				parts = append(parts, a)
			}
			for _, s := range as.AddressSets {
				parts = append(parts, "set:"+s)
			}
			fmt.Printf("  %-24s members: %s\n", as.Name, strings.Join(parts, ", "))
			// If filtering by name, show member details
			if filterName != "" {
				for _, a := range as.Addresses {
					for _, addr := range ab.Addresses {
						if addr.Name == a {
							fmt.Printf("    %-22s %s\n", addr.Name, addr.Value)
						}
					}
				}
			}
		}
	}

	if filterName == "" && len(ab.Addresses) == 0 && len(ab.AddressSets) == 0 {
		fmt.Println("Address book is empty")
	}

	return nil
}

func (c *CLI) showApplications(args []string) error {
	cfg := c.store.ActiveConfig()

	// Parse sub-commands: detail, <name>
	detail := false
	filterName := ""
	for _, a := range args {
		switch a {
		case "detail":
			detail = true
		default:
			filterName = a
		}
	}

	// Helper to print application detail
	printApp := func(app *config.Application, indent string) {
		if detail || filterName != "" {
			fmt.Printf("%sApplication: %s\n", indent, app.Name)
			if app.Description != "" {
				fmt.Printf("%s  Description: %s\n", indent, app.Description)
			}
			if app.Protocol != "" {
				fmt.Printf("%s  IP protocol: %s\n", indent, app.Protocol)
			}
			if app.DestinationPort != "" {
				fmt.Printf("%s  Destination port: %s\n", indent, app.DestinationPort)
			}
			if app.SourcePort != "" {
				fmt.Printf("%s  Source port: %s\n", indent, app.SourcePort)
			}
			if app.InactivityTimeout > 0 {
				fmt.Printf("%s  Inactivity timeout: %ds\n", indent, app.InactivityTimeout)
			}
			if app.ALG != "" {
				fmt.Printf("%s  ALG: %s\n", indent, app.ALG)
			}
		} else {
			port := app.DestinationPort
			if port == "" {
				port = "-"
			}
			fmt.Printf("%s%-24s protocol: %-6s port: %s\n", indent, app.Name, app.Protocol, port)
		}
	}

	// User-defined applications
	if cfg != nil && len(cfg.Applications.Applications) > 0 {
		if filterName == "" {
			fmt.Println("User-defined applications:")
		}
		names := make([]string, 0, len(cfg.Applications.Applications))
		for name := range cfg.Applications.Applications {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			app := cfg.Applications.Applications[name]
			if filterName != "" && app.Name != filterName {
				continue
			}
			printApp(app, "  ")
		}
		if filterName == "" {
			fmt.Println()
		}
	}

	// User-defined application-sets
	if cfg != nil && len(cfg.Applications.ApplicationSets) > 0 {
		names := make([]string, 0, len(cfg.Applications.ApplicationSets))
		for name := range cfg.Applications.ApplicationSets {
			names = append(names, name)
		}
		sort.Strings(names)

		if filterName == "" {
			fmt.Println("Application sets:")
		}
		for _, name := range names {
			as := cfg.Applications.ApplicationSets[name]
			if filterName != "" && as.Name != filterName {
				continue
			}
			if detail || filterName != "" {
				fmt.Printf("  Application set: %s\n", as.Name)
				fmt.Printf("    Members:\n")
				for _, member := range as.Applications {
					fmt.Printf("      %s\n", member)
					// Show member details if filtering by set name
					if filterName != "" {
						if cfg != nil {
							if app, ok := cfg.Applications.Applications[member]; ok {
								printApp(app, "        ")
							}
						}
					}
				}
			} else {
				fmt.Printf("  %-24s members: %s\n", as.Name, strings.Join(as.Applications, ", "))
			}
		}
		if filterName == "" {
			fmt.Println()
		}
	}

	// Show matching predefined application if filtering by name
	if filterName != "" {
		for _, app := range config.PredefinedApplications {
			if app.Name == filterName {
				fmt.Println("Predefined application:")
				printApp(app, "  ")
				return nil
			}
		}
		return nil
	}

	// Predefined applications (only in list mode)
	fmt.Println("Predefined applications:")
	for _, app := range config.PredefinedApplications {
		printApp(app, "  ")
	}

	return nil
}

func (c *CLI) handleShowRoute(args []string) error {
	if len(args) >= 2 && args[0] == "instance" {
		return c.showRoutesForInstance(args[1])
	}
	if len(args) >= 2 && args[0] == "table" {
		return c.showRoutesForVRF(args[1])
	}
	if len(args) >= 2 && args[0] == "protocol" {
		return c.showRoutesForProtocol(args[1])
	}
	if len(args) >= 1 && args[0] == "summary" {
		return c.showRouteSummary()
	}
	// Treat a single arg as prefix filter (e.g. "show route 10.0.1.0/24")
	if len(args) == 1 && (strings.Contains(args[0], "/") || strings.Contains(args[0], ".") || strings.Contains(args[0], ":")) {
		return c.showRoutesForPrefix(args[0])
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

func (c *CLI) showRoutesForVRF(vrfName string) error {
	if c.routing == nil {
		fmt.Println("Routing manager not available")
		return nil
	}

	entries, err := c.routing.GetVRFRoutes(vrfName)
	if err != nil {
		return fmt.Errorf("get VRF routes: %w", err)
	}

	if len(entries) == 0 {
		fmt.Printf("No routes in table %s\n", vrfName)
		return nil
	}

	fmt.Printf("Routing table: %s\n", vrfName)
	fmt.Printf("  %-24s %-20s %-14s %-12s %s\n",
		"Destination", "Next-hop", "Interface", "Proto", "Pref")
	for _, e := range entries {
		fmt.Printf("  %-24s %-20s %-14s %-12s %d\n",
			e.Destination, e.NextHop, e.Interface, e.Protocol, e.Preference)
	}
	return nil
}

func (c *CLI) showRoutesForProtocol(proto string) error {
	if c.routing == nil {
		fmt.Println("Routing manager not available")
		return nil
	}

	entries, err := c.routing.GetRoutes()
	if err != nil {
		return fmt.Errorf("get routes: %w", err)
	}

	proto = strings.ToLower(proto)
	fmt.Printf("Routes matching protocol: %s\n", proto)
	fmt.Printf("  %-24s %-20s %-14s %-12s %s\n",
		"Destination", "Next-hop", "Interface", "Proto", "Pref")
	count := 0
	for _, e := range entries {
		if strings.ToLower(e.Protocol) == proto {
			fmt.Printf("  %-24s %-20s %-14s %-12s %d\n",
				e.Destination, e.NextHop, e.Interface, e.Protocol, e.Preference)
			count++
		}
	}
	if count == 0 {
		fmt.Printf("  (no routes)\n")
	}
	return nil
}

func (c *CLI) showRoutesForPrefix(prefix string) error {
	if c.routing == nil {
		fmt.Println("Routing manager not available")
		return nil
	}

	entries, err := c.routing.GetRoutes()
	if err != nil {
		return fmt.Errorf("get routes: %w", err)
	}

	// Parse the filter as a CIDR prefix for subnet matching.
	// If no mask given, auto-add /32 or /128.
	filterPrefix := prefix
	if !strings.Contains(filterPrefix, "/") {
		if strings.Contains(filterPrefix, ":") {
			filterPrefix += "/128"
		} else {
			filterPrefix += "/32"
		}
	}

	fmt.Printf("Routes matching %s:\n", prefix)
	fmt.Printf("  %-24s %-20s %-14s %-12s %s\n",
		"Destination", "Next-hop", "Interface", "Proto", "Pref")
	count := 0
	for _, e := range entries {
		if routePrefixMatches(e.Destination, filterPrefix) {
			fmt.Printf("  %-24s %-20s %-14s %-12s %d\n",
				e.Destination, e.NextHop, e.Interface, e.Protocol, e.Preference)
			count++
		}
	}
	if count == 0 {
		fmt.Printf("  (no matching routes)\n")
	}
	return nil
}

// routePrefixMatches returns true if the route destination is within or equal to the filter prefix.
func routePrefixMatches(routeDst, filterCIDR string) bool {
	_, filterNet, err := net.ParseCIDR(filterCIDR)
	if err != nil {
		// Fallback to exact match
		return routeDst == filterCIDR
	}
	_, routeNet, err := net.ParseCIDR(routeDst)
	if err != nil {
		return false
	}
	// Route matches if the filter contains the route network, or the route contains the filter
	filterOnes, _ := filterNet.Mask.Size()
	routeOnes, _ := routeNet.Mask.Size()
	if filterOnes <= routeOnes {
		// Filter is broader or equal: route must be within filter
		return filterNet.Contains(routeNet.IP)
	}
	// Filter is more specific: check if route contains the filter address
	return routeNet.Contains(filterNet.IP)
}

func (c *CLI) showRouteSummary() error {
	if c.routing == nil {
		fmt.Println("Routing manager not available")
		return nil
	}

	entries, err := c.routing.GetRoutes()
	if err != nil {
		return fmt.Errorf("get routes: %w", err)
	}

	// Count by protocol and address family
	byProto := make(map[string]int)
	var v4Count, v6Count int
	for _, e := range entries {
		byProto[e.Protocol]++
		if strings.Contains(e.Destination, ":") {
			v6Count++
		} else {
			v4Count++
		}
	}

	fmt.Printf("Router ID: (not set)\n\n")
	fmt.Printf("inet.0: %d destinations\n", v4Count)
	fmt.Printf("inet6.0: %d destinations\n\n", v6Count)

	fmt.Printf("Route summary by protocol:\n")
	fmt.Printf("  %-14s %s\n", "Protocol", "Routes")
	// Sort protocols for deterministic output
	protos := make([]string, 0, len(byProto))
	for p := range byProto {
		protos = append(protos, p)
	}
	sort.Strings(protos)
	for _, p := range protos {
		fmt.Printf("  %-14s %d\n", p, byProto[p])
	}
	fmt.Printf("  %-14s %d\n", "Total", len(entries))
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

func (c *CLI) showIKE(args []string) error {
	cfg := c.store.ActiveConfig()
	if cfg == nil {
		fmt.Println("no active configuration")
		return nil
	}

	if len(args) > 0 && args[0] == "security-associations" {
		// Show IKE SA status from strongSwan
		if c.ipsec != nil {
			sas, err := c.ipsec.GetSAStatus()
			if err != nil {
				return fmt.Errorf("IKE SA status: %w", err)
			}
			if len(sas) == 0 {
				fmt.Println("No IKE security associations")
				return nil
			}
			for _, sa := range sas {
				fmt.Printf("IKE SA: %s  State: %s\n", sa.Name, sa.State)
				if sa.LocalAddr != "" {
					fmt.Printf("  Local:  %s\n", sa.LocalAddr)
				}
				if sa.RemoteAddr != "" {
					fmt.Printf("  Remote: %s\n", sa.RemoteAddr)
				}
				fmt.Println()
			}
			return nil
		}
		fmt.Println("IPsec manager not available")
		return nil
	}

	// Show configured IKE gateways
	gateways := cfg.Security.IPsec.Gateways
	if len(gateways) == 0 {
		fmt.Println("No IKE gateways configured")
		return nil
	}

	names := make([]string, 0, len(gateways))
	for name := range gateways {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		gw := gateways[name]
		fmt.Printf("IKE gateway: %s\n", name)
		if gw.Address != "" {
			fmt.Printf("  Remote address:     %s\n", gw.Address)
		}
		if gw.DynamicHostname != "" {
			fmt.Printf("  Dynamic hostname:   %s\n", gw.DynamicHostname)
		}
		if gw.LocalAddress != "" {
			fmt.Printf("  Local address:      %s\n", gw.LocalAddress)
		}
		if gw.ExternalIface != "" {
			fmt.Printf("  External interface: %s\n", gw.ExternalIface)
		}
		if gw.IKEPolicy != "" {
			fmt.Printf("  IKE policy:         %s\n", gw.IKEPolicy)
			if pol, ok := cfg.Security.IPsec.IKEPolicies[gw.IKEPolicy]; ok {
				fmt.Printf("    Mode:     %s\n", pol.Mode)
				fmt.Printf("    Proposal: %s\n", pol.Proposals)
			}
		}
		ver := gw.Version
		if ver == "" {
			ver = "v1+v2"
		}
		fmt.Printf("  IKE version:        %s\n", ver)
		if gw.DeadPeerDetect != "" {
			fmt.Printf("  DPD:                %s\n", gw.DeadPeerDetect)
		}
		if gw.NoNATTraversal {
			fmt.Printf("  NAT-T:              disabled\n")
		}
		if gw.LocalIDValue != "" {
			fmt.Printf("  Local identity:     %s %s\n", gw.LocalIDType, gw.LocalIDValue)
		}
		if gw.RemoteIDValue != "" {
			fmt.Printf("  Remote identity:    %s %s\n", gw.RemoteIDType, gw.RemoteIDValue)
		}
		fmt.Println()
	}

	// Show IKE proposals
	proposals := cfg.Security.IPsec.IKEProposals
	if len(proposals) > 0 {
		pNames := make([]string, 0, len(proposals))
		for name := range proposals {
			pNames = append(pNames, name)
		}
		sort.Strings(pNames)
		fmt.Println("IKE proposals:")
		for _, name := range pNames {
			p := proposals[name]
			fmt.Printf("  %s: auth=%s enc=%s dh=group%d", name, p.AuthMethod, p.EncryptionAlg, p.DHGroup)
			if p.LifetimeSeconds > 0 {
				fmt.Printf(" lifetime=%ds", p.LifetimeSeconds)
			}
			fmt.Println()
		}
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

	// Build reverse zone ID → name map for event display
	evZoneNames := make(map[uint16]string)
	if c.dp != nil {
		if cr := c.dp.LastCompileResult(); cr != nil {
			for name, id := range cr.ZoneIDs {
				evZoneNames[id] = name
			}
		}
	}
	zoneName := func(id uint16) string {
		if n, ok := evZoneNames[id]; ok {
			return n
		}
		return fmt.Sprintf("%d", id)
	}

	for _, e := range events {
		ts := e.Time.Format("15:04:05")
		if e.Type == "SCREEN_DROP" {
			fmt.Printf("%s %-14s screen=%-16s %s -> %s %s action=%s zone=%s\n",
				ts, e.Type, e.ScreenCheck, e.SrcAddr, e.DstAddr, e.Protocol, e.Action, zoneName(e.InZone))
		} else if e.Type == "SESSION_CLOSE" {
			fmt.Printf("%s %-14s %s -> %s %s action=%-6s policy=%d zone=%s->%s pkts=%d bytes=%d\n",
				ts, e.Type, e.SrcAddr, e.DstAddr, e.Protocol, e.Action,
				e.PolicyID, zoneName(e.InZone), zoneName(e.OutZone), e.SessionPkts, e.SessionBytes)
		} else {
			fmt.Printf("%s %-14s %s -> %s %s action=%-6s policy=%d zone=%s->%s\n",
				ts, e.Type, e.SrcAddr, e.DstAddr, e.Protocol, e.Action,
				e.PolicyID, zoneName(e.InZone), zoneName(e.OutZone))
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
	// Handle "show interfaces extensive" sub-command
	if len(args) > 0 && args[0] == "extensive" {
		return c.showInterfacesExtensive()
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
		if ifCfg, ok := cfg.Interfaces.Interfaces[physName]; ok && ifCfg.Description != "" {
			fmt.Printf("  Description: %s\n", ifCfg.Description)
		}

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
			// Check config-level disable flag
			if ifCfg, ok := cfg.Interfaces.Interfaces[u.physName]; ok && ifCfg.Disable {
				admin = "down"
			}
			link := "up"
			iface, err := net.InterfaceByName(u.physName)
			if err != nil {
				link = "down"
			} else {
				if iface.Flags&net.FlagUp == 0 {
					if admin == "up" {
						admin = "down" // kernel says down
					}
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

// showInterfacesExtensive shows detailed per-interface statistics including
// all error counters, queue depths, and ethtool-style information.
func (c *CLI) showInterfacesExtensive() error {
	links, err := netlink.LinkList()
	if err != nil {
		return fmt.Errorf("listing interfaces: %w", err)
	}

	sort.Slice(links, func(i, j int) bool {
		return links[i].Attrs().Name < links[j].Attrs().Name
	})

	// Build zone lookup from active config
	ifZoneMap := make(map[string]string)
	ifDescMap := make(map[string]string)
	if activeCfg := c.store.ActiveConfig(); activeCfg != nil {
		for _, z := range activeCfg.Security.Zones {
			for _, ifName := range z.Interfaces {
				ifZoneMap[ifName] = z.Name
			}
		}
		for _, ifc := range activeCfg.Interfaces.Interfaces {
			if ifc.Description != "" {
				ifDescMap[ifc.Name] = ifc.Description
			}
		}
	}

	for _, link := range links {
		attrs := link.Attrs()
		if attrs.Name == "lo" {
			continue
		}

		// State
		adminUp := attrs.Flags&net.FlagUp != 0
		operUp := attrs.OperState == netlink.OperUp
		adminStr := "Disabled"
		if adminUp {
			adminStr = "Enabled"
		}
		linkStr := "Down"
		if operUp {
			linkStr = "Up"
		}
		fmt.Printf("Physical interface: %s, %s, Physical link is %s\n", attrs.Name, adminStr, linkStr)
		if desc, ok := ifDescMap[attrs.Name]; ok {
			fmt.Printf("  Description: %s\n", desc)
		}
		if zone, ok := ifZoneMap[attrs.Name]; ok {
			fmt.Printf("  Security zone: %s\n", zone)
		}

		// Type + speed + MTU
		linkType := "Ethernet"
		if attrs.EncapType != "" {
			linkType = attrs.EncapType
		}
		speedStr := ""
		if speed := readLinkSpeed(attrs.Name); speed > 0 {
			speedStr = fmt.Sprintf(", Speed: %s", formatSpeed(speed))
		}
		fmt.Printf("  Link-level type: %s, MTU: %d%s, Link-mode: Full-duplex\n",
			linkType, attrs.MTU, speedStr)

		// MAC
		if len(attrs.HardwareAddr) > 0 {
			fmt.Printf("  Current address: %s, Hardware address: %s\n",
				attrs.HardwareAddr, attrs.HardwareAddr)
		}

		// Device flags
		var flags []string
		flags = append(flags, "Present")
		if operUp {
			flags = append(flags, "Running")
		}
		if !adminUp {
			flags = append(flags, "Down")
		}
		fmt.Printf("  Device flags   : %s\n", strings.Join(flags, " "))
		fmt.Printf("  Interface index: %d, SNMP ifIndex: %d\n", attrs.Index, attrs.Index)

		if attrs.TxQLen > 0 {
			fmt.Printf("  Link type      : %s, TxQueueLen: %d\n", attrs.EncapType, attrs.TxQLen)
		}

		// Detailed statistics
		if s := attrs.Statistics; s != nil {
			fmt.Println("  Traffic statistics:")
			fmt.Printf("    Input:  %d bytes, %d packets\n", s.RxBytes, s.RxPackets)
			fmt.Printf("    Output: %d bytes, %d packets\n", s.TxBytes, s.TxPackets)
			fmt.Println("  Input errors:")
			fmt.Printf("    Errors: %d, Drops: %d, Overruns: %d, Frame: %d\n",
				s.RxErrors, s.RxDropped, s.RxOverErrors, s.RxFrameErrors)
			fmt.Printf("    FIFO errors: %d, Missed: %d, Compressed: %d\n",
				s.RxFifoErrors, s.RxMissedErrors, s.RxCompressed)
			fmt.Println("  Output errors:")
			fmt.Printf("    Errors: %d, Drops: %d, Carrier: %d, Collisions: %d\n",
				s.TxErrors, s.TxDropped, s.TxCarrierErrors, s.Collisions)
			fmt.Printf("    FIFO errors: %d, Heartbeat: %d, Compressed: %d\n",
				s.TxFifoErrors, s.TxHeartbeatErrors, s.TxCompressed)
			if s.Multicast > 0 {
				fmt.Printf("    Multicast: %d\n", s.Multicast)
			}
		}

		// Addresses
		addrs, _ := netlink.AddrList(link, netlink.FAMILY_ALL)
		if len(addrs) > 0 {
			var v4, v6 []string
			for _, a := range addrs {
				if a.IP.To4() != nil {
					v4 = append(v4, a.IPNet.String())
				} else {
					v6 = append(v6, a.IPNet.String())
				}
			}
			if len(v4) > 0 {
				fmt.Printf("  Protocol inet, MTU: %d\n", attrs.MTU)
				for _, a := range v4 {
					fmt.Printf("    Local: %s\n", a)
				}
			}
			if len(v6) > 0 {
				fmt.Printf("  Protocol inet6, MTU: %d\n", attrs.MTU)
				for _, a := range v6 {
					flags := "Is-Preferred Is-Primary"
					if strings.HasPrefix(a, "fe80:") {
						flags = "Is-Preferred"
					}
					fmt.Printf("    Local: %s, Flags: %s\n", a, flags)
				}
			}
		}
		fmt.Println()
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
	sysTree := operationalTree["show"].children["system"].children
	if len(args) == 0 {
		fmt.Println("show system:")
		writeCompletionHelp(os.Stdout, treeHelpCandidates(sysTree))
		return nil
	}

	switch args[0] {
	case "rollback":
		if len(args) >= 2 {
			// "show system rollback compare N" — diff rollback N against active
			if args[1] == "compare" {
				if len(args) < 3 {
					return fmt.Errorf("usage: show system rollback compare <N>")
				}
				n, err := strconv.Atoi(args[2])
				if err != nil || n < 1 {
					return fmt.Errorf("usage: show system rollback compare <N>")
				}
				diff, err := c.store.ShowCompareRollback(n)
				if err != nil {
					return err
				}
				if diff == "" {
					fmt.Println("No differences found")
				} else {
					fmt.Print(diff)
				}
				return nil
			}

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
			} else if strings.Contains(rest, "compare") {
				diff, err := c.store.ShowCompareRollback(n)
				if err != nil {
					return err
				}
				if diff == "" {
					fmt.Println("No differences found")
				} else {
					fmt.Print(diff)
				}
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

	case "uptime":
		return c.showSystemUptime()

	case "memory":
		return c.showSystemMemory()

	case "processes":
		return c.showSystemProcesses()

	case "storage":
		return c.showSystemStorage()

	case "alarms":
		cfg := c.store.ActiveConfig()
		if cfg != nil {
			warnings := config.ValidateConfig(cfg)
			if len(warnings) == 0 {
				fmt.Println("No alarms currently active")
			} else {
				fmt.Printf("%d active alarm(s):\n", len(warnings))
				for _, w := range warnings {
					fmt.Printf("  WARNING: %s\n", w)
				}
			}
		} else {
			fmt.Println("No active configuration loaded")
		}
		return nil

	case "users":
		return c.showSystemUsers()

	case "connections":
		return c.showSystemConnections()

	case "license":
		fmt.Println("License: open-source (no license required)")
		return nil

	case "backup-router":
		return c.showBackupRouter()

	case "ntp":
		return c.showSystemNTP()

	case "services":
		return c.showSystemServices()

	case "syslog":
		return c.showSystemSyslog()

	case "buffers":
		return c.showSystemBuffers()

	default:
		return fmt.Errorf("unknown show system target: %s", args[0])
	}
}

func (c *CLI) showSystemBuffers() error {
	if c.dp == nil {
		fmt.Println("Dataplane not loaded")
		return nil
	}
	stats := c.dp.GetMapStats()
	if len(stats) == 0 {
		fmt.Println("No BPF maps available")
		return nil
	}
	fmt.Printf("%-24s %-12s %10s %10s %8s\n", "Map", "Type", "Max", "Used", "Usage%")
	fmt.Println(strings.Repeat("-", 68))
	for _, s := range stats {
		usage := ""
		if s.MaxEntries > 0 && s.Type != "Array" {
			pct := float64(s.UsedCount) / float64(s.MaxEntries) * 100
			usage = fmt.Sprintf("%.1f%%", pct)
		} else {
			usage = "-"
		}
		used := fmt.Sprintf("%d", s.UsedCount)
		if s.Type == "Array" {
			used = "-"
		}
		fmt.Printf("%-24s %-12s %10d %10s %8s\n", s.Name, s.Type, s.MaxEntries, used, usage)
	}
	return nil
}

func (c *CLI) showBackupRouter() error {
	cfg := c.store.ActiveConfig()
	if cfg == nil {
		fmt.Println("No active configuration")
		return nil
	}
	if cfg.System.BackupRouter == "" {
		fmt.Println("No backup router configured")
		return nil
	}
	fmt.Printf("Backup router: %s\n", cfg.System.BackupRouter)
	if cfg.System.BackupRouterDst != "" {
		fmt.Printf("  Destination: %s\n", cfg.System.BackupRouterDst)
	} else {
		fmt.Println("  Destination: 0.0.0.0/0 (default)")
	}
	return nil
}

func (c *CLI) showSystemNTP() error {
	cfg := c.store.ActiveConfig()
	if cfg == nil {
		fmt.Println("No active configuration")
		return nil
	}

	if len(cfg.System.NTPServers) == 0 {
		fmt.Println("No NTP servers configured")
		return nil
	}

	fmt.Println("NTP servers:")
	for _, server := range cfg.System.NTPServers {
		fmt.Printf("  %s\n", server)
	}

	// Try to get chrony/ntpd status via chronyc or ntpq
	if out, err := exec.Command("chronyc", "-n", "sources").CombinedOutput(); err == nil {
		fmt.Printf("\nChrony sources:\n%s\n", string(out))
	} else if out, err := exec.Command("ntpq", "-p").CombinedOutput(); err == nil {
		fmt.Printf("\nNTP peers:\n%s\n", string(out))
	} else if out, err := exec.Command("timedatectl", "show", "--property=NTPSynchronized", "--value").CombinedOutput(); err == nil {
		synced := strings.TrimSpace(string(out))
		fmt.Printf("\nNTP synchronized: %s\n", synced)
	}

	return nil
}

// showSystemServices displays configured system services.
func (c *CLI) showSystemServices() error {
	cfg := c.store.ActiveConfig()
	if cfg == nil {
		fmt.Println("No active configuration")
		return nil
	}

	fmt.Println("System services:")

	// gRPC
	fmt.Println("  gRPC:           127.0.0.1:50051 (always on)")
	// HTTP REST
	fmt.Println("  HTTP REST:      127.0.0.1:8080 (always on)")

	// SSH
	if cfg.System.Services != nil && cfg.System.Services.SSH != nil {
		if cfg.System.Services.SSH.RootLogin == "allow" {
			fmt.Println("  SSH root login: enabled")
		}
	}

	// SNMP
	if cfg.System.SNMP != nil {
		fmt.Println("  SNMP:           enabled")
		if cfg.System.SNMP.Description != "" {
			fmt.Printf("    Description:  %s\n", cfg.System.SNMP.Description)
		}
		if cfg.System.SNMP.Location != "" {
			fmt.Printf("    Location:     %s\n", cfg.System.SNMP.Location)
		}
		for name, comm := range cfg.System.SNMP.Communities {
			fmt.Printf("    Community:    %s (%s)\n", name, comm.Authorization)
		}
	}

	// DHCP server
	if cfg.System.DHCPServer.DHCPLocalServer != nil && len(cfg.System.DHCPServer.DHCPLocalServer.Groups) > 0 {
		fmt.Printf("  DHCP server:    %d group(s)\n", len(cfg.System.DHCPServer.DHCPLocalServer.Groups))
	}
	if cfg.System.DHCPServer.DHCPv6LocalServer != nil && len(cfg.System.DHCPServer.DHCPv6LocalServer.Groups) > 0 {
		fmt.Printf("  DHCPv6 server:  %d group(s)\n", len(cfg.System.DHCPServer.DHCPv6LocalServer.Groups))
	}

	// DNS
	if len(cfg.System.NameServers) > 0 {
		fmt.Printf("  DNS servers:    %s\n", strings.Join(cfg.System.NameServers, ", "))
	}

	// NTP
	if len(cfg.System.NTPServers) > 0 {
		fmt.Printf("  NTP servers:    %s\n", strings.Join(cfg.System.NTPServers, ", "))
	}

	// Syslog
	if len(cfg.Security.Log.Streams) > 0 {
		fmt.Printf("  Syslog:         %d stream(s)\n", len(cfg.Security.Log.Streams))
		for _, stream := range cfg.Security.Log.Streams {
			sev := "all"
			if stream.Severity != "" {
				sev = stream.Severity + "+"
			}
			cat := "all"
			if stream.Category != "" && stream.Category != "all" {
				cat = stream.Category
			}
			fmt.Printf("    %-16s %s:%d (severity=%s, category=%s)\n", stream.Name, stream.Host, stream.Port, sev, cat)
		}
	}

	// Flow monitoring / NetFlow
	if cfg.Services.FlowMonitoring != nil && cfg.Services.FlowMonitoring.Version9 != nil {
		fmt.Printf("  NetFlow v9:     %d template(s)\n", len(cfg.Services.FlowMonitoring.Version9.Templates))
	}
	if cfg.Services.FlowMonitoring != nil && cfg.Services.FlowMonitoring.VersionIPFIX != nil {
		fmt.Printf("  IPFIX:          %d template(s)\n", len(cfg.Services.FlowMonitoring.VersionIPFIX.Templates))
	}

	// Application identification
	if cfg.Services.ApplicationIdentification {
		fmt.Println("  AppID:          enabled")
	}

	// RPM probes
	if cfg.Services.RPM != nil && len(cfg.Services.RPM.Probes) > 0 {
		total := 0
		for _, probe := range cfg.Services.RPM.Probes {
			total += len(probe.Tests)
		}
		fmt.Printf("  RPM probes:     %d probe(s), %d test(s)\n", len(cfg.Services.RPM.Probes), total)
	}

	return nil
}

// showSystemSyslog displays system syslog configuration.
func (c *CLI) showSystemSyslog() error {
	cfg := c.store.ActiveConfig()
	if cfg == nil {
		fmt.Println("No active configuration")
		return nil
	}

	if cfg.System.Syslog == nil {
		fmt.Println("No system syslog configuration")
		return nil
	}

	sys := cfg.System.Syslog

	if len(sys.Hosts) > 0 {
		fmt.Println("Syslog hosts:")
		for _, h := range sys.Hosts {
			fmt.Printf("  %-20s", h.Address)
			if h.AllowDuplicates {
				fmt.Print(" allow-duplicates")
			}
			fmt.Println()
			for _, f := range h.Facilities {
				fmt.Printf("    %-20s %s\n", f.Facility, f.Severity)
			}
		}
	}

	if len(sys.Files) > 0 {
		fmt.Println("Syslog files:")
		for _, f := range sys.Files {
			fmt.Printf("  %-20s %s %s\n", f.Name, f.Facility, f.Severity)
		}
	}

	if len(sys.Users) > 0 {
		fmt.Println("Syslog users:")
		for _, u := range sys.Users {
			fmt.Printf("  %-20s %s %s\n", u.User, u.Facility, u.Severity)
		}
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

func monotonicSeconds() uint64 {
	var ts unix.Timespec
	_ = unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	return uint64(ts.Sec)
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
	fmt.Println("  show configuration | display json  Show as JSON")
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
	fmt.Println("  show | display json          Show as JSON")
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

	if len(cfg.Firewall.FiltersInet) == 0 && len(cfg.Firewall.FiltersInet6) == 0 {
		fmt.Println("No firewall filters configured")
		return nil
	}

	// Look up filter IDs from compile result for counter display
	var filterIDs map[string]uint32
	if c.dp != nil && c.dp.IsLoaded() {
		if cr := c.dp.LastCompileResult(); cr != nil {
			filterIDs = cr.FilterIDs
		}
	}

	showFilters := func(family string, filters map[string]*config.FirewallFilter, names []string) {
		for _, name := range names {
			f := filters[name]
			fmt.Printf("Filter: %s (family %s)\n", name, family)

			// Get filter config for counter lookup
			var ruleStart uint32
			var hasCounters bool
			if filterIDs != nil {
				if fid, ok := filterIDs[family+":"+name]; ok {
					if fcfg, err := c.dp.ReadFilterConfig(fid); err == nil {
						ruleStart = fcfg.RuleStart
						hasCounters = true
					}
				}
			}

			ruleOffset := ruleStart
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
				for _, port := range term.SourcePorts {
					fmt.Printf("    from source-port %s\n", port)
				}
				for _, ref := range term.SourcePrefixLists {
					mod := ""
					if ref.Except {
						mod = " except"
					}
					fmt.Printf("    from source-prefix-list %s%s\n", ref.Name, mod)
				}
				for _, ref := range term.DestPrefixLists {
					mod := ""
					if ref.Except {
						mod = " except"
					}
					fmt.Printf("    from destination-prefix-list %s%s\n", ref.Name, mod)
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
				if term.ForwardingClass != "" {
					fmt.Printf("    then forwarding-class %s\n", term.ForwardingClass)
				}
				if term.LossPriority != "" {
					fmt.Printf("    then loss-priority %s\n", term.LossPriority)
				}
				if term.DSCPRewrite != "" {
					fmt.Printf("    then dscp %s\n", term.DSCPRewrite)
				}
				if term.Log {
					fmt.Printf("    then log\n")
				}
				if term.Count != "" {
					fmt.Printf("    then count %s\n", term.Count)
				}
				fmt.Printf("    then %s\n", action)

				// Sum counters across all expanded BPF rules for this term.
				// Must match the cross-product in expandFilterTerm:
				// nSrc * nDst * nDstPorts * nSrcPorts
				if hasCounters {
					nSrc := len(term.SourceAddresses)
					for _, ref := range term.SourcePrefixLists {
						if !ref.Except {
							if pl, ok := cfg.PolicyOptions.PrefixLists[ref.Name]; ok {
								nSrc += len(pl.Prefixes)
							}
						}
					}
					if nSrc == 0 {
						nSrc = 1
					}
					nDst := len(term.DestAddresses)
					for _, ref := range term.DestPrefixLists {
						if !ref.Except {
							if pl, ok := cfg.PolicyOptions.PrefixLists[ref.Name]; ok {
								nDst += len(pl.Prefixes)
							}
						}
					}
					if nDst == 0 {
						nDst = 1
					}
					nDstPorts := len(term.DestinationPorts)
					if nDstPorts == 0 {
						nDstPorts = 1
					}
					nSrcPorts := len(term.SourcePorts)
					if nSrcPorts == 0 {
						nSrcPorts = 1
					}
					numRules := uint32(nSrc * nDst * nDstPorts * nSrcPorts)
					var totalPkts, totalBytes uint64
					for i := uint32(0); i < numRules; i++ {
						if ctrs, err := c.dp.ReadFilterCounters(ruleOffset + i); err == nil {
							totalPkts += ctrs.Packets
							totalBytes += ctrs.Bytes
						}
					}
					fmt.Printf("    Hit count: %d packets, %d bytes\n", totalPkts, totalBytes)
					ruleOffset += numRules
				}
			}
			fmt.Println()
		}
	}

	// Sort filter names for deterministic output (matches compiler order)
	inetNames := make([]string, 0, len(cfg.Firewall.FiltersInet))
	for name := range cfg.Firewall.FiltersInet {
		inetNames = append(inetNames, name)
	}
	sort.Strings(inetNames)

	inet6Names := make([]string, 0, len(cfg.Firewall.FiltersInet6))
	for name := range cfg.Firewall.FiltersInet6 {
		inet6Names = append(inet6Names, name)
	}
	sort.Strings(inet6Names)

	showFilters("inet", cfg.Firewall.FiltersInet, inetNames)
	showFilters("inet6", cfg.Firewall.FiltersInet6, inet6Names)
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

	if cfg.Services.FlowMonitoring != nil && cfg.Services.FlowMonitoring.VersionIPFIX != nil {
		ipfix := cfg.Services.FlowMonitoring.VersionIPFIX
		if len(ipfix.Templates) > 0 {
			hasConfig = true
			fmt.Println("Flow Monitoring IPFIX Templates:")
			for name, tmpl := range ipfix.Templates {
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
				if len(tmpl.ExportExtensions) > 0 {
					fmt.Printf("    Export extensions:     %s\n", strings.Join(tmpl.ExportExtensions, ", "))
				}
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

// showDaemonLog displays recent daemon log entries from journald,
// or if a filename argument is given, reads from /var/log/<filename>.
func (c *CLI) showDaemonLog(args []string) error {
	// If first arg is not a number, treat it as a syslog file name
	if len(args) > 0 {
		if _, err := strconv.Atoi(args[0]); err != nil {
			// Argument is a filename like "messages"
			filename := args[0]
			n := 50
			if len(args) > 1 {
				if v, err := strconv.Atoi(args[1]); err == nil && v > 0 {
					n = v
				}
			}
			logPath := filepath.Join("/var/log", filepath.Base(filename))
			out, err := exec.Command("tail", "-n", strconv.Itoa(n), logPath).CombinedOutput()
			if err != nil {
				return fmt.Errorf("read %s: %w", logPath, err)
			}
			fmt.Print(string(out))
			return nil
		}
	}

	n := 50
	if len(args) > 0 {
		if v, err := strconv.Atoi(args[0]); err == nil && v > 0 {
			n = v
		}
	}

	out, err := exec.Command("journalctl", "-u", "bpfrxd", "-n", strconv.Itoa(n), "--no-pager").CombinedOutput()
	if err != nil {
		return fmt.Errorf("journalctl: %w", err)
	}
	fmt.Print(string(out))
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
	// Show live results if RPM manager is available
	if c.rpmResultsFn != nil {
		results := c.rpmResultsFn()
		if len(results) == 0 {
			fmt.Println("No RPM probes configured")
			return nil
		}
		fmt.Println("RPM Probe Results:")
		for _, r := range results {
			fmt.Printf("  Probe: %s, Test: %s\n", r.ProbeName, r.TestName)
			fmt.Printf("    Type: %s, Target: %s\n", r.ProbeType, r.Target)
			fmt.Printf("    Status: %s", r.LastStatus)
			if r.LastRTT > 0 {
				fmt.Printf(", RTT: %s", r.LastRTT)
			}
			fmt.Println()
			fmt.Printf("    Sent: %d, Received: %d", r.TotalSent, r.TotalRecv)
			if r.TotalSent > 0 {
				loss := float64(r.TotalSent-r.TotalRecv) / float64(r.TotalSent) * 100
				fmt.Printf(", Loss: %.1f%%", loss)
			}
			fmt.Println()
			if !r.LastProbeAt.IsZero() {
				fmt.Printf("    Last probe: %s\n", r.LastProbeAt.Format("2006-01-02 15:04:05"))
			}
		}
		return nil
	}

	// Fallback: show config only
	cfg := c.store.ActiveConfig()
	if cfg == nil || cfg.Services.RPM == nil || len(cfg.Services.RPM.Probes) == 0 {
		fmt.Println("No RPM probes configured")
		return nil
	}

	fmt.Println("RPM Probe Configuration:")
	for probeName, probe := range cfg.Services.RPM.Probes {
		for testName, test := range probe.Tests {
			fmt.Printf("  Probe: %s, Test: %s\n", probeName, testName)
			fmt.Printf("    Type: %s, Target: %s\n", test.ProbeType, test.Target)
			if test.SourceAddress != "" {
				fmt.Printf("    Source: %s\n", test.SourceAddress)
			}
			if test.RoutingInstance != "" {
				fmt.Printf("    Routing instance: %s\n", test.RoutingInstance)
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

	// Runtime statistics
	if c.dhcpRelay != nil {
		stats := c.dhcpRelay.Stats()
		if len(stats) > 0 {
			fmt.Println("\nRelay statistics:")
			fmt.Printf("  %-16s %-20s %s\n", "Interface", "Requests relayed", "Replies forwarded")
			for _, s := range stats {
				fmt.Printf("  %-16s %-20d %d\n", s.Interface, s.RequestsRelayed, s.RepliesForwarded)
			}
		}
	}
	return nil
}

func (c *CLI) showDHCPServer() error {
	cfg := c.store.ActiveConfig()
	if cfg == nil || (cfg.System.DHCPServer.DHCPLocalServer == nil && cfg.System.DHCPServer.DHCPv6LocalServer == nil) {
		fmt.Println("No DHCP server configured")
		return nil
	}

	// Read Kea lease files directly
	leases4, _ := dhcpserver.New().GetLeases4()
	leases6, _ := dhcpserver.New().GetLeases6()

	if len(leases4) == 0 && len(leases6) == 0 {
		fmt.Println("No active leases")
		return nil
	}

	if len(leases4) > 0 {
		fmt.Println("DHCPv4 Leases:")
		fmt.Printf("  %-18s %-20s %-15s %-12s %s\n", "Address", "MAC", "Hostname", "Lifetime", "Expires")
		for _, l := range leases4 {
			fmt.Printf("  %-18s %-20s %-15s %-12s %s\n",
				l.Address, l.HWAddress, l.Hostname, l.ValidLife, l.ExpireTime)
		}
	}
	if len(leases6) > 0 {
		fmt.Println("DHCPv6 Leases:")
		fmt.Printf("  %-40s %-20s %-15s %-12s %s\n", "Address", "DUID", "Hostname", "Lifetime", "Expires")
		for _, l := range leases6 {
			fmt.Printf("  %-40s %-20s %-15s %-12s %s\n",
				l.Address, l.HWAddress, l.Hostname, l.ValidLife, l.ExpireTime)
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
			if pol.Description != "" {
				fmt.Printf("    Description: %s\n", pol.Description)
			}
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
		writeCompletionHelp(os.Stdout, treeHelpCandidates(operationalTree["monitor"].children))
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

// showSystemUptime shows system uptime (like Junos "show system uptime").
func (c *CLI) showSystemUptime() error {
	// Read /proc/uptime
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return fmt.Errorf("reading uptime: %w", err)
	}
	fields := strings.Fields(string(data))
	if len(fields) < 1 {
		return fmt.Errorf("unexpected /proc/uptime format")
	}
	var upSec float64
	fmt.Sscanf(fields[0], "%f", &upSec)

	days := int(upSec) / 86400
	hours := (int(upSec) % 86400) / 3600
	mins := (int(upSec) % 3600) / 60
	secs := int(upSec) % 60

	fmt.Printf("Current time: %s\n", time.Now().Format("2006-01-02 15:04:05 MST"))
	fmt.Printf("System booted: %s\n", time.Now().Add(-time.Duration(upSec)*time.Second).Format("2006-01-02 15:04:05 MST"))
	if days > 0 {
		fmt.Printf("Uptime: %d days, %d hours, %d minutes, %d seconds\n", days, hours, mins, secs)
	} else {
		fmt.Printf("Uptime: %d hours, %d minutes, %d seconds\n", hours, mins, secs)
	}
	return nil
}

// showSystemMemory shows memory usage (like Junos "show system memory").
func (c *CLI) showSystemMemory() error {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return fmt.Errorf("reading meminfo: %w", err)
	}

	info := make(map[string]uint64)
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			key := strings.TrimSuffix(parts[0], ":")
			val, _ := strconv.ParseUint(parts[1], 10, 64)
			info[key] = val
		}
	}

	total := info["MemTotal"]
	free := info["MemFree"]
	buffers := info["Buffers"]
	cached := info["Cached"]
	available := info["MemAvailable"]
	used := total - free - buffers - cached

	fmt.Printf("%-20s %10s\n", "Type", "kB")
	fmt.Printf("%-20s %10d\n", "Total memory", total)
	fmt.Printf("%-20s %10d\n", "Used memory", used)
	fmt.Printf("%-20s %10d\n", "Free memory", free)
	fmt.Printf("%-20s %10d\n", "Buffers", buffers)
	fmt.Printf("%-20s %10d\n", "Cached", cached)
	fmt.Printf("%-20s %10d\n", "Available", available)
	if total > 0 {
		fmt.Printf("Utilization: %.1f%%\n", float64(used)/float64(total)*100)
	}
	return nil
}

// showSystemProcesses shows top resource consumers.
func (c *CLI) showSystemProcesses() error {
	cmd := exec.Command("ps", "aux", "--sort=-rss")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// showSystemStorage shows filesystem usage (like Junos "show system storage").
func (c *CLI) showSystemStorage() error {
	var stat unix.Statfs_t
	mounts := []struct {
		path string
		name string
	}{
		{"/", "Root (/)"},
		{"/var", "/var"},
		{"/tmp", "/tmp"},
	}

	fmt.Printf("%-20s %12s %12s %12s %6s\n", "Filesystem", "Size", "Used", "Avail", "Use%")
	for _, m := range mounts {
		if err := unix.Statfs(m.path, &stat); err != nil {
			continue
		}
		total := stat.Blocks * uint64(stat.Bsize)
		free := stat.Bavail * uint64(stat.Bsize)
		used := total - (stat.Bfree * uint64(stat.Bsize))
		pct := float64(0)
		if total > 0 {
			pct = float64(used) / float64(total) * 100
		}
		fmt.Printf("%-20s %12s %12s %12s %5.0f%%\n",
			m.name, fmtBytes(total), fmtBytes(used), fmtBytes(free), pct)
	}
	return nil
}

// fmtBytes formats bytes as human-readable (K/M/G).
func fmtBytes(b uint64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.1fG", float64(b)/float64(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.1fM", float64(b)/float64(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.1fK", float64(b)/float64(1<<10))
	default:
		return fmt.Sprintf("%dB", b)
	}
}

// showARP shows the kernel ARP table (like Junos "show arp").
func (c *CLI) showARP() error {
	neighbors, err := netlink.NeighList(0, netlink.FAMILY_V4)
	if err != nil {
		return fmt.Errorf("listing ARP entries: %w", err)
	}

	fmt.Printf("%-18s %-20s %-12s %-10s\n", "MAC Address", "Address", "Interface", "State")
	for _, n := range neighbors {
		if n.IP == nil || n.HardwareAddr == nil {
			continue
		}
		ifName := ""
		if link, err := netlink.LinkByIndex(n.LinkIndex); err == nil {
			ifName = link.Attrs().Name
		}
		state := neighState(n.State)
		fmt.Printf("%-18s %-20s %-12s %-10s\n",
			n.HardwareAddr, n.IP, ifName, state)
	}
	return nil
}

// handleShowIPv6 dispatches show ipv6 sub-commands.
func (c *CLI) handleShowIPv6(args []string) error {
	if len(args) == 0 {
		fmt.Println("show ipv6:")
		fmt.Println("  neighbors        Show IPv6 neighbor cache")
		return nil
	}
	switch args[0] {
	case "neighbors":
		return c.showIPv6Neighbors()
	default:
		return fmt.Errorf("unknown show ipv6 target: %s", args[0])
	}
}

// showIPv6Neighbors shows the kernel IPv6 neighbor cache (like Junos "show ipv6 neighbors").
func (c *CLI) showIPv6Neighbors() error {
	neighbors, err := netlink.NeighList(0, netlink.FAMILY_V6)
	if err != nil {
		return fmt.Errorf("listing IPv6 neighbors: %w", err)
	}

	fmt.Printf("%-18s %-40s %-12s %-10s\n", "MAC Address", "IPv6 Address", "Interface", "State")
	for _, n := range neighbors {
		if n.IP == nil {
			continue
		}
		// Skip link-local multicast and unresolved entries without MACs
		if n.HardwareAddr == nil {
			continue
		}
		ifName := ""
		if link, err := netlink.LinkByIndex(n.LinkIndex); err == nil {
			ifName = link.Attrs().Name
		}
		state := neighState(n.State)
		fmt.Printf("%-18s %-40s %-12s %-10s\n",
			n.HardwareAddr, n.IP, ifName, state)
	}
	return nil
}

// neighState converts a kernel neighbor state to a human-readable string.
func neighState(state int) string {
	switch state {
	case netlink.NUD_REACHABLE:
		return "reachable"
	case netlink.NUD_STALE:
		return "stale"
	case netlink.NUD_DELAY:
		return "delay"
	case netlink.NUD_PROBE:
		return "probe"
	case netlink.NUD_FAILED:
		return "failed"
	case netlink.NUD_PERMANENT:
		return "permanent"
	case netlink.NUD_INCOMPLETE:
		return "incomplete"
	case netlink.NUD_NOARP:
		return "noarp"
	default:
		return "unknown"
	}
}

// showSystemUsers shows configured login users from the active config.
func (c *CLI) showSystemUsers() error {
	cfg := c.store.ActiveConfig()
	if cfg == nil || cfg.System.Login == nil || len(cfg.System.Login.Users) == 0 {
		fmt.Println("No login users configured")
		return nil
	}

	fmt.Printf("%-20s %-8s %-20s %s\n", "Username", "UID", "Class", "SSH Keys")
	for _, u := range cfg.System.Login.Users {
		uid := "-"
		if u.UID > 0 {
			uid = strconv.Itoa(u.UID)
		}
		class := u.Class
		if class == "" {
			class = "-"
		}
		keys := strconv.Itoa(len(u.SSHKeys))
		fmt.Printf("%-20s %-8s %-20s %s\n", u.Name, uid, class, keys)
	}
	return nil
}

// showSystemConnections shows active TCP connections.
func (c *CLI) showSystemConnections() error {
	cmd := exec.Command("ss", "-tnp")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// showVersion displays software version information.
func (c *CLI) showVersion() error {
	ver := c.version
	if ver == "" {
		ver = "dev"
	}
	fmt.Printf("bpfrx eBPF firewall %s\n", ver)
	var uts unix.Utsname
	if err := unix.Uname(&uts); err == nil {
		sysname := strings.TrimRight(string(uts.Sysname[:]), "\x00")
		release := strings.TrimRight(string(uts.Release[:]), "\x00")
		machine := strings.TrimRight(string(uts.Machine[:]), "\x00")
		nodename := strings.TrimRight(string(uts.Nodename[:]), "\x00")
		fmt.Printf("Hostname: %s\n", nodename)
		fmt.Printf("Kernel: %s %s (%s)\n", sysname, release, machine)
	}
	return nil
}

// showChassis shows hardware information (like Junos "show chassis hardware").
func (c *CLI) showChassis(args []string) error {
	if len(args) > 0 {
		switch args[0] {
		case "hardware":
			return c.showChassisHardware()
		case "cluster":
			return c.showChassisCluster(args[1:])
		case "environment":
			return c.showChassisEnvironment()
		}
	}
	fmt.Println("show chassis:")
	fmt.Println("  cluster          Show cluster/HA status")
	fmt.Println("  environment      Show temperature and power information")
	fmt.Println("  hardware         Show hardware information")
	return nil
}

// showChassisCluster shows cluster/HA configuration and status.
func (c *CLI) showChassisCluster(args []string) error {
	cfg := c.store.ActiveConfig()
	if cfg == nil || cfg.Chassis.Cluster == nil {
		fmt.Println("Cluster not configured")
		return nil
	}
	cluster := cfg.Chassis.Cluster

	fmt.Println("Chassis cluster status:")
	fmt.Printf("  RETH count: %d\n", cluster.RethCount)
	fmt.Println()

	for _, rg := range cluster.RedundancyGroups {
		fmt.Printf("Redundancy group: %d\n", rg.ID)
		for nodeID, priority := range rg.NodePriorities {
			fmt.Printf("  Node %d priority: %d\n", nodeID, priority)
		}
		if rg.GratuitousARPCount > 0 {
			fmt.Printf("  Gratuitous ARP count: %d\n", rg.GratuitousARPCount)
		}
		if len(rg.InterfaceMonitors) > 0 {
			fmt.Println("  Interface monitors:")
			for _, mon := range rg.InterfaceMonitors {
				fmt.Printf("    %-20s weight %d\n", mon.Interface, mon.Weight)
			}
		}
		fmt.Println()
	}

	// Show VRRP status if any
	if cfg.Security.Zones != nil {
		for _, zone := range cfg.Security.Zones {
			for _, iface := range zone.Interfaces {
				ifCfg, ok := cfg.Interfaces.Interfaces[iface]
				if !ok {
					continue
				}
				for _, unit := range ifCfg.Units {
					for addr, vg := range unit.VRRPGroups {
						fmt.Printf("VRRP on %s.%d: group %d, priority %d, VIP %s, address %s\n",
							iface, unit.Number, vg.ID, vg.Priority,
							strings.Join(vg.VirtualAddresses, ","), addr)
					}
				}
			}
		}
	}

	return nil
}

// showChassisEnvironment shows system temperature and power info.
func (c *CLI) showChassisEnvironment() error {
	// Thermal zones
	thermalZones, _ := filepath.Glob("/sys/class/thermal/thermal_zone*/temp")
	if len(thermalZones) > 0 {
		fmt.Println("Temperature:")
		for _, tz := range thermalZones {
			data, err := os.ReadFile(tz)
			if err != nil {
				continue
			}
			millideg, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
			if err != nil {
				continue
			}
			// Read type for zone name
			typeFile := filepath.Join(filepath.Dir(tz), "type")
			name := filepath.Base(filepath.Dir(tz))
			if typeData, err := os.ReadFile(typeFile); err == nil {
				name = strings.TrimSpace(string(typeData))
			}
			fmt.Printf("  %-30s %d.%d C\n", name, millideg/1000, (millideg%1000)/100)
		}
		fmt.Println()
	}

	// Power supply
	powerFiles, _ := filepath.Glob("/sys/class/power_supply/*/status")
	if len(powerFiles) > 0 {
		fmt.Println("Power supplies:")
		for _, pf := range powerFiles {
			name := filepath.Base(filepath.Dir(pf))
			status, err := os.ReadFile(pf)
			if err != nil {
				continue
			}
			fmt.Printf("  %-20s %s\n", name, strings.TrimSpace(string(status)))
		}
		fmt.Println()
	}

	// System uptime and load
	var sysinfo unix.Sysinfo_t
	if err := unix.Sysinfo(&sysinfo); err == nil {
		days := sysinfo.Uptime / 86400
		hours := (sysinfo.Uptime % 86400) / 3600
		mins := (sysinfo.Uptime % 3600) / 60
		fmt.Printf("System uptime: %d days, %d:%02d\n", days, hours, mins)
		fmt.Printf("Load average: %.2f %.2f %.2f\n",
			float64(sysinfo.Loads[0])/65536.0,
			float64(sysinfo.Loads[1])/65536.0,
			float64(sysinfo.Loads[2])/65536.0)
		fmt.Printf("Total RAM: %s, Free: %s\n",
			fmtBytes(sysinfo.Totalram), fmtBytes(sysinfo.Freeram))
	}

	return nil
}

// showChassisHardware shows CPU, memory, and NIC information.
func (c *CLI) showChassisHardware() error {
	// CPU info
	cpuData, err := os.ReadFile("/proc/cpuinfo")
	if err == nil {
		cpuModel := ""
		cpuCount := 0
		for _, line := range strings.Split(string(cpuData), "\n") {
			if strings.HasPrefix(line, "model name") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					cpuModel = strings.TrimSpace(parts[1])
				}
				cpuCount++
			}
		}
		if cpuModel != "" {
			fmt.Printf("CPU: %s (%d cores)\n", cpuModel, cpuCount)
		}
	}

	// Memory
	memData, err := os.ReadFile("/proc/meminfo")
	if err == nil {
		for _, line := range strings.Split(string(memData), "\n") {
			if strings.HasPrefix(line, "MemTotal:") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					if kb, err := strconv.ParseUint(parts[1], 10, 64); err == nil {
						fmt.Printf("Memory: %s total\n", fmtBytes(kb*1024))
					}
				}
				break
			}
		}
	}

	// Kernel version
	var uts unix.Utsname
	if err := unix.Uname(&uts); err == nil {
		release := strings.TrimRight(string(uts.Release[:]), "\x00")
		machine := strings.TrimRight(string(uts.Machine[:]), "\x00")
		fmt.Printf("Kernel: %s (%s)\n", release, machine)
	}

	// Network interfaces
	fmt.Println("\nNetwork interfaces:")
	links, err := netlink.LinkList()
	if err == nil {
		for _, link := range links {
			attrs := link.Attrs()
			if attrs.Name == "lo" {
				continue
			}
			state := "down"
			if attrs.OperState == netlink.OperUp {
				state = "up"
			}
			driver := link.Type()
			fmt.Printf("  %-16s %-8s %-10s %s\n", attrs.Name, state, driver, attrs.HardwareAddr)
		}
	}
	return nil
}

// showPolicyOptions displays prefix-lists and policy-statements.
func (c *CLI) showPolicyOptions() error {
	cfg := c.store.ActiveConfig()
	if cfg == nil {
		fmt.Println("No active configuration")
		return nil
	}
	po := &cfg.PolicyOptions

	if len(po.PrefixLists) > 0 {
		fmt.Println("Prefix lists:")
		for name, pl := range po.PrefixLists {
			fmt.Printf("  %-30s %d prefixes\n", name, len(pl.Prefixes))
			for _, p := range pl.Prefixes {
				fmt.Printf("    %s\n", p)
			}
		}
	}

	if len(po.PolicyStatements) > 0 {
		if len(po.PrefixLists) > 0 {
			fmt.Println()
		}
		fmt.Println("Policy statements:")
		for name, ps := range po.PolicyStatements {
			fmt.Printf("  %s", name)
			if ps.DefaultAction != "" {
				fmt.Printf(" (default: %s)", ps.DefaultAction)
			}
			fmt.Println()
			for _, t := range ps.Terms {
				fmt.Printf("    term %s:", t.Name)
				if t.FromProtocol != "" {
					fmt.Printf(" from protocol %s", t.FromProtocol)
				}
				if t.PrefixList != "" {
					fmt.Printf(" prefix-list %s", t.PrefixList)
				}
				if len(t.RouteFilters) > 0 {
					fmt.Printf(" %d route-filter(s)", len(t.RouteFilters))
				}
				if t.Action != "" {
					fmt.Printf(" then %s", t.Action)
				}
				if t.LoadBalance != "" {
					fmt.Printf(" load-balance %s", t.LoadBalance)
				}
				fmt.Println()
			}
		}
	}

	if len(po.PrefixLists) == 0 && len(po.PolicyStatements) == 0 {
		fmt.Println("No policy-options configured")
	}
	return nil
}

// showEventOptions displays event-driven policies.
func (c *CLI) showEventOptions() error {
	cfg := c.store.ActiveConfig()
	if cfg == nil {
		fmt.Println("No active configuration")
		return nil
	}
	if len(cfg.EventOptions) == 0 {
		fmt.Println("No event-options configured")
		return nil
	}

	for _, ep := range cfg.EventOptions {
		fmt.Printf("Policy: %s\n", ep.Name)
		if len(ep.Events) > 0 {
			fmt.Printf("  Events: %s\n", strings.Join(ep.Events, ", "))
		}
		for _, w := range ep.WithinClauses {
			fmt.Printf("  Within: %d seconds", w.Seconds)
			if w.TriggerOn > 0 {
				fmt.Printf(", trigger on %d", w.TriggerOn)
			}
			if w.TriggerUntil > 0 {
				fmt.Printf(", trigger until %d", w.TriggerUntil)
			}
			fmt.Println()
		}
		if len(ep.AttributesMatch) > 0 {
			fmt.Println("  Attributes match:")
			for _, am := range ep.AttributesMatch {
				fmt.Printf("    %s\n", am)
			}
		}
		if len(ep.ThenCommands) > 0 {
			fmt.Println("  Then commands:")
			for _, cmd := range ep.ThenCommands {
				fmt.Printf("    %s\n", cmd)
			}
		}
		fmt.Println()
	}
	return nil
}

// showRoutingOptions displays static routes and routing config.
func (c *CLI) showRoutingOptions() error {
	cfg := c.store.ActiveConfig()
	if cfg == nil {
		fmt.Println("No active configuration")
		return nil
	}
	ro := &cfg.RoutingOptions
	hasContent := false

	if ro.AutonomousSystem > 0 {
		fmt.Printf("Autonomous system: %d\n\n", ro.AutonomousSystem)
		hasContent = true
	}

	if ro.ForwardingTableExport != "" {
		fmt.Printf("Forwarding-table export: %s\n\n", ro.ForwardingTableExport)
		hasContent = true
	}

	if len(ro.StaticRoutes) > 0 {
		fmt.Println("Static routes (inet.0):")
		fmt.Printf("  %-24s %-20s %-6s %s\n", "Destination", "Next-Hop", "Pref", "Flags")
		for _, sr := range ro.StaticRoutes {
			if sr.Discard {
				fmt.Printf("  %-24s %-20s %-6s %s\n", sr.Destination, "discard", fmtPref(sr.Preference), "")
				continue
			}
			if sr.NextTable != "" {
				fmt.Printf("  %-24s %-20s %-6s %s\n", sr.Destination, "next-table "+sr.NextTable, fmtPref(sr.Preference), "")
				continue
			}
			for i, nh := range sr.NextHops {
				dest := sr.Destination
				if i > 0 {
					dest = "" // don't repeat destination for ECMP entries
				}
				nhStr := nh.Address
				if nh.Interface != "" {
					nhStr += " via " + nh.Interface
				}
				fmt.Printf("  %-24s %-20s %-6s %s\n", dest, nhStr, fmtPref(sr.Preference), "")
			}
		}
		fmt.Println()
		hasContent = true
	}

	if len(ro.Inet6StaticRoutes) > 0 {
		fmt.Println("Static routes (inet6.0):")
		fmt.Printf("  %-40s %-30s %-6s\n", "Destination", "Next-Hop", "Pref")
		for _, sr := range ro.Inet6StaticRoutes {
			if sr.Discard {
				fmt.Printf("  %-40s %-30s %-6s\n", sr.Destination, "discard", fmtPref(sr.Preference))
				continue
			}
			if sr.NextTable != "" {
				fmt.Printf("  %-40s %-30s %-6s\n", sr.Destination, "next-table "+sr.NextTable, fmtPref(sr.Preference))
				continue
			}
			for i, nh := range sr.NextHops {
				dest := sr.Destination
				if i > 0 {
					dest = ""
				}
				nhStr := nh.Address
				if nh.Interface != "" {
					nhStr += " via " + nh.Interface
				}
				fmt.Printf("  %-40s %-30s %-6s\n", dest, nhStr, fmtPref(sr.Preference))
			}
		}
		fmt.Println()
		hasContent = true
	}

	if len(ro.RibGroups) > 0 {
		fmt.Println("RIB groups:")
		for name, rg := range ro.RibGroups {
			fmt.Printf("  %-20s import-rib: %s\n", name, strings.Join(rg.ImportRibs, ", "))
		}
		fmt.Println()
		hasContent = true
	}

	if !hasContent {
		fmt.Println("No routing-options configured")
	}
	return nil
}

func (c *CLI) showRoutingInstances() error {
	cfg := c.store.ActiveConfig()
	if cfg == nil {
		fmt.Println("No active configuration")
		return nil
	}
	if len(cfg.RoutingInstances) == 0 {
		fmt.Println("No routing instances configured")
		return nil
	}

	fmt.Printf("%-20s %-16s %-6s %s\n", "Instance", "Type", "Table", "Interfaces")
	for _, ri := range cfg.RoutingInstances {
		tableID := "-"
		if ri.TableID > 0 {
			tableID = fmt.Sprintf("%d", ri.TableID)
		}
		ifaces := "-"
		if len(ri.Interfaces) > 0 {
			ifaces = strings.Join(ri.Interfaces, ", ")
		}
		fmt.Printf("%-20s %-16s %-6s %s\n", ri.Name, ri.InstanceType, tableID, ifaces)
		if ri.Description != "" {
			fmt.Printf("  Description: %s\n", ri.Description)
		}
	}
	return nil
}

func fmtPref(p int) string {
	if p == 0 {
		return "-"
	}
	return strconv.Itoa(p)
}

// showForwardingOptions displays forwarding/sampling configuration.
func (c *CLI) showForwardingOptions() error {
	cfg := c.store.ActiveConfig()
	if cfg == nil {
		fmt.Println("No active configuration")
		return nil
	}
	fo := &cfg.ForwardingOptions
	hasContent := false

	if fo.FamilyInet6Mode != "" {
		fmt.Printf("Family inet6 mode: %s\n", fo.FamilyInet6Mode)
		hasContent = true
	}

	if fo.Sampling != nil && len(fo.Sampling.Instances) > 0 {
		fmt.Println("Sampling:")
		for name, inst := range fo.Sampling.Instances {
			fmt.Printf("  Instance: %s\n", name)
			if inst.InputRate > 0 {
				fmt.Printf("    Input rate: 1/%d\n", inst.InputRate)
			}
			for _, fam := range []*config.SamplingFamily{inst.FamilyInet, inst.FamilyInet6} {
				if fam == nil {
					continue
				}
				for _, fs := range fam.FlowServers {
					fmt.Printf("    Flow server: %s:%d\n", fs.Address, fs.Port)
					if fs.Version9Template != "" {
						fmt.Printf("      Version 9 template: %s\n", fs.Version9Template)
					}
				}
				if fam.SourceAddress != "" {
					fmt.Printf("    Source address: %s\n", fam.SourceAddress)
				}
				if fam.InlineJflow {
					fmt.Printf("    Inline jflow: enabled\n")
				}
				if fam.InlineJflowSourceAddress != "" {
					fmt.Printf("    Inline jflow source: %s\n", fam.InlineJflowSourceAddress)
				}
			}
		}
		hasContent = true
	}

	if fo.DHCPRelay != nil {
		fmt.Println("DHCP relay: (see 'show dhcp-relay' for details)")
		hasContent = true
	}

	if !hasContent {
		fmt.Println("No forwarding-options configured")
	}
	return nil
}

// handleRequest dispatches request sub-commands (like Junos operational mode).
func (c *CLI) handleRequest(args []string) error {
	if len(args) == 0 {
		fmt.Println("request:")
		writeCompletionHelp(os.Stdout, treeHelpCandidates(operationalTree["request"].children))
		return nil
	}

	switch args[0] {
	case "dhcp":
		return c.handleRequestDHCP(args[1:])
	case "system":
		return c.handleRequestSystem(args[1:])
	default:
		return fmt.Errorf("unknown request target: %s", args[0])
	}
}

func (c *CLI) handleRequestDHCP(args []string) error {
	if len(args) == 0 || args[0] != "renew" {
		fmt.Println("request dhcp:")
		writeCompletionHelp(os.Stdout, treeHelpCandidates(operationalTree["request"].children["dhcp"].children))
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

func (c *CLI) handleRequestSystem(args []string) error {
	if len(args) == 0 {
		fmt.Println("request system:")
		writeCompletionHelp(os.Stdout, treeHelpCandidates(operationalTree["request"].children["system"].children))
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
		configDir := "/etc/bpfrx"
		files, _ := os.ReadDir(configDir)
		for _, f := range files {
			if strings.HasSuffix(f.Name(), ".conf") || strings.HasPrefix(f.Name(), "rollback") {
				os.Remove(configDir + "/" + f.Name())
			}
		}

		// Remove BPF pins
		os.RemoveAll("/sys/fs/bpf/bpfrx")

		// Remove managed networkd files
		ndFiles, _ := os.ReadDir("/etc/systemd/network")
		for _, f := range ndFiles {
			if strings.HasPrefix(f.Name(), "10-bpfrx-") {
				os.Remove("/etc/systemd/network/" + f.Name())
			}
		}

		// Remove FRR managed section
		exec.Command("systemctl", "stop", "bpfrxd").Run()

		fmt.Println("System zeroized. Configuration erased.")
		fmt.Println("Reboot to complete factory reset.")
		return nil

	default:
		return fmt.Errorf("unknown request system command: %s", args[0])
	}
}
