// Package cli implements the Junos-style interactive CLI for bpfrx.
package cli

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/chzyer/readline"
	"github.com/psaab/bpfrx/pkg/cluster"
	"github.com/psaab/bpfrx/pkg/cmdtree"
	"github.com/psaab/bpfrx/pkg/config"
	"github.com/psaab/bpfrx/pkg/configstore"
	"github.com/psaab/bpfrx/pkg/dataplane"
	"github.com/psaab/bpfrx/pkg/dhcp"
	"github.com/psaab/bpfrx/pkg/dhcprelay"
	"github.com/psaab/bpfrx/pkg/dhcpserver"
	"github.com/psaab/bpfrx/pkg/feeds"
	"github.com/psaab/bpfrx/pkg/frr"
	"github.com/psaab/bpfrx/pkg/ipsec"
	"github.com/psaab/bpfrx/pkg/lldp"
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
	dp          dataplane.DataPlane
	eventBuf    *logging.EventBuffer
	eventReader *logging.EventReader
	routing     *routing.Manager
	frr         *frr.Manager
	ipsec       *ipsec.Manager
	dhcp         *dhcp.Manager
	dhcpRelay    *dhcprelay.Manager
	cluster      *cluster.Manager
	rpmResultsFn     func() []*rpm.ProbeResult
	feedsFn          func() map[string]feeds.FeedInfo
	lldpNeighborsFn  func() []*lldp.Neighbor
	hostname     string
	username     string
	userClass    string
	version      string
	startTime    time.Time
}

// New creates a new CLI.
func New(store *configstore.Store, dp dataplane.DataPlane, eventBuf *logging.EventBuffer, eventReader *logging.EventReader, rm *routing.Manager, fm *frr.Manager, im *ipsec.Manager, dm *dhcp.Manager, dr *dhcprelay.Manager, cm *cluster.Manager) *CLI {
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
		startTime:   time.Now(),
		frr:         fm,
		ipsec:       im,
		dhcp:        dm,
		dhcpRelay:   dr,
		cluster:     cm,
		hostname:    hostname,
		username:    username,
	}
}

// SetRPMResultsFn sets a callback for retrieving live RPM probe results.
func (c *CLI) SetRPMResultsFn(fn func() []*rpm.ProbeResult) {
	c.rpmResultsFn = fn
}

// SetFeedsFn sets a callback for retrieving live dynamic address feed status.
func (c *CLI) SetFeedsFn(fn func() map[string]feeds.FeedInfo) {
	c.feedsFn = fn
}

// SetLLDPNeighborsFn sets a callback for retrieving live LLDP neighbor data.
func (c *CLI) SetLLDPNeighborsFn(fn func() []*lldp.Neighbor) {
	c.lldpNeighborsFn = fn
}

// SetVersion sets the software version string for show version.
func (c *CLI) SetVersion(v string) {
	c.version = v
}

// SetUserClass sets the login class for RBAC permission checks.
func (c *CLI) SetUserClass(class string) {
	c.userClass = class
}

// checkPermission verifies the current user's login class permits the given action.
// If userClass is empty (not set), all actions are allowed for backward compatibility.
func (c *CLI) checkPermission(action string) error {
	if c.userClass == "" {
		return nil
	}

	perms, ok := config.LoginClassPermissions[c.userClass]
	if !ok {
		return fmt.Errorf("permission denied: unknown login class %q", c.userClass)
	}

	// Determine required permission for the action.
	var required config.LoginClassPermission
	switch action {
	case "show", "ping", "traceroute", "monitor":
		required = config.PermView
	case "clear":
		required = config.PermClear
	case "request", "test":
		required = config.PermControl
	case "configure":
		required = config.PermConfig
	default:
		required = config.PermAll
	}

	for _, p := range perms {
		if p == config.PermAll || p == required {
			return nil
		}
	}

	return fmt.Errorf("permission denied: %q requires class super-user or higher", action)
}

// completionNode is a static command completion tree node.
// completionNode is an alias for the canonical cmdtree.Node type.
type completionNode = cmdtree.Node

// operationalTree references the canonical tree in pkg/cmdtree.
var operationalTree = cmdtree.OperationalTree

// configTopLevel references the canonical config tree in pkg/cmdtree.
var configTopLevel = cmdtree.ConfigTopLevel

// cliCompleter implements readline.AutoCompleter.
type cliCompleter struct {
	cli *CLI
}

func (cc *cliCompleter) Do(line []rune, pos int) ([][]rune, int) {
	text := string(line[:pos])

	// Pipe filter completion: "show ... | <tab>"
	if pipeCandidates, handled := completePipeFilter(text); handled {
		if len(pipeCandidates) == 0 {
			return nil, 0
		}
		// Determine partial (text after "| ")
		idx := strings.LastIndex(text, "|")
		after := strings.TrimLeft(text[idx+1:], " ")
		partial := after

		sort.Slice(pipeCandidates, func(i, j int) bool { return pipeCandidates[i].name < pipeCandidates[j].name })
		if len(pipeCandidates) == 1 {
			suffix := pipeCandidates[0].name[len(partial):]
			return [][]rune{[]rune(suffix + " ")}, len(partial)
		}
		writeCompletionHelp(cc.cli.rl.Stdout(), pipeCandidates)
		names := make([]string, len(pipeCandidates))
		for i, c := range pipeCandidates {
			names[i] = c.name
		}
		cp := commonPrefix(names)
		suffix := cp[len(partial):]
		if suffix == "" {
			return nil, 0
		}
		return [][]rune{[]rune(suffix)}, len(partial)
	}

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
				candidates = append(candidates, completionCandidate{name: name, desc: node.Desc})
			}
		}
		return candidates
	}

	switch words[0] {
	case "set", "delete", "show", "edit":
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
			if node == nil || node.Children == nil {
				return nil
			}
			var candidates []completionCandidate
			for name, child := range node.Children {
				if strings.HasPrefix(name, partial) {
					candidates = append(candidates, completionCandidate{name: name, desc: child.Desc})
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

			// Pipe filter help: "show ... | ?"
			if pipeCandidates, handled := completePipeFilter(text + " "); handled {
				if len(pipeCandidates) > 0 {
					writeCompletionHelp(c.rl.Stdout(), pipeCandidates)
				}
				return cleanLine, pos - 1, true
			}

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
	c.store.SetCentralRollbackHandler(func(cfg *config.Config) {
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

	// Catch SIGINT to prevent process termination.
	// readline handles ^C during input (returns ErrInterrupt).
	// During dispatch, this absorbs the signal so it doesn't kill the daemon.
	// Double Ctrl-C within 2s exits the CLI.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	defer signal.Stop(sigCh)

	exitCh := make(chan struct{})
	go func() {
		var lastInterrupt time.Time
		for range sigCh {
			now := time.Now()
			if now.Sub(lastInterrupt) < 2*time.Second {
				if c.store.InConfigMode() {
					c.store.ExitConfigure()
				}
				close(exitCh)
				return
			}
			lastInterrupt = now
		}
	}()

	for {
		select {
		case <-exitCh:
			return nil
		default:
		}
		if c.store.IsConfirmPending() {
			fmt.Println("[commit confirmed pending - issue 'commit' to confirm]")
		}
		line, err := c.rl.Readline()
		if err != nil {
			if err == readline.ErrInterrupt || err == io.EOF {
				continue
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
	// Extract pipe filter (| match, | except, | find, | count, | last, | no-more).
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
// Recognized filters: match, except, find, count, last, no-more.
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
	case "match", "grep", "except", "find", "count", "last", "no-more":
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
	case "find":
		lowerPattern := strings.ToLower(pipeArg)
		found := false
		for _, line := range lines {
			if !found && strings.Contains(strings.ToLower(line), lowerPattern) {
				found = true
			}
			if found {
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
	"configure", "show", "clear", "ping", "test", "traceroute",
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

	// RBAC permission check
	if err := c.checkPermission(parts[0]); err != nil {
		return err
	}

	switch parts[0] {
	case "configure":
		if len(parts) >= 2 && parts[1] == "exclusive" {
			if err := c.store.EnterConfigureExclusive("cli"); err != nil {
				return err
			}
			c.rl.SetPrompt(c.configPrompt())
			fmt.Println("Entering configuration mode (exclusive)")
			fmt.Println("[edit]")
		} else {
			if err := c.store.EnterConfigure(); err != nil {
				return err
			}
			c.rl.SetPrompt(c.configPrompt())
			fmt.Println("Entering configuration mode")
			fmt.Println("[edit]")
		}
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

	case "test":
		return c.handleTest(parts[1:])

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
	case "edit":
		if len(parts) < 2 {
			fmt.Println("edit: missing path")
			return nil
		}
		newPath := append(c.store.GetEditPath(), parts[1:]...)
		c.store.SetEditPath(newPath)
		c.rl.SetPrompt(c.configPrompt())
		fmt.Printf("[edit %s]\n", strings.Join(newPath, " "))
		return nil

	case "top":
		c.store.NavigateTop()
		c.rl.SetPrompt(c.configPrompt())
		fmt.Println("[edit]")
		return nil

	case "up":
		c.store.NavigateUp()
		c.rl.SetPrompt(c.configPrompt())
		editPath := c.store.GetEditPath()
		if len(editPath) > 0 {
			fmt.Printf("[edit %s]\n", strings.Join(editPath, " "))
		} else {
			fmt.Println("[edit]")
		}
		return nil

	case "set":
		if len(parts) < 2 {
			return fmt.Errorf("set: missing path")
		}
		fullPath := append(c.store.GetEditPath(), parts[1:]...)
		return c.store.SetFromInput(strings.Join(fullPath, " "))

	case "delete":
		if len(parts) < 2 {
			return fmt.Errorf("delete: missing path")
		}
		fullPath := append(c.store.GetEditPath(), parts[1:]...)
		return c.store.DeleteFromInput(strings.Join(fullPath, " "))

	case "copy", "rename":
		return c.handleCopyRename(parts)

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

	case "annotate":
		if len(parts) < 3 {
			fmt.Println("usage: annotate <path> \"comment\"")
			return nil
		}
		line := strings.Join(parts[1:], " ")
		quoteIdx := strings.Index(line, "\"")
		if quoteIdx < 0 {
			fmt.Println("usage: annotate <path> \"comment\"")
			return nil
		}
		pathStr := strings.TrimSpace(line[:quoteIdx])
		comment := strings.Trim(line[quoteIdx:], "\"")
		pathParts := append(c.store.GetEditPath(), strings.Fields(pathStr)...)
		if err := c.store.Annotate(pathParts, comment); err != nil {
			return err
		}
		fmt.Println("annotation set")
		return nil

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
		if strings.Contains(rest, "| display json") {
			fmt.Print(c.store.ShowActiveJSON())
		} else if strings.Contains(rest, "| display set") {
			fmt.Print(c.store.ShowActiveSet())
		} else if strings.Contains(rest, "| display xml") {
			fmt.Print(c.store.ShowActiveXML())
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
			return c.showFirewallFilter(args[2])
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
		return c.showARP()

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

	default:
		return fmt.Errorf("unknown show target: %s", args[0])
	}
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
func enabledStr(v bool) string {
	if v {
		return "enabled"
	}
	return "disabled"
}

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

// showPoliciesDetail displays an expanded Junos-style detail view of security policies.
func (c *CLI) showPoliciesDetail(cfg *config.Config, fromZone, toZone string) error {
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
		fmt.Printf("Policy: %s -> %s, State: enabled\n", zpp.FromZone, zpp.ToZone)
		for i, pol := range zpp.Policies {
			action := "permit"
			switch pol.Action {
			case 1:
				action = "deny"
			case 2:
				action = "reject"
			}
			ruleID := policySetID*dataplane.MaxRulesPerPolicy + uint32(i)
			fmt.Printf("\n  Policy: %s, action-type: %s\n", pol.Name, capitalizeFirst(action))
			if pol.Description != "" {
				fmt.Printf("    Description: %s\n", pol.Description)
			}
			fmt.Printf("    Match:\n")
			fmt.Printf("      Source zone: %s\n", zpp.FromZone)
			fmt.Printf("      Destination zone: %s\n", zpp.ToZone)

			fmt.Printf("      Source addresses:\n")
			for _, addr := range pol.Match.SourceAddresses {
				resolved := resolveAddress(cfg, addr)
				fmt.Printf("        %s%s\n", addr, resolved)
			}

			fmt.Printf("      Destination addresses:\n")
			for _, addr := range pol.Match.DestinationAddresses {
				resolved := resolveAddress(cfg, addr)
				fmt.Printf("        %s%s\n", addr, resolved)
			}

			fmt.Printf("      Applications:\n")
			for _, app := range pol.Match.Applications {
				fmt.Printf("        %s\n", app)
			}

			fmt.Printf("    Then:\n")
			fmt.Printf("      %s\n", action)
			if pol.Log != nil {
				fmt.Printf("      log\n")
			}
			if pol.Count {
				fmt.Printf("      count\n")
			}

			if c.dp != nil && c.dp.IsLoaded() {
				if counters, err := c.dp.ReadPolicyCounters(ruleID); err == nil {
					fmt.Printf("    Session statistics:\n")
					fmt.Printf("      %d packets, %d bytes\n", counters.Packets, counters.Bytes)
				}
			}
		}
		policySetID++
		fmt.Println()
	}

	// Global policies
	if len(cfg.Security.GlobalPolicies) > 0 && fromZone == "" && toZone == "" {
		fmt.Printf("Global policies:\n")
		for i, pol := range cfg.Security.GlobalPolicies {
			action := "permit"
			switch pol.Action {
			case 1:
				action = "deny"
			case 2:
				action = "reject"
			}
			ruleID := policySetID*dataplane.MaxRulesPerPolicy + uint32(i)
			fmt.Printf("\n  Policy: %s, action-type: %s\n", pol.Name, capitalizeFirst(action))
			if pol.Description != "" {
				fmt.Printf("    Description: %s\n", pol.Description)
			}
			fmt.Printf("    Match:\n")
			fmt.Printf("      Source addresses:\n")
			for _, addr := range pol.Match.SourceAddresses {
				resolved := resolveAddress(cfg, addr)
				fmt.Printf("        %s%s\n", addr, resolved)
			}
			fmt.Printf("      Destination addresses:\n")
			for _, addr := range pol.Match.DestinationAddresses {
				resolved := resolveAddress(cfg, addr)
				fmt.Printf("        %s%s\n", addr, resolved)
			}
			fmt.Printf("      Applications:\n")
			for _, app := range pol.Match.Applications {
				fmt.Printf("        %s\n", app)
			}
			fmt.Printf("    Then:\n")
			fmt.Printf("      %s\n", action)
			if pol.Log != nil {
				fmt.Printf("      log\n")
			}
			if pol.Count {
				fmt.Printf("      count\n")
			}
			if c.dp != nil && c.dp.IsLoaded() {
				if counters, err := c.dp.ReadPolicyCounters(ruleID); err == nil {
					fmt.Printf("    Session statistics:\n")
					fmt.Printf("      %d packets, %d bytes\n", counters.Packets, counters.Bytes)
				}
			}
		}
		fmt.Println()
	}
	return nil
}

// resolveAddress looks up a named address in the global address book and returns its CIDR suffix.
func resolveAddress(cfg *config.Config, name string) string {
	if name == "any" {
		return ""
	}
	ab := cfg.Security.AddressBook
	if ab == nil {
		return ""
	}
	if addr, ok := ab.Addresses[name]; ok && addr.Value != "" {
		return " (" + addr.Value + ")"
	}
	if _, ok := ab.AddressSets[name]; ok {
		return " (address-set)"
	}
	return ""
}

// capitalizeFirst returns the string with the first letter capitalized.
func capitalizeFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func (c *CLI) showZonesDisplay(cfg *config.Config, detail bool, filterZone string) error {
	// Sort zone names for stable output
	zoneNames := make([]string, 0, len(cfg.Security.Zones))
	for name := range cfg.Security.Zones {
		zoneNames = append(zoneNames, name)
	}
	sort.Strings(zoneNames)

	for _, name := range zoneNames {
		if filterZone != "" && name != filterZone {
			continue
		}
		zone := cfg.Security.Zones[name]

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

		// Detail mode: per-interface breakdown, per-policy details, screen profile summary
		if detail {
			// Per-interface detail
			if len(zone.Interfaces) > 0 {
				fmt.Println("  Interface details:")
				for _, ifName := range zone.Interfaces {
					fmt.Printf("    %s:\n", ifName)
					if ifc, ok := cfg.Interfaces.Interfaces[ifName]; ok {
						for _, unit := range ifc.Units {
							for _, addr := range unit.Addresses {
								fmt.Printf("      Address: %s\n", addr)
							}
							if unit.DHCP {
								fmt.Printf("      DHCPv4: enabled\n")
							}
							if unit.DHCPv6 {
								fmt.Printf("      DHCPv6: enabled\n")
							}
						}
					}
				}
			}

			// Screen profile details
			if zone.ScreenProfile != "" {
				if profile, ok := cfg.Security.Screen[zone.ScreenProfile]; ok {
					fmt.Printf("  Screen profile details (%s):\n", zone.ScreenProfile)
					var checks []string
					if profile.TCP.Land {
						checks = append(checks, "land")
					}
					if profile.TCP.SynFin {
						checks = append(checks, "syn-fin")
					}
					if profile.TCP.NoFlag {
						checks = append(checks, "no-flag")
					}
					if profile.TCP.FinNoAck {
						checks = append(checks, "fin-no-ack")
					}
					if profile.TCP.WinNuke {
						checks = append(checks, "winnuke")
					}
					if profile.TCP.SynFrag {
						checks = append(checks, "syn-frag")
					}
					if profile.TCP.SynFlood != nil {
						checks = append(checks, fmt.Sprintf("syn-flood(threshold:%d)", profile.TCP.SynFlood.AttackThreshold))
					}
					if profile.ICMP.PingDeath {
						checks = append(checks, "ping-death")
					}
					if profile.ICMP.FloodThreshold > 0 {
						checks = append(checks, fmt.Sprintf("icmp-flood(threshold:%d)", profile.ICMP.FloodThreshold))
					}
					if profile.IP.SourceRouteOption {
						checks = append(checks, "source-route-option")
					}
					if profile.IP.TearDrop {
						checks = append(checks, "teardrop")
					}
					if profile.UDP.FloodThreshold > 0 {
						checks = append(checks, fmt.Sprintf("udp-flood(threshold:%d)", profile.UDP.FloodThreshold))
					}
					if len(checks) > 0 {
						fmt.Printf("    Enabled checks: %s\n", strings.Join(checks, ", "))
					} else {
						fmt.Printf("    Enabled checks: (none)\n")
					}
				}
			}

			// Policy detail breakdown
			fmt.Println("  Policy summary:")
			totalPolicies := 0
			for _, zpp := range cfg.Security.Policies {
				if zpp.FromZone == name || zpp.ToZone == name {
					for _, pol := range zpp.Policies {
						action := "permit"
						switch pol.Action {
						case 1:
							action = "deny"
						case 2:
							action = "reject"
						}
						fmt.Printf("    %s -> %s: %s (%s)\n",
							zpp.FromZone, zpp.ToZone, pol.Name, action)
						totalPolicies++
					}
				}
			}
			if totalPolicies == 0 {
				fmt.Println("    (no policies)")
			}
		}

		fmt.Println()
	}
	if filterZone != "" {
		if _, ok := cfg.Security.Zones[filterZone]; !ok {
			fmt.Printf("Zone '%s' not found\n", filterZone)
		}
	}
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
		readCtr := func(idx uint32) uint64 {
			v, _ := c.dp.ReadGlobalCounter(idx)
			return v
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

	return nil
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
		return fmt.Errorf("usage: show security screen statistics zone <zone-name>")
	default:
		return c.showScreen()
	}
}

func (c *CLI) showScreenIdsOption(name string) error {
	cfg := c.store.ActiveConfig()
	if cfg == nil {
		fmt.Println("no active configuration")
		return nil
	}
	profile, ok := cfg.Security.Screen[name]
	if !ok {
		fmt.Printf("Screen profile '%s' not found\n", name)
		return nil
	}

	fmt.Printf("Screen object status:\n\n")
	fmt.Printf("  %-45s %s\n", "Name", "Value")
	if profile.TCP.Land {
		fmt.Printf("  %-45s %s\n", "TCP land attack", "enabled")
	}
	if profile.TCP.SynFin {
		fmt.Printf("  %-45s %s\n", "TCP SYN+FIN", "enabled")
	}
	if profile.TCP.NoFlag {
		fmt.Printf("  %-45s %s\n", "TCP no-flag", "enabled")
	}
	if profile.TCP.FinNoAck {
		fmt.Printf("  %-45s %s\n", "TCP FIN-no-ACK", "enabled")
	}
	if profile.TCP.WinNuke {
		fmt.Printf("  %-45s %s\n", "TCP WinNuke", "enabled")
	}
	if profile.TCP.SynFrag {
		fmt.Printf("  %-45s %s\n", "TCP SYN fragment", "enabled")
	}
	if profile.TCP.SynFlood != nil {
		fmt.Printf("  %-45s %d\n", "TCP SYN flood attack threshold", profile.TCP.SynFlood.AttackThreshold)
		if profile.TCP.SynFlood.SourceThreshold > 0 {
			fmt.Printf("  %-45s %d\n", "TCP SYN flood source threshold", profile.TCP.SynFlood.SourceThreshold)
		}
		if profile.TCP.SynFlood.DestinationThreshold > 0 {
			fmt.Printf("  %-45s %d\n", "TCP SYN flood destination threshold", profile.TCP.SynFlood.DestinationThreshold)
		}
		if profile.TCP.SynFlood.Timeout > 0 {
			fmt.Printf("  %-45s %d\n", "TCP SYN flood timeout", profile.TCP.SynFlood.Timeout)
		}
	}
	if profile.ICMP.PingDeath {
		fmt.Printf("  %-45s %s\n", "ICMP ping of death", "enabled")
	}
	if profile.ICMP.FloodThreshold > 0 {
		fmt.Printf("  %-45s %d\n", "ICMP flood threshold", profile.ICMP.FloodThreshold)
	}
	if profile.IP.SourceRouteOption {
		fmt.Printf("  %-45s %s\n", "IP source route option", "enabled")
	}
	if profile.UDP.FloodThreshold > 0 {
		fmt.Printf("  %-45s %d\n", "UDP flood threshold", profile.UDP.FloodThreshold)
	}

	// Show zones using this profile
	var zones []string
	for zname, zone := range cfg.Security.Zones {
		if zone.ScreenProfile == name {
			zones = append(zones, zname)
		}
	}
	if len(zones) > 0 {
		sort.Strings(zones)
		fmt.Printf("\n  Bound to zones: %s\n", strings.Join(zones, ", "))
	}
	return nil
}

func (c *CLI) showScreenIdsOptionDetail(name string) error {
	cfg := c.store.ActiveConfig()
	if cfg == nil {
		fmt.Println("no active configuration")
		return nil
	}
	profile, ok := cfg.Security.Screen[name]
	if !ok {
		fmt.Printf("Screen profile '%s' not found\n", name)
		return nil
	}

	fmt.Printf("Screen object status (detail):\n\n")
	fmt.Printf("  %-45s %-12s %s\n", "Name", "Value", "Default")

	// TCP checks
	fmt.Printf("  %-45s %-12s %s\n", "TCP land attack",
		enabledStr(profile.TCP.Land), "disabled")
	fmt.Printf("  %-45s %-12s %s\n", "TCP SYN+FIN",
		enabledStr(profile.TCP.SynFin), "disabled")
	fmt.Printf("  %-45s %-12s %s\n", "TCP no-flag",
		enabledStr(profile.TCP.NoFlag), "disabled")
	fmt.Printf("  %-45s %-12s %s\n", "TCP FIN-no-ACK",
		enabledStr(profile.TCP.FinNoAck), "disabled")
	fmt.Printf("  %-45s %-12s %s\n", "TCP WinNuke",
		enabledStr(profile.TCP.WinNuke), "disabled")
	fmt.Printf("  %-45s %-12s %s\n", "TCP SYN fragment",
		enabledStr(profile.TCP.SynFrag), "disabled")

	if profile.TCP.SynFlood != nil {
		fmt.Printf("  %-45s %-12s %s\n", "TCP SYN flood protection", "enabled", "disabled")
		fmt.Printf("  %-45s %-12d %s\n", "  Attack threshold",
			profile.TCP.SynFlood.AttackThreshold, "200")
		if profile.TCP.SynFlood.AlarmThreshold > 0 {
			fmt.Printf("  %-45s %-12d %s\n", "  Alarm threshold",
				profile.TCP.SynFlood.AlarmThreshold, "512")
		} else {
			fmt.Printf("  %-45s %-12s %s\n", "  Alarm threshold", "(default)", "512")
		}
		if profile.TCP.SynFlood.SourceThreshold > 0 {
			fmt.Printf("  %-45s %-12d %s\n", "  Source threshold",
				profile.TCP.SynFlood.SourceThreshold, "4000")
		} else {
			fmt.Printf("  %-45s %-12s %s\n", "  Source threshold", "(default)", "4000")
		}
		if profile.TCP.SynFlood.DestinationThreshold > 0 {
			fmt.Printf("  %-45s %-12d %s\n", "  Destination threshold",
				profile.TCP.SynFlood.DestinationThreshold, "4000")
		} else {
			fmt.Printf("  %-45s %-12s %s\n", "  Destination threshold", "(default)", "4000")
		}
		if profile.TCP.SynFlood.Timeout > 0 {
			fmt.Printf("  %-45s %-12d %s\n", "  Timeout (seconds)",
				profile.TCP.SynFlood.Timeout, "20")
		} else {
			fmt.Printf("  %-45s %-12s %s\n", "  Timeout (seconds)", "(default)", "20")
		}
	} else {
		fmt.Printf("  %-45s %-12s %s\n", "TCP SYN flood protection", "disabled", "disabled")
	}

	// ICMP checks
	fmt.Printf("  %-45s %-12s %s\n", "ICMP ping of death",
		enabledStr(profile.ICMP.PingDeath), "disabled")
	if profile.ICMP.FloodThreshold > 0 {
		fmt.Printf("  %-45s %-12d %s\n", "ICMP flood threshold",
			profile.ICMP.FloodThreshold, "1000")
	} else {
		fmt.Printf("  %-45s %-12s %s\n", "ICMP flood threshold", "disabled", "disabled")
	}

	// IP checks
	fmt.Printf("  %-45s %-12s %s\n", "IP source route option",
		enabledStr(profile.IP.SourceRouteOption), "disabled")
	fmt.Printf("  %-45s %-12s %s\n", "IP teardrop",
		enabledStr(profile.IP.TearDrop), "disabled")

	// UDP checks
	if profile.UDP.FloodThreshold > 0 {
		fmt.Printf("  %-45s %-12d %s\n", "UDP flood threshold",
			profile.UDP.FloodThreshold, "1000")
	} else {
		fmt.Printf("  %-45s %-12s %s\n", "UDP flood threshold", "disabled", "disabled")
	}

	// Zones using this profile
	var zones []string
	for zname, zone := range cfg.Security.Zones {
		if zone.ScreenProfile == name {
			zones = append(zones, zname)
		}
	}
	if len(zones) > 0 {
		sort.Strings(zones)
		fmt.Printf("\n  Bound to zones: %s\n", strings.Join(zones, ", "))
	} else {
		fmt.Printf("\n  Bound to zones: (none)\n")
	}
	return nil
}

func (c *CLI) showScreenStatistics(zoneName string) error {
	cfg := c.store.ActiveConfig()
	if cfg == nil {
		fmt.Println("no active configuration")
		return nil
	}
	if c.dp == nil || !c.dp.IsLoaded() {
		fmt.Println("dataplane not loaded")
		return nil
	}
	cr := c.dp.LastCompileResult()
	if cr == nil {
		fmt.Println("no compile result available")
		return nil
	}
	zoneID, ok := cr.ZoneIDs[zoneName]
	if !ok {
		fmt.Printf("Zone '%s' not found\n", zoneName)
		return nil
	}
	fs, err := c.dp.ReadFloodCounters(zoneID)
	if err != nil {
		fmt.Printf("Error reading flood counters: %v\n", err)
		return nil
	}
	totalSyn, totalICMP, totalUDP := fs.SynCount, fs.ICMPCount, fs.UDPCount
	screenProfile := ""
	if z, ok := cfg.Security.Zones[zoneName]; ok {
		screenProfile = z.ScreenProfile
	}
	fmt.Printf("Screen statistics for zone '%s':\n", zoneName)
	if screenProfile != "" {
		fmt.Printf("  Screen profile: %s\n", screenProfile)
	}
	fmt.Printf("  %-30s %s\n", "Counter", "Value")
	fmt.Printf("  %-30s %d\n", "SYN flood events", totalSyn)
	fmt.Printf("  %-30s %d\n", "ICMP flood events", totalICMP)
	fmt.Printf("  %-30s %d\n", "UDP flood events", totalUDP)
	return nil
}

func (c *CLI) showStatistics(detail bool) error {
	if c.dp == nil || !c.dp.IsLoaded() {
		fmt.Println("Statistics: dataplane not loaded")
		return nil
	}

	readCounter := func(idx uint32) uint64 {
		v, _ := c.dp.ReadGlobalCounter(idx)
		return v
	}

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
		fmt.Printf("  %-25s %d\n", n.name+":", readCounter(n.idx))
	}

	if !detail {
		return nil
	}

	// Active session counts
	v4, v6 := c.dp.SessionCount()
	fmt.Printf("\nActive sessions:\n")
	fmt.Printf("  %-25s %d\n", "IPv4 sessions:", v4)
	fmt.Printf("  %-25s %d\n", "IPv6 sessions:", v6)
	fmt.Printf("  %-25s %d\n", "Total:", v4+v6)

	// Screen drops breakdown
	screenDrops := readCounter(dataplane.GlobalCtrScreenDrops)
	if screenDrops > 0 {
		fmt.Printf("\nScreen drop details:\n")
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
			{dataplane.GlobalCtrScreenTearDrop, "Teardrop"},
			{dataplane.GlobalCtrScreenTCPSynFin, "TCP SYN+FIN"},
			{dataplane.GlobalCtrScreenTCPNoFlag, "TCP no flag"},
			{dataplane.GlobalCtrScreenTCPFinNoAck, "TCP FIN no ACK"},
			{dataplane.GlobalCtrScreenWinNuke, "WinNuke"},
			{dataplane.GlobalCtrScreenIPSrcRoute, "IP source route"},
			{dataplane.GlobalCtrScreenSynFrag, "SYN fragment"},
		}
		for _, sc := range screenCounters {
			v := readCounter(sc.idx)
			if v > 0 {
				fmt.Printf("  %-25s %d\n", sc.name+":", v)
			}
		}
	}

	// Map utilization summary for key maps
	fmt.Printf("\nKey map utilization:\n")
	stats := c.dp.GetMapStats()
	for _, s := range stats {
		if s.MaxEntries > 0 && s.Type != "Array" && s.Type != "PerCPUArray" {
			pct := float64(s.UsedCount) / float64(s.MaxEntries) * 100
			flag := ""
			if pct >= 80 {
				flag = " !"
			}
			fmt.Printf("  %-24s %d/%d (%.1f%%)%s\n", s.Name+":", s.UsedCount, s.MaxEntries, pct, flag)
		}
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

	if strings.Contains(line, "| display xml") {
		fmt.Print(c.store.ShowCandidateXML())
		return nil
	}

	// Show scoped to edit path
	editPath := c.store.GetEditPath()
	if len(editPath) > 0 {
		// Build full path: editPath + any extra args (excluding pipe)
		fullPath := append([]string{}, editPath...)
		for _, a := range args {
			if a == "|" {
				break
			}
			fullPath = append(fullPath, a)
		}
		output := c.store.ShowCandidatePath(fullPath)
		if output == "" {
			fmt.Printf("configuration path not found: %s\n", strings.Join(fullPath, " "))
		} else {
			fmt.Print(output)
		}
		return nil
	}

	fmt.Print(c.store.ShowCandidate())
	return nil
}

func (c *CLI) handleCopyRename(parts []string) error {
	cmd := parts[0]
	toIdx := -1
	for i, p := range parts {
		if p == "to" {
			toIdx = i
			break
		}
	}
	if toIdx < 2 || toIdx >= len(parts)-1 {
		fmt.Printf("usage: %s <src-path> to <dst-path>\n", cmd)
		return nil
	}
	srcPath := parts[1:toIdx]
	dstPath := parts[toIdx+1:]
	editPath := c.store.GetEditPath()
	if len(editPath) > 0 {
		srcPath = append(append([]string{}, editPath...), srcPath...)
		dstPath = append(append([]string{}, editPath...), dstPath...)
	}
	if cmd == "rename" {
		return c.store.Rename(srcPath, dstPath)
	}
	return c.store.Copy(srcPath, dstPath)
}

func (c *CLI) handleLoad(args []string) error {
	if len(args) < 2 {
		fmt.Println("load:")
		fmt.Println("  override terminal    Replace candidate with pasted config")
		fmt.Println("  merge terminal       Merge pasted config into candidate")
		fmt.Println("  set terminal         Load set commands from terminal")
		fmt.Println("  override <file>      Replace candidate with file contents")
		fmt.Println("  merge <file>         Merge file contents into candidate")
		return nil
	}

	mode := args[0] // "override", "merge", or "set"
	if mode != "override" && mode != "merge" && mode != "set" {
		return fmt.Errorf("load: unknown mode %q (use 'override', 'merge', or 'set')", mode)
	}

	source := args[1]
	if mode == "set" && source != "terminal" {
		return fmt.Errorf("load set: only 'terminal' source is supported")
	}
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

	switch mode {
	case "set":
		count, err := c.store.LoadSet(content)
		if err != nil {
			return fmt.Errorf("load set: %w", err)
		}
		fmt.Printf("load set complete: %d commands applied\n", count)
		return nil
	default:
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

	if len(args) > 0 && args[0] == "comment" {
		if len(args) < 2 {
			return fmt.Errorf("usage: commit comment \"description\"")
		}
		desc := strings.Join(args[1:], " ")
		desc = strings.Trim(desc, "\"'")

		diffSummary := c.store.CommitDiffSummary()

		compiled, err := c.store.CommitWithDescription(desc)
		if err != nil {
			return fmt.Errorf("commit failed: %w", err)
		}

		if c.dp != nil {
			if err := c.applyToDataplane(compiled); err != nil {
				fmt.Fprintf(os.Stderr, "warning: dataplane apply failed: %v\n", err)
			}
		}
		c.reloadSyslog(compiled)
		c.refreshPrompt()

		if diffSummary != "" {
			fmt.Printf("commit complete: %s\n", diffSummary)
		} else {
			fmt.Println("commit complete")
		}
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
		c.refreshPrompt()

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

	// Capture diff summary before commit (active will change)
	diffSummary := c.store.CommitDiffSummary()

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
	c.refreshPrompt()

	if diffSummary != "" {
		fmt.Printf("commit complete: %s\n", diffSummary)
	} else {
		fmt.Println("commit complete")
	}
	return nil
}

// refreshPrompt re-reads the system hostname and updates the readline prompt.
func (c *CLI) refreshPrompt() {
	if h, err := os.Hostname(); err == nil && h != "" {
		c.hostname = h
	}
	if c.rl != nil {
		if c.store.InConfigMode() {
			c.rl.SetPrompt(c.configPrompt())
		} else {
			c.rl.SetPrompt(c.operationalPrompt())
		}
	}
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
			OSPFv3:       cfg.Protocols.OSPFv3,
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
				OSPFv3:       ri.OSPFv3,
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

// builtinApp defines a well-known Junos application by protocol and port.
type builtinApp struct {
	proto uint8
	port  uint16
}

// builtinApps maps Junos application names to protocol/port.
var builtinApps = map[string]builtinApp{
	"junos-http":        {proto: 6, port: 80},
	"junos-https":       {proto: 6, port: 443},
	"junos-ssh":         {proto: 6, port: 22},
	"junos-telnet":      {proto: 6, port: 23},
	"junos-ftp":         {proto: 6, port: 21},
	"junos-smtp":        {proto: 6, port: 25},
	"junos-dns-tcp":     {proto: 6, port: 53},
	"junos-dns-udp":     {proto: 17, port: 53},
	"junos-bgp":         {proto: 6, port: 179},
	"junos-ntp":         {proto: 17, port: 123},
	"junos-snmp":        {proto: 17, port: 161},
	"junos-syslog":      {proto: 17, port: 514},
	"junos-dhcp-client": {proto: 17, port: 68},
	"junos-ike":         {proto: 17, port: 500},
	"junos-ipsec-nat-t": {proto: 17, port: 4500},
}

// resolveAppName resolves a session's protocol and destination port to a
// known application name, checking user-defined apps first then builtins.
func resolveAppName(proto uint8, dstPort uint16, cfg *config.Config) string {
	if cfg != nil {
		for name, app := range cfg.Applications.Applications {
			var appProto uint8
			switch strings.ToLower(app.Protocol) {
			case "tcp":
				appProto = 6
			case "udp":
				appProto = 17
			case "icmp":
				appProto = 1
			default:
				continue
			}
			if appProto != proto {
				continue
			}
			// Parse destination port (handle ranges like "8080-8090")
			portStr := app.DestinationPort
			if portStr == "" {
				continue
			}
			if strings.Contains(portStr, "-") {
				parts := strings.SplitN(portStr, "-", 2)
				lo, err1 := strconv.Atoi(parts[0])
				hi, err2 := strconv.Atoi(parts[1])
				if err1 == nil && err2 == nil && int(dstPort) >= lo && int(dstPort) <= hi {
					return name
				}
			} else {
				if v, err := strconv.Atoi(portStr); err == nil && uint16(v) == dstPort {
					return name
				}
			}
		}
	}
	for name, ba := range builtinApps {
		if ba.proto == proto && ba.port == dstPort {
			return name
		}
	}
	return ""
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
	summary bool           // only show count
	brief   bool           // compact tabular view
	appName string         // application name filter
	sortBy  string         // "bytes" or "packets" for top-talkers
	cfg     *config.Config // for application resolution
}

func (c *CLI) parseSessionFilter(args []string) sessionFilter {
	var f sessionFilter
	f.cfg = c.store.ActiveConfig()
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
				// Resolve interface name to zone ID for session filtering.
				if f.cfg != nil && c.dp != nil {
					if cr := c.dp.LastCompileResult(); cr != nil {
						for zname, zone := range f.cfg.Security.Zones {
							for _, ifRef := range zone.Interfaces {
								if ifRef == f.iface || strings.HasPrefix(ifRef, f.iface+".") {
									if zid, ok := cr.ZoneIDs[zname]; ok && f.zoneID == 0 {
										f.zoneID = zid
									}
								}
							}
						}
					}
				}
			}
		case "application":
			if i+1 < len(args) {
				i++
				f.appName = args[i]
			}
		case "summary":
			f.summary = true
		case "brief":
			f.brief = true
		case "sort-by":
			if i+1 < len(args) {
				i++
				f.sortBy = args[i] // "bytes" or "packets"
			}
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
	if f.appName != "" {
		if resolveAppName(key.Protocol, ntohs(key.DstPort), f.cfg) != f.appName {
			return false
		}
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
	if f.appName != "" {
		if resolveAppName(key.Protocol, ntohs(key.DstPort), f.cfg) != f.appName {
			return false
		}
	}
	return true
}

func (f *sessionFilter) hasFilter() bool {
	return f.zoneID != 0 || f.proto != 0 || f.srcNet != nil || f.dstNet != nil ||
		f.srcPort != 0 || f.dstPort != 0 || f.natOnly || f.iface != "" || f.appName != ""
}

func (c *CLI) showFlowSession(args []string) error {
	if c.dp == nil || !c.dp.IsLoaded() {
		fmt.Println("Session table: dataplane not loaded")
		return nil
	}

	f := c.parseSessionFilter(args)

	// Top-talkers mode: collect, sort, display top 20
	if f.sortBy == "bytes" || f.sortBy == "packets" {
		return c.showTopTalkers(f)
	}

	count := 0

	// Summary counters for protocol/zone/NAT breakdown
	var byProto map[uint8]int
	var byZonePair map[string]int
	var v4Count, v6Count, natCount int
	if f.summary {
		byProto = make(map[uint8]int)
		byZonePair = make(map[string]int)
	}

	if f.brief {
		fmt.Printf("%-5s %-22s %-22s %-5s %-20s %-3s %-5s %5s %s\n",
			"ID", "Source", "Destination", "Proto", "Zone", "NAT", "State", "Age", "Pkts(f/r)")
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

		inZone := zoneNames[val.IngressZone]
		outZone := zoneNames[val.EgressZone]
		if inZone == "" {
			inZone = fmt.Sprintf("%d", val.IngressZone)
		}
		if outZone == "" {
			outZone = fmt.Sprintf("%d", val.EgressZone)
		}

		if f.brief {
			natFlag := " "
			if val.Flags&dataplane.SessFlagSNAT != 0 {
				natFlag = "S"
			}
			if val.Flags&dataplane.SessFlagDNAT != 0 {
				natFlag = "D"
			}
			if val.Flags&(dataplane.SessFlagSNAT|dataplane.SessFlagDNAT) == (dataplane.SessFlagSNAT | dataplane.SessFlagDNAT) {
				natFlag = "B"
			}
			var age uint64
			if now > val.Created {
				age = now - val.Created
			}
			fmt.Printf("%-5d %-22s %-22s %-5s %-20s %-3s %-5s %5d %d/%d\n",
				count,
				fmt.Sprintf("%s:%d", srcIP, srcPort),
				fmt.Sprintf("%s:%d", dstIP, dstPort),
				protoName, inZone+"->"+outZone, natFlag,
				stateName[:min(5, len(stateName))], age,
				val.FwdPackets, val.RevPackets)
			return true
		}

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

		if appName := resolveAppName(key.Protocol, dstPort, f.cfg); appName != "" {
			fmt.Printf("  Application: %s\n", appName)
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

		inZone := zoneNames[val.IngressZone]
		outZone := zoneNames[val.EgressZone]
		if inZone == "" {
			inZone = fmt.Sprintf("%d", val.IngressZone)
		}
		if outZone == "" {
			outZone = fmt.Sprintf("%d", val.EgressZone)
		}

		if f.brief {
			natFlag := " "
			if val.Flags&dataplane.SessFlagSNAT != 0 {
				natFlag = "S"
			}
			if val.Flags&dataplane.SessFlagDNAT != 0 {
				natFlag = "D"
			}
			if val.Flags&(dataplane.SessFlagSNAT|dataplane.SessFlagDNAT) == (dataplane.SessFlagSNAT | dataplane.SessFlagDNAT) {
				natFlag = "B"
			}
			var age uint64
			if now > val.Created {
				age = now - val.Created
			}
			fmt.Printf("%-5d %-22s %-22s %-5s %-20s %-3s %-5s %5d %d/%d\n",
				count,
				fmt.Sprintf("[%s]:%d", srcIP, srcPort),
				fmt.Sprintf("[%s]:%d", dstIP, dstPort),
				protoName, inZone+"->"+outZone, natFlag,
				stateName[:min(5, len(stateName))], age,
				val.FwdPackets, val.RevPackets)
			return true
		}

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

		if appName := resolveAppName(key.Protocol, dstPort, f.cfg); appName != "" {
			fmt.Printf("  Application: %s\n", appName)
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

// topTalkerEntry holds a session's display info for sorting.
type topTalkerEntry struct {
	src, dst, proto, zone, state, app string
	fwdPkts, revPkts                  uint64
	fwdBytes, revBytes                uint64
	age                               uint64
}

func (c *CLI) showTopTalkers(f sessionFilter) error {
	zoneNames := make(map[uint16]string)
	if cr := c.dp.LastCompileResult(); cr != nil {
		for name, id := range cr.ZoneIDs {
			zoneNames[id] = name
		}
	}
	now := monotonicSeconds()
	var entries []topTalkerEntry

	_ = c.dp.IterateSessions(func(key dataplane.SessionKey, val dataplane.SessionValue) bool {
		if val.IsReverse != 0 {
			return true
		}
		if f.hasFilter() && !f.matchesV4(key, val) {
			return true
		}
		srcIP := net.IP(key.SrcIP[:])
		dstIP := net.IP(key.DstIP[:])
		inZone := zoneNames[val.IngressZone]
		outZone := zoneNames[val.EgressZone]
		if inZone == "" {
			inZone = fmt.Sprintf("%d", val.IngressZone)
		}
		if outZone == "" {
			outZone = fmt.Sprintf("%d", val.EgressZone)
		}
		var age uint64
		if now > val.Created {
			age = now - val.Created
		}
		entries = append(entries, topTalkerEntry{
			src:      fmt.Sprintf("%s:%d", srcIP, ntohs(key.SrcPort)),
			dst:      fmt.Sprintf("%s:%d", dstIP, ntohs(key.DstPort)),
			proto:    protoNameFromNum(key.Protocol),
			zone:     inZone + "->" + outZone,
			state:    sessionStateName(val.State),
			app:      resolveAppName(key.Protocol, ntohs(key.DstPort), f.cfg),
			fwdPkts:  val.FwdPackets,
			revPkts:  val.RevPackets,
			fwdBytes: val.FwdBytes,
			revBytes: val.RevBytes,
			age:      age,
		})
		return true
	})

	_ = c.dp.IterateSessionsV6(func(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
		if val.IsReverse != 0 {
			return true
		}
		if f.hasFilter() && !f.matchesV6(key, val) {
			return true
		}
		srcIP := net.IP(key.SrcIP[:])
		dstIP := net.IP(key.DstIP[:])
		inZone := zoneNames[val.IngressZone]
		outZone := zoneNames[val.EgressZone]
		if inZone == "" {
			inZone = fmt.Sprintf("%d", val.IngressZone)
		}
		if outZone == "" {
			outZone = fmt.Sprintf("%d", val.EgressZone)
		}
		var age uint64
		if now > val.Created {
			age = now - val.Created
		}
		entries = append(entries, topTalkerEntry{
			src:      fmt.Sprintf("[%s]:%d", srcIP, ntohs(key.SrcPort)),
			dst:      fmt.Sprintf("[%s]:%d", dstIP, ntohs(key.DstPort)),
			proto:    protoNameFromNum(key.Protocol),
			zone:     inZone + "->" + outZone,
			state:    sessionStateName(val.State),
			app:      resolveAppName(key.Protocol, ntohs(key.DstPort), f.cfg),
			fwdPkts:  val.FwdPackets,
			revPkts:  val.RevPackets,
			fwdBytes: val.FwdBytes,
			revBytes: val.RevBytes,
			age:      age,
		})
		return true
	})

	if f.sortBy == "bytes" {
		sort.Slice(entries, func(i, j int) bool {
			return (entries[i].fwdBytes + entries[i].revBytes) > (entries[j].fwdBytes + entries[j].revBytes)
		})
	} else {
		sort.Slice(entries, func(i, j int) bool {
			return (entries[i].fwdPkts + entries[i].revPkts) > (entries[j].fwdPkts + entries[j].revPkts)
		})
	}

	limit := 20
	if limit > len(entries) {
		limit = len(entries)
	}

	fmt.Printf("Top %d sessions by %s (of %d total):\n", limit, f.sortBy, len(entries))
	fmt.Printf("%-5s %-22s %-22s %-5s %-20s %12s %12s %5s %s\n",
		"#", "Source", "Destination", "Proto", "Zone", "Bytes(f/r)", "Pkts(f/r)", "Age", "App")
	for i := 0; i < limit; i++ {
		e := entries[i]
		fmt.Printf("%-5d %-22s %-22s %-5s %-20s %5d/%-6d %5d/%-6d %5d %s\n",
			i+1, e.src, e.dst, e.proto, e.zone,
			e.fwdBytes, e.revBytes, e.fwdPkts, e.revPkts, e.age, e.app)
	}
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
	if flow.TCPMSSIPsecVPN > 0 || flow.TCPMSSGreIn > 0 || flow.TCPMSSGreOut > 0 {
		fmt.Println()
		fmt.Println("TCP MSS clamping:")
		if flow.TCPMSSIPsecVPN > 0 {
			fmt.Printf("  %-30s %d\n", "IPsec VPN MSS:", flow.TCPMSSIPsecVPN)
		}
		if flow.TCPMSSGreIn > 0 {
			fmt.Printf("  %-30s %d\n", "GRE ingress MSS:", flow.TCPMSSGreIn)
		}
		if flow.TCPMSSGreOut > 0 {
			fmt.Printf("  %-30s %d\n", "GRE egress MSS:", flow.TCPMSSGreOut)
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

	readCounter := func(idx uint32) uint64 {
		v, _ := c.dp.ReadGlobalCounter(idx)
		return v
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
	clearTree := operationalTree["clear"].Children
	showHelp := func() {
		fmt.Println("clear:")
		writeCompletionHelp(os.Stdout, treeHelpCandidates(clearTree))
	}
	if len(args) < 1 {
		showHelp()
		return nil
	}

	switch args[0] {
	case "arp":
		return c.handleClearArp()
	case "ipv6":
		return c.handleClearIPv6(args[1:])
	case "security":
		return c.handleClearSecurity(args[1:])
	case "firewall":
		return c.handleClearFirewall(args[1:])
	case "dhcp":
		return c.handleClearDHCP(args[1:])
	case "interfaces":
		return c.handleClearInterfaces(args[1:])
	default:
		showHelp()
		return nil
	}
}

func (c *CLI) handleClearInterfaces(args []string) error {
	if len(args) >= 1 && args[0] == "statistics" {
		fmt.Println("Interface statistics counters noted")
		fmt.Println("(kernel counters are cumulative and cannot be reset)")
		return nil
	}
	cmdtree.PrintTreeHelp("clear interfaces:", operationalTree, "clear", "interfaces")
	return nil
}

func (c *CLI) handleClearArp() error {
	out, err := exec.Command("ip", "-4", "neigh", "flush", "all").CombinedOutput()
	if err != nil {
		return fmt.Errorf("flush ARP: %s", strings.TrimSpace(string(out)))
	}
	fmt.Println("ARP cache cleared")
	return nil
}

func (c *CLI) handleClearIPv6(args []string) error {
	if len(args) < 1 || args[0] != "neighbors" {
		cmdtree.PrintTreeHelp("clear ipv6:", operationalTree, "clear", "ipv6")
		return nil
	}
	out, err := exec.Command("ip", "-6", "neigh", "flush", "all").CombinedOutput()
	if err != nil {
		return fmt.Errorf("flush IPv6 neighbors: %s", strings.TrimSpace(string(out)))
	}
	fmt.Println("IPv6 neighbor cache cleared")
	return nil
}

func (c *CLI) handleClearSecurity(args []string) error {
	if len(args) < 1 {
		fmt.Println("clear security:")
		writeCompletionHelp(os.Stdout, treeHelpCandidates(operationalTree["clear"].Children["security"].Children))
		return nil
	}

	switch args[0] {
	case "nat":
		if len(args) >= 3 && args[1] == "source" && args[2] == "persistent-nat-table" {
			return c.clearPersistentNAT()
		}
		if len(args) >= 2 && args[1] == "statistics" {
			if c.dp == nil || !c.dp.IsLoaded() {
				fmt.Println("dataplane not loaded")
				return nil
			}
			if err := c.dp.ClearNATRuleCounters(); err != nil {
				return fmt.Errorf("clear NAT counters: %w", err)
			}
			fmt.Println("NAT translation statistics cleared")
			return nil
		}
		cmdtree.PrintTreeHelp("clear security nat:", operationalTree, "clear", "security", "nat")
		return nil
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
		cmdtree.PrintTreeHelp("clear security:", operationalTree, "clear", "security")
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
		cmdtree.PrintTreeHelp("clear firewall:", operationalTree, "clear", "firewall")
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
		cmdtree.PrintTreeHelp("clear dhcp:", operationalTree, "clear", "dhcp")
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
		writeCompletionHelp(os.Stdout, treeHelpCandidates(operationalTree["show"].Children["security"].Children["nat"].Children))
		return nil
	}

	switch args[0] {
	case "source":
		if len(args) >= 2 && args[1] == "persistent-nat-table" {
			if len(args) >= 3 && args[2] == "detail" {
				return c.showPersistentNATDetail()
			}
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
			if len(args) > 1 && args[1] == "detail" {
				return c.showNATSourceRuleDetail(cfg)
			}
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
	if allocFails, err := c.dp.ReadGlobalCounter(dataplane.GlobalCtrNATAllocFail); err == nil {
		fmt.Printf("NAT allocation failures: %d\n", allocFails)
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

	// Count active SNAT translations and per-rule-set sessions
	totalSNAT := 0
	type ruleSetKey struct{ from, to string }
	rsSessionsV4 := make(map[ruleSetKey]int)
	if c.dp != nil && c.dp.IsLoaded() {
		cr := c.dp.LastCompileResult()
		// Build reverse zone ID map
		var zoneByID map[uint16]string
		if cr != nil {
			zoneByID = make(map[uint16]string, len(cr.ZoneIDs))
			for name, id := range cr.ZoneIDs {
				zoneByID[id] = name
			}
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
		// Count SNAT sessions per zone pair
		_ = c.dp.IterateSessions(func(_ dataplane.SessionKey, val dataplane.SessionValue) bool {
			if val.IsReverse == 0 && val.Flags&dataplane.SessFlagSNAT != 0 {
				totalSNAT++
				if zoneByID != nil {
					rsSessionsV4[ruleSetKey{zoneByID[val.IngressZone], zoneByID[val.EgressZone]}]++
				}
			}
			return true
		})
		// Count IPv6 SNAT sessions
		_ = c.dp.IterateSessionsV6(func(_ dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
			if val.IsReverse == 0 && val.Flags&dataplane.SessFlagSNAT != 0 {
				totalSNAT++
				if zoneByID != nil {
					rsSessionsV4[ruleSetKey{zoneByID[val.IngressZone], zoneByID[val.EgressZone]}]++
				}
			}
			return true
		})
		for i := range pools {
			if pools[i].isIface {
				pools[i].used = totalSNAT // interface NAT counts all SNAT sessions
			}
		}
	}

	fmt.Printf("Total active translations: %d\n", totalSNAT)
	fmt.Printf("Total pools: %d\n", len(pools))
	fmt.Println()
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

	// Per-rule-set session counts
	if len(rsSessionsV4) > 0 {
		fmt.Println()
		fmt.Printf("%-30s %-12s\n", "Rule-set (from -> to)", "Sessions")
		for _, rs := range cfg.Security.NAT.Source {
			key := ruleSetKey{rs.FromZone, rs.ToZone}
			if cnt, ok := rsSessionsV4[key]; ok {
				fmt.Printf("%-30s %-12d\n",
					fmt.Sprintf("%s -> %s", rs.FromZone, rs.ToZone), cnt)
			}
		}
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

// showNATSourceRuleDetail displays Junos-style detailed source NAT rules.
func (c *CLI) showNATSourceRuleDetail(cfg *config.Config) error {
	if cfg == nil || len(cfg.Security.NAT.Source) == 0 {
		fmt.Println("No source NAT rules configured")
		return nil
	}

	// Count active SNAT sessions per rule-set
	type ruleSetKey struct{ from, to string }
	rsSessions := make(map[ruleSetKey]int)
	if c.dp != nil && c.dp.IsLoaded() && c.dp.LastCompileResult() != nil {
		cr := c.dp.LastCompileResult()
		zoneByID := make(map[uint16]string, len(cr.ZoneIDs))
		for name, id := range cr.ZoneIDs {
			zoneByID[id] = name
		}
		_ = c.dp.IterateSessions(func(_ dataplane.SessionKey, val dataplane.SessionValue) bool {
			if val.IsReverse == 0 && val.Flags&dataplane.SessFlagSNAT != 0 {
				rsSessions[ruleSetKey{zoneByID[val.IngressZone], zoneByID[val.EgressZone]}]++
			}
			return true
		})
	}

	ruleIdx := 0
	for _, rs := range cfg.Security.NAT.Source {
		for _, rule := range rs.Rules {
			ruleIdx++
			action := "interface"
			if rule.Then.PoolName != "" {
				action = "pool " + rule.Then.PoolName
			} else if rule.Then.Off {
				action = "off"
			}
			srcMatch := "0.0.0.0/0"
			if rule.Match.SourceAddress != "" {
				srcMatch = rule.Match.SourceAddress
			}
			dstMatch := "0.0.0.0/0"
			if rule.Match.DestinationAddress != "" {
				dstMatch = rule.Match.DestinationAddress
			}

			fmt.Printf("source NAT rule: %s\n", rule.Name)
			fmt.Printf("  Rule-set: %s                        ID: %d\n", rs.Name, ruleIdx)
			fmt.Printf("    From zone: %s    To zone: %s\n", rs.FromZone, rs.ToZone)
			fmt.Printf("    Match:\n")
			fmt.Printf("      Source addresses:      %s\n", srcMatch)
			fmt.Printf("      Destination addresses: %s\n", dstMatch)
			if rule.Match.Protocol != "" {
				fmt.Printf("      IP protocol:           %s\n", rule.Match.Protocol)
			}
			fmt.Printf("    Action:                  %s\n", action)

			if rule.Then.PoolName != "" && cfg.Security.NAT.SourcePools != nil {
				if pool, ok := cfg.Security.NAT.SourcePools[rule.Then.PoolName]; ok {
					if pool.PersistentNAT != nil {
						fmt.Printf("    Persistent NAT:          enabled\n")
					}
					if len(pool.Addresses) > 0 {
						fmt.Printf("    Pool addresses:          %s\n", strings.Join(pool.Addresses, ", "))
					}
					portLow, portHigh := pool.PortLow, pool.PortHigh
					if portLow == 0 {
						portLow = 1024
					}
					if portHigh == 0 {
						portHigh = 65535
					}
					fmt.Printf("    Port range:              %d-%d\n", portLow, portHigh)
				}
			}

			if c.dp != nil && c.dp.LastCompileResult() != nil {
				ruleKey := rs.Name + "/" + rule.Name
				if cid, ok := c.dp.LastCompileResult().NATCounterIDs[ruleKey]; ok {
					cnt, err := c.dp.ReadNATRuleCounter(uint32(cid))
					if err == nil {
						fmt.Printf("    Translation hits:        %d packets  %d bytes\n",
							cnt.Packets, cnt.Bytes)
					}
				}
			}

			sessions := rsSessions[ruleSetKey{rs.FromZone, rs.ToZone}]
			fmt.Printf("    Number of sessions:      %d\n", sessions)
			fmt.Println()
		}
	}
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
			if len(args) > 1 && args[1] == "detail" {
				return c.showNATDestinationRuleDetail(cfg)
			}
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

	// Count active DNAT sessions per pool and per rule-set
	poolHits := make(map[string]int)
	totalDNAT := 0
	type ruleSetKey struct{ from, to string }
	rsSessions := make(map[ruleSetKey]int)

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
						poolHits[rule.Then.PoolName] += int(cnt.Packets)
					}
				}
			}
		}

		// Count active DNAT sessions by iterating sessions
		zoneByID := make(map[uint16]string, len(cr.ZoneIDs))
		for name, id := range cr.ZoneIDs {
			zoneByID[id] = name
		}
		_ = c.dp.IterateSessions(func(_ dataplane.SessionKey, val dataplane.SessionValue) bool {
			if val.IsReverse == 0 && val.Flags&dataplane.SessFlagDNAT != 0 {
				totalDNAT++
				rsSessions[ruleSetKey{zoneByID[val.IngressZone], zoneByID[val.EgressZone]}]++
			}
			return true
		})
		_ = c.dp.IterateSessionsV6(func(_ dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
			if val.IsReverse == 0 && val.Flags&dataplane.SessFlagDNAT != 0 {
				totalDNAT++
				rsSessions[ruleSetKey{zoneByID[val.IngressZone], zoneByID[val.EgressZone]}]++
			}
			return true
		})
	}

	fmt.Printf("Total active translations: %d\n", totalDNAT)
	fmt.Printf("Total pools: %d\n", len(dnat.Pools))
	fmt.Println()
	fmt.Printf("%-20s %-20s %-8s %-12s\n",
		"Pool", "Address", "Port", "Hits")
	for name, pool := range dnat.Pools {
		portStr := "-"
		if pool.Port != 0 {
			portStr = fmt.Sprintf("%d", pool.Port)
		}
		hits := poolHits[name]
		fmt.Printf("%-20s %-20s %-8s %-12d\n",
			name, pool.Address, portStr, hits)
	}

	// Per-rule-set session counts
	if len(rsSessions) > 0 {
		fmt.Println()
		fmt.Printf("%-30s %-12s\n", "Rule-set (from -> to)", "Sessions")
		for _, rs := range dnat.RuleSets {
			key := ruleSetKey{rs.FromZone, rs.ToZone}
			if cnt, ok := rsSessions[key]; ok {
				fmt.Printf("%-30s %-12d\n",
					fmt.Sprintf("%s -> %s", rs.FromZone, rs.ToZone), cnt)
			}
		}
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

// showNATDestinationRuleDetail displays Junos-style detailed destination NAT rules.
func (c *CLI) showNATDestinationRuleDetail(cfg *config.Config) error {
	dnat := cfg.Security.NAT.Destination
	if dnat == nil || len(dnat.RuleSets) == 0 {
		fmt.Println("No destination NAT rules configured")
		return nil
	}

	// Count active DNAT sessions per rule-set
	type ruleSetKey struct{ from, to string }
	rsSessions := make(map[ruleSetKey]int)
	if c.dp != nil && c.dp.IsLoaded() && c.dp.LastCompileResult() != nil {
		cr := c.dp.LastCompileResult()
		zoneByID := make(map[uint16]string, len(cr.ZoneIDs))
		for name, id := range cr.ZoneIDs {
			zoneByID[id] = name
		}
		_ = c.dp.IterateSessions(func(_ dataplane.SessionKey, val dataplane.SessionValue) bool {
			if val.IsReverse == 0 && val.Flags&dataplane.SessFlagDNAT != 0 {
				rsSessions[ruleSetKey{zoneByID[val.IngressZone], zoneByID[val.EgressZone]}]++
			}
			return true
		})
	}

	ruleIdx := 0
	for _, rs := range dnat.RuleSets {
		for _, rule := range rs.Rules {
			ruleIdx++
			action := "off"
			if rule.Then.PoolName != "" {
				action = "pool " + rule.Then.PoolName
			}
			dstMatch := "0.0.0.0/0"
			if rule.Match.DestinationAddress != "" {
				dstMatch = rule.Match.DestinationAddress
			}

			fmt.Printf("destination NAT rule: %s\n", rule.Name)
			fmt.Printf("  Rule-set: %s                        ID: %d\n", rs.Name, ruleIdx)
			fmt.Printf("    From zone: %s    To zone: %s\n", rs.FromZone, rs.ToZone)
			fmt.Printf("    Match:\n")
			fmt.Printf("      Destination addresses: %s\n", dstMatch)
			if rule.Match.DestinationPort != 0 {
				fmt.Printf("      Destination port:      %d\n", rule.Match.DestinationPort)
			}
			if rule.Match.Protocol != "" {
				fmt.Printf("      IP protocol:           %s\n", rule.Match.Protocol)
			}
			if rule.Match.Application != "" {
				fmt.Printf("      Application:           %s\n", rule.Match.Application)
			}
			fmt.Printf("    Action:                  %s\n", action)

			if rule.Then.PoolName != "" && dnat.Pools != nil {
				if pool, ok := dnat.Pools[rule.Then.PoolName]; ok {
					fmt.Printf("    Pool address:            %s\n", pool.Address)
					if pool.Port != 0 {
						fmt.Printf("    Pool port:               %d\n", pool.Port)
					}
				}
			}

			if c.dp != nil && c.dp.LastCompileResult() != nil {
				ruleKey := rs.Name + "/" + rule.Name
				if cid, ok := c.dp.LastCompileResult().NATCounterIDs[ruleKey]; ok {
					cnt, err := c.dp.ReadNATRuleCounter(uint32(cid))
					if err == nil {
						fmt.Printf("    Translation hits:        %d packets  %d bytes\n",
							cnt.Packets, cnt.Bytes)
					}
				}
			}

			sessions := rsSessions[ruleSetKey{rs.FromZone, rs.ToZone}]
			fmt.Printf("    Number of sessions:      %d\n", sessions)
			fmt.Println()
		}
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
	if len(args) >= 1 && args[0] == "terse" {
		return c.showRouteTerse()
	}
	if len(args) >= 1 && args[0] == "summary" {
		return c.showRouteSummary()
	}
	if len(args) >= 1 && args[0] == "detail" {
		return c.showRouteDetail()
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

func (c *CLI) showRouteTerse() error {
	if c.routing == nil {
		fmt.Println("Routing manager not available")
		return nil
	}
	entries, err := c.routing.GetRoutes()
	if err != nil {
		return fmt.Errorf("get routes: %w", err)
	}
	fmt.Print(routing.FormatRouteTerse(entries))
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

	// Determine router ID from config (OSPF or BGP)
	routerID := ""
	cfg := c.store.ActiveConfig()
	if cfg != nil {
		if cfg.Protocols.OSPF != nil && cfg.Protocols.OSPF.RouterID != "" {
			routerID = cfg.Protocols.OSPF.RouterID
		} else if cfg.Protocols.BGP != nil && cfg.Protocols.BGP.RouterID != "" {
			routerID = cfg.Protocols.BGP.RouterID
		}
	}
	if routerID != "" {
		fmt.Printf("Router ID: %s\n\n", routerID)
	}

	// Count by protocol and address family
	v4ByProto := make(map[string]int)
	v6ByProto := make(map[string]int)
	var v4Count, v6Count int
	for _, e := range entries {
		if strings.Contains(e.Destination, ":") {
			v6Count++
			v6ByProto[e.Protocol]++
		} else {
			v4Count++
			v4ByProto[e.Protocol]++
		}
	}

	// Print inet.0 summary
	fmt.Printf("inet.0: %d destinations, %d routes (%d active)\n", v4Count, v4Count, v4Count)
	v4Protos := make([]string, 0, len(v4ByProto))
	for p := range v4ByProto {
		v4Protos = append(v4Protos, p)
	}
	sort.Strings(v4Protos)
	for _, p := range v4Protos {
		fmt.Printf("  %-14s %d routes, %d active\n", p+":", v4ByProto[p], v4ByProto[p])
	}

	if v6Count > 0 {
		fmt.Println()
		fmt.Printf("inet6.0: %d destinations, %d routes (%d active)\n", v6Count, v6Count, v6Count)
		v6Protos := make([]string, 0, len(v6ByProto))
		for p := range v6ByProto {
			v6Protos = append(v6Protos, p)
		}
		sort.Strings(v6Protos)
		for _, p := range v6Protos {
			fmt.Printf("  %-14s %d routes, %d active\n", p+":", v6ByProto[p], v6ByProto[p])
		}
	}

	return nil
}

func (c *CLI) showRouteDetail() error {
	if c.frr == nil {
		fmt.Println("FRR manager not available")
		return nil
	}

	routes, err := c.frr.GetRouteDetailJSON()
	if err != nil {
		return fmt.Errorf("get route detail: %w", err)
	}

	if len(routes) == 0 {
		fmt.Println("No routes")
		return nil
	}

	fmt.Print(frr.FormatRouteDetail(routes))
	return nil
}

func (c *CLI) handleShowProtocols(args []string) error {
	if len(args) == 0 {
		cmdtree.PrintTreeHelp("show protocols:", operationalTree, "show", "protocols")
		return nil
	}

	switch args[0] {
	case "ospf":
		return c.showOSPF(args[1:])
	case "bgp":
		return c.showBGP(args[1:])
	case "bfd":
		return c.showBFD(args[1:])
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
		cmdtree.PrintTreeHelp("show protocols ospf:", operationalTree, "show", "protocols", "ospf")
		return nil
	}

	switch args[0] {
	case "neighbor":
		if len(args) >= 2 && args[1] == "detail" {
			output, err := c.frr.GetOSPFNeighborDetail()
			if err != nil {
				return fmt.Errorf("OSPF neighbor detail: %w", err)
			}
			fmt.Print(output)
			return nil
		}
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

	case "interface":
		output, err := c.frr.GetOSPFInterface()
		if err != nil {
			return fmt.Errorf("OSPF interface: %w", err)
		}
		fmt.Print(output)
		return nil

	case "routes":
		output, err := c.frr.GetOSPFRoutes()
		if err != nil {
			return fmt.Errorf("OSPF routes: %w", err)
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
		cmdtree.PrintTreeHelp("show protocols bgp:", operationalTree, "show", "protocols", "bgp")
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

	case "neighbor":
		ip := ""
		if len(args) >= 2 {
			ip = args[1]
		}
		// Check for sub-commands: received-routes, advertised-routes
		if len(args) >= 3 {
			switch args[2] {
			case "received-routes":
				output, err := c.frr.GetBGPNeighborReceivedRoutes(ip)
				if err != nil {
					return fmt.Errorf("BGP received routes: %w", err)
				}
				fmt.Print(output)
				return nil
			case "advertised-routes":
				output, err := c.frr.GetBGPNeighborAdvertisedRoutes(ip)
				if err != nil {
					return fmt.Errorf("BGP advertised routes: %w", err)
				}
				fmt.Print(output)
				return nil
			}
		}
		output, err := c.frr.GetBGPNeighborDetail(ip)
		if err != nil {
			return fmt.Errorf("BGP neighbor: %w", err)
		}
		fmt.Print(output)
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

	if len(args) > 0 && args[0] == "statistics" {
		return c.showIPsecStatistics()
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

func (c *CLI) showIPsecStatistics() error {
	if c.ipsec == nil {
		fmt.Println("IPsec manager not available")
		return nil
	}
	sas, err := c.ipsec.GetSAStatus()
	if err != nil {
		return fmt.Errorf("IPsec statistics: %w", err)
	}

	activeTunnels := 0
	for _, sa := range sas {
		if sa.State == "ESTABLISHED" || sa.State == "INSTALLED" {
			activeTunnels++
		}
	}

	fmt.Println("IPsec statistics:")
	fmt.Printf("  Active tunnels: %d\n", activeTunnels)
	fmt.Printf("  Total SAs:      %d\n", len(sas))
	fmt.Println()

	if len(sas) > 0 {
		fmt.Printf("  %-20s %-14s %-12s %-12s\n", "Name", "State", "Bytes In", "Bytes Out")
		for _, sa := range sas {
			inBytes := sa.InBytes
			if inBytes == "" {
				inBytes = "-"
			}
			outBytes := sa.OutBytes
			if outBytes == "" {
				outBytes = "-"
			}
			fmt.Printf("  %-20s %-14s %-12s %-12s\n", sa.Name, sa.State, inBytes, outBytes)
		}
	}

	// Show configured VPN count
	cfg := c.store.ActiveConfig()
	if cfg != nil && len(cfg.Security.IPsec.VPNs) > 0 {
		fmt.Printf("\n  Configured VPNs: %d\n", len(cfg.Security.IPsec.VPNs))
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
		if t.KeepaliveInfo != "" {
			fmt.Printf("  Keepalive: %s\n", t.KeepaliveInfo)
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
	// Handle "show interfaces detail" sub-command
	if len(args) > 0 && args[0] == "detail" {
		return c.showInterfacesDetail("")
	}
	// Handle "show interfaces extensive" sub-command
	if len(args) > 0 && args[0] == "extensive" {
		return c.showInterfacesExtensive()
	}
	// Handle "show interfaces statistics" sub-command
	if len(args) > 0 && args[0] == "statistics" {
		return c.showInterfacesStatistics()
	}

	// Handle "show interfaces <name> detail"
	if len(args) >= 2 && args[len(args)-1] == "detail" {
		return c.showInterfacesDetail(args[0])
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
		var linkDetails []string
		if speed := readLinkSpeed(physName); speed > 0 {
			linkDetails = append(linkDetails, "Speed: "+formatSpeed(speed))
		}
		if duplex := readLinkDuplex(physName); duplex != "" {
			linkDetails = append(linkDetails, "Link-mode: "+formatDuplex(duplex))
		}
		extra := ""
		if len(linkDetails) > 0 {
			extra = ", " + strings.Join(linkDetails, ", ")
		}

		fmt.Printf("  Link-level type: %s, MTU: %d%s\n", linkType, mtu, extra)

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

// showInterfacesDetail shows per-interface info with key stats but less
// verbose than extensive (omits per-error-type breakdowns and BPF counters).
func (c *CLI) showInterfacesDetail(filterName string) error {
	links, err := netlink.LinkList()
	if err != nil {
		return fmt.Errorf("listing interfaces: %w", err)
	}

	sort.Slice(links, func(i, j int) bool {
		return links[i].Attrs().Name < links[j].Attrs().Name
	})

	// Build zone + description lookup from active config
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

	found := false
	for _, link := range links {
		attrs := link.Attrs()
		if attrs.Name == "lo" {
			continue
		}
		if filterName != "" && attrs.Name != filterName {
			continue
		}
		found = true

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
		fmt.Printf("  Interface index: %d, SNMP ifIndex: %d\n", attrs.Index, attrs.Index)

		// Link type, MTU, speed, duplex
		linkType := "Ethernet"
		if attrs.EncapType != "" {
			linkType = attrs.EncapType
		}
		speedStr := ""
		if speed := readLinkSpeed(attrs.Name); speed > 0 {
			speedStr = ", Speed: " + formatSpeed(speed)
		}
		duplexStr := ""
		if d := readLinkDuplex(attrs.Name); d != "" {
			duplexStr = ", Duplex: " + formatDuplex(d)
		}
		fmt.Printf("  Link-level type: %s, MTU: %d%s%s\n", linkType, attrs.MTU, speedStr, duplexStr)

		if len(attrs.HardwareAddr) > 0 {
			fmt.Printf("  Current address: %s\n", attrs.HardwareAddr)
		}
		if zone, ok := ifZoneMap[attrs.Name]; ok {
			fmt.Printf("  Security zone: %s\n", zone)
		}

		// Logical interface with flags and addresses
		var flags []string
		if adminUp {
			flags = append(flags, "Up")
		}
		if attrs.RawFlags&0x2 != 0 { // IFF_BROADCAST
			flags = append(flags, "BROADCAST")
		}
		if attrs.OperState == netlink.OperUp {
			flags = append(flags, "RUNNING")
		}
		if attrs.RawFlags&0x1000 != 0 { // IFF_MULTICAST
			flags = append(flags, "MULTICAST")
		}
		fmt.Printf("  Logical interface %s.0\n", attrs.Name)
		if len(flags) > 0 {
			fmt.Printf("    Flags: %s\n", strings.Join(flags, " "))
		}

		addrs, _ := netlink.AddrList(link, netlink.FAMILY_ALL)
		if len(addrs) > 0 {
			fmt.Println("    Addresses:")
			for _, a := range addrs {
				fmt.Printf("      %s\n", a.IPNet)
			}
		}

		// Traffic statistics
		if s := attrs.Statistics; s != nil {
			fmt.Println("  Traffic statistics:")
			fmt.Printf("    Input  packets:             %12d\n", s.RxPackets)
			fmt.Printf("    Output packets:             %12d\n", s.TxPackets)
			fmt.Printf("    Input  bytes:               %12d\n", s.RxBytes)
			fmt.Printf("    Output bytes:               %12d\n", s.TxBytes)
			fmt.Printf("    Input  errors:              %12d\n", s.RxErrors)
			fmt.Printf("    Output errors:              %12d\n", s.TxErrors)
		}
		fmt.Println()
	}
	if filterName != "" && !found {
		fmt.Printf("Interface %s not found\n", filterName)
	}
	return nil
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
	ifCfgMap := make(map[string]*config.InterfaceConfig)
	if activeCfg := c.store.ActiveConfig(); activeCfg != nil {
		for _, z := range activeCfg.Security.Zones {
			for _, ifName := range z.Interfaces {
				ifZoneMap[ifName] = z.Name
			}
		}
		for _, ifc := range activeCfg.Interfaces.Interfaces {
			ifCfgMap[ifc.Name] = ifc
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
		if ifCfg, ok := ifCfgMap[attrs.Name]; ok {
			if ifCfg.Speed != "" {
				fmt.Printf("  Configured speed: %s\n", ifCfg.Speed)
			}
			if ifCfg.Duplex != "" {
				fmt.Printf("  Configured duplex: %s\n", ifCfg.Duplex)
			}
		}

		// Type + speed + MTU
		linkType := "Ethernet"
		if attrs.EncapType != "" {
			linkType = attrs.EncapType
		}
		var linkExtras []string
		if speed := readLinkSpeed(attrs.Name); speed > 0 {
			linkExtras = append(linkExtras, "Speed: "+formatSpeed(speed))
		}
		duplexStr := "Full-duplex"
		if duplex := readLinkDuplex(attrs.Name); duplex != "" {
			duplexStr = formatDuplex(duplex)
		}
		linkExtras = append(linkExtras, "Link-mode: "+duplexStr)
		fmt.Printf("  Link-level type: %s, MTU: %d, %s\n",
			linkType, attrs.MTU, strings.Join(linkExtras, ", "))

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

		// BPF traffic counters (XDP/TC level)
		if c.dp != nil && c.dp.IsLoaded() {
			if ctrs, err := c.dp.ReadInterfaceCounters(attrs.Index); err == nil && (ctrs.RxPackets > 0 || ctrs.TxPackets > 0) {
				fmt.Println("  BPF statistics:")
				fmt.Printf("    Input:  %d packets, %d bytes\n", ctrs.RxPackets, ctrs.RxBytes)
				fmt.Printf("    Output: %d packets, %d bytes\n", ctrs.TxPackets, ctrs.TxBytes)
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

func (c *CLI) showInterfacesStatistics() error {
	links, err := netlink.LinkList()
	if err != nil {
		return fmt.Errorf("listing links: %w", err)
	}

	sort.Slice(links, func(i, j int) bool {
		return links[i].Attrs().Name < links[j].Attrs().Name
	})

	fmt.Printf("%-16s %15s %15s %15s %15s %10s %10s\n",
		"Interface", "Input packets", "Input bytes", "Output packets", "Output bytes", "In errors", "Out errors")

	for _, l := range links {
		name := l.Attrs().Name
		if name == "lo" || strings.HasPrefix(name, "vrf-") ||
			strings.HasPrefix(name, "xfrm") || strings.HasPrefix(name, "gre-") {
			continue
		}
		stats := l.Attrs().Statistics
		if stats == nil {
			continue
		}
		fmt.Printf("%-16s %15d %15d %15d %15d %10d %10d\n",
			name, stats.RxPackets, stats.RxBytes, stats.TxPackets, stats.TxBytes,
			stats.RxErrors, stats.TxErrors)
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

// readLinkDuplex reads the link duplex from sysfs. Returns "" on error.
func readLinkDuplex(ifaceName string) string {
	data, err := os.ReadFile("/sys/class/net/" + ifaceName + "/duplex")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// formatSpeed formats a link speed in Mbps to a human-readable string.
func formatSpeed(mbps int) string {
	if mbps >= 1000 {
		return fmt.Sprintf("%dGbps", mbps/1000)
	}
	return fmt.Sprintf("%dMbps", mbps)
}

// formatDuplex formats a sysfs duplex string to display form.
func formatDuplex(duplex string) string {
	switch strings.ToLower(duplex) {
	case "full":
		return "Full-duplex"
	case "half":
		return "Half-duplex"
	default:
		return duplex
	}
}

func (c *CLI) handleShowSystem(args []string) error {
	sysTree := operationalTree["show"].Children["system"].Children
	if len(args) == 0 {
		fmt.Println("show system:")
		writeCompletionHelp(os.Stdout, treeHelpCandidates(sysTree))
		return nil
	}

	switch args[0] {
	case "commit":
		// "show system commit history"
		if len(args) >= 2 && args[1] == "history" {
			entries, err := c.store.ListCommitHistory(50)
			if err != nil {
				return fmt.Errorf("commit history: %v", err)
			}
			if len(entries) == 0 {
				fmt.Println("No commit history available")
				return nil
			}
			for i, e := range entries {
				detail := ""
				if e.Detail != "" {
					detail = "  " + e.Detail
				}
				fmt.Printf("  %d  %s  %s%s\n", i, e.Timestamp.Format("2006-01-02 15:04:05"), e.Action, detail)
			}
			return nil
		}
		fmt.Println("show system commit:")
		fmt.Println("  history              Show recent commit log")
		return nil

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

	case "boot-messages":
		return c.showSystemBootMessages()

	case "core-dumps":
		return c.showCoreDumps()

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
		if len(args) >= 2 && args[1] == "detail" {
			return c.showSystemBuffersDetail()
		}
		return c.showSystemBuffers()

	case "login":
		cfg := c.store.ActiveConfig()
		if cfg == nil {
			return fmt.Errorf("no active configuration")
		}
		fmt.Print(c.store.ShowActivePath([]string{"system", "login"}))
		return nil

	case "internet-options":
		cfg := c.store.ActiveConfig()
		if cfg == nil {
			return fmt.Errorf("no active configuration")
		}
		fmt.Print(c.store.ShowActivePath([]string{"system", "internet-options"}))
		return nil

	case "root-authentication":
		cfg := c.store.ActiveConfig()
		if cfg == nil {
			return fmt.Errorf("no active configuration")
		}
		fmt.Print(c.store.ShowActivePath([]string{"system", "root-authentication"}))
		return nil

	case "configuration":
		if len(args) >= 2 && args[1] == "rescue" {
			content, err := c.store.LoadRescueConfig()
			if err != nil {
				return err
			}
			if content == "" {
				fmt.Println("No rescue configuration saved")
			} else {
				fmt.Print(content)
			}
			return nil
		}
		fmt.Println("show system configuration:")
		writeCompletionHelp(os.Stdout, treeHelpCandidates(operationalTree["show"].Children["system"].Children["configuration"].Children))
		return nil

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
	fmt.Printf("%-24s %-14s %10s %10s %8s %s\n", "Map", "Type", "Max", "Used", "Usage%", "Status")
	fmt.Println(strings.Repeat("-", 78))
	var warnings int
	for _, s := range stats {
		usage := ""
		status := ""
		if s.MaxEntries > 0 && s.Type != "Array" && s.Type != "PerCPUArray" {
			pct := float64(s.UsedCount) / float64(s.MaxEntries) * 100
			usage = fmt.Sprintf("%.1f%%", pct)
			if pct >= 90 {
				status = "CRITICAL"
				warnings++
			} else if pct >= 80 {
				status = "WARNING"
				warnings++
			}
		} else {
			usage = "-"
		}
		used := fmt.Sprintf("%d", s.UsedCount)
		if s.Type == "Array" || s.Type == "PerCPUArray" {
			used = "-"
		}
		fmt.Printf("%-24s %-14s %10d %10s %8s %s\n", s.Name, s.Type, s.MaxEntries, used, usage, status)
	}
	if warnings > 0 {
		fmt.Printf("\n%d map(s) at high utilization — consider increasing max_entries\n", warnings)
	}

	// Session counts
	v4, v6 := c.dp.SessionCount()
	if v4 > 0 || v6 > 0 {
		fmt.Printf("\nActive sessions: %d IPv4, %d IPv6, %d total\n", v4, v6, v4+v6)
	}
	return nil
}

func (c *CLI) showSystemBuffersDetail() error {
	if c.dp == nil {
		fmt.Println("Dataplane not loaded")
		return nil
	}
	stats := c.dp.GetMapStats()
	if len(stats) == 0 {
		fmt.Println("No BPF maps available")
		return nil
	}

	// Filter out Array/PerCPUArray types (always "full") and compute usage
	type mapDetail struct {
		name       string
		mapType    string
		maxEntries uint32
		usedCount  uint32
		keySize    uint32
		valueSize  uint32
		pct        float64
	}
	var details []mapDetail
	for _, s := range stats {
		if s.Type == "Array" || s.Type == "PerCPUArray" {
			continue
		}
		pct := float64(0)
		if s.MaxEntries > 0 {
			pct = float64(s.UsedCount) / float64(s.MaxEntries) * 100
		}
		details = append(details, mapDetail{
			name:       s.Name,
			mapType:    s.Type,
			maxEntries: s.MaxEntries,
			usedCount:  s.UsedCount,
			keySize:    s.KeySize,
			valueSize:  s.ValueSize,
			pct:        pct,
		})
	}

	// Sort by usage percentage descending
	sort.Slice(details, func(i, j int) bool {
		return details[i].pct > details[j].pct
	})

	fmt.Printf("BPF Map Details (sorted by utilization):\n\n")
	for _, d := range details {
		status := "OK"
		if d.pct >= 90 {
			status = "CRITICAL"
		} else if d.pct >= 80 {
			status = "WARNING"
		}
		fmt.Printf("Map: %s\n", d.name)
		fmt.Printf("  Type: %s, Max: %d, Used: %d, Usage: %.1f%%\n", d.mapType, d.maxEntries, d.usedCount, d.pct)
		fmt.Printf("  Key size: %d bytes, Value size: %d bytes\n", d.keySize, d.valueSize)
		fmt.Printf("  Status: %s\n\n", status)
	}

	// Session counts
	v4, v6 := c.dp.SessionCount()
	if v4 > 0 || v6 > 0 {
		fmt.Printf("Active sessions: %d IPv4, %d IPv6, %d total\n", v4, v6, v4+v6)
	}
	return nil
}

func (c *CLI) showCoreDumps() error {
	dirs := []string{"/var/crash", "/var/lib/systemd/coredump"}
	var found bool
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			info, err := e.Info()
			if err != nil {
				continue
			}
			if !found {
				fmt.Printf("%-40s %-20s %10s\n", "Name", "Date", "Size")
				found = true
			}
			fmt.Printf("%-40s %-20s %10d\n", e.Name(), info.ModTime().Format("2006-01-02 15:04:05"), info.Size())
		}
	}
	if !found {
		fmt.Println("No core dumps found")
	}
	return nil
}

func (c *CLI) showTask() error {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	uptime := time.Since(c.startTime).Truncate(time.Second)
	fmt.Println("Task: bpfrxd daemon")
	fmt.Printf("  Goroutines: %d\n", runtime.NumGoroutine())
	fmt.Printf("  Memory allocated: %.1f MB\n", float64(m.Alloc)/1024/1024)
	fmt.Printf("  System memory: %.1f MB\n", float64(m.Sys)/1024/1024)
	fmt.Printf("  GC cycles: %d\n", m.NumGC)
	fmt.Printf("  Uptime: %s\n", uptime)
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

	// Try chronyc tracking for detailed sync status
	if out, err := exec.Command("chronyc", "tracking").CombinedOutput(); err == nil {
		fmt.Println()
		printChronyTracking(string(out))
	} else if out, err := exec.Command("ntpq", "-pn").CombinedOutput(); err == nil {
		fmt.Printf("\nNTP peers:\n%s\n", string(out))
	} else if out, err := exec.Command("timedatectl", "show", "--property=NTPSynchronized", "--value").CombinedOutput(); err == nil {
		synced := strings.TrimSpace(string(out))
		fmt.Printf("\nNTP synchronized: %s\n", synced)
	}

	return nil
}

// printChronyTracking parses chronyc tracking output and prints key fields.
func printChronyTracking(output string) {
	fields := map[string]string{}
	for _, line := range strings.Split(output, "\n") {
		if idx := strings.Index(line, " : "); idx > 0 {
			key := strings.TrimSpace(line[:idx])
			val := strings.TrimSpace(line[idx+3:])
			fields[key] = val
		}
	}

	fmt.Println("NTP sync status:")
	if v, ok := fields["Reference ID"]; ok {
		fmt.Printf("  Reference: %s\n", v)
	}
	if v, ok := fields["Stratum"]; ok {
		fmt.Printf("  Stratum: %s\n", v)
	}
	if v, ok := fields["Ref time (UTC)"]; ok {
		fmt.Printf("  Reference time: %s\n", v)
	}
	if v, ok := fields["System time"]; ok {
		fmt.Printf("  System time offset: %s\n", v)
	}
	if v, ok := fields["Last offset"]; ok {
		fmt.Printf("  Last offset: %s\n", v)
	}
	if v, ok := fields["RMS offset"]; ok {
		fmt.Printf("  RMS offset: %s\n", v)
	}
	if v, ok := fields["Frequency"]; ok {
		fmt.Printf("  Frequency: %s\n", v)
	}
	if v, ok := fields["Root delay"]; ok {
		fmt.Printf("  Root delay: %s\n", v)
	}
	if v, ok := fields["Root dispersion"]; ok {
		fmt.Printf("  Root dispersion: %s\n", v)
	}
	if v, ok := fields["Update interval"]; ok {
		fmt.Printf("  Poll interval: %s\n", v)
	}
	if v, ok := fields["Leap status"]; ok {
		fmt.Printf("  Leap status: %s\n", v)
	}
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

	// Web management / API auth
	if cfg.System.Services != nil && cfg.System.Services.WebManagement != nil {
		wm := cfg.System.Services.WebManagement
		if wm.APIAuth != nil && (len(wm.APIAuth.Users) > 0 || len(wm.APIAuth.APIKeys) > 0) {
			fmt.Printf("  API auth:       %d user(s), %d API key(s)\n", len(wm.APIAuth.Users), len(wm.APIAuth.APIKeys))
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
	cmdtree.WriteHelp(os.Stdout, cmdtree.HelpCandidates(operationalTree))
	fmt.Println()
	fmt.Println("  <command> | match/grep <pattern>    Filter output by pattern")
	fmt.Println("  <command> | except <pattern>        Exclude lines matching pattern")
	fmt.Println("  <command> | find <pattern>          Show from first match to end")
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

	// Show delegated prefixes
	pds := c.dhcp.DelegatedPrefixes()
	if len(pds) > 0 {
		fmt.Println("Delegated prefixes (DHCPv6 PD):")
		for _, dp := range pds {
			elapsed := time.Since(dp.Obtained).Round(time.Second)
			remaining := dp.ValidLifetime - elapsed
			if remaining < 0 {
				remaining = 0
			}
			fmt.Printf("  Interface: %s\n", dp.Interface)
			fmt.Printf("    Prefix:    %s\n", dp.Prefix)
			fmt.Printf("    Preferred: %s\n", dp.PreferredLifetime.Round(time.Second))
			fmt.Printf("    Valid:     %s (remaining: %s)\n", dp.ValidLifetime.Round(time.Second), remaining.Round(time.Second))
			fmt.Printf("    Obtained:  %s\n", dp.Obtained.Format("2006-01-02 15:04:05"))
			fmt.Println()
		}
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
	cmdtree.WriteHelp(os.Stdout, cmdtree.HelpCandidates(configTopLevel))
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

func (c *CLI) showFirewallFilter(name string) error {
	cfg := c.store.ActiveConfig()
	if cfg == nil {
		fmt.Println("No active configuration")
		return nil
	}

	// Find filter by name in both families
	var filter *config.FirewallFilter
	var family string
	if f, ok := cfg.Firewall.FiltersInet[name]; ok {
		filter = f
		family = "inet"
	} else if f, ok := cfg.Firewall.FiltersInet6[name]; ok {
		filter = f
		family = "inet6"
	}
	if filter == nil {
		fmt.Printf("Filter not found: %s\n", name)
		return nil
	}

	// Resolve filter IDs for counter display
	var ruleStart uint32
	var hasCounters bool
	if c.dp != nil && c.dp.IsLoaded() {
		if cr := c.dp.LastCompileResult(); cr != nil {
			if fid, ok := cr.FilterIDs[family+":"+name]; ok {
				if fcfg, err := c.dp.ReadFilterConfig(fid); err == nil {
					ruleStart = fcfg.RuleStart
					hasCounters = true
				}
			}
		}
	}

	fmt.Printf("Filter: %s (family %s)\n", name, family)

	ruleOffset := ruleStart
	for _, term := range filter.Terms {
		fmt.Printf("\n  Term: %s\n", term.Name)
		if term.DSCP != "" {
			fmt.Printf("    from dscp %s\n", term.DSCP)
		}
		if term.Protocol != "" {
			fmt.Printf("    from protocol %s\n", term.Protocol)
		}
		for _, addr := range term.SourceAddresses {
			fmt.Printf("    from source-address %s\n", addr)
		}
		for _, ref := range term.SourcePrefixLists {
			mod := ""
			if ref.Except {
				mod = " except"
			}
			fmt.Printf("    from source-prefix-list %s%s\n", ref.Name, mod)
		}
		for _, addr := range term.DestAddresses {
			fmt.Printf("    from destination-address %s\n", addr)
		}
		for _, ref := range term.DestPrefixLists {
			mod := ""
			if ref.Except {
				mod = " except"
			}
			fmt.Printf("    from destination-prefix-list %s%s\n", ref.Name, mod)
		}
		if len(term.SourcePorts) > 0 {
			fmt.Printf("    from source-port %s\n", strings.Join(term.SourcePorts, ", "))
		}
		if len(term.DestinationPorts) > 0 {
			fmt.Printf("    from destination-port %s\n", strings.Join(term.DestinationPorts, ", "))
		}
		if term.ICMPType >= 0 {
			fmt.Printf("    from icmp-type %d\n", term.ICMPType)
		}
		if term.ICMPCode >= 0 {
			fmt.Printf("    from icmp-code %d\n", term.ICMPCode)
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
		action := term.Action
		if action == "" {
			action = "accept"
		}
		fmt.Printf("    then %s\n", action)

		// Sum counters across all expanded BPF rules for this term
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
	return nil
}

func (c *CLI) handleShowClassOfService(args []string) error {
	if len(args) == 0 || args[0] != "interface" {
		cmdtree.PrintTreeHelp("show class-of-service:", operationalTree, "show", "class-of-service")
		return nil
	}
	return c.showClassOfServiceInterface()
}

func (c *CLI) showClassOfServiceInterface() error {
	cfg := c.store.ActiveConfig()
	if cfg == nil {
		fmt.Println("No active configuration")
		return nil
	}

	// Collect interfaces with filter bindings
	type ifBinding struct {
		name       string
		inputV4    string
		outputV4   string
		inputV6    string
		outputV6   string
	}
	var bindings []ifBinding
	for _, ifc := range cfg.Interfaces.Interfaces {
		for _, unit := range ifc.Units {
			b := ifBinding{name: ifc.Name}
			b.inputV4 = unit.FilterInputV4
			b.outputV4 = unit.FilterOutputV4
			b.inputV6 = unit.FilterInputV6
			b.outputV6 = unit.FilterOutputV6
			if b.inputV4 != "" || b.outputV4 != "" || b.inputV6 != "" || b.outputV6 != "" {
				bindings = append(bindings, b)
			}
		}
	}

	if len(bindings) == 0 {
		fmt.Println("No interfaces with class-of-service configuration")
		return nil
	}

	sort.Slice(bindings, func(i, j int) bool { return bindings[i].name < bindings[j].name })

	for _, b := range bindings {
		fmt.Printf("Interface: %s\n", b.name)
		printFilterBinding := func(dir, family, filterName string) {
			filters := cfg.Firewall.FiltersInet
			if family == "inet6" {
				filters = cfg.Firewall.FiltersInet6
			}
			f, ok := filters[filterName]
			if !ok {
				fmt.Printf("  %s filter (%s): %s (not found)\n", dir, family, filterName)
				return
			}
			fmt.Printf("  %s filter (%s): %s\n", dir, family, filterName)
			for _, term := range f.Terms {
				var matchParts []string
				if term.DSCP != "" {
					matchParts = append(matchParts, "dscp "+term.DSCP)
				}
				if term.Protocol != "" {
					matchParts = append(matchParts, "protocol "+term.Protocol)
				}
				if len(term.DestinationPorts) > 0 {
					matchParts = append(matchParts, "port "+strings.Join(term.DestinationPorts, ","))
				}
				if term.ICMPType >= 0 {
					matchParts = append(matchParts, fmt.Sprintf("icmp-type %d", term.ICMPType))
				}
				if term.ICMPCode >= 0 {
					matchParts = append(matchParts, fmt.Sprintf("icmp-code %d", term.ICMPCode))
				}
				matchStr := "any"
				if len(matchParts) > 0 {
					matchStr = strings.Join(matchParts, " ")
				}
				action := term.Action
				if action == "" {
					action = "accept"
				}
				extras := ""
				if term.ForwardingClass != "" {
					extras += " forwarding-class " + term.ForwardingClass
				}
				if term.DSCPRewrite != "" {
					extras += " dscp " + term.DSCPRewrite
				}
				if term.Log {
					extras += " log"
				}
				fmt.Printf("    Term %s: match %s -> %s%s\n", term.Name, matchStr, action, extras)
			}
		}
		if b.inputV4 != "" {
			printFilterBinding("Input", "inet", b.inputV4)
		}
		if b.outputV4 != "" {
			printFilterBinding("Output", "inet", b.outputV4)
		}
		if b.inputV6 != "" {
			printFilterBinding("Input", "inet6", b.inputV6)
		}
		if b.outputV6 != "" {
			printFilterBinding("Output", "inet6", b.outputV6)
		}
		fmt.Println()
	}
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

	// Get runtime feed status if available.
	var runtimeFeeds map[string]feeds.FeedInfo
	if c.feedsFn != nil {
		runtimeFeeds = c.feedsFn()
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

		if fi, ok := runtimeFeeds[name]; ok {
			fmt.Printf("    Prefixes: %d\n", fi.Prefixes)
			if !fi.LastFetch.IsZero() {
				age := time.Since(fi.LastFetch).Truncate(time.Second)
				fmt.Printf("    Last fetch: %s (%s ago)\n", fi.LastFetch.Format("2006-01-02 15:04:05"), age)
			} else {
				fmt.Printf("    Last fetch: never\n")
			}
		}
	}

	return nil
}

func (c *CLI) showSecurityAlarms(args []string) error {
	detail := len(args) >= 1 && args[0] == "detail"

	cfg := c.store.ActiveConfig()
	var alarmCount int

	// Config validation warnings
	if cfg != nil {
		warnings := config.ValidateConfig(cfg)
		for _, w := range warnings {
			alarmCount++
			if detail {
				fmt.Printf("Alarm %d:\n  Class: Configuration\n  Severity: Warning\n  Description: %s\n\n", alarmCount, w)
			}
		}
	}

	// Screen drop alarms — any non-zero screen counter indicates detected attacks
	if c.dp != nil && c.dp.IsLoaded() {
		readCtr := func(idx uint32) uint64 {
			v, _ := c.dp.ReadGlobalCounter(idx)
			return v
		}
		screenNames := []struct {
			idx  uint32
			name string
		}{
			{dataplane.GlobalCtrScreenSynFlood, "SYN flood"},
			{dataplane.GlobalCtrScreenICMPFlood, "ICMP flood"},
			{dataplane.GlobalCtrScreenUDPFlood, "UDP flood"},
			{dataplane.GlobalCtrScreenLandAttack, "LAND attack"},
			{dataplane.GlobalCtrScreenPingOfDeath, "Ping of death"},
			{dataplane.GlobalCtrScreenTearDrop, "Tear-drop"},
			{dataplane.GlobalCtrScreenTCPSynFin, "TCP SYN+FIN"},
			{dataplane.GlobalCtrScreenTCPNoFlag, "TCP no-flag"},
			{dataplane.GlobalCtrScreenTCPFinNoAck, "TCP FIN-no-ACK"},
			{dataplane.GlobalCtrScreenWinNuke, "WinNuke"},
			{dataplane.GlobalCtrScreenIPSrcRoute, "IP source-route"},
			{dataplane.GlobalCtrScreenSynFrag, "SYN fragment"},
		}
		for _, s := range screenNames {
			val := readCtr(s.idx)
			if val > 0 {
				alarmCount++
				if detail {
					fmt.Printf("Alarm %d:\n  Class: IDS\n  Severity: Major\n  Description: %s attack detected (%d drops)\n\n", alarmCount, s.name, val)
				}
			}
		}
	}

	if alarmCount == 0 {
		fmt.Println("No security alarms currently active")
	} else if !detail {
		fmt.Printf("%d security alarm(s) currently active\n", alarmCount)
		fmt.Println("  run 'show security alarms detail' for details")
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
		cmdtree.PrintTreeHelp("show services:", operationalTree, "show", "services")
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
			if r.MinRTT > 0 {
				fmt.Printf("    RTT: min %s, max %s, avg %s, jitter %s\n",
					r.MinRTT, r.MaxRTT, r.AvgRTT, r.Jitter)
			}
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
		cmdtree.PrintTreeHelp("show protocols isis:", operationalTree, "show", "protocols", "isis")
		return nil
	}

	switch args[0] {
	case "adjacency":
		if len(args) >= 2 && args[1] == "detail" {
			output, err := c.frr.GetISISAdjacencyDetail()
			if err != nil {
				return fmt.Errorf("IS-IS adjacency detail: %w", err)
			}
			fmt.Print(output)
			return nil
		}
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

	case "database":
		output, err := c.frr.GetISISDatabase()
		if err != nil {
			return fmt.Errorf("IS-IS database: %w", err)
		}
		fmt.Print(output)
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

func (c *CLI) showBFD(args []string) error {
	if c.frr == nil {
		fmt.Println("FRR manager not available")
		return nil
	}
	if len(args) == 0 {
		cmdtree.PrintTreeHelp("show protocols bfd:", operationalTree, "show", "protocols", "bfd")
		return nil
	}
	if args[0] == "peers" {
		output, err := c.frr.GetBFDPeers()
		if err != nil {
			return fmt.Errorf("BFD peers: %w", err)
		}
		if output == "" {
			fmt.Println("No BFD peers")
			return nil
		}
		fmt.Print(output)
		return nil
	}
	return fmt.Errorf("unknown show protocols bfd target: %s", args[0])
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

func (c *CLI) showDHCPServer(detail bool) error {
	cfg := c.store.ActiveConfig()
	if cfg == nil || (cfg.System.DHCPServer.DHCPLocalServer == nil && cfg.System.DHCPServer.DHCPv6LocalServer == nil) {
		fmt.Println("No DHCP server configured")
		return nil
	}

	// In detail mode, show pool configuration first
	if detail {
		if srv := cfg.System.DHCPServer.DHCPLocalServer; srv != nil && len(srv.Groups) > 0 {
			fmt.Println("DHCPv4 Server Configuration:")
			for name, group := range srv.Groups {
				fmt.Printf("  Group: %s\n", name)
				if len(group.Interfaces) > 0 {
					fmt.Printf("    Interfaces: %s\n", strings.Join(group.Interfaces, ", "))
				}
				for _, pool := range group.Pools {
					fmt.Printf("    Pool: %s\n", pool.Name)
					if pool.Subnet != "" {
						fmt.Printf("      Subnet: %s\n", pool.Subnet)
					}
					if pool.RangeLow != "" {
						fmt.Printf("      Range: %s - %s\n", pool.RangeLow, pool.RangeHigh)
					}
					if pool.Router != "" {
						fmt.Printf("      Router: %s\n", pool.Router)
					}
					if len(pool.DNSServers) > 0 {
						fmt.Printf("      DNS: %s\n", strings.Join(pool.DNSServers, ", "))
					}
					if pool.LeaseTime > 0 {
						fmt.Printf("      Lease time: %ds\n", pool.LeaseTime)
					}
				}
			}
			fmt.Println()
		}
		if srv := cfg.System.DHCPServer.DHCPv6LocalServer; srv != nil && len(srv.Groups) > 0 {
			fmt.Println("DHCPv6 Server Configuration:")
			for name, group := range srv.Groups {
				fmt.Printf("  Group: %s\n", name)
				if len(group.Interfaces) > 0 {
					fmt.Printf("    Interfaces: %s\n", strings.Join(group.Interfaces, ", "))
				}
				for _, pool := range group.Pools {
					fmt.Printf("    Pool: %s\n", pool.Name)
					if pool.Subnet != "" {
						fmt.Printf("      Subnet: %s\n", pool.Subnet)
					}
					if pool.RangeLow != "" {
						fmt.Printf("      Range: %s - %s\n", pool.RangeLow, pool.RangeHigh)
					}
				}
			}
			fmt.Println()
		}
	}

	// Read Kea lease files directly
	leases4, _ := dhcpserver.New().GetLeases4()
	leases6, _ := dhcpserver.New().GetLeases6()

	if len(leases4) == 0 && len(leases6) == 0 {
		if !detail {
			fmt.Println("No active leases")
		} else {
			fmt.Println("Active leases: none")
		}
		return nil
	}

	if len(leases4) > 0 {
		fmt.Printf("DHCPv4 Leases (%d active):\n", len(leases4))
		if detail {
			fmt.Printf("  %-18s %-20s %-15s %-10s %-12s %s\n", "Address", "MAC", "Hostname", "Subnet", "Lifetime", "Expires")
			for _, l := range leases4 {
				fmt.Printf("  %-18s %-20s %-15s %-10s %-12s %s\n",
					l.Address, l.HWAddress, l.Hostname, l.SubnetID, l.ValidLife, l.ExpireTime)
			}
		} else {
			fmt.Printf("  %-18s %-20s %-15s %-12s %s\n", "Address", "MAC", "Hostname", "Lifetime", "Expires")
			for _, l := range leases4 {
				fmt.Printf("  %-18s %-20s %-15s %-12s %s\n",
					l.Address, l.HWAddress, l.Hostname, l.ValidLife, l.ExpireTime)
			}
		}
	}
	if len(leases6) > 0 {
		fmt.Printf("DHCPv6 Leases (%d active):\n", len(leases6))
		if detail {
			fmt.Printf("  %-40s %-20s %-15s %-10s %-12s %s\n", "Address", "DUID", "Hostname", "Subnet", "Lifetime", "Expires")
			for _, l := range leases6 {
				fmt.Printf("  %-40s %-20s %-15s %-10s %-12s %s\n",
					l.Address, l.HWAddress, l.Hostname, l.SubnetID, l.ValidLife, l.ExpireTime)
			}
		} else {
			fmt.Printf("  %-40s %-20s %-15s %-12s %s\n", "Address", "DUID", "Hostname", "Lifetime", "Expires")
			for _, l := range leases6 {
				fmt.Printf("  %-40s %-20s %-15s %-12s %s\n",
					l.Address, l.HWAddress, l.Hostname, l.ValidLife, l.ExpireTime)
			}
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

	if len(snmpCfg.V3Users) > 0 {
		fmt.Println("SNMPv3 USM users:")
		for name, u := range snmpCfg.V3Users {
			auth := u.AuthProtocol
			if auth == "" {
				auth = "none"
			}
			priv := u.PrivProtocol
			if priv == "" {
				priv = "none"
			}
			fmt.Printf("  %s: auth=%s priv=%s\n", name, auth, priv)
		}
	}
	return nil
}

func (c *CLI) showSNMPv3() error {
	cfg := c.store.ActiveConfig()
	if cfg == nil || cfg.System.SNMP == nil || len(cfg.System.SNMP.V3Users) == 0 {
		fmt.Println("No SNMPv3 users configured")
		return nil
	}
	fmt.Println("SNMPv3 USM Users:")
	fmt.Printf("  %-20s %-12s %-12s\n", "User", "Auth", "Privacy")
	for _, u := range cfg.System.SNMP.V3Users {
		auth := u.AuthProtocol
		if auth == "" {
			auth = "none"
		}
		priv := u.PrivProtocol
		if priv == "" {
			priv = "none"
		}
		fmt.Printf("  %-20s %-12s %-12s\n", u.Name, auth, priv)
	}
	return nil
}

func (c *CLI) showLLDP() error {
	cfg := c.store.ActiveConfig()
	if cfg == nil || cfg.Protocols.LLDP == nil {
		fmt.Println("LLDP not configured")
		return nil
	}
	lldpCfg := cfg.Protocols.LLDP
	if lldpCfg.Disable {
		fmt.Println("LLDP: disabled")
		return nil
	}
	fmt.Println("LLDP:")
	interval := lldpCfg.Interval
	if interval <= 0 {
		interval = 30
	}
	holdMult := lldpCfg.HoldMultiplier
	if holdMult <= 0 {
		holdMult = 4
	}
	fmt.Printf("  Transmit interval: %ds\n", interval)
	fmt.Printf("  Hold multiplier:   %d\n", holdMult)
	fmt.Printf("  Hold time:         %ds\n", interval*holdMult)
	if len(lldpCfg.Interfaces) > 0 {
		fmt.Printf("  Interfaces:        %s\n", strings.Join(lldpCfg.Interfaces, ", "))
	}
	if c.lldpNeighborsFn != nil {
		neighbors := c.lldpNeighborsFn()
		fmt.Printf("  Neighbors:         %d\n", len(neighbors))
	}
	return nil
}

func (c *CLI) showLLDPNeighbors() error {
	if c.lldpNeighborsFn == nil {
		fmt.Println("LLDP not running")
		return nil
	}
	neighbors := c.lldpNeighborsFn()
	if len(neighbors) == 0 {
		fmt.Println("No LLDP neighbors discovered")
		return nil
	}
	fmt.Printf("%-12s %-20s %-16s %-20s %-6s %s\n",
		"Interface", "Chassis ID", "Port ID", "System Name", "TTL", "Age")
	for _, n := range neighbors {
		age := time.Since(n.LastSeen).Truncate(time.Second)
		fmt.Printf("%-12s %-20s %-16s %-20s %-6d %s\n",
			n.Interface, n.ChassisID, n.PortID, n.SystemName, n.TTL, age)
	}
	return nil
}

func (c *CLI) showPersistentNAT() error {
	if c.dp == nil || c.dp.GetPersistentNAT() == nil {
		fmt.Println("Persistent NAT table not available")
		return nil
	}
	bindings := c.dp.GetPersistentNAT().All()
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

// showPersistentNATDetail displays detailed persistent NAT bindings with session counts and age.
func (c *CLI) showPersistentNATDetail() error {
	if c.dp == nil || c.dp.GetPersistentNAT() == nil {
		fmt.Println("Persistent NAT table not available")
		return nil
	}
	bindings := c.dp.GetPersistentNAT().All()
	if len(bindings) == 0 {
		fmt.Println("No persistent NAT bindings")
		return nil
	}

	// Count sessions per NAT IP:port pair
	type natKey struct {
		ip   uint32
		port uint16
	}
	sessionCounts := make(map[natKey]int)
	if c.dp.IsLoaded() {
		_ = c.dp.IterateSessions(func(_ dataplane.SessionKey, val dataplane.SessionValue) bool {
			if val.IsReverse == 0 && val.Flags&dataplane.SessFlagSNAT != 0 {
				sessionCounts[natKey{val.NATSrcIP, val.NATSrcPort}]++
			}
			return true
		})
	}

	fmt.Printf("Total persistent NAT bindings: %d\n\n", len(bindings))
	for i, b := range bindings {
		if i > 0 {
			fmt.Println()
		}
		remaining := time.Until(b.LastSeen.Add(b.Timeout))
		if remaining < 0 {
			remaining = 0
		}

		// Match sessions by NAT IP — use NativeEndian for BPF uint32
		natIP := b.NatIP.As4()
		nk := natKey{
			ip:   binary.NativeEndian.Uint32(natIP[:]),
			port: b.NatPort,
		}
		sessions := sessionCounts[nk]

		fmt.Printf("Persistent NAT binding:\n")
		fmt.Printf("  Internal IP:        %s\n", b.SrcIP)
		fmt.Printf("  Internal port:      %d\n", b.SrcPort)
		fmt.Printf("  Reflexive IP:       %s\n", b.NatIP)
		fmt.Printf("  Reflexive port:     %d\n", b.NatPort)
		fmt.Printf("  Pool:               %s\n", b.PoolName)
		if b.PermitAnyRemoteHost {
			fmt.Printf("  Any remote host:    yes\n")
		}
		fmt.Printf("  Current sessions:   %d\n", sessions)
		fmt.Printf("  Left time:          %s\n", remaining.Truncate(time.Second))
		fmt.Printf("  Configured timeout: %ds\n", int(b.Timeout.Seconds()))
	}
	return nil
}

func (c *CLI) clearPersistentNAT() error {
	if c.dp == nil || c.dp.GetPersistentNAT() == nil {
		fmt.Println("Persistent NAT table not available")
		return nil
	}
	count := c.dp.GetPersistentNAT().Len()
	c.dp.GetPersistentNAT().Clear()
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
	if len(args) == 0 {
		fmt.Println("monitor:")
		writeCompletionHelp(os.Stdout, treeHelpCandidates(operationalTree["monitor"].Children))
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

	now := time.Now()
	fmt.Printf("Current time: %s\n", now.Format("2006-01-02 15:04:05 MST"))
	fmt.Printf("System booted: %s\n", now.Add(-time.Duration(upSec)*time.Second).Format("2006-01-02 15:04:05 MST"))
	fmt.Printf("Daemon uptime: %s\n", time.Since(c.startTime).Truncate(time.Second))
	if days > 0 {
		fmt.Printf("System uptime: %d days, %d hours, %d minutes, %d seconds\n", days, hours, mins, secs)
	} else {
		fmt.Printf("System uptime: %d hours, %d minutes, %d seconds\n", hours, mins, secs)
	}
	return nil
}

// showSystemBootMessages shows recent boot messages via journalctl.
func (c *CLI) showSystemBootMessages() error {
	cmd := exec.Command("journalctl", "--boot", "-n", "100", "--no-pager")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
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

	// Count entries by state and interface
	var total int
	stateCounts := make(map[string]int)
	ifaceCounts := make(map[string]int)
	for _, n := range neighbors {
		if n.IP == nil || n.HardwareAddr == nil {
			continue
		}
		total++
		stateCounts[neighState(n.State)]++
		if link, err := netlink.LinkByIndex(n.LinkIndex); err == nil {
			ifaceCounts[link.Attrs().Name]++
		}
	}

	// Summary
	fmt.Printf("Total entries: %d", total)
	if total > 0 {
		var parts []string
		for _, s := range []string{"reachable", "stale", "permanent", "delay", "probe", "failed", "incomplete"} {
			if cnt := stateCounts[s]; cnt > 0 {
				parts = append(parts, fmt.Sprintf("%s: %d", s, cnt))
			}
		}
		if len(parts) > 0 {
			fmt.Printf(" (%s)", strings.Join(parts, ", "))
		}
	}
	fmt.Println()
	if len(ifaceCounts) > 1 {
		var ifNames []string
		for name := range ifaceCounts {
			ifNames = append(ifNames, name)
		}
		sort.Strings(ifNames)
		for _, name := range ifNames {
			fmt.Printf("  %-12s %d entries\n", name, ifaceCounts[name])
		}
	}
	fmt.Println()

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
		cmdtree.PrintTreeHelp("show ipv6:", operationalTree, "show", "ipv6")
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

	// Count entries by state and interface
	var total int
	stateCounts := make(map[string]int)
	ifaceCounts := make(map[string]int)
	for _, n := range neighbors {
		if n.IP == nil || n.HardwareAddr == nil {
			continue
		}
		total++
		stateCounts[neighState(n.State)]++
		if link, err := netlink.LinkByIndex(n.LinkIndex); err == nil {
			ifaceCounts[link.Attrs().Name]++
		}
	}

	// Summary
	fmt.Printf("Total entries: %d", total)
	if total > 0 {
		var parts []string
		for _, s := range []string{"reachable", "stale", "permanent", "delay", "probe", "failed", "incomplete"} {
			if cnt := stateCounts[s]; cnt > 0 {
				parts = append(parts, fmt.Sprintf("%s: %d", s, cnt))
			}
		}
		if len(parts) > 0 {
			fmt.Printf(" (%s)", strings.Join(parts, ", "))
		}
	}
	fmt.Println()
	if len(ifaceCounts) > 1 {
		var ifNames []string
		for name := range ifaceCounts {
			ifNames = append(ifNames, name)
		}
		sort.Strings(ifNames)
		for _, name := range ifNames {
			fmt.Printf("  %-12s %d entries\n", name, ifaceCounts[name])
		}
	}
	fmt.Println()

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
	cmdtree.PrintTreeHelp("show chassis:", operationalTree, "show", "chassis")
	return nil
}

// showChassisCluster shows cluster/HA configuration and status.
func (c *CLI) showChassisCluster(args []string) error {
	if len(args) > 0 {
		switch args[0] {
		case "status":
			return c.showChassisClusterStatus()
		case "interfaces":
			return c.showChassisClusterInterfaces()
		case "information":
			return c.showChassisClusterInformation()
		case "statistics":
			return c.showChassisClusterStatistics()
		}
	}
	// Default: show status
	return c.showChassisClusterStatus()
}

func (c *CLI) showChassisClusterStatus() error {
	if c.cluster != nil {
		fmt.Print(c.cluster.FormatStatus())
	} else {
		fmt.Println("Cluster not configured")
	}

	// Show VRRP status if any
	cfg := c.store.ActiveConfig()
	if cfg != nil && cfg.Security.Zones != nil {
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

func (c *CLI) showChassisClusterInterfaces() error {
	cfg := c.store.ActiveConfig()
	if cfg == nil || cfg.Chassis.Cluster == nil {
		fmt.Println("Cluster not configured")
		return nil
	}
	cc := cfg.Chassis.Cluster
	fmt.Println("Control link status: Up")
	fmt.Println()
	fmt.Printf("RETH count: %d\n", cc.RethCount)
	if c.routing != nil {
		rethNames := c.routing.RethNames()
		if len(rethNames) > 0 {
			fmt.Printf("RETH interfaces: %s\n", strings.Join(rethNames, ", "))
		}
	}
	fmt.Println()
	monStatuses := make(map[int][]routing.InterfaceMonitorStatus)
	if c.routing != nil {
		monStatuses = c.routing.InterfaceMonitorStatuses()
	}
	for _, rg := range cc.RedundancyGroups {
		if len(rg.InterfaceMonitors) == 0 {
			continue
		}
		fmt.Printf("Interface monitoring for redundancy group %d:\n", rg.ID)
		fmt.Printf("  %-20s %-8s %s\n", "Interface", "Weight", "Status")
		if statuses, ok := monStatuses[rg.ID]; ok {
			for _, st := range statuses {
				state := "Up"
				if !st.Up {
					state = "Down"
				}
				fmt.Printf("  %-20s %-8d %s\n", st.Interface, st.Weight, state)
			}
		} else {
			for _, mon := range rg.InterfaceMonitors {
				fmt.Printf("  %-20s %-8d %s\n", mon.Interface, mon.Weight, "Unknown")
			}
		}
		fmt.Println()
	}
	return nil
}

func (c *CLI) showChassisClusterInformation() error {
	if c.cluster != nil {
		fmt.Print(c.cluster.FormatInformation())
		return nil
	}
	cfg := c.store.ActiveConfig()
	if cfg == nil || cfg.Chassis.Cluster == nil {
		fmt.Println("Cluster not configured")
		return nil
	}
	cc := cfg.Chassis.Cluster
	hbInterval := cc.HeartbeatInterval
	if hbInterval == 0 {
		hbInterval = 1000
	}
	hbThreshold := cc.HeartbeatThreshold
	if hbThreshold == 0 {
		hbThreshold = 3
	}
	fmt.Printf("Cluster ID: %d\n", cc.ClusterID)
	fmt.Printf("Node ID: %d\n", cc.NodeID)
	fmt.Printf("RETH count: %d\n", cc.RethCount)
	fmt.Printf("Heartbeat interval: %d ms\n", hbInterval)
	fmt.Printf("Heartbeat threshold: %d\n", hbThreshold)
	fmt.Printf("Redundancy groups: %d\n", len(cc.RedundancyGroups))
	return nil
}

func (c *CLI) showChassisClusterStatistics() error {
	if c.cluster == nil {
		fmt.Println("Cluster not configured")
		return nil
	}
	states := c.cluster.GroupStates()
	fmt.Println("Cluster statistics:")
	for _, rg := range states {
		fmt.Printf("  Redundancy group %d: failover count %d, weight %d\n",
			rg.GroupID, rg.FailoverCount, rg.Weight)
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

// showRouteMap displays FRR route-map information via vtysh.
func (c *CLI) showRouteMap() error {
	if c.frr == nil {
		fmt.Println("FRR manager not available")
		return nil
	}
	output, err := c.frr.GetRouteMapList()
	if err != nil {
		return fmt.Errorf("get route-map: %w", err)
	}
	if output == "" {
		fmt.Println("No route-maps configured")
		return nil
	}
	fmt.Print(output)
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
				fmt.Printf("    term %s:\n", t.Name)
				if t.FromProtocol != "" {
					fmt.Printf("      from protocol %s\n", t.FromProtocol)
				}
				if t.PrefixList != "" {
					fmt.Printf("      from prefix-list %s\n", t.PrefixList)
				}
				for _, rf := range t.RouteFilters {
					match := rf.MatchType
					if rf.MatchType == "upto" && rf.UptoLen > 0 {
						match = fmt.Sprintf("upto /%d", rf.UptoLen)
					}
					fmt.Printf("      from route-filter %s %s\n", rf.Prefix, match)
				}
				if t.Action != "" {
					fmt.Printf("      then %s\n", t.Action)
				}
				if t.NextHop != "" {
					fmt.Printf("      then next-hop %s\n", t.NextHop)
				}
				if t.LoadBalance != "" {
					fmt.Printf("      then load-balance %s\n", t.LoadBalance)
				}
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

func (c *CLI) showRoutingInstances(detail bool) error {
	cfg := c.store.ActiveConfig()
	if cfg == nil {
		fmt.Println("No active configuration")
		return nil
	}
	if len(cfg.RoutingInstances) == 0 {
		fmt.Println("No routing instances configured")
		return nil
	}

	if !detail {
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

	for _, ri := range cfg.RoutingInstances {
		fmt.Printf("Instance: %s\n", ri.Name)
		if ri.Description != "" {
			fmt.Printf("  Description: %s\n", ri.Description)
		}
		fmt.Printf("  Type: %s\n", ri.InstanceType)
		if ri.TableID > 0 {
			fmt.Printf("  Table ID: %d\n", ri.TableID)
		}
		if len(ri.Interfaces) > 0 {
			fmt.Printf("  Interfaces: %s\n", strings.Join(ri.Interfaces, ", "))
		}
		if ri.TableID > 0 && c.routing != nil {
			if routes, err := c.routing.GetRoutesForTable(ri.TableID); err == nil {
				fmt.Printf("  Route count: %d\n", len(routes))
			}
		}
		var protos []string
		if ri.OSPF != nil {
			protos = append(protos, "OSPF")
		}
		if ri.BGP != nil {
			protos = append(protos, "BGP")
		}
		if ri.RIP != nil {
			protos = append(protos, "RIP")
		}
		if ri.ISIS != nil {
			protos = append(protos, "IS-IS")
		}
		if len(protos) > 0 {
			fmt.Printf("  Protocols: %s\n", strings.Join(protos, ", "))
		}
		if len(ri.StaticRoutes) > 0 {
			fmt.Printf("  Static routes: %d\n", len(ri.StaticRoutes))
			for _, sr := range ri.StaticRoutes {
				if sr.Discard {
					fmt.Printf("    %s -> discard\n", sr.Destination)
					continue
				}
				for _, nh := range sr.NextHops {
					nhStr := nh.Address
					if nh.Interface != "" {
						nhStr += " via " + nh.Interface
					}
					fmt.Printf("    %s -> %s\n", sr.Destination, nhStr)
				}
			}
		}
		if ri.InterfaceRoutesRibGroup != "" {
			fmt.Printf("  Interface routes rib-group: %s\n", ri.InterfaceRoutesRibGroup)
		}
		fmt.Println()
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

	if fo.PortMirroring != nil && len(fo.PortMirroring.Instances) > 0 {
		fmt.Println("Port mirroring:")
		for name, inst := range fo.PortMirroring.Instances {
			fmt.Printf("  Instance: %s\n", name)
			if inst.InputRate > 0 {
				fmt.Printf("    Sampling rate: 1/%d\n", inst.InputRate)
			}
			if len(inst.Input) > 0 {
				fmt.Printf("    Input interfaces:  %s\n", strings.Join(inst.Input, ", "))
			}
			if inst.Output != "" {
				fmt.Printf("    Output interface:  %s\n", inst.Output)
			}
		}
		hasContent = true
	}

	if !hasContent {
		fmt.Println("No forwarding-options configured")
	}
	return nil
}

// showPortMirroring displays port mirroring (SPAN) configuration.
func (c *CLI) showPortMirroring() error {
	cfg := c.store.ActiveConfig()
	if cfg == nil {
		fmt.Println("No active configuration")
		return nil
	}

	pm := cfg.ForwardingOptions.PortMirroring
	if pm == nil || len(pm.Instances) == 0 {
		fmt.Println("No port-mirroring instances configured")
		return nil
	}

	for name, inst := range pm.Instances {
		fmt.Printf("Instance: %s\n", name)
		if inst.InputRate > 0 {
			fmt.Printf("  Input rate: 1/%d\n", inst.InputRate)
		} else {
			fmt.Printf("  Input rate: all packets\n")
		}
		if len(inst.Input) > 0 {
			fmt.Printf("  Input interfaces: %s\n", strings.Join(inst.Input, ", "))
		}
		if inst.Output != "" {
			fmt.Printf("  Output interface: %s\n", inst.Output)
		}
		fmt.Println()
	}
	return nil
}

// showVlans displays VLAN assignments per interface (like Junos "show vlans").
func (c *CLI) showVlans() error {
	cfg := c.store.ActiveConfig()
	if cfg == nil {
		fmt.Println("No active configuration")
		return nil
	}

	// Build zone lookup: interface name → zone name
	ifZone := make(map[string]string)
	for zoneName, zone := range cfg.Security.Zones {
		for _, iface := range zone.Interfaces {
			ifZone[iface] = zoneName
		}
	}

	// Collect VLAN entries
	type vlanEntry struct {
		iface  string
		unit   int
		vlanID int
		zone   string
		trunk  bool
	}
	var entries []vlanEntry
	for _, ifc := range cfg.Interfaces.Interfaces {
		for unitNum, unit := range ifc.Units {
			if unit.VlanID > 0 || ifc.VlanTagging {
				zone := ifZone[ifc.Name]
				entries = append(entries, vlanEntry{
					iface:  ifc.Name,
					unit:   unitNum,
					vlanID: unit.VlanID,
					zone:   zone,
					trunk:  ifc.VlanTagging,
				})
			}
		}
	}

	if len(entries) == 0 {
		fmt.Println("No VLANs configured")
		return nil
	}

	sort.Slice(entries, func(i, j int) bool {
		if entries[i].iface != entries[j].iface {
			return entries[i].iface < entries[j].iface
		}
		return entries[i].unit < entries[j].unit
	})

	fmt.Printf("%-16s %-6s %-8s %-12s %s\n", "Interface", "Unit", "VLAN ID", "Zone", "Mode")
	for _, e := range entries {
		mode := "access"
		if e.trunk {
			mode = "trunk"
		}
		vid := fmt.Sprintf("%d", e.vlanID)
		if e.vlanID == 0 {
			vid = "native"
		}
		fmt.Printf("%-16s %-6d %-8s %-12s %s\n", e.iface, e.unit, vid, e.zone, mode)
	}
	return nil
}

// handleRequest dispatches request sub-commands (like Junos operational mode).
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
	if len(args) == 0 || args[0] != "failover" {
		fmt.Println("request chassis cluster:")
		writeCompletionHelp(os.Stdout, treeHelpCandidates(operationalTree["request"].Children["chassis"].Children["cluster"].Children))
		return nil
	}
	args = args[1:] // consume "failover"

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

	// "request chassis cluster failover redundancy-group <N>"
	if len(args) >= 2 && args[0] == "redundancy-group" {
		rgID, err := strconv.Atoi(args[1])
		if err != nil {
			return fmt.Errorf("invalid redundancy-group ID: %s", args[1])
		}
		if err := c.cluster.ManualFailover(rgID); err != nil {
			return err
		}
		fmt.Printf("Manual failover triggered for redundancy group %d\n", rgID)
		return nil
	}

	return fmt.Errorf("usage: request chassis cluster failover redundancy-group <N>")
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

	case "configuration":
		return c.handleRequestSystemConfiguration(args[1:])

	default:
		return fmt.Errorf("unknown request system command: %s", args[0])
	}
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
