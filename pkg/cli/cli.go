// Package cli implements the Junos-style interactive CLI for bpfrx.
package cli

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/chzyer/readline"
	"github.com/psaab/bpfrx/pkg/appid"
	"github.com/psaab/bpfrx/pkg/cluster"
	"github.com/psaab/bpfrx/pkg/cmdtree"
	"github.com/psaab/bpfrx/pkg/config"
	"github.com/psaab/bpfrx/pkg/configstore"
	"github.com/psaab/bpfrx/pkg/dataplane"
	dpuserspace "github.com/psaab/bpfrx/pkg/dataplane/userspace"
	"github.com/psaab/bpfrx/pkg/dhcp"
	"github.com/psaab/bpfrx/pkg/dhcprelay"
	"github.com/psaab/bpfrx/pkg/feeds"
	"github.com/psaab/bpfrx/pkg/frr"
	pb "github.com/psaab/bpfrx/pkg/grpcapi/bpfrxv1"
	"github.com/psaab/bpfrx/pkg/ipsec"
	"github.com/psaab/bpfrx/pkg/lldp"
	"github.com/psaab/bpfrx/pkg/logging"
	"github.com/psaab/bpfrx/pkg/routing"
	"github.com/psaab/bpfrx/pkg/rpm"
	"github.com/psaab/bpfrx/pkg/vrrp"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

// CLI is the interactive command-line interface.
type CLI struct {
	rl              *readline.Instance
	store           *configstore.Store
	dp              dataplane.DataPlane
	eventBuf        *logging.EventBuffer
	eventReader     *logging.EventReader
	routing         *routing.Manager
	frr             *frr.Manager
	ipsec           *ipsec.Manager
	dhcp            *dhcp.Manager
	dhcpRelay       *dhcprelay.Manager
	cluster         *cluster.Manager
	rpmResultsFn    func() []*rpm.ProbeResult
	feedsFn         func() map[string]feeds.FeedInfo
	lldpNeighborsFn func() []*lldp.Neighbor
	hostname        string
	username        string
	userClass       string
	version         string
	startTime       time.Time

	vrrpMgr *vrrp.Manager

	// Fabric peer dialing for cluster-wide queries (fab0 + optional fab1).
	fabricPeerAddrFn   func() []string
	fabricVRFDevice    string
	peerSystemActionFn func(ctx context.Context, action string) (string, error)

	// Monitor security flow state (per-CLI-session).
	monitorFlow *monitorFlowState

	// Command cancellation: Ctrl-C during a running external command cancels it.
	cmdMu     sync.Mutex
	cmdCancel context.CancelFunc
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

// SetVRRPManager sets the VRRP manager for runtime state queries.
func (c *CLI) SetVRRPManager(m *vrrp.Manager) {
	c.vrrpMgr = m
}

// SetFabricPeer configures fabric peer dialing for cluster-wide queries.
func (c *CLI) SetFabricPeer(addrFn func() []string, vrfDevice string) {
	c.fabricPeerAddrFn = addrFn
	c.fabricVRFDevice = vrfDevice
}

// dialPeer establishes a gRPC connection to the cluster peer, trying fab0
// then fab1 if dual-fabric is configured. Returns nil if not in cluster mode.
func (c *CLI) dialPeer() *grpc.ClientConn {
	if c.fabricPeerAddrFn == nil {
		return nil
	}
	peerIPs := c.fabricPeerAddrFn()
	if len(peerIPs) == 0 {
		return nil
	}

	dialOpts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
	if c.fabricVRFDevice != "" {
		dialOpts = append(dialOpts, grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
			dialer := &net.Dialer{
				Control: func(network, address string, rc syscall.RawConn) error {
					var err error
					rc.Control(func(fd uintptr) {
						err = unix.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, c.fabricVRFDevice)
					})
					return err
				},
			}
			return dialer.DialContext(ctx, "tcp", addr)
		}))
	}

	for _, ip := range peerIPs {
		peerAddr := fmt.Sprintf("%s:50051", ip)
		conn, err := grpc.NewClient(peerAddr, dialOpts...)
		if err != nil {
			continue
		}
		// Quick TCP probe to verify the address is reachable.
		d := &net.Dialer{Timeout: 2 * time.Second}
		if c.fabricVRFDevice != "" {
			d.Control = func(network, address string, rc syscall.RawConn) error {
				var err error
				rc.Control(func(fd uintptr) {
					err = unix.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, c.fabricVRFDevice)
				})
				return err
			}
		}
		tc, err := d.DialContext(context.Background(), "tcp", peerAddr)
		if err != nil {
			conn.Close()
			slog.Debug("peer dial failed, trying next fabric address", "addr", peerAddr, "err", err)
			continue
		}
		tc.Close()
		return conn
	}
	slog.Warn("failed to dial peer on any fabric address")
	return nil
}

func (c *CLI) requestPeerSystemAction(ctx context.Context, action string) (string, error) {
	ctx = metadata.AppendToOutgoingContext(ctx, "x-peer-forwarded", "1")
	if c.peerSystemActionFn != nil {
		return c.peerSystemActionFn(ctx, action)
	}
	conn := c.dialPeer()
	if conn == nil {
		return "", fmt.Errorf("cluster peer not reachable")
	}
	defer conn.Close()

	peerCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	resp, err := pb.NewBpfrxServiceClient(conn).SystemAction(peerCtx, &pb.SystemActionRequest{Action: action})
	if err != nil {
		return "", err
	}
	return resp.Message, nil
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
	cli         *CLI
	helpWritten bool // set by ? Listener to suppress duplicate help from Do()
}

func (cc *cliCompleter) Do(line []rune, pos int) ([][]rune, int) {
	// If the ? Listener already wrote help, suppress duplicate output.
	if cc.helpWritten {
		cc.helpWritten = false
		return nil, 0
	}

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
		// "show configuration <path>" — delegate sub-path to config schema
		if len(words) >= 2 && words[0] == "show" && words[1] == "configuration" {
			subPath := words[2:]
			schemaCompletions := config.CompleteSetPathWithValues(subPath, cc.cli.valueProvider)
			if schemaCompletions != nil {
				for _, sc := range schemaCompletions {
					if partial == "" || strings.HasPrefix(sc.Name, partial) {
						candidates = append(candidates, completionCandidate{name: sc.Name, desc: sc.Desc})
					}
				}
			}
		}
		if len(candidates) == 0 {
			candidates = completeFromTreeWithDesc(operationalTree, words, partial, cc.cli.store.ActiveConfig())
		}
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
		for _, sc := range schemaCompletions {
			if strings.HasPrefix(sc.Name, partial) {
				candidates = append(candidates, completionCandidate{name: sc.Name, desc: sc.Desc})
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
	completer := &cliCompleter{cli: c}
	c.rl, err = readline.NewEx(&readline.Config{
		Prompt:          c.operationalPrompt(),
		HistoryFile:     filepath.Join(os.Getenv("HOME"), ".bpfrx_history"),
		HistoryLimit:    10000,
		InterruptPrompt: "^C",
		EOFPrompt:       "exit",
		AutoComplete:    completer,
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
				// Suppress duplicate help if readline calls Do() for this key.
				completer.helpWritten = true
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
				// "show configuration <path>" — delegate sub-path to config schema
				if len(words) >= 2 && words[0] == "show" && words[1] == "configuration" {
					subPath := words[2:]
					schemaCompletions := config.CompleteSetPathWithValues(subPath, c.valueProvider)
					if schemaCompletions != nil {
						for _, sc := range schemaCompletions {
							if partial == "" || strings.HasPrefix(sc.Name, partial) {
								candidates = append(candidates, completionCandidate{name: sc.Name, desc: sc.Desc})
							}
						}
					}
				}
				if len(candidates) == 0 {
					candidates = completeFromTreeWithDesc(operationalTree, words, partial, c.store.ActiveConfig())
				}
			}
			if len(candidates) > 0 {
				writeCompletionHelp(c.rl.Stdout(), candidates)
			}
			// Suppress duplicate help if readline calls Do() for this key.
			completer.helpWritten = true
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
			// If an external command is running, cancel it.
			c.cmdMu.Lock()
			cancel := c.cmdCancel
			c.cmdMu.Unlock()
			if cancel != nil {
				cancel()
				continue
			}
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
			if err == readline.ErrInterrupt {
				continue
			}
			if err == io.EOF {
				// Ctrl-D: exit config mode, or exit CLI if already in operational mode.
				if c.store.InConfigMode() {
					c.store.ExitConfigure()
					c.rl.SetPrompt(c.operationalPrompt())
					fmt.Println("\nExiting configuration mode")
					continue
				}
				return nil
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
		// Refresh prompt after every command so cluster role
		// changes (failover) are reflected immediately.
		c.refreshPrompt()
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
		for _, line := range lines {
			if strings.Contains(line, pipeArg) {
				fmt.Fprintln(origStdout, line)
			}
		}
	case "except":
		for _, line := range lines {
			if !strings.Contains(line, pipeArg) {
				fmt.Fprintln(origStdout, line)
			}
		}
	case "find":
		found := false
		for _, line := range lines {
			if !found && strings.Contains(line, pipeArg) {
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
		// Block configure mode on secondary node — config changes must
		// be made on the primary (RG0 is config authority).
		if c.cluster != nil && !c.cluster.IsLocalPrimary(0) {
			return fmt.Errorf("error: node is not primary for RG0, configure on the primary node")
		}
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

	case "insert":
		return c.handleInsert(parts)

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
		// "show security policies global" — only show global policies
		globalOnly := len(args) >= 2 && args[1] == "global"
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
		if !globalOnly {
			for _, zpp := range cfg.Security.Policies {
				if fromZone != "" && zpp.FromZone != fromZone {
					policySetID++
					continue
				}
				if toZone != "" && zpp.ToZone != toZone {
					policySetID++
					continue
				}
				// Junos format: "From zone: X, To zone: Y" header
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
					// Junos: Policy: <name>, State: enabled, Index: <N>, Scope Policy: 0, Sequence number: <N>
					fmt.Printf("  Policy: %s, State: enabled, Index: %d, Scope Policy: 0, Sequence number: %d\n",
						pol.Name, ruleID, i+1)
					if pol.Description != "" {
						fmt.Printf("    Description: %s\n", pol.Description)
					}
					fmt.Printf("    Source addresses: %s\n",
						strings.Join(pol.Match.SourceAddresses, ", "))
					fmt.Printf("    Destination addresses: %s\n",
						strings.Join(pol.Match.DestinationAddresses, ", "))
					fmt.Printf("    Applications: %s\n",
						strings.Join(pol.Match.Applications, ", "))
					actionStr := action
					if pol.Log != nil {
						actionStr += ", log"
					}
					fmt.Printf("    Action: %s\n", actionStr)
				}
				policySetID++
			}
		} else {
			// When globalOnly, still count zone-pair policy sets to get correct global ruleID base
			policySetID = uint32(len(cfg.Security.Policies))
		}
		// Global policies
		if len(cfg.Security.GlobalPolicies) > 0 && (globalOnly || (fromZone == "" && toZone == "")) {
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
				// Junos global: Policy: <name>, State: enabled, Index: <N>, Scope Policy: 0, Sequence number: <N>
				fmt.Printf("  Policy: %s, State: enabled, Index: %d, Scope Policy: 0, Sequence number: %d\n",
					pol.Name, ruleID, i+1)
				if pol.Description != "" {
					fmt.Printf("    Description: %s\n", pol.Description)
				}
				fmt.Printf("    From zones: any\n")
				fmt.Printf("    To zones: any\n")
				fmt.Printf("    Source addresses: %s\n",
					strings.Join(pol.Match.SourceAddresses, ", "))
				fmt.Printf("    Destination addresses: %s\n",
					strings.Join(pol.Match.DestinationAddresses, ", "))
				fmt.Printf("    Applications: %s\n",
					strings.Join(pol.Match.Applications, ", "))
				actionStr := action
				if pol.Log != nil {
					actionStr += ", log"
				}
				fmt.Printf("    Action: %s\n", actionStr)
			}
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
		// Accept optional "status" subcommand
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
func resolveAddressDetail(cfg *config.Config, name string) string {
	ab := cfg.Security.AddressBook
	if ab != nil {
		if addr, ok := ab.Addresses[name]; ok && addr.Value != "" {
			return addr.Value
		}
	}
	return name
}

// printAppDetail prints Junos-style application detail lines (protocol, ports, timeout).
func (c *CLI) printAppDetail(cfg *config.Config, appName string) {
	if appName == "any" {
		fmt.Printf("    IP protocol: 0, ALG: 0, Inactivity timeout: 0\n")
		fmt.Printf("      Source port range: [0-0]\n")
		fmt.Printf("      Destination ports: [0-0]\n")
		return
	}
	if cfg.Applications.Applications == nil {
		return
	}
	app, ok := cfg.Applications.Applications[appName]
	if !ok {
		return
	}
	proto := app.Protocol
	if proto == "" {
		proto = "0"
	}
	timeout := 0
	if app.InactivityTimeout > 0 {
		timeout = app.InactivityTimeout
	}
	algVal := "0"
	if app.ALG != "" {
		algVal = app.ALG
	}
	fmt.Printf("    IP protocol: %s, ALG: %s, Inactivity timeout: %d\n", proto, algVal, timeout)
	srcPort := "0-0"
	if app.SourcePort != "" {
		srcPort = app.SourcePort
	}
	dstPort := "0-0"
	if app.DestinationPort != "" {
		dstPort = app.DestinationPort
	}
	fmt.Printf("      Source port range: [%s]\n", srcPort)
	fmt.Printf("      Destination ports: [%s]\n", dstPort)
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
		return c.showScreenStatisticsAll()
	default:
		return c.showScreen()
	}
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

	// Build path from editPath + args before the pipe (used by all display formats).
	var displayPath []string
	{
		editPath := c.store.GetEditPath()
		displayPath = append(displayPath, editPath...)
		for _, a := range args {
			if a == "|" {
				break
			}
			displayPath = append(displayPath, a)
		}
	}

	if strings.Contains(line, "| display json") {
		if len(displayPath) > 0 {
			output := c.store.ShowCandidatePathJSON(displayPath)
			if output == "" {
				fmt.Printf("configuration path not found: %s\n", strings.Join(displayPath, " "))
			} else {
				fmt.Print(output)
			}
		} else {
			fmt.Print(c.store.ShowCandidateJSON())
		}
		return nil
	}

	if strings.Contains(line, "| display set") {
		if len(displayPath) > 0 {
			output := c.store.ShowCandidatePathSet(displayPath)
			if output == "" {
				fmt.Printf("configuration path not found: %s\n", strings.Join(displayPath, " "))
			} else {
				fmt.Print(output)
			}
		} else {
			fmt.Print(c.store.ShowCandidateSet())
		}
		return nil
	}

	if strings.Contains(line, "| display xml") {
		if len(displayPath) > 0 {
			output := c.store.ShowCandidatePathXML(displayPath)
			if output == "" {
				fmt.Printf("configuration path not found: %s\n", strings.Join(displayPath, " "))
			} else {
				fmt.Print(output)
			}
		} else {
			fmt.Print(c.store.ShowCandidateXML())
		}
		return nil
	}

	if strings.Contains(line, "| display inheritance") {
		if len(displayPath) > 0 {
			output := c.store.ShowCandidatePathInheritance(displayPath)
			if output == "" {
				fmt.Printf("configuration path not found: %s\n", strings.Join(displayPath, " "))
			} else {
				fmt.Print(output)
			}
		} else {
			fmt.Print(c.store.ShowCandidateInheritance())
		}
		return nil
	}

	// Unknown pipe command
	if idx := strings.Index(line, "| "); idx >= 0 {
		pipeParts := strings.Fields(strings.TrimSpace(line[idx+2:]))
		if len(pipeParts) >= 2 && pipeParts[0] == "display" {
			fmt.Printf("syntax error: unknown display option '%s'\n", pipeParts[1])
		} else if len(pipeParts) > 0 {
			fmt.Printf("syntax error: unknown pipe command '%s'\n", pipeParts[0])
		}
		return nil
	}

	// Show scoped to path (editPath + args)
	fullPath := append([]string{}, c.store.GetEditPath()...)
	for _, a := range args {
		if a == "|" {
			break
		}
		fullPath = append(fullPath, a)
	}
	if len(fullPath) > 0 {
		output := c.store.ShowCandidatePath(fullPath)
		if output == "" {
			fmt.Printf("configuration path not found: %s\n", strings.Join(fullPath, " "))
		} else {
			fmt.Print(output)
		}
	} else {
		fmt.Print(c.store.ShowCandidate())
	}
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

// handleInsert handles:
//
//	insert <element-path> before|after <ref-identifier>
//
// The ref-identifier (e.g., "policy allow-all") is relative to the same parent
// as the element. The full reference path is constructed by replacing the
// element's trailing identifier tokens with the ref-identifier tokens.
func (c *CLI) handleInsert(parts []string) error {
	// Find "before" or "after" keyword.
	kwIdx := -1
	isBefore := false
	for i, p := range parts {
		if p == "before" {
			kwIdx = i
			isBefore = true
			break
		}
		if p == "after" {
			kwIdx = i
			break
		}
	}
	if kwIdx < 2 || kwIdx >= len(parts)-1 {
		fmt.Println("usage: insert <element-path> before|after <ref-identifier>")
		return nil
	}
	elemPath := parts[1:kwIdx]
	refTokens := parts[kwIdx+1:]
	editPath := c.store.GetEditPath()
	if len(editPath) > 0 {
		elemPath = append(append([]string{}, editPath...), elemPath...)
	}
	// Construct the full reference path: element's parent path + ref tokens.
	// The ref tokens replace the element's trailing identifier (same keyword + name).
	if len(refTokens) > len(elemPath) {
		fmt.Println("error: reference identifier is longer than element path")
		return nil
	}
	parentPath := elemPath[:len(elemPath)-len(refTokens)]
	refPath := append(append([]string{}, parentPath...), refTokens...)
	return c.store.Insert(elemPath, refPath, isBefore)
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
	// Update zone name mapping for structured log format
	// Uses sorted zone names → sequential IDs (matches compiler order)
	names := make([]string, 0, len(cfg.Security.Zones))
	for name := range cfg.Security.Zones {
		names = append(names, name)
	}
	sort.Strings(names)
	znMap := make(map[uint16]string, len(names))
	for i, name := range names {
		znMap[uint16(i+1)] = name
	}
	c.eventReader.SetZoneNames(znMap)

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
		// Per-stream format overrides global log format
		format := stream.Format
		if format == "" {
			format = cfg.Security.Log.Format
		}
		if format != "" {
			client.Format = format
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
			if ifc.Tunnel != nil && ifc.Tunnel.Source != "" {
				tunnels = append(tunnels, ifc.Tunnel)
			}
			for _, unit := range ifc.Units {
				if unit.Tunnel != nil {
					tunnels = append(tunnels, unit.Tunnel)
				}
			}
		}
		if err := c.routing.ApplyTunnels(tunnels); err != nil {
			fmt.Fprintf(os.Stderr, "warning: tunnel apply failed: %v\n", err)
		}
		if err := c.routing.ApplyXfrmi(cfg.Security.IPsec.VPNs); err != nil {
			fmt.Fprintf(os.Stderr, "warning: xfrmi apply failed: %v\n", err)
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
		// Collect interface bandwidths and point-to-point flags for FRR.
		ifaceBandwidths := make(map[string]uint64)
		ifaceP2P := make(map[string]bool)
		for name, ifc := range cfg.Interfaces.Interfaces {
			if ifc.Bandwidth > 0 {
				ifaceBandwidths[name] = ifc.Bandwidth
			}
			for _, unit := range ifc.Units {
				if unit.PointToPoint {
					ifaceP2P[name] = true
				}
			}
		}

		fc := &frr.FullConfig{
			OSPF:                  cfg.Protocols.OSPF,
			OSPFv3:                cfg.Protocols.OSPFv3,
			BGP:                   cfg.Protocols.BGP,
			StaticRoutes:          cfg.RoutingOptions.StaticRoutes,
			InterfaceBandwidths:   ifaceBandwidths,
			InterfacePointToPoint: ifaceP2P,
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
	if c.ipsec != nil {
		if err := c.ipsec.Apply(ipsec.PrepareConfig(cfg)); err != nil {
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
	zoneID   uint16 // 0 = any
	proto    uint8  // 0 = any
	srcNet   *net.IPNet
	dstNet   *net.IPNet
	srcPort  uint16         // 0 = any
	dstPort  uint16         // 0 = any
	natOnly  bool           // show only NAT sessions
	iface    string         // ingress/egress interface name filter
	summary  bool           // only show count
	brief    bool           // compact tabular view
	appName  string         // application name filter
	sortBy   string         // "bytes" or "packets" for top-talkers
	cfg      *config.Config // for application resolution
	appNames map[uint16]string

	// Populated by showFlowSession before iteration for interface matching.
	zoneIfaces      map[uint16]string          // zone ID → first interface name
	egressIfacesMap map[sessionIfaceKey]string // {ifindex,vlanID} → interface name
}

func (c *CLI) parseSessionFilter(args []string) sessionFilter {
	var f sessionFilter
	f.cfg = c.store.ActiveConfig()
	if c.dp != nil {
		if cr := c.dp.LastCompileResult(); cr != nil {
			f.appNames = cr.AppNames
		}
	}
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
		case "nat", "nat-only":
			f.natOnly = true
		case "interface":
			if i+1 < len(args) {
				i++
				f.iface = args[i]
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
	if f.iface != "" {
		inIf := f.zoneIfaces[val.IngressZone]
		outIf := f.resolveEgressIface(val.FibIfindex, val.FibVlanID, val.EgressZone)
		if !f.ifaceMatches(inIf) && !f.ifaceMatches(outIf) {
			return false
		}
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
		if !appid.SessionMatches(f.appName, f.appNames, f.cfg,
			key.Protocol, ntohs(key.DstPort), val.AppID) {
			return false
		}
	}
	return true
}

func (f *sessionFilter) matchesV6(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
	if f.zoneID != 0 && val.IngressZone != f.zoneID && val.EgressZone != f.zoneID {
		return false
	}
	if f.iface != "" {
		inIf := f.zoneIfaces[val.IngressZone]
		outIf := f.resolveEgressIface(val.FibIfindex, val.FibVlanID, val.EgressZone)
		if !f.ifaceMatches(inIf) && !f.ifaceMatches(outIf) {
			return false
		}
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
		if !appid.SessionMatches(f.appName, f.appNames, f.cfg,
			key.Protocol, ntohs(key.DstPort), val.AppID) {
			return false
		}
	}
	return true
}

func (f *sessionFilter) hasFilter() bool {
	return f.zoneID != 0 || f.proto != 0 || f.srcNet != nil || f.dstNet != nil ||
		f.srcPort != 0 || f.dstPort != 0 || f.natOnly || f.iface != "" || f.appName != ""
}

// ifaceMatches checks whether ifName matches the filter's interface name.
// It matches the exact name or the parent interface (e.g. filter "ge-0/0/0"
// matches session interface "ge-0/0/0.50").
func (f *sessionFilter) ifaceMatches(ifName string) bool {
	if ifName == "" {
		return false
	}
	return ifName == f.iface || strings.HasPrefix(ifName, f.iface+".")
}

// resolveEgressIface resolves a session's egress interface name from FIB
// lookup result, falling back to the zone's first interface.
func (f *sessionFilter) resolveEgressIface(fibIfindex uint32, fibVlanID uint16, egressZone uint16) string {
	if fibIfindex != 0 {
		if ifName, ok := f.egressIfacesMap[sessionIfaceKey{ifindex: fibIfindex, vlanID: fibVlanID}]; ok && ifName != "" {
			return ifName
		}
	}
	return f.zoneIfaces[egressZone]
}

func (c *CLI) fetchPeerSessions(f sessionFilter) *pb.GetSessionsResponse {
	conn := c.dialPeer()
	if conn == nil {
		return nil
	}
	defer conn.Close()

	client := pb.NewBpfrxServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req := &pb.GetSessionsRequest{Limit: 10000}
	if f.proto != 0 {
		req.Protocol = strings.ToUpper(protoNameFromNum(f.proto))
	}
	if f.srcNet != nil {
		req.SourcePrefix = f.srcNet.String()
	}
	if f.dstNet != nil {
		req.DestinationPrefix = f.dstNet.String()
	}
	if f.srcPort != 0 {
		req.SourcePort = uint32(f.srcPort)
	}
	if f.dstPort != 0 {
		req.DestinationPort = uint32(f.dstPort)
	}
	if f.natOnly {
		req.NatOnly = true
	}
	if f.appName != "" {
		req.Application = f.appName
	}
	if f.iface != "" {
		req.InterfaceFilter = f.iface
	}

	resp, err := client.GetSessions(ctx, req)
	if err != nil {
		slog.Warn("failed to fetch peer sessions", "err", err)
		return nil
	}
	return resp
}

// fetchPeerSessionSummary dials the cluster peer's gRPC and returns its session summary.
func (c *CLI) fetchPeerSessionSummary() *pb.GetSessionSummaryResponse {
	conn := c.dialPeer()
	if conn == nil {
		return nil
	}
	defer conn.Close()

	client := pb.NewBpfrxServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	resp, err := client.GetSessionSummary(ctx, &pb.GetSessionSummaryRequest{})
	if err != nil {
		slog.Warn("failed to fetch peer session summary", "err", err)
		return nil
	}
	return resp
}

// topTalkerEntry holds a session's display info for sorting.
type topTalkerEntry struct {
	src, dst, proto, zone, state, app string
	fwdPkts, revPkts                  uint64
	fwdBytes, revBytes                uint64
	age                               uint64
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
	case "system":
		return c.handleClearSystem(args[1:])
	default:
		showHelp()
		return nil
	}
}

func (c *CLI) handleClearSystem(args []string) error {
	if len(args) < 1 || args[0] != "config-lock" {
		cmdtree.PrintTreeHelp("clear system:", operationalTree, "clear", "system")
		return nil
	}
	holder, locked := c.store.ConfigHolder()
	if !locked {
		fmt.Println("No configuration lock held")
		return nil
	}
	c.store.ForceExitConfigure()
	fmt.Printf("Configuration lock cleared (was held by %s)\n", holder)
	return nil
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
		c.clearPeerSessions(nil)
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
	c.clearPeerSessions(&f)
	return nil
}

// clearPeerSessions forwards a clear request to the cluster peer.
func (c *CLI) clearPeerSessions(f *sessionFilter) {
	if c.cluster == nil {
		return
	}
	conn := c.dialPeer()
	if conn == nil {
		return
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req := &pb.ClearSessionsRequest{}
	if f != nil {
		if f.srcNet != nil {
			req.SourcePrefix = f.srcNet.String()
		}
		if f.dstNet != nil {
			req.DestinationPrefix = f.dstNet.String()
		}
		if f.proto != 0 {
			switch f.proto {
			case 6:
				req.Protocol = "tcp"
			case 17:
				req.Protocol = "udp"
			case 1:
				req.Protocol = "icmp"
			}
		}
		req.SourcePort = uint32(f.srcPort)
		req.DestinationPort = uint32(f.dstPort)
		req.Application = f.appName
	}
	ctx = metadata.AppendToOutgoingContext(ctx, "x-peer-forwarded", "1")
	_, _ = pb.NewBpfrxServiceClient(conn).ClearSessions(ctx, req)
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
	case "nptv6":
		return c.showNPTv6(cfg)
	default:
		return fmt.Errorf("unknown show security nat target: %s", args[0])
	}
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
	// Treat first arg as prefix filter (e.g. "show route 10.0.1.0/24")
	// Optional second arg is a modifier: exact, longer, orlonger
	if len(args) >= 1 && (strings.Contains(args[0], "/") || strings.Contains(args[0], ".") || strings.Contains(args[0], ":")) {
		modifier := ""
		if len(args) >= 2 {
			switch args[1] {
			case "exact", "longer", "orlonger":
				modifier = args[1]
			}
		}
		return c.showRoutesForPrefix(args[0], modifier)
	}
	return c.showRoutes()
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

func (c *CLI) dhcpLease(ifaceName string, af dhcp.AddressFamily) *dhcp.Lease {
	if c.dhcp == nil {
		return nil
	}
	return c.dhcp.LeaseFor(ifaceName, af)
}

// showInterfacesDetail shows per-interface info with key stats but less
// verbose than extensive (omits per-error-type breakdowns and BPF counters).

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
		summary := len(args) >= 2 && args[1] == "summary"
		return c.showSystemProcesses(summary)

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

func protoNameFromNum(p uint8) string {
	switch p {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 1:
		return "icmp"
	case 47:
		return "gre"
	case 50:
		return "esp"
	case 4:
		return "ipip"
	case 41:
		return "ipv6"
	case dataplane.ProtoICMPv6:
		return "icmpv6"
	default:
		return fmt.Sprintf("%d", p)
	}
}

// protoNameToID converts a protocol name (e.g. "TCP") to its numeric string ("6").
func protoNameToID(name string) string {
	switch strings.ToUpper(name) {
	case "TCP":
		return "6"
	case "UDP":
		return "17"
	case "ICMP":
		return "1"
	case "GRE":
		return "47"
	case "ICMPV6":
		return "58"
	default:
		return name
	}
}

// splitAddrPort splits "addr:port" into address and port strings.
// Handles IPv6 bracket notation like "[::1]:443".
func splitAddrPort(s string) (string, string) {
	if s == "" {
		return "", ""
	}
	// IPv6 bracket notation: [addr]:port
	if strings.HasPrefix(s, "[") {
		idx := strings.LastIndex(s, "]:")
		if idx >= 0 {
			return s[1:idx], s[idx+2:]
		}
		return strings.Trim(s, "[]"), ""
	}
	// IPv4: last colon separates addr:port
	idx := strings.LastIndex(s, ":")
	if idx < 0 {
		return s, ""
	}
	// Make sure it's not an IPv6 address without brackets
	if strings.Count(s, ":") > 1 {
		return s, ""
	}
	return s[:idx], s[idx+1:]
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

func (c *CLI) valueProvider(hint config.ValueHint, path []string) []config.SchemaCompletion {
	cfg := c.store.ActiveConfig()
	if cfg == nil {
		return nil
	}
	switch hint {
	case config.ValueHintZoneName:
		var out []config.SchemaCompletion
		for name, zone := range cfg.Security.Zones {
			desc := zone.Description
			if desc == "" {
				desc = "(configured)"
			}
			out = append(out, config.SchemaCompletion{Name: name, Desc: desc})
		}
		return out
	case config.ValueHintAddressName:
		var out []config.SchemaCompletion
		if cfg.Security.AddressBook != nil {
			for _, addr := range cfg.Security.AddressBook.Addresses {
				out = append(out, config.SchemaCompletion{Name: addr.Name, Desc: addr.Value})
			}
			for _, as := range cfg.Security.AddressBook.AddressSets {
				out = append(out, config.SchemaCompletion{Name: as.Name, Desc: "address-set"})
			}
		}
		return out
	case config.ValueHintAppName:
		var out []config.SchemaCompletion
		for _, app := range cfg.Applications.Applications {
			out = append(out, config.SchemaCompletion{Name: app.Name, Desc: app.Description})
		}
		for _, as := range cfg.Applications.ApplicationSets {
			out = append(out, config.SchemaCompletion{Name: as.Name, Desc: "application-set"})
		}
		for name := range config.PredefinedApplications {
			out = append(out, config.SchemaCompletion{Name: name, Desc: "predefined"})
		}
		return out
	case config.ValueHintAppSetName:
		var out []config.SchemaCompletion
		for _, as := range cfg.Applications.ApplicationSets {
			out = append(out, config.SchemaCompletion{Name: as.Name, Desc: "application-set"})
		}
		return out
	case config.ValueHintPoolName:
		var out []config.SchemaCompletion
		for name := range cfg.Security.NAT.SourcePools {
			out = append(out, config.SchemaCompletion{Name: name, Desc: "source pool"})
		}
		if cfg.Security.NAT.Destination != nil {
			for name := range cfg.Security.NAT.Destination.Pools {
				out = append(out, config.SchemaCompletion{Name: name, Desc: "destination pool"})
			}
		}
		return out
	case config.ValueHintScreenProfile:
		var out []config.SchemaCompletion
		for name := range cfg.Security.Screen {
			out = append(out, config.SchemaCompletion{Name: name, Desc: "screen profile"})
		}
		return out
	case config.ValueHintStreamName:
		var out []config.SchemaCompletion
		for name := range cfg.Security.Log.Streams {
			out = append(out, config.SchemaCompletion{Name: name, Desc: "log stream"})
		}
		return out
	case config.ValueHintInterfaceName:
		var out []config.SchemaCompletion
		for name, iface := range cfg.Interfaces.Interfaces {
			desc := iface.Description
			if desc == "" {
				desc = "(configured)"
			}
			out = append(out, config.SchemaCompletion{Name: name, Desc: desc})
		}
		return out
	case config.ValueHintPolicyAddress:
		out := []config.SchemaCompletion{
			{Name: "any", Desc: "Any IPv4 or IPv6 address"},
			{Name: "any-ipv4", Desc: "Any IPv4 address"},
			{Name: "any-ipv6", Desc: "Any IPv6 address"},
		}
		if cfg.Security.AddressBook != nil {
			for _, addr := range cfg.Security.AddressBook.Addresses {
				out = append(out, config.SchemaCompletion{Name: addr.Name, Desc: addr.Value})
			}
			for _, as := range cfg.Security.AddressBook.AddressSets {
				out = append(out, config.SchemaCompletion{Name: as.Name, Desc: "address-set"})
			}
		}
		return out
	case config.ValueHintPolicyApp:
		out := []config.SchemaCompletion{
			{Name: "any", Desc: "Any application"},
		}
		for _, app := range cfg.Applications.Applications {
			out = append(out, config.SchemaCompletion{Name: app.Name, Desc: app.Description})
		}
		for _, as := range cfg.Applications.ApplicationSets {
			out = append(out, config.SchemaCompletion{Name: as.Name, Desc: "application-set"})
		}
		for name := range config.PredefinedApplications {
			out = append(out, config.SchemaCompletion{Name: name, Desc: "predefined"})
		}
		return out
	case config.ValueHintPolicyName:
		// Extract zone pair from path: ["security","policies","from-zone","X","to-zone","Y","policy"]
		// or global: ["security","policies","global","policy"]
		var policies []*config.Policy
		for i, tok := range path {
			if tok == "from-zone" && i+3 < len(path) && path[i+2] == "to-zone" {
				fromZone := path[i+1]
				toZone := path[i+3]
				for _, zpp := range cfg.Security.Policies {
					if zpp.FromZone == fromZone && zpp.ToZone == toZone {
						policies = zpp.Policies
						break
					}
				}
				break
			}
			if tok == "global" {
				policies = cfg.Security.GlobalPolicies
				break
			}
		}
		var out []config.SchemaCompletion
		for _, pol := range policies {
			desc := pol.Description
			if desc == "" {
				desc = "(configured)"
			}
			out = append(out, config.SchemaCompletion{Name: pol.Name, Desc: desc})
		}
		return out
	case config.ValueHintUnitNumber:
		// Find the interface name from the path context.
		var ifaceName string
		for i, tok := range path {
			if tok == "interfaces" && i+1 < len(path) {
				ifaceName = path[i+1]
				break
			}
		}
		if ifaceName == "" {
			return nil
		}
		iface := cfg.Interfaces.Interfaces[ifaceName]
		if iface == nil {
			return nil
		}
		var out []config.SchemaCompletion
		for num, unit := range iface.Units {
			desc := unit.Description
			if desc == "" {
				desc = "(configured)"
			}
			out = append(out, config.SchemaCompletion{Name: fmt.Sprintf("%d", num), Desc: desc})
		}
		return out
	}
	return nil
}

func (c *CLI) clusterPrefix() string {
	if c.cluster == nil {
		return ""
	}
	rg0 := c.cluster.GroupState(0)
	if rg0 == nil {
		return ""
	}
	role := "secondary"
	if rg0.State == cluster.StatePrimary {
		role = "primary"
	}
	return fmt.Sprintf("{%s:node%d}", role, c.cluster.NodeID())
}

func (c *CLI) operationalPrompt() string {
	return fmt.Sprintf("%s%s@%s> ", c.clusterPrefix(), c.username, c.hostname)
}

func (c *CLI) configPrompt() string {
	return fmt.Sprintf("%s%s@%s# ", c.clusterPrefix(), c.username, c.hostname)
}

func (c *CLI) handleShowClassOfService(args []string) error {
	if len(args) == 0 || args[0] != "interface" {
		cmdtree.PrintTreeHelp("show class-of-service:", operationalTree, "show", "class-of-service")
		return nil
	}
	return c.showClassOfServiceInterface()
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

// showVRRP displays VRRP status.
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

// showSystemUptime shows system uptime (like Junos "show system uptime").
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

// showARP shows the kernel ARP table (like Junos "show arp no-resolve").
func (c *CLI) handleShowIPv6(args []string) error {
	if len(args) == 0 {
		cmdtree.PrintTreeHelp("show ipv6:", operationalTree, "show", "ipv6")
		return nil
	}
	switch args[0] {
	case "neighbors":
		return c.showIPv6Neighbors()
	case "router-advertisement":
		return c.showIPv6RouterAdvertisement()
	default:
		return fmt.Errorf("unknown show ipv6 target: %s", args[0])
	}
}

// showIPv6Neighbors shows the kernel IPv6 neighbor cache (like Junos "show ipv6 neighbors").
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

// showIPv6RouterAdvertisement shows RA configuration from the active config.

func (c *CLI) buildInterfacesInput() cluster.InterfacesInput {
	var input cluster.InterfacesInput
	cfg := c.store.ActiveConfig()
	if cfg == nil || cfg.Chassis.Cluster == nil {
		return input
	}
	cc := cfg.Chassis.Cluster
	input.ControlInterface = cc.ControlInterface
	input.FabricInterface = cc.FabricInterface
	if fabIfc, ok := cfg.Interfaces.Interfaces[cc.FabricInterface]; ok {
		input.FabricMembers = fabIfc.FabricMembers
	}
	input.Fabric1Interface = cc.Fabric1Interface
	if fab1Ifc, ok := cfg.Interfaces.Interfaces[cc.Fabric1Interface]; ok {
		input.Fabric1Members = fab1Ifc.FabricMembers
	}

	// Build RETH info from config.
	rethMap := cfg.RethToPhysical() // reth-name -> physical-member
	for name, ifc := range cfg.Interfaces.Interfaces {
		if ifc.RedundancyGroup > 0 && strings.HasPrefix(name, "reth") {
			status := "Up"
			// Check physical member link state.
			if phys, ok := rethMap[name]; ok {
				linuxName := config.LinuxIfName(phys)
				link, err := netlink.LinkByName(linuxName)
				if err != nil || (link.Attrs().OperState != netlink.OperUp &&
					link.Attrs().Flags&net.FlagUp == 0) {
					status = "Down"
				}
			}
			input.Reths = append(input.Reths, cluster.RethInfo{
				Name:            name,
				RedundancyGroup: ifc.RedundancyGroup,
				Status:          status,
			})
		}
	}
	sort.Slice(input.Reths, func(i, j int) bool { return input.Reths[i].Name < input.Reths[j].Name })

	// Build local interface monitor info.
	localMonMap := make(map[string]bool) // track which interfaces are local
	monStatuses := make(map[int][]routing.InterfaceMonitorStatus)
	if c.routing != nil {
		if ms := c.routing.InterfaceMonitorStatuses(); ms != nil {
			monStatuses = ms
		}
	}
	for _, rg := range cc.RedundancyGroups {
		if statuses, ok := monStatuses[rg.ID]; ok {
			for _, st := range statuses {
				input.Monitors = append(input.Monitors, cluster.InterfaceMonitorInfo{
					Interface:       st.Interface,
					Weight:          st.Weight,
					Up:              st.Up,
					RedundancyGroup: rg.ID,
				})
				localMonMap[st.Interface] = true
			}
		} else {
			for _, mon := range rg.InterfaceMonitors {
				input.Monitors = append(input.Monitors, cluster.InterfaceMonitorInfo{
					Interface:       mon.Interface,
					Weight:          mon.Weight,
					Up:              true, // unknown, assume up
					RedundancyGroup: rg.ID,
				})
				localMonMap[mon.Interface] = true
			}
		}
	}

	// Build peer interface monitor info from heartbeat.
	if c.cluster != nil {
		peerLive := c.cluster.PeerMonitorStatuses()
		peerMap := make(map[string]bool)
		for _, pm := range peerLive {
			peerMap[pm.Interface] = true
			input.PeerMonitors = append(input.PeerMonitors, pm)
		}
		// Fill config-only peer monitors (not local, not in heartbeat) as down.
		for _, rg := range cc.RedundancyGroups {
			for _, mon := range rg.InterfaceMonitors {
				if localMonMap[mon.Interface] {
					continue
				}
				if peerMap[mon.Interface] {
					continue
				}
				input.PeerMonitors = append(input.PeerMonitors, cluster.InterfaceMonitorInfo{
					Interface:       mon.Interface,
					Weight:          mon.Weight,
					Up:              false,
					RedundancyGroup: rg.ID,
				})
			}
		}
	}

	return input
}

func (c *CLI) userspaceDataplaneStatus() (dpuserspace.ProcessStatus, error) {
	provider, ok := c.dp.(interface {
		Status() (dpuserspace.ProcessStatus, error)
	})
	if !ok {
		return dpuserspace.ProcessStatus{}, fmt.Errorf("userspace status unavailable")
	}
	return provider.Status()
}

func (c *CLI) userspaceDataplaneControl() (interface {
	Status() (dpuserspace.ProcessStatus, error)
	SetForwardingArmed(bool) (dpuserspace.ProcessStatus, error)
	SetQueueState(uint32, bool, bool) (dpuserspace.ProcessStatus, error)
	SetBindingState(uint32, bool, bool) (dpuserspace.ProcessStatus, error)
	InjectPacket(dpuserspace.InjectPacketRequest) (dpuserspace.ProcessStatus, error)
}, error) {
	provider, ok := c.dp.(interface {
		Status() (dpuserspace.ProcessStatus, error)
		SetForwardingArmed(bool) (dpuserspace.ProcessStatus, error)
		SetQueueState(uint32, bool, bool) (dpuserspace.ProcessStatus, error)
		SetBindingState(uint32, bool, bool) (dpuserspace.ProcessStatus, error)
		InjectPacket(dpuserspace.InjectPacketRequest) (dpuserspace.ProcessStatus, error)
	})
	if !ok {
		return nil, fmt.Errorf("userspace dataplane control unavailable")
	}
	return provider, nil
}

func fmtPref(p int) string {
	if p == 0 {
		return "-"
	}
	return strconv.Itoa(p)
}

// showForwardingOptions displays forwarding/sampling configuration.
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

	return fmt.Errorf("usage: request chassis cluster failover redundancy-group <N> [node <N>]")
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
	fmt.Println("  systemctl stop bpfrxd && <replace binary> && systemctl start bpfrxd")
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
