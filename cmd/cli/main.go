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
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/chzyer/readline"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/psaab/bpfrx/pkg/cmdtree"
	pb "github.com/psaab/bpfrx/pkg/grpcapi/bpfrxv1"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:50051", "bpfrxd gRPC address")
	cmdFlag := flag.String("c", "", "run a single command non-interactively and exit")
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
		client:        client,
		hostname:      hostname,
		username:      username,
		configMode:    false,
		clusterRole:   resp.ClusterRole,
		clusterNodeID: resp.ClusterNodeId,
	}

	// Non-interactive mode: run single command and exit.
	if *cmdFlag != "" {
		c.startCmd()
		err := c.dispatch(*cmdFlag)
		c.endCmd()
		if err != nil && err != errExit {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	rc := &remoteCompleter{ctl: c}
	rl, err := readline.NewEx(&readline.Config{
		Prompt:          c.operationalPrompt(),
		HistoryFile:     filepath.Join(os.Getenv("HOME"), ".bpfrx_cli_history"),
		HistoryLimit:    10000,
		InterruptPrompt: "^C",
		EOFPrompt:       "exit",
		AutoComplete:    rc,
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
			text := string(cleanLine[:pos-1])
			// Use gRPC Complete to get candidates.
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			resp, err := c.client.Complete(ctx, &pb.CompleteRequest{
				Line:       text,
				Pos:        int32(len(text)),
				ConfigMode: c.configMode,
			})
			if err != nil || len(resp.Candidates) == 0 {
				fmt.Fprintln(c.rl.Stdout(), "  (no help available)")
				rc.helpWritten = true
				return cleanLine, pos - 1, true
			}
			candidates := make([]cmdtree.Candidate, len(resp.Candidates))
			for i, name := range resp.Candidates {
				desc := ""
				// Use server-provided descriptions if available.
				if i < len(resp.Descriptions) && resp.Descriptions[i] != "" {
					desc = resp.Descriptions[i]
				} else if strings.Contains(text, "|") {
					desc = pipeFilterDescs[name]
				} else {
					desc = remoteLookupDesc(strings.Fields(text), name, c.configMode)
				}
				candidates[i] = cmdtree.Candidate{Name: name, Desc: desc}
			}
			sort.Slice(candidates, func(i, j int) bool { return candidates[i].Name < candidates[j].Name })
			cmdtree.WriteHelp(c.rl.Stdout(), candidates)
			// Suppress duplicate help if readline calls Do() for this key.
			rc.helpWritten = true
			return cleanLine, pos - 1, true
		}),
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

	// Handle SIGINT: first press cancels running command, second exits CLI.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	var lastInterrupt time.Time
	go func() {
		for range sigCh {
			// If a command is running, cancel it.
			if c.cancelCmd() {
				fmt.Fprintln(os.Stderr, "\n^C (command cancelled)")
				continue
			}
			// No command running — double Ctrl-C within 2s exits.
			now := time.Now()
			if now.Sub(lastInterrupt) < 2*time.Second {
				// Clean exit: leave config mode if active.
				if c.configMode {
					_, _ = client.ExitConfigure(context.Background(), &pb.ExitConfigureRequest{})
				}
				os.Exit(0)
			}
			lastInterrupt = now
			fmt.Fprintln(os.Stderr, "\n^C (press again within 2s to exit)")
			// Refresh prompt.
			rl.Refresh()
		}
	}()
	defer signal.Stop(sigCh)

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
				// Ctrl-D: exit config mode, or exit CLI if in operational mode.
				if c.configMode {
					c.configMode = false
					c.editPath = nil
					_, _ = client.ExitConfigure(context.Background(), &pb.ExitConfigureRequest{})
					rl.SetPrompt(c.operationalPrompt())
					fmt.Println("\nExiting configuration mode")
					continue
				}
				break
			}
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			break
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		c.startCmd()
		err = c.dispatch(line)
		c.endCmd()
		if err != nil {
			if err == errExit {
				break
			}
			if err == context.Canceled {
				continue // command was cancelled by Ctrl-C
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
	editPath   []string
	clusterRole   string // "primary", "secondary", or "" (not clustered)
	clusterNodeID int32

	// Command cancellation: Ctrl-C during a running command cancels it.
	cmdMu     sync.Mutex
	cmdCtx    context.Context    // per-command context, cancelled by Ctrl-C
	cmdCancel context.CancelFunc // non-nil while a command is executing
}

// startCmd creates a cancellable context for the current command.
// Must call endCmd() when the command finishes.
func (c *ctl) startCmd() {
	c.cmdMu.Lock()
	c.cmdCtx, c.cmdCancel = context.WithCancel(context.Background())
	c.cmdMu.Unlock()
}

// endCmd clears the per-command context.
func (c *ctl) endCmd() {
	c.cmdMu.Lock()
	if c.cmdCancel != nil {
		c.cmdCancel()
	}
	c.cmdCtx = nil
	c.cmdCancel = nil
	c.cmdMu.Unlock()
}

// ctx returns the current command context, or background if none.
func (c *ctl) ctx() context.Context {
	c.cmdMu.Lock()
	defer c.cmdMu.Unlock()
	if c.cmdCtx != nil {
		return c.cmdCtx
	}
	return context.Background()
}

// cancelCmd cancels any running command. Returns true if a command was cancelled.
func (c *ctl) cancelCmd() bool {
	c.cmdMu.Lock()
	defer c.cmdMu.Unlock()
	if c.cmdCancel != nil {
		c.cmdCancel()
		return true
	}
	return false
}

func (c *ctl) dispatch(line string) error {
	// Extract pipe filter (| match, | except, | find, | count, | last, | no-more).
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
	case "match", "grep", "except", "find", "count", "last", "no-more":
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
	case "find":
		lp := strings.ToLower(pipeArg)
		found := false
		for _, line := range lines {
			if !found && strings.Contains(strings.ToLower(line), lp) {
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
		exclusive := len(parts) >= 2 && parts[1] == "exclusive"
		_, err := c.client.EnterConfigure(c.ctx(), &pb.EnterConfigureRequest{
			Exclusive: exclusive,
		})
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		c.configMode = true
		c.rl.SetPrompt(c.configPrompt())
		if exclusive {
			fmt.Println("Entering configuration mode (exclusive)")
		} else {
			fmt.Println("Entering configuration mode")
		}
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

	case "test":
		return c.handleTest(parts[1:])

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

func (c *ctl) dispatchConfig(line string) error {
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
		c.editPath = append(c.editPath, parts[1:]...)
		c.rl.SetPrompt(c.configPrompt())
		fmt.Printf("[edit %s]\n", strings.Join(c.editPath, " "))
		return nil

	case "top":
		c.editPath = nil
		c.rl.SetPrompt(c.configPrompt())
		fmt.Println("[edit]")
		return nil

	case "up":
		if len(c.editPath) > 0 {
			c.editPath = c.editPath[:len(c.editPath)-1]
		}
		c.rl.SetPrompt(c.configPrompt())
		if len(c.editPath) > 0 {
			fmt.Printf("[edit %s]\n", strings.Join(c.editPath, " "))
		} else {
			fmt.Println("[edit]")
		}
		return nil

	case "set":
		if len(parts) < 2 {
			return fmt.Errorf("set: missing path")
		}
		fullPath := append(append([]string{}, c.editPath...), parts[1:]...)
		_, err := c.client.Set(c.ctx(), &pb.SetRequest{
			Input: strings.Join(fullPath, " "),
		})
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		return nil

	case "delete":
		if len(parts) < 2 {
			return fmt.Errorf("delete: missing path")
		}
		fullPath := append(append([]string{}, c.editPath...), parts[1:]...)
		_, err := c.client.Delete(c.ctx(), &pb.DeleteRequest{
			Input: strings.Join(fullPath, " "),
		})
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		return nil

	case "copy", "rename":
		toIdx := -1
		for i, p := range parts {
			if p == "to" {
				toIdx = i
				break
			}
		}
		if toIdx < 2 || toIdx >= len(parts)-1 {
			fmt.Printf("usage: %s <src-path> to <dst-path>\n", parts[0])
			return nil
		}
		srcParts := parts[1:toIdx]
		dstParts := parts[toIdx+1:]
		if len(c.editPath) > 0 {
			srcParts = append(append([]string{}, c.editPath...), srcParts...)
			dstParts = append(append([]string{}, c.editPath...), dstParts...)
		}
		fullInput := parts[0] + " " + strings.Join(srcParts, " ") + " to " + strings.Join(dstParts, " ")
		_, err := c.client.Set(c.ctx(), &pb.SetRequest{Input: fullInput})
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		return nil

	case "insert":
		// Find "before" or "after" keyword.
		kwIdx := -1
		for i, p := range parts {
			if p == "before" || p == "after" {
				kwIdx = i
				break
			}
		}
		if kwIdx < 2 || kwIdx >= len(parts)-1 {
			fmt.Println("usage: insert <element-path> before|after <ref-identifier>")
			return nil
		}
		elemParts := parts[1:kwIdx]
		kw := parts[kwIdx]
		refTokens := parts[kwIdx+1:]
		if len(c.editPath) > 0 {
			elemParts = append(append([]string{}, c.editPath...), elemParts...)
		}
		// Send: insert <full-elem-path> before|after <ref-tokens>
		// Server constructs full ref path from element's parent.
		fullInput := "insert " + strings.Join(elemParts, " ") + " " + kw + " " + strings.Join(refTokens, " ")
		_, err := c.client.Set(c.ctx(), &pb.SetRequest{Input: fullInput})
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
		_, err := c.client.Rollback(c.ctx(), &pb.RollbackRequest{N: n})
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
		_, _ = c.client.ExitConfigure(c.ctx(), &pb.ExitConfigureRequest{})
		c.configMode = false
		c.editPath = nil
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
		printRemoteTreeHelp("show: specify what to show", "show")
		return nil
	}

	switch args[0] {
	case "chassis":
		if len(args) >= 2 {
			switch args[1] {
			case "cluster":
				if len(args) >= 3 {
					switch args[2] {
					case "status":
						return c.showText("chassis-cluster-status")
					case "interfaces":
						return c.showText("chassis-cluster-interfaces")
					case "information":
						return c.showText("chassis-cluster-information")
					case "statistics":
						return c.showText("chassis-cluster-statistics")
					case "control-plane":
						if len(args) >= 4 && args[3] == "statistics" {
							return c.showText("chassis-cluster-control-plane-statistics")
						}
						return c.showText("chassis-cluster-control-plane-statistics")
					case "data-plane":
						if len(args) >= 4 {
							switch args[3] {
							case "statistics":
								return c.showText("chassis-cluster-data-plane-statistics")
							case "interfaces":
								return c.showText("chassis-cluster-data-plane-interfaces")
							}
						}
						return c.showText("chassis-cluster-data-plane-statistics")
					case "ip-monitoring":
						if len(args) >= 4 && args[3] == "status" {
							return c.showText("chassis-cluster-ip-monitoring-status")
						}
						return c.showText("chassis-cluster-ip-monitoring-status")
					case "fabric":
						if len(args) >= 4 && args[3] == "statistics" {
							return c.showText("chassis-cluster-fabric-statistics")
						}
						return c.showText("chassis-cluster-fabric-statistics")
					}
				}
				return c.showText("chassis-cluster")
			case "environment":
				return c.showText("chassis-environment")
			case "hardware":
				return c.showText("chassis-hardware")
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
		} else if strings.Contains(rest, "| display xml") {
			format = pb.ConfigFormat_XML
		} else if strings.Contains(rest, "| display inheritance") {
			format = pb.ConfigFormat_INHERITANCE
		} else if idx := strings.Index(rest, "| "); idx >= 0 {
			pipeParts := strings.Fields(strings.TrimSpace(rest[idx+2:]))
			if len(pipeParts) >= 2 && pipeParts[0] == "display" {
				fmt.Printf("syntax error: unknown display option '%s'\n", pipeParts[1])
			} else if len(pipeParts) > 0 {
				fmt.Printf("syntax error: unknown pipe command '%s'\n", pipeParts[0])
			}
			return nil
		}
		// Extract path components (everything after "configuration" before "|")
		var path []string
		for _, a := range args[1:] {
			if a == "|" {
				break
			}
			path = append(path, a)
		}
		resp, err := c.client.ShowConfig(c.ctx(), &pb.ShowConfigRequest{
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

	case "class-of-service":
		if len(args) >= 2 && args[1] == "interface" {
			return c.showText("class-of-service")
		}
		printRemoteTreeHelp("show class-of-service:", "show", "class-of-service")
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
		printRemoteTreeHelp("show dhcp:", "show", "dhcp")
		return nil

	case "route":
		if len(args) >= 2 && args[1] == "terse" {
			return c.showText("route-terse")
		}
		if len(args) >= 2 && args[1] == "detail" {
			return c.showText("route-detail")
		}
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
		// Prefix filter with optional modifier (e.g. "show route 10.0.1.0/24 exact")
		if len(args) >= 2 && (strings.Contains(args[1], "/") || strings.Contains(args[1], ".") || strings.Contains(args[1], ":")) {
			topic := "route-prefix:" + args[1]
			if len(args) >= 3 {
				switch args[2] {
				case "exact", "longer", "orlonger":
					topic += " " + args[2]
				}
			}
			return c.showText(topic)
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
		if len(args) >= 2 && args[1] == "v3" {
			return c.showText("snmp-v3")
		}
		return c.showText("snmp")

	case "lldp":
		if len(args) >= 2 && args[1] == "neighbors" {
			return c.showText("lldp-neighbors")
		}
		return c.showText("lldp")

	case "dhcp-relay":
		return c.showText("dhcp-relay")

	case "dhcp-server":
		if len(args) >= 2 && args[1] == "detail" {
			return c.showText("dhcp-server-detail")
		}
		return c.showText("dhcp-server")

	case "firewall":
		if len(args) >= 3 && args[1] == "filter" {
			return c.showText("firewall-filter:" + args[2])
		}
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
		if len(args) >= 2 && args[1] == "router-advertisement" {
			return c.showText("ipv6-router-advertisement")
		}
		printRemoteTreeHelp("show ipv6:", "show", "ipv6")
		return nil

	case "policy-options":
		return c.showText("policy-options")

	case "route-map":
		return c.showText("route-map")

	case "event-options":
		return c.showText("event-options")

	case "routing-options":
		return c.showText("routing-options")

	case "routing-instances":
		if len(args) >= 2 && args[1] == "detail" {
			return c.showText("routing-instances-detail")
		}
		return c.showText("routing-instances")

	case "forwarding-options":
		if len(args) >= 2 && args[1] == "port-mirroring" {
			return c.showText("forwarding-options-port-mirroring")
		}
		return c.showText("forwarding-options")

	case "vlans":
		return c.showText("vlans")

	case "task":
		return c.showText("task")

	case "monitor":
		if len(args) >= 3 && args[1] == "security" && args[2] == "flow" {
			return c.showText("monitor-security-flow")
		}
		printRemoteTreeHelp("show monitor:", "show", "monitor")
		return nil

	default:
		return fmt.Errorf("unknown show target: %s", args[0])
	}
}

func (c *ctl) handleShowServices(args []string) error {
	if len(args) == 0 {
		printRemoteTreeHelp("show services:", "show", "services")
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
		printRemoteTreeHelp("show security:", "show", "security")
		return nil
	}

	switch args[0] {
	case "zones":
		if len(args) >= 2 && args[1] == "detail" {
			return c.showText("zones-detail")
		}
		return c.showZones()
	case "policies":
		if len(args) >= 2 && args[1] == "brief" {
			return c.showPoliciesBrief()
		}
		if len(args) >= 2 && args[1] == "detail" {
			// Parse optional from-zone/to-zone filters
			var filterParts []string
			for i := 2; i+1 < len(args); i++ {
				if args[i] == "from-zone" || args[i] == "to-zone" {
					filterParts = append(filterParts, args[i], args[i+1])
					i++
				}
			}
			return c.showTextFiltered("policies-detail", strings.Join(filterParts, " "))
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
		if len(args) >= 2 && args[1] == "ids-option" && len(args) >= 3 {
			if len(args) >= 4 && args[3] == "detail" {
				return c.showText("screen-ids-option-detail:" + args[2])
			}
			return c.showText("screen-ids-option:" + args[2])
		}
		if len(args) >= 2 && args[1] == "statistics" {
			if len(args) >= 4 && args[2] == "zone" {
				return c.showText("screen-statistics:" + args[3])
			}
			return c.showText("screen-statistics-all")
		}
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
		detail := len(args) >= 2 && args[1] == "detail"
		return c.showStatistics(detail)
	case "ipsec":
		return c.showIPsec(args[1:])
	case "ike":
		return c.showIKE(args[1:])
	case "match-policies":
		return c.showMatchPolicies(args[1:])
	case "vrrp":
		return c.showVRRP()
	case "alarms":
		if len(args) >= 2 && args[1] == "detail" {
			return c.showText("security-alarms-detail")
		}
		return c.showText("security-alarms")
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
	resp, err := c.client.GetZones(c.ctx(), &pb.GetZonesRequest{})
	if err != nil {
		return fmt.Errorf("%v", err)
	}

	// Fetch policies for cross-reference
	polResp, _ := c.client.GetPolicies(c.ctx(), &pb.GetPoliciesRequest{})

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
	resp, err := c.client.GetPolicies(c.ctx(), &pb.GetPoliciesRequest{})
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
	req := &pb.GetSessionsRequest{Limit: 100, IncludePeer: true}
	brief := false
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
		case "application":
			if i+1 < len(args) {
				i++
				req.Application = args[i]
			}
		case "summary":
			return c.showSessionSummary()
		case "brief":
			brief = true
		case "interface":
			if i+1 < len(args) {
				i++ // consume value; interface filter handled locally only
			}
		case "sort-by":
			if i+1 < len(args) {
				i++
				return c.showText("sessions-top:" + args[i])
			}
		}
	}

	resp, err := c.client.GetSessions(c.ctx(), req)
	if err != nil {
		return fmt.Errorf("%v", err)
	}

	hasPeer := resp.Peer != nil

	if hasPeer {
		printNodeSessionHeader(int(resp.NodeId))
	}
	printSessionEntries(resp, brief)

	if hasPeer {
		fmt.Println()
		printNodeSessionHeader(int(resp.Peer.NodeId))
		printSessionEntries(resp.Peer, brief)
	}
	return nil
}

func printNodeSessionHeader(nodeID int) {
	fmt.Printf("node%d:\n", nodeID)
	fmt.Println("--------------------------------------------------------------------------")
}

func printSessionEntries(resp *pb.GetSessionsResponse, brief bool) {
	if brief {
		fmt.Printf("%-5s %-22s %-22s %-5s %-20s %-3s %-5s %5s %s\n",
			"ID", "Source", "Destination", "Proto", "Zone", "NAT", "State", "Age", "Pkts(f/r)")
		for _, se := range resp.Sessions {
			inZone := se.IngressZoneName
			if inZone == "" {
				inZone = fmt.Sprintf("%d", se.IngressZone)
			}
			outZone := se.EgressZoneName
			if outZone == "" {
				outZone = fmt.Sprintf("%d", se.EgressZone)
			}
			natFlag := " "
			if se.Nat != "" {
				if strings.Contains(se.Nat, "SNAT") {
					natFlag = "S"
				}
				if strings.Contains(se.Nat, "DNAT") || strings.HasPrefix(se.Nat, "dst") {
					natFlag = "D"
				}
			}
			st := se.State
			if len(st) > 5 {
				st = st[:5]
			}
			sid := se.SessionId
			if sid == 0 {
				sid = uint64(resp.Offset) + 1
			}
			fmt.Printf("%-5d %-22s %-22s %-5s %-20s %-3s %-5s %5d %d/%d\n",
				sid,
				fmt.Sprintf("%s/%d", se.SrcAddr, se.SrcPort),
				fmt.Sprintf("%s/%d", se.DstAddr, se.DstPort),
				se.Protocol, inZone+"->"+outZone, natFlag,
				st, se.AgeSeconds,
				se.FwdPackets, se.RevPackets)
		}
		fmt.Printf("Total sessions: %d\n", resp.Total)
		return
	}

	for _, se := range resp.Sessions {
		polDisplay := se.PolicyName
		if polDisplay == "" {
			polDisplay = fmt.Sprintf("%d", se.PolicyId)
		}
		sid := se.SessionId
		if sid == 0 {
			sid = uint64(resp.Offset) + 1
		}

		// Junos format header
		haStr := ""
		if se.HaActive {
			haStr = "Active"
		} else {
			haStr = "Backup"
		}
		fmt.Printf("Session ID: %d, Policy name: %s/%d, HA State: %s, Timeout: %d, Session State: Valid\n",
			sid, polDisplay, se.PolicyId, haStr, se.TimeoutSeconds)

		// In line: original direction
		inIf := se.IngressInterface
		if inIf == "" {
			inIf = se.IngressZoneName
		}
		fmt.Printf("  In: %s/%d --> %s/%d;%s, Conn Tag: 0x0, If: %s, Pkts: %d, Bytes: %d,\n",
			se.SrcAddr, se.SrcPort, se.DstAddr, se.DstPort,
			se.Protocol, inIf, se.FwdPackets, se.FwdBytes)

		// Out line: reverse direction (with NAT translations applied)
		outSrcAddr := se.DstAddr
		outSrcPort := se.DstPort
		outDstAddr := se.SrcAddr
		outDstPort := se.SrcPort
		if se.NatSrcAddr != "" {
			outDstAddr = se.NatSrcAddr
			outDstPort = se.NatSrcPort
		}
		if se.NatDstAddr != "" {
			outSrcAddr = se.NatDstAddr
			outSrcPort = se.NatDstPort
		}
		outIf := se.EgressInterface
		if outIf == "" {
			outIf = se.EgressZoneName
		}
		fmt.Printf("  Out: %s/%d --> %s/%d;%s, Conn Tag: 0x0, If: %s, Pkts: %d, Bytes: %d,\n",
			outSrcAddr, outSrcPort, outDstAddr, outDstPort,
			se.Protocol, outIf, se.RevPackets, se.RevBytes)
		fmt.Println()
	}
	fmt.Printf("Total sessions: %d\n", resp.Total)
}

func (c *ctl) showSessionSummary() error {
	resp, err := c.client.GetSessionSummary(c.ctx(), &pb.GetSessionSummaryRequest{IncludePeer: true})
	if err != nil {
		return fmt.Errorf("%v", err)
	}

	if resp.Peer != nil {
		// Cluster mode: print both nodes with Junos-style headers.
		printNodeSessionSummary(int(resp.NodeId), resp)
		fmt.Println()
		printNodeSessionSummary(int(resp.Peer.NodeId), resp.Peer)
	} else {
		// Standalone: Junos-style summary without node headers.
		printSessionSummaryBlock(resp)
	}
	return nil
}

func printNodeSessionSummary(nodeID int, resp *pb.GetSessionSummaryResponse) {
	fmt.Printf("node%d:\n", nodeID)
	fmt.Println("--------------------------------------------------------------------------")
	printSessionSummaryBlock(resp)
}

func printSessionSummaryBlock(resp *pb.GetSessionSummaryResponse) {
	unicast := resp.ForwardOnly
	fmt.Printf("Unicast-sessions: %d\n", unicast)
	fmt.Printf("Multicast-sessions: 0\n")
	fmt.Printf("Services-offload-sessions: 0\n")
	fmt.Printf("Failed-sessions: 0\n")
	fmt.Printf("Sessions-in-drop-flow: 0\n")
	fmt.Printf("Sessions-in-use: %d\n", unicast)
	fmt.Printf("  Valid sessions: %d\n", unicast)
	fmt.Printf("  Pending sessions: 0\n")
	fmt.Printf("  Invalidated sessions: 0\n")
	fmt.Printf("  Sessions in other states: 0\n")
	fmt.Printf("Maximum-sessions: 10000000\n")
}

func (c *ctl) handleShowNAT(args []string) error {
	if len(args) == 0 {
		printRemoteTreeHelp("show security nat:", "show", "security", "nat")
		return nil
	}
	switch args[0] {
	case "static":
		return c.showText("nat-static")
	case "nptv6":
		return c.showText("nat-nptv6")
	case "source":
		if len(args) >= 2 && args[1] == "summary" {
			return c.showNATSourceSummary()
		}
		if len(args) >= 2 && args[1] == "pool" {
			return c.showNATPoolStats()
		}
		if len(args) >= 3 && args[1] == "persistent-nat-table" && args[2] == "detail" {
			return c.showText("persistent-nat-detail")
		}
		if len(args) >= 2 && args[1] == "persistent-nat-table" {
			return c.showText("persistent-nat")
		}
		if len(args) >= 3 && args[1] == "rule" && args[2] == "detail" {
			return c.showText("nat-source-rule-detail")
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
		resp, err := c.client.GetNATSource(c.ctx(), &pb.GetNATSourceRequest{})
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
		if len(args) >= 3 && args[1] == "rule" && args[2] == "detail" {
			return c.showText("nat-dest-rule-detail")
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
		resp, err := c.client.GetNATDestination(c.ctx(), &pb.GetNATDestinationRequest{})
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

	resp, err := c.client.MatchPolicies(c.ctx(), req)
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
	resp, err := c.client.GetVRRPStatus(c.ctx(), &pb.GetVRRPStatusRequest{})
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
	resp, err := c.client.GetNATPoolStats(c.ctx(), &pb.GetNATPoolStatsRequest{})
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	fmt.Printf("Total active translations: %d\n", resp.TotalActiveTranslations)
	fmt.Printf("Total pools: %d\n", len(resp.Pools))
	fmt.Println()
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
	if len(resp.RuleSetSessions) > 0 {
		fmt.Println()
		fmt.Printf("%-30s %-12s\n", "Rule-set (from -> to)", "Sessions")
		for _, rs := range resp.RuleSetSessions {
			fmt.Printf("%-30s %-12d\n",
				fmt.Sprintf("%s -> %s", rs.FromZone, rs.ToZone), rs.Sessions)
		}
	}
	return nil
}

func (c *ctl) showNATPoolStats() error {
	resp, err := c.client.GetNATPoolStats(c.ctx(), &pb.GetNATPoolStatsRequest{})
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
	resp, err := c.client.GetNATRuleStats(c.ctx(), &pb.GetNATRuleStatsRequest{
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
	resp, err := c.client.GetNATDestination(c.ctx(), &pb.GetNATDestinationRequest{})
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
	statsResp, err := c.client.GetNATRuleStats(c.ctx(), &pb.GetNATRuleStatsRequest{
		NatType: "destination",
	})
	poolHits := make(map[string]uint64)
	if err == nil {
		for _, r := range statsResp.Rules {
			poolHits[r.Action] += r.HitPackets
		}
	}

	fmt.Printf("Total active translations: %d\n", resp.TotalActiveTranslations)
	fmt.Printf("Total pools: %d\n", len(pools))
	fmt.Println()
	fmt.Printf("%-20s %-20s %-8s %-12s\n", "Pool", "Address", "Port", "Hits")
	for addr, p := range pools {
		portStr := "-"
		if p.port > 0 {
			portStr = fmt.Sprintf("%d", p.port)
		}
		fmt.Printf("%-20s %-20s %-8s %-12d\n", addr, addr, portStr, poolHits["pool "+addr])
	}
	if len(resp.RuleSetSessions) > 0 {
		fmt.Println()
		fmt.Printf("%-30s %-12s\n", "Rule-set (from -> to)", "Sessions")
		for _, rs := range resp.RuleSetSessions {
			fmt.Printf("%-30s %-12d\n",
				fmt.Sprintf("%s -> %s", rs.FromZone, rs.ToZone), rs.Sessions)
		}
	}
	return nil
}

func (c *ctl) showNATDestinationPool() error {
	resp, err := c.client.GetNATDestination(c.ctx(), &pb.GetNATDestinationRequest{})
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
	resp, err := c.client.GetNATRuleStats(c.ctx(), &pb.GetNATRuleStatsRequest{
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
	// Use ShowText for server-side formatting with full name resolution
	filter := ""
	for _, a := range args {
		if _, err := strconv.Atoi(a); err == nil {
			filter = a
			break
		}
	}
	return c.showTextFiltered("security-log", filter)
}

func (c *ctl) showStatistics(detail bool) error {
	resp, err := c.client.GetGlobalStats(c.ctx(), &pb.GetGlobalStatsRequest{})
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

	if !detail {
		return nil
	}

	// Screen drops breakdown
	if resp.ScreenDrops > 0 {
		fmt.Printf("\nScreen drop details:\n")
		for name, count := range resp.ScreenDropDetails {
			fmt.Printf("  %-25s %d\n", name+":", count)
		}
	}

	// Buffers/map utilization via text topic
	text, err := c.client.ShowText(c.ctx(), &pb.ShowTextRequest{Topic: "buffers"})
	if err == nil && text.Output != "" {
		fmt.Printf("\n%s", text.Output)
	}
	return nil
}

func (c *ctl) showFlowStatistics() error {
	resp, err := c.client.GetGlobalStats(c.ctx(), &pb.GetGlobalStatsRequest{})
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
		resp, err := c.client.GetIPsecSA(c.ctx(), &pb.GetIPsecSARequest{})
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
		resp, err := c.client.GetIPsecSA(c.ctx(), &pb.GetIPsecSARequest{})
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		fmt.Print(resp.Output)
		return nil
	}
	if len(args) > 0 && args[0] == "statistics" {
		return c.showText("ipsec-statistics")
	}
	printRemoteTreeHelp("show security ipsec:", "show", "security", "ipsec")
	return nil
}

func (c *ctl) showInterfaces(args []string) error {
	if len(args) > 0 && args[0] == "tunnel" {
		return c.showText("tunnels")
	}
	if len(args) > 0 && args[0] == "extensive" {
		return c.showText("interfaces-extensive")
	}
	if len(args) > 0 && args[0] == "statistics" {
		return c.showText("interfaces-statistics")
	}
	if len(args) > 0 && args[0] == "detail" {
		return c.showText("interfaces-detail")
	}
	// Handle "show interfaces <name> detail"
	if len(args) >= 2 && args[len(args)-1] == "detail" {
		return c.showTextFiltered("interfaces-detail", args[0])
	}
	req := &pb.ShowInterfacesDetailRequest{}
	for _, a := range args {
		if a == "terse" {
			req.Terse = true
		} else {
			req.Filter = a
		}
	}
	resp, err := c.client.ShowInterfacesDetail(c.ctx(), req)
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	fmt.Print(resp.Output)
	return nil
}

func (c *ctl) showDHCPLeases() error {
	resp, err := c.client.GetDHCPLeases(c.ctx(), &pb.GetDHCPLeasesRequest{})
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
		if len(l.DelegatedPrefixes) > 0 {
			fmt.Println("    Delegated prefixes:")
			for _, dp := range l.DelegatedPrefixes {
				fmt.Printf("      Prefix:    %s\n", dp.Prefix)
				fmt.Printf("      Preferred: %s\n", dp.PreferredLifetime)
				fmt.Printf("      Valid:     %s\n", dp.ValidLifetime)
			}
		}
		fmt.Println()
	}
	return nil
}

func (c *ctl) showDHCPClientIdentifier() error {
	resp, err := c.client.GetDHCPClientIdentifiers(c.ctx(), &pb.GetDHCPClientIdentifiersRequest{})
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
	return c.showText("route-all")
}

func (c *ctl) handleShowProtocols(args []string) error {
	if len(args) == 0 {
		printRemoteTreeHelp("show protocols:", "show", "protocols")
		return nil
	}
	switch args[0] {
	case "ospf":
		typ := "neighbor"
		if len(args) >= 2 {
			typ = args[1]
			if typ == "neighbor" && len(args) >= 3 && args[2] == "detail" {
				typ = "neighbor-detail"
			}
		}
		resp, err := c.client.GetOSPFStatus(c.ctx(), &pb.GetOSPFStatusRequest{Type: typ})
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		fmt.Print(resp.Output)
		return nil
	case "bgp":
		typ := "summary"
		if len(args) >= 2 {
			typ = args[1]
			// "show protocols bgp neighbor <ip>" → type "neighbor:<ip>"
			// "show protocols bgp neighbor <ip> received-routes" → type "received-routes:<ip>"
			// "show protocols bgp neighbor <ip> advertised-routes" → type "advertised-routes:<ip>"
			if typ == "neighbor" && len(args) >= 3 {
				ip := args[2]
				if len(args) >= 4 {
					switch args[3] {
					case "received-routes":
						typ = "received-routes:" + ip
					case "advertised-routes":
						typ = "advertised-routes:" + ip
					default:
						typ = "neighbor:" + ip
					}
				} else {
					typ = "neighbor:" + ip
				}
			}
		}
		resp, err := c.client.GetBGPStatus(c.ctx(), &pb.GetBGPStatusRequest{Type: typ})
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		fmt.Print(resp.Output)
		return nil
	case "bfd":
		if len(args) >= 2 && args[1] == "peers" {
			return c.showText("bfd-peers")
		}
		printRemoteTreeHelp("show protocols bfd:", "show", "protocols", "bfd")
		return nil
	case "rip":
		resp, err := c.client.GetRIPStatus(c.ctx(), &pb.GetRIPStatusRequest{})
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		fmt.Print(resp.Output)
		return nil
	case "isis":
		typ := "adjacency"
		if len(args) >= 2 {
			typ = args[1]
			if typ == "adjacency" && len(args) >= 3 && args[2] == "detail" {
				typ = "adjacency-detail"
			}
		}
		resp, err := c.client.GetISISStatus(c.ctx(), &pb.GetISISStatusRequest{Type: typ})
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
		printRemoteTreeHelp("show system:", "show", "system")
		return nil
	}

	switch args[0] {
	case "commit":
		// "show system commit history"
		if len(args) >= 2 && args[1] == "history" {
			return c.showText("commit-history")
		}
		printRemoteTreeHelp("show system commit:", "show", "system", "commit")
		return nil

	case "rollback":
		if len(args) >= 2 {
			// "show system rollback compare N"
			if args[1] == "compare" && len(args) >= 3 {
				n, err := strconv.Atoi(args[2])
				if err != nil || n < 1 {
					return fmt.Errorf("usage: show system rollback compare <N>")
				}
				resp, err := c.client.ShowCompare(c.ctx(), &pb.ShowCompareRequest{
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
			} else if strings.Contains(rest, "| display xml") {
				format = pb.ConfigFormat_XML
			} else if strings.Contains(rest, "compare") {
				// "show system rollback N compare"
				resp, err := c.client.ShowCompare(c.ctx(), &pb.ShowCompareRequest{
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
			resp, err := c.client.ShowRollback(c.ctx(), &pb.ShowRollbackRequest{
				N:      int32(n),
				Format: format,
			})
			if err != nil {
				return fmt.Errorf("%v", err)
			}
			fmt.Print(resp.Output)
			return nil
		}

		resp, err := c.client.ListHistory(c.ctx(), &pb.ListHistoryRequest{})
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
		if len(args) >= 2 && args[1] == "detail" {
			return c.showText("buffers-detail")
		}
		return c.showText("buffers")

	case "boot-messages":
		return c.showSystemInfo("boot-messages")

	case "core-dumps":
		return c.showText("core-dumps")

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
			resp, err := c.client.ShowCompare(c.ctx(), &pb.ShowCompareRequest{RollbackN: int32(n)})
			if err != nil {
				return fmt.Errorf("%v", err)
			}
			fmt.Print(resp.Output)
			return nil
		}
		resp, err := c.client.ShowCompare(c.ctx(), &pb.ShowCompareRequest{})
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
	} else if strings.Contains(line, "| display xml") {
		format = pb.ConfigFormat_XML
	} else if strings.Contains(line, "| display inheritance") {
		format = pb.ConfigFormat_INHERITANCE
	} else if idx := strings.Index(line, "| "); idx >= 0 {
		pipeParts := strings.Fields(strings.TrimSpace(line[idx+2:]))
		if len(pipeParts) >= 2 && pipeParts[0] == "display" {
			fmt.Printf("syntax error: unknown display option '%s'\n", pipeParts[1])
		} else if len(pipeParts) > 0 {
			fmt.Printf("syntax error: unknown pipe command '%s'\n", pipeParts[0])
		}
		return nil
	}
	// Build path from editPath + any explicit path args (before pipe)
	var path []string
	if len(c.editPath) > 0 {
		path = append(path, c.editPath...)
	}
	for _, a := range args {
		if a == "|" {
			break
		}
		path = append(path, a)
	}
	resp, err := c.client.ShowConfig(c.ctx(), &pb.ShowConfigRequest{
		Format: format,
		Target: pb.ConfigTarget_CANDIDATE,
		Path:   path,
	})
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	fmt.Print(resp.Output)
	return nil
}

func (c *ctl) handleCommit(args []string) error {
	if len(args) > 0 && args[0] == "check" {
		_, err := c.client.CommitCheck(c.ctx(), &pb.CommitCheckRequest{})
		if err != nil {
			return fmt.Errorf("commit check failed: %v", err)
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
		resp, err := c.client.Commit(c.ctx(), &pb.CommitRequest{Comment: desc})
		if err != nil {
			return fmt.Errorf("commit failed: %v", err)
		}
		c.refreshPrompt()
		if resp.Summary != "" {
			fmt.Printf("commit complete: %s\n", resp.Summary)
		} else {
			fmt.Println("commit complete")
		}
		return nil
	}

	if len(args) > 0 && args[0] == "confirmed" {
		minutes := int32(10)
		if len(args) >= 2 {
			if v, err := strconv.Atoi(args[1]); err == nil && v > 0 {
				minutes = int32(v)
			}
		}
		_, err := c.client.CommitConfirmed(c.ctx(), &pb.CommitConfirmedRequest{Minutes: minutes})
		if err != nil {
			return fmt.Errorf("commit confirmed failed: %v", err)
		}
		c.refreshPrompt()
		fmt.Printf("commit confirmed will be automatically rolled back in %d minutes unless confirmed\n", minutes)
		return nil
	}

	resp, err := c.client.Commit(c.ctx(), &pb.CommitRequest{})
	if err != nil {
		return fmt.Errorf("commit failed: %v", err)
	}
	c.refreshPrompt()
	if resp.Summary != "" {
		fmt.Printf("commit complete: %s\n", resp.Summary)
	} else {
		fmt.Println("commit complete")
	}
	return nil
}

// refreshPrompt re-reads the system hostname and cluster status, and updates the readline prompt.
func (c *ctl) refreshPrompt() {
	if h, err := os.Hostname(); err == nil && h != "" {
		c.hostname = h
	}
	// Refresh cluster status from server.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	if resp, err := c.client.GetStatus(ctx, &pb.GetStatusRequest{}); err == nil {
		c.clusterRole = resp.ClusterRole
		c.clusterNodeID = resp.ClusterNodeId
	}
	cancel()
	if c.rl != nil {
		if c.configMode {
			c.rl.SetPrompt(c.configPrompt())
		} else {
			c.rl.SetPrompt(c.operationalPrompt())
		}
	}
}

func (c *ctl) handleClear(args []string) error {
	showHelp := func() {
		printRemoteTreeHelp("clear:", "clear")
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

func (c *ctl) handleClearSystem(args []string) error {
	if len(args) < 1 || args[0] != "config-lock" {
		printRemoteTreeHelp("clear system:", "clear", "system")
		return nil
	}
	resp, err := c.client.SystemAction(c.ctx(), &pb.SystemActionRequest{
		Action: "clear-config-lock",
	})
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	fmt.Println(resp.Message)
	return nil
}

func (c *ctl) handleClearInterfaces(args []string) error {
	if len(args) >= 1 && args[0] == "statistics" {
		resp, err := c.client.SystemAction(c.ctx(), &pb.SystemActionRequest{
			Action: "clear-interfaces-statistics",
		})
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		fmt.Println(resp.Message)
		return nil
	}
	printRemoteTreeHelp("clear interfaces:", "clear", "interfaces")
	return nil
}

func (c *ctl) handleClearArp() error {
	resp, err := c.client.SystemAction(c.ctx(), &pb.SystemActionRequest{
		Action: "clear-arp",
	})
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	fmt.Println(resp.Message)
	return nil
}

func (c *ctl) handleClearIPv6(args []string) error {
	if len(args) < 1 || args[0] != "neighbors" {
		printRemoteTreeHelp("clear ipv6:", "clear", "ipv6")
		return nil
	}
	resp, err := c.client.SystemAction(c.ctx(), &pb.SystemActionRequest{
		Action: "clear-ipv6-neighbors",
	})
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	fmt.Println(resp.Message)
	return nil
}

func (c *ctl) handleClearSecurity(args []string) error {
	if len(args) < 1 {
		printRemoteTreeHelp("clear security:", "clear", "security")
		return nil
	}

	switch args[0] {
	case "nat":
		if len(args) >= 3 && args[1] == "source" && args[2] == "persistent-nat-table" {
			resp, err := c.client.SystemAction(c.ctx(), &pb.SystemActionRequest{
				Action: "clear-persistent-nat",
			})
			if err != nil {
				return fmt.Errorf("%v", err)
			}
			fmt.Println(resp.Message)
			return nil
		}
		if len(args) >= 2 && args[1] == "statistics" {
			resp, err := c.client.SystemAction(c.ctx(), &pb.SystemActionRequest{
				Action: "clear-nat-counters",
			})
			if err != nil {
				return fmt.Errorf("%v", err)
			}
			fmt.Println(resp.Message)
			return nil
		}
		printRemoteTreeHelp("clear security nat:", "clear", "security", "nat")
		return nil

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
			case "application":
				i++
				req.Application = args[i]
			}
		}
		resp, err := c.client.ClearSessions(c.ctx(), req)
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		fmt.Printf("%d IPv4 and %d IPv6 session entries cleared\n", resp.Ipv4Cleared, resp.Ipv6Cleared)
		return nil

	case "policies":
		if len(args) >= 2 && args[1] == "hit-count" {
			resp, err := c.client.SystemAction(c.ctx(), &pb.SystemActionRequest{
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
		_, err := c.client.ClearCounters(c.ctx(), &pb.ClearCountersRequest{})
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		fmt.Println("all counters cleared")
		return nil

	default:
		printRemoteTreeHelp("clear security:", "clear", "security")
		return nil
	}
}

func (c *ctl) handleClearFirewall(args []string) error {
	if len(args) < 1 || args[0] != "all" {
		printRemoteTreeHelp("clear firewall:", "clear", "firewall")
		return nil
	}
	resp, err := c.client.SystemAction(c.ctx(), &pb.SystemActionRequest{
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
		printRemoteTreeHelp("clear dhcp:", "clear", "dhcp")
		return nil
	}

	req := &pb.ClearDHCPClientIdentifierRequest{}
	if len(args) >= 3 && args[1] == "interface" {
		req.Interface = args[2]
	}

	resp, err := c.client.ClearDHCPClientIdentifier(c.ctx(), req)
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
	resp, err := c.client.ShowText(c.ctx(), &pb.ShowTextRequest{
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
	resp, err := c.client.GetSystemInfo(c.ctx(), &pb.GetSystemInfoRequest{Type: typ})
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	fmt.Print(resp.Output)
	return nil
}

func (c *ctl) showPoliciesBrief() error {
	resp, err := c.client.GetPolicies(c.ctx(), &pb.GetPoliciesRequest{})
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
		printRemoteTreeHelp("request:", "request")
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
		// fall through to existing logic below
	default:
		return fmt.Errorf("unknown request target: %s", args[0])
	}
	if len(args) < 2 {
		printRemoteTreeHelp("request system:", "request", "system")
		return nil
	}

	switch args[1] {
	case "reboot", "halt", "power-off":
		fmt.Printf("%s the system? [yes,no] (no) ", strings.Title(args[1]))
		c.rl.SetPrompt("")
		line, err := c.rl.Readline()
		c.rl.SetPrompt(c.operationalPrompt())
		if err != nil || strings.TrimSpace(strings.ToLower(line)) != "yes" {
			fmt.Printf("%s cancelled\n", strings.Title(args[1]))
			return nil
		}
		resp, err := c.client.SystemAction(c.ctx(), &pb.SystemActionRequest{
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
		resp, err := c.client.SystemAction(c.ctx(), &pb.SystemActionRequest{
			Action: "zeroize",
		})
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		fmt.Println(resp.Message)
		return nil
	case "software":
		if len(args) < 3 || args[2] != "in-service-upgrade" {
			printRemoteTreeHelp("request system software:", "request", "system", "software")
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
		resp, err := c.client.SystemAction(c.ctx(), &pb.SystemActionRequest{
			Action: "in-service-upgrade",
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

func (c *ctl) handleRequestChassis(args []string) error {
	if len(args) == 0 || args[0] != "cluster" {
		printRemoteTreeHelp("request chassis:", "request", "chassis")
		return nil
	}
	args = args[1:] // consume "cluster"
	if len(args) == 0 || args[0] != "failover" {
		printRemoteTreeHelp("request chassis cluster:", "request", "chassis", "cluster")
		return nil
	}
	args = args[1:] // consume "failover"

	// "request chassis cluster failover reset redundancy-group <N>"
	if len(args) >= 1 && args[0] == "reset" {
		if len(args) < 3 || args[1] != "redundancy-group" {
			return fmt.Errorf("usage: request chassis cluster failover reset redundancy-group <N>")
		}
		action := "cluster-failover-reset:" + args[2]
		resp, err := c.client.SystemAction(c.ctx(), &pb.SystemActionRequest{
			Action: action,
		})
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		fmt.Println(resp.Message)
		return nil
	}

	// "request chassis cluster failover redundancy-group <N> [node <N>]"
	if len(args) >= 2 && args[0] == "redundancy-group" {
		actionSuffix := args[1]
		// Pass "node <N>" if specified.
		if len(args) >= 4 && args[2] == "node" {
			actionSuffix += ":node" + args[3]
		}
		action := "cluster-failover:" + actionSuffix
		resp, err := c.client.SystemAction(c.ctx(), &pb.SystemActionRequest{
			Action: action,
		})
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		fmt.Println(resp.Message)
		return nil
	}

	return fmt.Errorf("usage: request chassis cluster failover redundancy-group <N> [node <N>]")
}

func (c *ctl) handleRequestDHCP(args []string) error {
	if len(args) == 0 || args[0] != "renew" {
		printRemoteTreeHelp("request dhcp:", "request", "dhcp")
		return nil
	}
	if len(args) < 2 {
		return fmt.Errorf("usage: request dhcp renew <interface>")
	}
	resp, err := c.client.SystemAction(c.ctx(), &pb.SystemActionRequest{
		Action: "dhcp-renew",
		Target: args[1],
	})
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	fmt.Println(resp.Message)
	return nil
}

func (c *ctl) handleRequestProtocols(args []string) error {
	if len(args) == 0 {
		printRemoteTreeHelp("request protocols:", "request", "protocols")
		return nil
	}
	switch args[0] {
	case "ospf":
		if len(args) < 2 || args[1] != "clear" {
			printRemoteTreeHelp("request protocols ospf:", "request", "protocols", "ospf")
			return nil
		}
		resp, err := c.client.SystemAction(c.ctx(), &pb.SystemActionRequest{
			Action: "ospf-clear",
		})
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		fmt.Println(resp.Message)
		return nil
	case "bgp":
		if len(args) < 2 || args[1] != "clear" {
			printRemoteTreeHelp("request protocols bgp:", "request", "protocols", "bgp")
			return nil
		}
		resp, err := c.client.SystemAction(c.ctx(), &pb.SystemActionRequest{
			Action: "bgp-clear",
		})
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		fmt.Println(resp.Message)
		return nil
	default:
		return fmt.Errorf("unknown request protocols target: %s", args[0])
	}
}

func (c *ctl) handleRequestSecurity(args []string) error {
	if len(args) == 0 {
		printRemoteTreeHelp("request security:", "request", "security")
		return nil
	}
	if args[0] != "ipsec" {
		return fmt.Errorf("unknown request security target: %s", args[0])
	}
	if len(args) < 3 || args[1] != "sa" || args[2] != "clear" {
		printRemoteTreeHelp("request security ipsec sa:", "request", "security", "ipsec", "sa")
		return nil
	}
	resp, err := c.client.SystemAction(c.ctx(), &pb.SystemActionRequest{
		Action: "ipsec-sa-clear",
	})
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	fmt.Println(resp.Message)
	return nil
}

// --- Tab completion ---

// pipeFilterDescs maps pipe filter names to descriptions for ? help.
var pipeFilterDescs = map[string]string{
	"count":   "Count occurrences",
	"display": "Show additional kinds of information",
	"except":  "Show only text that does not match a pattern",
	"find":    "Search for first occurrence of pattern",
	"grep":    "Show only text that matches a pattern",
	"last":    "Display end of output only",
	"match":   "Show only text that matches a pattern",
	"no-more": "Don't paginate output",
}

type remoteCompleter struct {
	ctl         *ctl
	helpWritten bool // set by ? Listener to suppress duplicate help from Do()
}

func (rc *remoteCompleter) Do(line []rune, pos int) ([][]rune, int) {
	// If the ? Listener already wrote help, suppress duplicate output.
	if rc.helpWritten {
		rc.helpWritten = false
		return nil, 0
	}

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

	// Determine partial: for pipe filters, partial is text after "| "
	isPipe := strings.Contains(text, "|")
	var partial string
	if isPipe {
		idx := strings.LastIndex(text, "|")
		after := strings.TrimLeft(text[idx+1:], " ")
		trailingSpace := len(text) > 0 && text[len(text)-1] == ' '
		if !trailingSpace && after != "" {
			partial = after
		}
	} else {
		words := strings.Fields(text)
		trailingSpace := len(text) > 0 && text[len(text)-1] == ' '
		if !trailingSpace && len(words) > 0 {
			partial = words[len(words)-1]
		}
	}

	sort.Strings(resp.Candidates)

	if len(resp.Candidates) == 1 {
		suffix := resp.Candidates[0][len(partial):]
		return [][]rune{[]rune(suffix + " ")}, len(partial)
	}

	// Multiple matches: show descriptions above prompt.
	words := strings.Fields(text)
	candidates := make([]cmdtree.Candidate, len(resp.Candidates))
	for i, name := range resp.Candidates {
		desc := ""
		if i < len(resp.Descriptions) && resp.Descriptions[i] != "" {
			desc = resp.Descriptions[i]
		} else if isPipe {
			desc = pipeFilterDescs[name]
		} else {
			desc = remoteLookupDesc(words, name, rc.ctl.configMode)
		}
		candidates[i] = cmdtree.Candidate{Name: name, Desc: desc}
	}
	cmdtree.WriteHelp(rc.ctl.rl.Stdout(), candidates)

	cp := cmdtree.CommonPrefix(resp.Candidates)
	suffix := cp[len(partial):]
	if suffix == "" {
		return nil, 0
	}
	return [][]rune{[]rune(suffix)}, len(partial)
}

// --- Prompts ---

func (c *ctl) clusterPrefix() string {
	if c.clusterRole == "" {
		return ""
	}
	return fmt.Sprintf("{%s:node%d}", c.clusterRole, c.clusterNodeID)
}

func (c *ctl) operationalPrompt() string {
	return fmt.Sprintf("%s%s@%s> ", c.clusterPrefix(), c.username, c.hostname)
}

func (c *ctl) configPrompt() string {
	return fmt.Sprintf("%s%s@%s# ", c.clusterPrefix(), c.username, c.hostname)
}

// --- Help ---

func (c *ctl) showOperationalHelp() {
	cmdtree.WriteHelp(os.Stdout, cmdtree.HelpCandidates(cmdtree.OperationalTree))
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
	ctx, cancel := context.WithTimeout(c.ctx(), 60*time.Second)
	defer cancel()
	stream, err := c.client.Ping(ctx, req)
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	for {
		resp, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		fmt.Println(resp.Output)
	}
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
	ctx, cancel := context.WithTimeout(c.ctx(), 60*time.Second)
	defer cancel()
	stream, err := c.client.Traceroute(ctx, req)
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	for {
		resp, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		fmt.Println(resp.Output)
	}
	return nil
}

func (c *ctl) handleMonitor(args []string) error {
	if len(args) == 0 {
		cmdtree.PrintTreeHelp("monitor:", cmdtree.OperationalTree, "monitor")
		return nil
	}
	switch args[0] {
	case "traffic":
		return fmt.Errorf("monitor traffic is only available on the local CLI")
	case "interface":
		return c.handleMonitorInterface(args[1:])
	case "security":
		return c.handleMonitorSecurity(args[1:])
	default:
		return fmt.Errorf("unknown monitor target: %s", args[0])
	}
}

func (c *ctl) handleMonitorInterface(args []string) error {
	req := &pb.MonitorInterfaceRequest{}
	if len(args) > 0 && args[0] != "traffic" {
		req.InterfaceName = args[0]
	}
	// "traffic" or no args → summary mode (empty interface_name).

	ctx, cancel := context.WithCancel(c.ctx())
	defer cancel()
	stream, err := c.client.MonitorInterface(ctx, req)
	if err != nil {
		return fmt.Errorf("%v", err)
	}

	// Enter alternate screen buffer for full-screen display.
	fmt.Print("\x1b[?1049h\x1b[?25l")
	defer fmt.Print("\x1b[?25h\x1b[?1049l")

	for {
		resp, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		// Clear screen and print the frame.
		fmt.Print("\x1b[2J\x1b[H")
		fmt.Print(resp.Frame)
	}
	return nil
}

func (c *ctl) handleMonitorSecurity(args []string) error {
	if len(args) == 0 {
		cmdtree.PrintTreeHelp("monitor security:", cmdtree.OperationalTree, "monitor", "security")
		return nil
	}
	switch args[0] {
	case "flow":
		return fmt.Errorf("monitor security flow is only available on the local CLI")
	case "packet-drop":
		return c.handleMonitorSecurityPacketDrop(args[1:])
	default:
		return fmt.Errorf("unknown monitor security target: %s", args[0])
	}
}

func (c *ctl) handleMonitorSecurityPacketDrop(args []string) error {
	req := &pb.MonitorPacketDropRequest{}
	for i := 0; i < len(args); i++ {
		switch args[i] {
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
				if v, err := strconv.Atoi(args[i]); err == nil {
					req.SourcePort = uint32(v)
				}
			}
		case "destination-port":
			if i+1 < len(args) {
				i++
				if v, err := strconv.Atoi(args[i]); err == nil {
					req.DestinationPort = uint32(v)
				}
			}
		case "protocol":
			if i+1 < len(args) {
				i++
				req.Protocol = args[i]
			}
		case "from-zone":
			if i+1 < len(args) {
				i++
				req.FromZone = args[i]
			}
		case "interface":
			if i+1 < len(args) {
				i++
				req.Interface = args[i]
			}
		case "count":
			if i+1 < len(args) {
				i++
				if v, err := strconv.Atoi(args[i]); err == nil {
					req.Count = int32(v)
				}
			}
		case "node":
			if i+1 < len(args) {
				i++
				req.Node = args[i]
			}
		}
	}

	ctx, cancel := context.WithCancel(c.ctx())
	defer cancel()
	stream, err := c.client.MonitorPacketDrop(ctx, req)
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	for {
		resp, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		fmt.Println(resp.Line)
	}
	return nil
}

func (c *ctl) handleLoad(args []string) error {
	if len(args) < 2 {
		printConfigTreeHelp("load:", "load")
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

	_, err := c.client.Load(c.ctx(), &pb.LoadRequest{
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
	cmdtree.WriteHelp(os.Stdout, cmdtree.HelpCandidates(cmdtree.ConfigTopLevel))
}

// --- Completion helpers (descriptions from canonical cmdtree) ---

// remoteLookupDesc finds the description for a candidate name by walking
func (c *ctl) handleTest(args []string) error {
	if len(args) == 0 {
		printRemoteTreeHelp("test: specify a test command", "test")
		return nil
	}

	switch args[0] {
	case "policy":
		return c.testPolicy(args[1:])
	case "routing":
		return c.testRouting(args[1:])
	case "security-zone":
		return c.testSecurityZone(args[1:])
	default:
		return fmt.Errorf("unknown test command: %s", args[0])
	}
}

func (c *ctl) testPolicy(args []string) error {
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

	topic := fmt.Sprintf("test-policy:from=%s,to=%s", fromZone, toZone)
	if srcIP != "" {
		topic += ",src=" + srcIP
	}
	if dstIP != "" {
		topic += ",dst=" + dstIP
	}
	if dstPort > 0 {
		topic += ",port=" + strconv.Itoa(dstPort)
	}
	if proto != "" {
		topic += ",proto=" + proto
	}
	return c.showText(topic)
}

func (c *ctl) testRouting(args []string) error {
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

	topic := "test-routing:dest=" + dest
	if instance != "" {
		topic += ",instance=" + instance
	}
	return c.showText(topic)
}

func (c *ctl) testSecurityZone(args []string) error {
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

	return c.showText("test-zone:interface=" + ifName)
}

// the canonical command tree in pkg/cmdtree. No manual desc map needed.
func remoteLookupDesc(words []string, name string, configMode bool) string {
	return cmdtree.LookupDesc(words, name, configMode)
}

// printRemoteTreeHelp prints self-generating help by walking the canonical
// command tree. path elements are used to navigate to the right subtree.
func printRemoteTreeHelp(header string, path ...string) {
	cmdtree.PrintTreeHelp(header, cmdtree.OperationalTree, path...)
}

// printConfigTreeHelp prints self-generating help from the config tree.
func printConfigTreeHelp(header string, path ...string) {
	cmdtree.PrintTreeHelp(header, cmdtree.ConfigTopLevel, path...)
}
