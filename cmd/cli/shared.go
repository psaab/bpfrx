// cli is the remote CLI client for bpfrxd.
//
// It connects to the bpfrxd gRPC API and provides the same Junos-style
// interactive CLI as the embedded console.
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/chzyer/readline"
	"github.com/psaab/bpfrx/pkg/cmdtree"
	pb "github.com/psaab/bpfrx/pkg/grpcapi/bpfrxv1"
)

var errExit = fmt.Errorf("exit")

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

type ctl struct {
	client        pb.BpfrxServiceClient
	rl            *readline.Instance
	hostname      string
	username      string
	configMode    bool
	editPath      []string
	clusterRole   string // "primary", "secondary", or "" (not clustered)
	clusterNodeID int32

	// Command cancellation: Ctrl-C during a running command cancels it.
	cmdMu     sync.Mutex
	cmdCtx    context.Context    // per-command context, cancelled by Ctrl-C
	cmdCancel context.CancelFunc // non-nil while a command is executing
}

type remoteCompleter struct {
	ctl         *ctl
	helpWritten bool // set by ? Listener to suppress duplicate help from Do()
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

	outputCh := make(chan []byte, 1)
	go func() {
		output, _ := io.ReadAll(r)
		r.Close()
		outputCh <- output
	}()

	cmdErr := c.dispatch(cmd)
	w.Close()
	os.Stdout = origStdout

	output := <-outputCh

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

func (c *ctl) refreshPrompt() {
	if h, err := os.Hostname(); err == nil && h != "" {
		c.hostname = h
	}
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

func (c *ctl) showConfigHelp() {
	cmdtree.WriteHelp(os.Stdout, cmdtree.HelpCandidates(cmdtree.ConfigTopLevel))
}

func (rc *remoteCompleter) Do(line []rune, pos int) ([][]rune, int) {
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

// remoteLookupDesc finds the description for a candidate name by walking
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
