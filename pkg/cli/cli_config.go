package cli

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

// commitApply invokes the reconcile path for a freshly-committed config.
// Prefers the daemon's full applyConfig (single source of truth used by
// gRPC/HTTP) so D3 RSS indirection, cluster, VRRP, DHCP, etc. all
// re-converge. Falls back to the legacy applyToDataplane() when
// applyConfigFn is not wired. Warnings are non-fatal (match the prior
// applyToDataplane contract).
//
// #797 H2: worker-count changes and rss-indirection enable|disable
// committed through the in-process CLI must trigger D3 reapply; that
// only happens on the applyConfig path.
func (c *CLI) commitApply(compiled *config.Config) {
	if c.applyConfigFn != nil {
		c.applyConfigFn(compiled)
		return
	}
	if c.dp != nil {
		if err := c.applyToDataplane(compiled); err != nil {
			fmt.Fprintf(os.Stderr, "warning: dataplane apply failed: %v\n", err)
		}
	}
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

		compiled, err := c.runCommit(desc)
		if err != nil {
			return fmt.Errorf("commit failed: %w", err)
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

		compiled, err := c.runCommitConfirmed(minutes)
		if err != nil {
			return fmt.Errorf("commit confirmed failed: %w", err)
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

	compiled, err := c.runCommit("")
	if err != nil {
		return fmt.Errorf("commit failed: %w", err)
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

// runCommit dispatches to the daemon's atomic commit+apply when
// wired (#846); otherwise falls back to store.Commit followed by
// commitApply (the legacy path used by standalone CLI without a
// daemon). The atomic path serializes against HTTP/gRPC/event-engine
// commits via d.applySem.
//
// Uses a cancellable context registered with the CLI's Ctrl-C
// handler so an operator can interrupt a commit that's hung
// waiting for the apply lock (e.g. a long-running peer-sync apply
// holding it).
func (c *CLI) runCommit(comment string) (*config.Config, error) {
	if c.commitFn != nil {
		ctx, done := c.commitCtx()
		defer done()
		return c.commitFn(ctx, comment)
	}
	var compiled *config.Config
	var err error
	if comment != "" {
		compiled, err = c.store.CommitWithDescription(comment)
	} else {
		compiled, err = c.store.Commit()
	}
	if err != nil {
		return nil, err
	}
	c.commitApply(compiled)
	return compiled, nil
}

// runCommitConfirmed is the commit-confirmed analogue of runCommit.
func (c *CLI) runCommitConfirmed(minutes int) (*config.Config, error) {
	if c.commitConfirmedFn != nil {
		ctx, done := c.commitCtx()
		defer done()
		return c.commitConfirmedFn(ctx, minutes)
	}
	compiled, err := c.store.CommitConfirmed(minutes)
	if err != nil {
		return nil, err
	}
	c.commitApply(compiled)
	return compiled, nil
}

// commitCtx returns a cancellable context registered with the CLI's
// Ctrl-C handler (cmdCancel). The returned `done` cleans up the
// registration; callers MUST defer it. Used by runCommit /
// runCommitConfirmed so an operator can interrupt a commit that's
// hung waiting for the daemon's apply semaphore.
func (c *CLI) commitCtx() (context.Context, func()) {
	ctx, cancel := context.WithCancel(context.Background())
	c.cmdMu.Lock()
	c.cmdCancel = cancel
	c.cmdMu.Unlock()
	return ctx, func() {
		c.cmdMu.Lock()
		if c.cmdCancel != nil {
			// only clear if still ours (a nested handler hasn't
			// already replaced it).
			c.cmdCancel = nil
		}
		c.cmdMu.Unlock()
		cancel()
	}
}
