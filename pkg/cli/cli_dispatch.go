package cli

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/psaab/xpf/pkg/cliterm"
)

var errExit = fmt.Errorf("exit")

func (c *CLI) dispatch(line string) error {
	if cmd, pipeType, pipeArg, ok := extractPipe(line); ok {
		return c.dispatchWithPipe(cmd, pipeType, pipeArg)
	}

	if c.store.InConfigMode() {
		return c.dispatchConfig(line)
	}

	if strings.HasPrefix(strings.TrimSpace(line), "show ") {
		return c.dispatchWithPager(line)
	}

	return c.dispatchOperational(line)
}

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

// dispatchWithPipe runs a command and applies a Junos-style output filter
// (| match/except/find/count/last/no-more) to its output. The command writes to
// a pipe that a concurrent filter goroutine consumes line-by-line via the #4709
// lineSource, so a huge "show ... | match ..." streams with bounded memory
// instead of being buffered whole with io.ReadAll first (#4731). At most one
// line (match/except/find/no-more), a running tally (count), or an n-line ring
// (last) is ever held, regardless of total output.
func (c *CLI) dispatchWithPipe(cmd, pipeType, pipeArg string) error {
	origStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("pipe: %w", err)
	}
	os.Stdout = w

	// The filter runs concurrently with the command: it reads the command's
	// output from r as it is produced and writes the filtered result straight
	// to the real stdout, so output is consumed lazily instead of materialized
	// up front. Every filter reads to EOF (which arrives when w is closed), so
	// no early-return drain is needed to unblock the writer.
	done := make(chan struct{})
	go func() {
		filterStream(r, origStdout, pipeType, pipeArg)
		r.Close()
		close(done)
	}()

	// Restore stdout and reap the reader in ONE deferred block (#7171) so no
	// exit path can leave the daemon's stdout pointing at the pipe. The
	// failure this was filed for -- a panic between the swap and the restore
	// -- is NOT reachable today: nothing on this path recovers, so a panic
	// takes the process down and a leaked swap cannot be observed. The class
	// that IS reachable is an early return: this function is short enough
	// that adding an error check between the swap and the restore is a
	// natural edit, and such a return would have left every later write going
	// into a pipe nobody drains AND leaked the reader goroutine blocked on
	// read. Closing w must precede <-done or the reader never sees EOF and
	// this deadlocks.
	defer func() {
		w.Close()
		os.Stdout = origStdout
		<-done
	}()

	return c.dispatch(cmd)
}

// filterStream applies a Junos-style output filter to src, writing to out as
// each line is read.
//
// #7210: the implementation now lives in pkg/cliterm and is SHARED with the
// remote CLI client (cmd/cli). It used to live here, and the remote surface
// carried its own copy — which drifted, producing the #4968 case-folding
// divergence where `| match Foo` matched `foo` on remote but not local. A
// divergence between the two surfaces is always a bug, never a legitimate
// difference, so there is now one implementation rather than an agreement to
// maintain between two.
//
// This wrapper is kept deliberately: it preserves this package's call sites and
// keeps the #4731 / #5037 / #5069 regression tests exercising the real code path
// rather than being decommissioned by the move.
func filterStream(src io.Reader, out io.Writer, pipeType, pipeArg string) {
	cliterm.FilterStream(src, out, pipeType, pipeArg)
}

// maxTailLines is an ALIAS for the shared cap, not a second copy of the number.
// Pinning the literal again here would let the two drift silently, which is the
// failure this consolidation exists to remove.
const maxTailLines = cliterm.MaxTailLines

// parseLastCount delegates to the shared parser (see filterStream).
func parseLastCount(arg string) int {
	return cliterm.ParseLastCount(arg)
}

// dispatchWithPager runs a "show" command and pages its output. The command
// writes to a pipe that a concurrent pager goroutine consumes incrementally, so
// a huge table (a full BGP route table, millions of flow sessions) is streamed
// to the terminal a screenful at a time rather than being buffered whole in
// memory first (#4709). At most one screen of lines (plus one lookahead line
// and the OS pipe buffer) is ever held at once, regardless of total output.
// stdoutIsTerminal reports whether the process-global os.Stdout is a real
// terminal (#4886 B). It probes with TCGETS, NOT os.ModeCharDevice — /dev/null
// is a CharDevice too (CLAUDE.md TTY-detection rule). A pipe (the `| match`
// filter's os.Stdout redirect), a file redirect, or a non-interactive run all
// read as non-terminal, so the pager auto-disables and cannot nest / hang.
func stdoutIsTerminal() bool {
	_, err := unix.IoctlGetTermios(int(os.Stdout.Fd()), unix.TCGETS)
	return err == nil
}

func (c *CLI) dispatchWithPager(line string) error {
	// #4886 B: only page when stdout is a real terminal. A non-TTY stdout means
	// output is redirected — most importantly into the `| match/except/…` filter
	// pipe: dispatchWithPipe redirects os.Stdout to the pipe, then calls dispatch,
	// which routes a bare `show` back HERE. Engaging the pager then wrote
	// `--More--` into the hidden outer pipe while blocking on os.Stdin, so
	// `show … | match X` HUNG with no visible prompt; it also mis-paged
	// scripted / file-redirected shows. Standard pager auto-disable (like less):
	// when stdout is not a TTY, stream straight through with no pager.
	if !stdoutIsTerminal() {
		return c.dispatchOperational(line)
	}
	origStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		return c.dispatchOperational(line)
	}
	os.Stdout = w

	termHeight := 24
	if ws, wErr := unix.IoctlGetWinsize(int(origStdout.Fd()), unix.TIOCGWINSZ); wErr == nil && ws.Row > 0 {
		termHeight = int(ws.Row)
	}
	pageSize := termHeight - 1

	// The pager runs concurrently with the command: it reads the command's
	// output from r as it is produced and pauses at each "--More--". While it
	// waits for a keypress the pipe fills and the command blocks on write, so
	// output is produced lazily on demand instead of materialized up front.
	done := make(chan struct{})
	go func() {
		pageStream(r, origStdout, os.Stdin, pageSize)
		r.Close()
		close(done)
	}()

	// Restore stdout and reap the reader in ONE deferred block (#7171) so no
	// exit path can leave the daemon's stdout pointing at the pipe. The
	// failure this was filed for -- a panic between the swap and the restore
	// -- is NOT reachable today: nothing on this path recovers, so a panic
	// takes the process down and a leaked swap cannot be observed. The class
	// that IS reachable is an early return: this function is short enough
	// that adding an error check between the swap and the restore is a
	// natural edit, and such a return would have left every later write going
	// into a pipe nobody drains AND leaked the reader goroutine blocked on
	// read. Closing w must precede <-done or the reader never sees EOF and
	// this deadlocks.
	defer func() {
		w.Close()
		os.Stdout = origStdout
		<-done
	}()

	return c.dispatchOperational(line)
}

// pageStream reads newline-delimited output from src and writes it to out one
// screenful (pageSize lines) at a time, reading a single keypress from keys at
// each "--More--" prompt (space = next page, Enter = one more line, q = quit).
// It never buffers more than a single page plus one lookahead line, so the
// caller's total output can be arbitrarily large without a proportional
// allocation. On quit it drains the remaining input so a producer writing into
// a pipe never blocks.
func pageStream(src io.Reader, out io.Writer, keys io.Reader, pageSize int) {
	if pageSize < 1 {
		pageSize = 1
	}
	ls := cliterm.NewLineSource(src)

	for ls.HasMore() {
		printed := 0
		for printed < pageSize {
			l, ok := ls.Next()
			if !ok {
				break
			}
			fmt.Fprintln(out, l)
			printed++
		}

		if !ls.HasMore() {
			break
		}

		fmt.Fprint(out, "\033[7m--More--\033[0m")
		buf := make([]byte, 1)
		keys.Read(buf)
		fmt.Fprint(out, "\r        \r")

		switch buf[0] {
		case 'q', 'Q':
			// Discard the rest so a blocked pipe writer can finish.
			io.Copy(io.Discard, src)
			return
		case '\n', '\r':
			if l, ok := ls.Next(); ok {
				fmt.Fprintln(out, l)
			}
			continue
		default:
		}
	}
}

// lineSource yields newline-delimited lines from an io.Reader with one line of
// lookahead. It mirrors the semantics of strings.Split(output, "\n") with a
// trailing empty element dropped: a final line terminated by "\n" does not
// produce a phantom empty line, while an unterminated final line is returned as
// its own line. Only "\n" is treated as the delimiter, so a trailing "\r" stays
// on the line exactly as the previous strings.Split did.
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

	if err := c.checkPermission(parts); err != nil {
		return err
	}

	switch parts[0] {
	case "configure":
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
	case "deactivate":
		if len(parts) < 2 {
			return fmt.Errorf("deactivate: missing path")
		}
		fullPath := append(c.store.GetEditPath(), parts[1:]...)
		return c.store.DeactivateFromInput(strings.Join(fullPath, " "))
	case "activate":
		if len(parts) < 2 {
			return fmt.Errorf("activate: missing path")
		}
		fullPath := append(c.store.GetEditPath(), parts[1:]...)
		return c.store.ActivateFromInput(strings.Join(fullPath, " "))
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
			// Strict integer parse: a malformed token (e.g. "foo",
			// "1x") or a negative value must NOT silently fall through
			// to rollback 0, which discards the candidate (#3447).
			v, err := strconv.Atoi(parts[1])
			if err != nil {
				return fmt.Errorf("rollback: invalid rollback number %q", parts[1])
			}
			if v < 0 {
				return fmt.Errorf("rollback: rollback number must be >= 0, got %d", v)
			}
			n = v
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
