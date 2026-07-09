package cli

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
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

func (c *CLI) dispatchWithPipe(cmd, pipeType, pipeArg string) error {
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
		for _, line := range lines {
			fmt.Fprintln(origStdout, line)
		}
	}

	return cmdErr
}

// dispatchWithPager runs a "show" command and pages its output. The command
// writes to a pipe that a concurrent pager goroutine consumes incrementally, so
// a huge table (a full BGP route table, millions of flow sessions) is streamed
// to the terminal a screenful at a time rather than being buffered whole in
// memory first (#4709). At most one screen of lines (plus one lookahead line
// and the OS pipe buffer) is ever held at once, regardless of total output.
func (c *CLI) dispatchWithPager(line string) error {
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

	cmdErr := c.dispatchOperational(line)
	w.Close()
	os.Stdout = origStdout
	<-done
	return cmdErr
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
	ls := &lineSource{r: bufio.NewReader(src)}

	for ls.hasMore() {
		printed := 0
		for printed < pageSize {
			l, ok := ls.next()
			if !ok {
				break
			}
			fmt.Fprintln(out, l)
			printed++
		}

		if !ls.hasMore() {
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
			if l, ok := ls.next(); ok {
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
type lineSource struct {
	r       *bufio.Reader
	peeked  string
	hasPeek bool
	done    bool
}

// read pulls the next line directly from the underlying reader.
func (ls *lineSource) read() (string, bool) {
	line, err := ls.r.ReadString('\n')
	if len(line) == 0 && err != nil {
		ls.done = true
		return "", false
	}
	if err != nil {
		ls.done = true
	}
	return strings.TrimSuffix(line, "\n"), true
}

// next returns the next line, or ("", false) at end of input.
func (ls *lineSource) next() (string, bool) {
	if ls.hasPeek {
		ls.hasPeek = false
		return ls.peeked, true
	}
	return ls.read()
}

// hasMore reports whether another line is available, buffering it for the next
// next() call.
func (ls *lineSource) hasMore() bool {
	if ls.hasPeek {
		return true
	}
	if ls.done {
		return false
	}
	l, ok := ls.read()
	if !ok {
		return false
	}
	ls.peeked = l
	ls.hasPeek = true
	return true
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
