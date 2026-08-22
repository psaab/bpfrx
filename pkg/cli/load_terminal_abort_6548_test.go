package cli

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/chzyer/readline"
)

// #6548: the LOCAL CONSOLE `load {override,merge,set} terminal` treated Ctrl-C
// — and any other read error — as end-of-input, applied the PARTIAL pasted
// configuration to the candidate, and printed a success message.
//
// This is the #4883-D bug. It was fixed on the remote CLI (cmd/cli) and never
// applied here. It survived because no test in this package exercised
// handleLoad's terminal read loop: the loop read straight from
// `c.rl.Readline`, so there was no way to drive it, and the difference between
// a committed paste and an aborted one has no observable outside the process.
//
// The failure mode is silent and actively misleading. The operator aborts a
// paste, sees "load merge complete", and commits a TRUNCATED configuration —
// and a truncated `security policies` stanza is a WIDENED one, because the
// deny terms that would have followed never arrive.
//
// FAIL-ON-REVERT: restore the pre-fix loop in handleLoad —
//
//	var lines []string
//	for { line, err := c.rl.Readline(); if err != nil { break }; lines = append(lines, line) }
//	content = strings.Join(lines, "\n")
//
// — and every abort subtest below goes green on the truncated config: no
// error, and the candidate carries the prefix.

// scriptedReader replays a fixed sequence of lines and then returns endErr.
type scriptedReader struct {
	lines  []string
	i      int
	endErr error
}

func (s *scriptedReader) read() (string, error) {
	if s.i < len(s.lines) {
		s.i++
		return s.lines[s.i-1], nil
	}
	return "", s.endErr
}

// pastedPolicy is the shape that makes this a security bug and not a nuisance:
// the permit term comes first and the deny term last, so a truncated paste is
// a WIDER policy than the operator wrote.
var pastedPolicy = []string{
	"set security policies from-zone trust to-zone untrust policy allow-web match source-address any",
	"set security policies from-zone trust to-zone untrust policy allow-web match destination-address any",
	"set security policies from-zone trust to-zone untrust policy allow-web match application junos-http",
	"set security policies from-zone trust to-zone untrust policy allow-web then permit",
	"set security policies from-zone trust to-zone untrust policy block-rest match source-address any",
	"set security policies from-zone trust to-zone untrust policy block-rest match destination-address any",
	"set security policies from-zone trust to-zone untrust policy block-rest match application any",
	"set security policies from-zone trust to-zone untrust policy block-rest then deny",
}

func newLoadCLI(t *testing.T, r *scriptedReader) *CLI {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "config.db"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	return &CLI{store: store, readLineFn: r.read}
}

// TestConsoleLoadSetTerminalAbortDiscardsPartialPaste is the core
// RED-on-revert: Ctrl-C part-way through a paste must abort, not commit a
// prefix.
func TestConsoleLoadSetTerminalAbortDiscardsPartialPaste(t *testing.T) {
	for _, tc := range []struct {
		name string
		end  error
	}{
		{"ctrl-c", readline.ErrInterrupt},
		{"read-error", errors.New("terminal read failed")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// The operator gets four lines in — the permit half — and aborts.
			r := &scriptedReader{lines: pastedPolicy[:4], endErr: tc.end}
			c := newLoadCLI(t, r)

			err := c.handleLoad([]string{"set", "terminal"})
			if err == nil {
				t.Fatal("an ABORTED paste reported success — the operator is " +
					"told the load completed and can commit a truncated " +
					"(and therefore widened) policy")
			}
			if !strings.Contains(err.Error(), "abort") &&
				!strings.Contains(err.Error(), "read error") {
				t.Errorf("error %q does not report an abort", err)
			}

			// The candidate must be untouched.
			if got := c.store.ShowCandidate(); strings.Contains(got, "allow-web") {
				t.Errorf("the partial paste reached the candidate:\n%s", got)
			}
		})
	}
}

// TestConsoleLoadMergeTerminalAbortDiscardsPartialPaste covers the
// hierarchical merge path, which takes a different branch of handleLoad.
func TestConsoleLoadMergeTerminalAbortDiscardsPartialPaste(t *testing.T) {
	// The prefix is a SYNTACTICALLY COMPLETE block. That is the whole point:
	// if the abort were only "caught" because a half-open brace fails to
	// parse, this test would pass on the buggy code for the wrong reason and
	// prove nothing. A balanced prefix loads cleanly, so the ONLY thing
	// standing between the Ctrl-C and a truncated candidate is the abort.
	r := &scriptedReader{
		lines: []string{
			"system {",
			"    host-name fw-truncated;",
			"}",
		},
		endErr: readline.ErrInterrupt,
	}
	c := newLoadCLI(t, r)
	if err := c.handleLoad([]string{"merge", "terminal"}); err == nil {
		t.Fatal("an aborted `load merge terminal` reported success")
	}
	if got := c.store.ShowCandidate(); strings.Contains(got, "fw-truncated") {
		t.Errorf("the partial paste reached the candidate:\n%s", got)
	}
}

// TestConsoleLoadOverrideTerminalAbortDiscardsPartialPaste covers the override
// path — the most destructive of the three, since it REPLACES the candidate.
func TestConsoleLoadOverrideTerminalAbortDiscardsPartialPaste(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "config.db"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if _, err := store.LoadSet("set system host-name fw-original\n"); err != nil {
		t.Fatalf("seed candidate: %v", err)
	}
	// Balanced prefix again — it must be a paste that WOULD apply cleanly.
	r := &scriptedReader{
		lines: []string{
			"system {",
			"    host-name fw-truncated;",
			"}",
		},
		endErr: readline.ErrInterrupt,
	}
	c := &CLI{store: store, readLineFn: r.read}

	if err := c.handleLoad([]string{"override", "terminal"}); err == nil {
		t.Fatal("an aborted `load override terminal` reported success")
	}
	got := c.store.ShowCandidate()
	if strings.Contains(got, "fw-truncated") {
		t.Errorf("the partial paste reached the candidate:\n%s", got)
	}
	if !strings.Contains(got, "fw-original") {
		t.Errorf("an ABORTED override destroyed the existing candidate:\n%s", got)
	}
}

// TestConsoleLoadSetTerminalEOFStillCommits is the negative control and the
// half that must NOT change: Ctrl-D (io.EOF) is the terminator, and a complete
// paste still applies.
func TestConsoleLoadSetTerminalEOFStillCommits(t *testing.T) {
	r := &scriptedReader{lines: pastedPolicy, endErr: io.EOF}
	c := newLoadCLI(t, r)

	if err := c.handleLoad([]string{"set", "terminal"}); err != nil {
		t.Fatalf("a COMPLETE paste terminated by Ctrl-D must apply: %v", err)
	}
	got := c.store.ShowCandidate()
	for _, want := range []string{"allow-web", "block-rest"} {
		if !strings.Contains(got, want) {
			t.Errorf("candidate is missing %q after a complete paste:\n%s", want, got)
		}
	}
}

// TestConsoleLoadMergeTerminalEOFStillCommits: the merge path's control.
func TestConsoleLoadMergeTerminalEOFStillCommits(t *testing.T) {
	r := &scriptedReader{
		lines:  []string{"system {", "    host-name fw-complete;", "}"},
		endErr: io.EOF,
	}
	c := newLoadCLI(t, r)
	if err := c.handleLoad([]string{"merge", "terminal"}); err != nil {
		t.Fatalf("a complete `load merge terminal` must apply: %v", err)
	}
	if got := c.store.ShowCandidate(); !strings.Contains(got, "fw-complete") {
		t.Errorf("candidate is missing the merged host-name:\n%s", got)
	}
}

// TestConsoleLoadFromFileIsUnaffected: the file source does not go through the
// terminal read loop and must keep working.
func TestConsoleLoadFromFileIsUnaffected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cfg.conf")
	if err := os.WriteFile(path, []byte("system {\n    host-name fw-from-file;\n}\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	store := newConfigStore(t, filepath.Join(dir, "config.db"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	// readLineFn deliberately errors: a file load must never touch it.
	c := &CLI{store: store, readLineFn: func() (string, error) {
		t.Error("load from a FILE read the terminal")
		return "", readline.ErrInterrupt
	}}
	if err := c.handleLoad([]string{"merge", path}); err != nil {
		t.Fatalf("load merge <file>: %v", err)
	}
	if got := c.store.ShowCandidate(); !strings.Contains(got, "fw-from-file") {
		t.Errorf("candidate is missing the file contents:\n%s", got)
	}
}

// TestConsoleAndRemoteShareOneTerminalReadLoop pins the structural fix. The
// two CLIs had SEPARATE copies of this loop and the copies diverged for two
// years — #4883-D landed on one and not the other. A divergence between them
// is always a bug, so there is one implementation, and this asserts the
// console routes through it rather than growing a private copy again.
func TestConsoleAndRemoteShareOneTerminalReadLoop(t *testing.T) {
	// The console's abort message must be the shared one, byte for byte. If
	// handleLoad reimplemented the loop it would almost certainly word this
	// differently — and would not be held to the shared semantics at all.
	r := &scriptedReader{
		lines:  []string{"system {", "    host-name fw-x;", "}"},
		endErr: readline.ErrInterrupt,
	}
	c := newLoadCLI(t, r)
	err := c.handleLoad([]string{"merge", "terminal"})
	if err == nil {
		t.Fatal("aborted load reported success")
	}
	if err.Error() != "load terminal: aborted (partial input discarded)" {
		t.Errorf("console abort message %q is not the shared cliterm one — "+
			"the console has its own read loop again", err)
	}
}
