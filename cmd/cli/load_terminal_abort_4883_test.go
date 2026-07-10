// #4883-D: the `load ... terminal` read loop took the same `break` for EOF
// (the intended Ctrl-D commit), readline.ErrInterrupt (Ctrl-C), and every
// other read error, then Loaded whatever partial lines had been collected —
// printing "load ... complete". Aborting a paste could silently apply a valid
// prefix while omitting later stanzas. Only EOF may commit; interrupt / read
// error must ABORT with the partial input discarded.

package main

import (
	"errors"
	"io"
	"testing"

	"github.com/chzyer/readline"
)

// A Ctrl-C (readline.ErrInterrupt) mid-collection must abort and discard the
// partial input.
//
// Goes RED on revert: the old break-and-join loop returns the collected prefix
// with a nil error, so content would be non-empty and err nil.
func TestReadTerminalConfigAbortsOnInterrupt_4883(t *testing.T) {
	seq := []struct {
		line string
		err  error
	}{
		{"set system host-name fw", nil},
		{"set interfaces ge-0-0-0 unit 0 family inet address 10.0.0.1/24", nil},
		{"", readline.ErrInterrupt},
	}
	i := 0
	read := func() (string, error) {
		s := seq[i]
		i++
		return s.line, s.err
	}

	content, err := readTerminalConfig(read)
	if err == nil {
		t.Fatal("readTerminalConfig aborted with Ctrl-C returned nil error; a partial config must not be committed")
	}
	if content != "" {
		t.Fatalf("content = %q; want empty (partial input must be discarded on abort)", content)
	}
}

// A non-EOF read error must likewise abort.
func TestReadTerminalConfigAbortsOnReadError_4883(t *testing.T) {
	seq := []struct {
		line string
		err  error
	}{
		{"set a", nil},
		{"", errors.New("terminal read failure")},
	}
	i := 0
	read := func() (string, error) {
		s := seq[i]
		i++
		return s.line, s.err
	}

	content, err := readTerminalConfig(read)
	if err == nil {
		t.Fatal("readTerminalConfig with a read error returned nil error; expected an abort")
	}
	if content != "" {
		t.Fatalf("content = %q; want empty on read-error abort", content)
	}
}

// EOF (Ctrl-D) still commits the collected lines — the intended terminator.
func TestReadTerminalConfigCommitsOnEOF_4883(t *testing.T) {
	seq := []struct {
		line string
		err  error
	}{
		{"set a", nil},
		{"set b", nil},
		{"", io.EOF},
	}
	i := 0
	read := func() (string, error) {
		s := seq[i]
		i++
		return s.line, s.err
	}

	content, err := readTerminalConfig(read)
	if err != nil {
		t.Fatalf("readTerminalConfig on EOF returned error %v; EOF must commit", err)
	}
	if content != "set a\nset b" {
		t.Fatalf("content = %q; want %q", content, "set a\nset b")
	}
}
