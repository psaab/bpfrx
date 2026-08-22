package cliterm

import (
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/chzyer/readline"
)

// The contract this package exists to hold, asserted directly rather than only
// through either CLI's entry point: ONLY Ctrl-D (io.EOF) commits a pasted
// configuration. Everything else discards it.
//
// Both CLIs previously owned a copy of this loop, both copies took the same
// `break` for EOF / ErrInterrupt / read error, and #4883-D fixed one of them.
// The console kept applying Ctrl-C-truncated pastes as complete until #6548.

func scripted(lines []string, end error) func() (string, error) {
	i := 0
	return func() (string, error) {
		if i < len(lines) {
			i++
			return lines[i-1], nil
		}
		return "", end
	}
}

func TestEOFCommitsTheCollectedLines(t *testing.T) {
	got, err := ReadConfig(scripted([]string{"a", "b", "c"}, io.EOF))
	if err != nil {
		t.Fatalf("EOF must commit: %v", err)
	}
	if got != "a\nb\nc" {
		t.Fatalf("content = %q, want %q", got, "a\nb\nc")
	}
}

func TestEOFWithNoLinesIsEmptyAndNotAnError(t *testing.T) {
	// An immediate Ctrl-D is an empty paste, not an abort; the caller's own
	// empty-input check reports it.
	got, err := ReadConfig(scripted(nil, io.EOF))
	if err != nil || got != "" {
		t.Fatalf("got (%q, %v), want (\"\", nil)", got, err)
	}
}

func TestInterruptAbortsAndDiscardsThePartialPaste(t *testing.T) {
	got, err := ReadConfig(scripted([]string{"a", "b"}, readline.ErrInterrupt))
	if err == nil {
		t.Fatal("Ctrl-C must abort, not commit the partial paste")
	}
	if got != "" {
		t.Fatalf("aborted read returned partial content %q — a caller that "+
			"ignores the error would apply it", got)
	}
	if !strings.Contains(err.Error(), "aborted") {
		t.Errorf("error %q does not say the paste was aborted", err)
	}
}

func TestOtherReadErrorsAlsoAbort(t *testing.T) {
	got, err := ReadConfig(scripted([]string{"a"}, errors.New("tty vanished")))
	if err == nil {
		t.Fatal("a read error must abort")
	}
	if got != "" {
		t.Fatalf("aborted read returned partial content %q", got)
	}
	if !strings.Contains(err.Error(), "tty vanished") {
		t.Errorf("error %q loses the underlying cause", err)
	}
}
