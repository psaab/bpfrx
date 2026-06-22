package cli

import (
	"path/filepath"
	"testing"
)

// #2288: tab-completion must not panic when the typed partial is longer than
// (or unrelated to) any candidate name. cmdtree's CompleteFromTreeWithDesc has
// an unfiltered fall-through (the "f"-matches branch) so commonPrefix(names)
// can be SHORTER than the typed partial — the old completion.go computed
// suffix := cp[len(partial):] unguarded and crashed the whole CLI with a
// "slice bounds out of range" panic.
//
// This drives the REAL cliCompleter.Do() entry point (not a helper). The
// completer's helpWriter() falls back to io.Discard when no readline instance
// is wired, so the multi-candidate path (which would otherwise dereference
// cc.cli.rl.Stdout()) is exercised end-to-end without a TTY. Removing
// completionSuffix and restoring the bare slice expression makes this test
// panic with the exact "slice bounds out of range" error from the issue.

// newCompletionCLI builds a CLI in operational mode. No readline instance is
// wired; cliCompleter.helpWriter() discards completion help in that case.
func newCompletionCLI(t *testing.T) *cliCompleter {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	c := &CLI{store: store}
	return &cliCompleter{cli: c}
}

func TestCliCompleterDo_OverTypedDoesNotPanic(t *testing.T) {
	cases := []string{
		"c zzzzz",        // single resolved verb (clear) + over-typed child
		"clear s zzzzz",  // resolved clear, ambiguous "s", over-typed
		"show f zzzzz",   // resolved show, ambiguous "f" (flow/filter/...), over-typed
		"show zzzzzzzzz", // over-typed top-level token, no match
		"zzzzzzzzz",      // over-typed top-level, single word
	}
	for _, in := range cases {
		t.Run(in, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("Do(%q) panicked: %v", in, r)
				}
			}()
			line := []rune(in)
			suggestions, length := cc(t).Do(line, len(line))
			// Sanity: a "no completion" result is acceptable (and expected
			// for over-typed garbage). We only require no panic and a
			// non-negative length offset.
			if length < 0 {
				t.Fatalf("Do(%q) returned negative length %d", in, length)
			}
			_ = suggestions
		})
	}
}

// helper so each sub-test gets a fresh completer (the readline instance and
// store are cheap and isolation avoids cross-case state).
func cc(t *testing.T) *cliCompleter {
	t.Helper()
	return newCompletionCLI(t)
}

// TestCliCompleterDo_PipeOverTypedDoesNotPanic exercises the pipe-filter
// branch (completion.go:55/64) with an over-typed filter token after "|".
func TestCliCompleterDo_PipeOverTypedDoesNotPanic(t *testing.T) {
	cases := []string{
		"show route | mzzzzz",  // "m" alone would resolve to "match"/"more-ish"; over-typed
		"show route | gzzzzz",  // "g" -> grep, but over-typed
		"show route | ezzzzz",  // "e" -> except, over-typed
		"show route | zzzzzzz", // no filter prefix match at all
	}
	for _, in := range cases {
		t.Run(in, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("Do(%q) panicked: %v", in, r)
				}
			}()
			line := []rune(in)
			_, length := newCompletionCLI(t).Do(line, len(line))
			if length < 0 {
				t.Fatalf("Do(%q) returned negative length %d", in, length)
			}
		})
	}
}

// TestCompletionSuffix verifies the guard contract directly.
func TestCompletionSuffix(t *testing.T) {
	tests := []struct {
		name, partial string
		wantSuffix    string
		wantOK        bool
	}{
		{"filter", "f", "ilter", true},   // normal extension
		{"flow", "flow", "", true},       // exact match -> empty suffix, ok
		{"f", "zzzzz", "", false},        // partial longer than name -> guarded
		{"flow", "fz", "", false},        // same length region but not a prefix
		{"filter", "show", "", false},    // unrelated, partial<name but no prefix
		{"", "", "", true},               // both empty
		{"abc", "", "abc", true},         // empty partial -> whole name
	}
	for _, tt := range tests {
		gotSuffix, gotOK := completionSuffix(tt.name, tt.partial)
		if gotSuffix != tt.wantSuffix || gotOK != tt.wantOK {
			t.Errorf("completionSuffix(%q,%q) = (%q,%v), want (%q,%v)",
				tt.name, tt.partial, gotSuffix, gotOK, tt.wantSuffix, tt.wantOK)
		}
	}
}

// TestCliCompleterDo_NormalCompletionStillWorks guards against the fix
// over-suppressing legitimate completions: a normal in-prefix partial must
// still produce a suffix.
func TestCliCompleterDo_NormalCompletionStillWorks(t *testing.T) {
	completer := newCompletionCLI(t)
	line := []rune("sho")
	suggestions, length := completer.Do(line, len(line))
	if len(suggestions) == 0 {
		t.Fatalf("Do(%q) returned no completion; expected the 'w' suffix for 'show'", "sho")
	}
	if length != 3 {
		t.Fatalf("Do(%q) length = %d, want 3", "sho", length)
	}
	if string(suggestions[0]) != "w " && string(suggestions[0]) != "w" {
		t.Fatalf("Do(%q) suffix = %q, want completion toward 'show'", "sho", string(suggestions[0]))
	}
}
