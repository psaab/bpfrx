package main

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/cliterm"
)

// TestApplyPipeFilterCaseSensitive pins the remote CLI pipe filter to
// case-SENSITIVE semantics. Junos `| match` never case-folds; the earlier remote
// implementation lowercased both operands, so `| match Foo` matched `foo` on
// remote but not local (#4968).
//
// #7210 changed what this test can fail on, so read the change before trusting
// it. The remote surface no longer has its own filter: it calls
// cliterm.FilterStream, the same implementation pkg/cli uses. The specific
// divergence #4968 found is therefore structurally impossible now rather than
// merely tested against.
//
// The test is KEPT and pointed at the shared function rather than deleted,
// because the property it pins — these semantics are case-sensitive — is still
// worth a guard, and the assertions are unchanged. What it no longer proves on
// its own is that the two surfaces AGREE; that is now carried by
// TestRemotePipeUsesTheSharedFilter7210, which pins the delegation itself. A
// test that outlives the structure it was written for should say which half of
// its original claim it still carries.
func TestApplyPipeFilterCaseSensitive(t *testing.T) {
	lines := []string{
		"Foo matches exactly",
		"foo lower only",
		"FOO upper only",
		"unrelated line",
	}

	cases := []struct {
		name     string
		pipeType string
		pipeArg  string
		want     []string
	}{
		{
			name:     "match is case sensitive",
			pipeType: "match",
			pipeArg:  "Foo",
			want:     []string{"Foo matches exactly"},
		},
		{
			name:     "grep alias is case sensitive",
			pipeType: "grep",
			pipeArg:  "foo",
			want:     []string{"foo lower only"},
		},
		{
			name:     "except is case sensitive",
			pipeType: "except",
			pipeArg:  "Foo",
			want:     []string{"foo lower only", "FOO upper only", "unrelated line"},
		},
		{
			name:     "find is case sensitive",
			pipeType: "find",
			pipeArg:  "FOO",
			want:     []string{"FOO upper only", "unrelated line"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf strings.Builder
			cliterm.FilterStream(strings.NewReader(strings.Join(lines, "\n")+"\n"),
				&buf, tc.pipeType, tc.pipeArg)
			got := splitNonEmptyLines(buf.String())
			if !equalStringSlices(got, tc.want) {
				t.Fatalf("FilterStream(%q, %q) = %#v, want %#v",
					tc.pipeType, tc.pipeArg, got, tc.want)
			}
		})
	}
}

func splitNonEmptyLines(s string) []string {
	s = strings.TrimSuffix(s, "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
