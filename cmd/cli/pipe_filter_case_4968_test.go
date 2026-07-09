package main

import (
	"strings"
	"testing"
)

// TestApplyPipeFilterCaseSensitive pins the remote CLI pipe filter to the same
// case-SENSITIVE semantics as the local CLI's pkg/cli.filterStream. Junos
// `| match` never case-folds; the earlier remote implementation lowercased both
// operands, so `| match Foo` matched `foo` on remote but not local (#4968).
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
			applyPipeFilter(lines, &buf, tc.pipeType, tc.pipeArg)
			got := splitNonEmptyLines(buf.String())
			if !equalStringSlices(got, tc.want) {
				t.Fatalf("applyPipeFilter(%q, %q) = %#v, want %#v",
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
