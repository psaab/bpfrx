package main

import (
	"testing"
	"unicode/utf8"
)

// TestCompletionCursorByteOffset pins the remote completion wire contract:
// CompleteRequest.Pos is a BYTE offset into CompleteRequest.Line, not a rune
// index. readline hands Do() a rune index; sending it verbatim made the server
// re-slice req.Line mid-rune whenever a multibyte rune preceded the cursor,
// corrupting the completion token (#4970). completionCursor must return the
// byte length of the prefix so the units agree.
func TestCompletionCursorByteOffset(t *testing.T) {
	cases := []struct {
		name string
		line string
	}{
		{name: "ascii", line: "show sec"},
		{name: "multibyte-zone", line: "show zöne"},
		{name: "emoji", line: "set x 😀"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			line := []rune(tc.line)
			pos := len(line) // rune index of the cursor (at end of line)
			text, cursor := completionCursor(line, pos)
			if text != tc.line {
				t.Fatalf("text = %q, want %q", text, tc.line)
			}
			// The wire cursor must be the byte length of the prefix so the
			// server's text[:req.Pos] never cuts inside a multibyte rune.
			if int(cursor) != len(text) {
				t.Fatalf("cursor = %d, want byte length %d (rune-index bug)", cursor, len(text))
			}
			// For a multibyte prefix the byte length strictly exceeds the
			// rune index — exactly the case the old int32(pos) send corrupted.
			runeCount := utf8.RuneCountInString(text)
			if runeCount != pos {
				t.Fatalf("rune count %d != pos %d", runeCount, pos)
			}
		})
	}
}
