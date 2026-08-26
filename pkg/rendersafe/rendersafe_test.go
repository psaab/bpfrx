package rendersafe

import (
	"strings"
	"testing"
)

// TestReplaceControlBytesReplacesTheWholeC0SetAndDEL is the primitive's own
// contract. It is exhaustive over the byte range rather than sampling, because
// the failure this guards is a future edit NARROWING the class -- "surely 0x0B
// is harmless" -- and a sampled test is exactly what such an edit slips past.
func TestReplaceControlBytesReplacesTheWholeC0SetAndDEL(t *testing.T) {
	for b := 0; b < 0x100; b++ {
		in := string([]byte{'a', byte(b), 'z'})
		got := ReplaceControlBytes(in, '_')
		ctl := b < 0x20 || b == 0x7f
		want := in
		if ctl {
			want = "a_z"
		}
		if got != want {
			t.Fatalf("byte %#02x: got %q, want %q (control=%v)", b, got, want, ctl)
		}
	}
}

// TestReplaceControlBytesLeavesCleanInputUnaltered pins the fast path's
// OBSERVABLE half. A version that always rebuilt the string would still be
// correct, so this asserts equality of contents rather than identity of the
// backing array -- the property a caller can actually depend on.
func TestReplaceControlBytesLeavesCleanInputUnaltered(t *testing.T) {
	for _, s := range []string{"", "plain", "with spaces", "non-ascii: \u00fc\u00f1", "tabs?no"} {
		if got := ReplaceControlBytes(s, '_'); got != s {
			t.Errorf("clean input %q was altered to %q", s, got)
		}
	}
}

// TestReplaceControlBytesNeverSplitsARune asserts the UTF-8 safety claim the doc
// comment makes, rather than leaving it as prose.
//
// It holds because C0 and DEL can never appear as a UTF-8 continuation byte, so
// a byte-wise scan cannot land inside a multi-byte rune. If someone widened the
// class to "any byte >= 0x7F", this reds -- and that widening is precisely the
// plausible-looking edit the package doc warns about.
func TestReplaceControlBytesNeverSplitsARune(t *testing.T) {
	in := "a\u00e9\u65e5b\u00e7"
	got := ReplaceControlBytes(in, ' ')
	for _, r := range []rune{'\u00e9', '\u65e5', '\u00e7'} {
		if !strings.ContainsRune(got, r) {
			t.Fatalf("multi-byte rune %q did not survive: %q -> %q", r, in, got)
		}
	}
}

// TestReplaceControlBytesHonoursTheCallersSubstitute pins that the substitute is
// the CALLER's choice.
//
// The whole point of #6833 is that the safe substitute is a per-consumer fact. A
// primitive that hardcoded a space would pull that decision back inside, which is
// the shape this package exists to undo.
func TestReplaceControlBytesHonoursTheCallersSubstitute(t *testing.T) {
	if got := ReplaceControlBytes("a\nb", '\t'); got != "a\tb" {
		t.Errorf("got %q, want a<tab>b", got)
	}
	if got := ReplaceControlBytes("a\nb", '?'); got != "a?b" {
		t.Errorf("got %q, want %q", got, "a?b")
	}
}
