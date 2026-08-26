package userspace

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// session_offset_wiring_6816_test.go — #6816, the WIRING half.
//
// The offset cells live in pkg/dataplane and assert that
// SessionValueCreatedOffset resolves to the right field. None of them can see
// whether THIS package actually uses it — and that gap is not hypothetical: the
// mutation matrix reverted this file's decode to the hand-written literal 16 and
// the whole suite stayed GREEN. That revert is the entire defect restored.
//
// The property is textual by nature ("do not hand-write an ABI offset here"), so
// it is asserted textually, on comment-stripped source. A source-scanning gate
// that greps for a string its own doc comment contains is satisfied by the
// comment, so the needles are assembled at runtime and comments are stripped.

var lineComment6816 = regexp.MustCompile(`(?m)//.*$`)

// rawSessionDecode6816 matches a 64-bit ABI field READ at a HAND-WRITTEN
// numeric offset — `binary.…Uint64(val[16:24])` and friends. A read through the
// exported constant does not match, because its index is an identifier rather
// than a digit.
//
// It is deliberately narrower than "any slice at a numeric offset", which was
// the first cut and which fired on `maps_sync.go`'s cpumap writes:
//
//	val := make([]byte, 8)
//	binary.NativeEndian.PutUint32(val[0:4], 2048) // qsize
//	binary.NativeEndian.PutUint32(val[4:8], 0)    // no attached program
//
// That is a LOCALLY-DEFINED two-field 8-byte struct with no padding, written on
// the spot — the offsets cannot drift from a layout the same function declares
// three lines up, and there is no exported constant to use instead. Flagging it
// would have been a gate firing on correct code, which gets a gate suppressed
// rather than obeyed. Exempting the FILE would have been worse: it would also
// hide a real session-value decode landing there, and `maps_sync.go` is where
// this defect used to live.
//
// So the predicate is the actual #6816 shape: a Uint64 read (the width every
// padded ABI field in the session value uses) out of a byte slice at a literal
// offset.
var rawSessionDecode6816 = regexp.MustCompile(`Uint64\(\s*\w+\[\d+\s*:`)

// A package-wide sweep for hand-written offsets was tried and DELIBERATELY
// DROPPED. The predicate cannot tell a padded C-ABI decode from a local
// wire-format decode without knowing the type, and this package legitimately
// contains two of the latter:
//
//   - maps_sync.go writes a cpumap value — a locally-declared, unpadded
//     two-field 8-byte struct — as `PutUint32(val[0:4], …)` / `val[4:8]`;
//   - eventstream.go reads its own 16-byte frame header as
//     `Uint64(hdr[8:16])`, with the matching writer a few functions away.
//
// Both are correct: the offsets cannot drift from a layout the same file
// declares, and there is no exported constant to reach for. A gate that fires on
// correct code gets suppressed rather than obeyed, and exempting those FILES
// would be worse still — it would also hide a real session-value decode landing
// in them, and maps_sync.go is where this very defect used to live.
//
// So the binding is scoped to the file that decodes a session value, which is
// the one the mutation matrix showed was unbound.

// TestCleanupDecodesThroughTheExportedOffset6816 binds the consumer to the
// derived constant.
//
// FAIL-ON-REVERT: change the decode in helper_status_apply.go back to
// `val[16:end]` and this reds — which is exactly the mutation that escaped
// before this cell existed.
func TestCleanupDecodesThroughTheExportedOffset6816(t *testing.T) {
	const file = "helper_status_apply.go"
	src := lineComment6816.ReplaceAllString(readUserspaceSource6816(t, file), "")

	want := "dataplane.SessionValue" + "CreatedOffset"
	if !strings.Contains(src, want) {
		t.Fatalf("%s does not decode Created through %s; a hand-written offset "+
			"silently reads the wrong field — the pre-#6816 code read a SESSION ID "+
			"and compared it against a seconds-since-boot cutoff", file, want)
	}
	if m := rawSessionDecode6816.FindString(src); m != "" {
		t.Errorf("%s still slices a session value at a hand-written numeric "+
			"offset (%q). Field offsets in this ABI move: Flags widened in #5460 "+
			"and three padding gaps were made explicit in #6082, and the literal "+
			"that survived both is what #6816 fixed. Use the exported "+
			"dataplane.SessionValue*Offset constants.", file, m)
	}
}

// TestTheOffsetSweepMatchesAHandWrittenDecode6816 is the sensitivity control.
//
// Without it, both cells passing means either "no hand-written offsets" or "the
// pattern matches nothing" — the same green.
func TestTheOffsetSweepMatchesAHandWrittenDecode6816(t *testing.T) {
	for _, bad := range []string{
		"created := binary.NativeEndian.Uint64(val[16:24])",
		"x := binary.NativeEndian.Uint64(value[24 : 24+8])",
		"n := binary.NativeEndian.Uint64(raw[8:16])",
	} {
		if !rawSessionDecode6816.MatchString(bad) {
			t.Errorf("the sweep does not match %q; it would pass over the exact "+
				"shape #6816 fixed", bad)
		}
	}
	for _, good := range []string{
		"created := binary.NativeEndian.Uint64(val[dataplane.SessionValueCreatedOffset:end])",
		"z := other[i:j]",
		"w := someSlice[start:stop]",
		// A locally-declared, unpadded struct written on the spot: the offsets
		// cannot drift from a layout the same function declares, and there is no
		// exported constant to reach for. This is maps_sync.go's cpumap write,
		// and the first cut of this sweep flagged it.
		"binary.NativeEndian.PutUint32(val[0:4], 2048)",
		"binary.NativeEndian.PutUint32(val[4:8], 0)",
	} {
		if rawSessionDecode6816.MatchString(good) {
			t.Errorf("the sweep matches %q; a decode through the exported constant "+
				"(or an unrelated slice) must not be flagged", good)
		}
	}
}

func readUserspaceSource6816(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(b)
}
