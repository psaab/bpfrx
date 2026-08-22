package userspace

import (
	"fmt"
	"reflect"
	"testing"
)

// appPortSpecCorpus is the spec population both port paths must agree on. It
// covers each arm of the parse — empty, exact, exact-zero, wide range, reversed
// range (#3726), zero-anchored range, malformed halves, out-of-u16 values — plus
// the boundary of the low-side clamp coalescePortRanges applies.
var appPortSpecCorpus = []string{
	"", "0", "1", "80", "65535",
	"0-0", "0-1", "0-65535", "1-1", "1-65535", "20-23", "20000-20003",
	"200-100", "65535-1",
	"-", "-80", "80-", "http", "80-http", "http-80",
	"65536", "1-65536", "70000", "-1", "1-",
	" 80", "80 ", "8 0",
}

// #5250 (A6-b2 F3). Three NAT builder sites read
// coalescePortRanges(appPortsFromSpec(spec)), and the DNAT term carried the
// expanded []int all the way into the emit loop — so `destination-port 1-65535`
// materialized ~65k ints per application (and again per application-set member)
// purely to be collapsed back into one range. appPortRangesFromSpec emits the
// range directly.
//
// This is an AGREEMENT test, not a table of hand-picked expectations: it
// asserts the new function returns EXACTLY what the composition it replaced
// returns, for every spec in the corpus. A hand-written expectation table could
// encode the same mistake twice; this cannot, because the reference side still
// runs the original code.
func TestAppPortRangesFromSpecMatchesCoalescedSlice(t *testing.T) {
	for _, spec := range appPortSpecCorpus {
		t.Run(fmt.Sprintf("%q", spec), func(t *testing.T) {
			want := coalescePortRanges(appPortsFromSpec(spec))
			got := appPortRangesFromSpec(spec)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("appPortRangesFromSpec(%q) = %v, coalescePortRanges(appPortsFromSpec(%q)) = %v",
					spec, got, spec, want)
			}
		})
	}
}

// The point of the change: a wide range costs ONE range and no per-port slice.
// A revert to the materializing path is caught by the allocation count, which
// scales with the range width and cannot be made to pass by accident.
func TestAppPortRangesFromSpecDoesNotMaterializeTheRange(t *testing.T) {
	const wide = "1-65535"
	got := appPortRangesFromSpec(wide)
	if len(got) != 1 || got[0].Low != 1 || got[0].High != 65535 {
		t.Fatalf("appPortRangesFromSpec(%q) = %v, want one [1,65535] range", wide, got)
	}
	allocs := testing.AllocsPerRun(100, func() {
		_ = appPortRangesFromSpec(wide)
	})
	// One allocation: the single-element result slice. The old composition
	// allocated the 65535-int slice (repeatedly, as append grew it) plus the
	// dedup map plus the uniq slice.
	if allocs > 2 {
		t.Fatalf("appPortRangesFromSpec(%q) made %.0f allocations per call — the "+
			"per-port slice is being materialized again", wide, allocs)
	}
}
