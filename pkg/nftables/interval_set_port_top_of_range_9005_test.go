package nftables

import (
	"encoding/hex"
	"testing"
)

// Issue 9005 — the PORT twin of #8597.
//
// `portEnd` returned a WRAPPED 0x0000 for a range reaching 65535, and the
// caller emitted it as an interval-end element. That is not an end marker at
// the top of the key space; it is an end marker at the BOTTOM, and the kernel
// stores it as such. #8597 measured exactly that for addresses and fixed it by
// emitting NO end element for a top-of-range prefix.
//
// THE ASSERTION IS ON THE EMITTED RULESET, not on the helper. A unit test over
// `portNext` would pass against a caller that ignored its second return value,
// and the defect lives in what reaches the kernel.
//
// REACHABILITY, because the fixture depends on it: a SINGLE port range compiles
// to an `expr.Range`, not a set, and emits no elements at all. The set path is
// taken only with two or more entries — so a one-range fixture measures
// nothing, and the first version of this measurement returned `[]` for exactly
// that reason.

// portSetKeys builds a dport match and returns its set elements as
// "hexkey" / "hexkey!end" strings, in emission order.
func portSetKeys(t *testing.T, ports []nlPort) []string {
	t.Helper()
	p := newBuildPlan(t, "xpf_pt_9005", hostInboundPriority)
	p.rule().l4Port(6, "dport", ports, false).emit(verdictAccept()...)
	if p.err != nil {
		t.Fatalf("build: %v", p.err)
	}
	var out []string
	for _, els := range p.sets {
		for _, e := range els {
			k := hex.EncodeToString(e.Key)
			if e.IntervalEnd {
				k += "!end"
			}
			out = append(out, k)
		}
	}
	return out
}

func TestTopOfRangePortHasNoEndElement_9005(t *testing.T) {
	for _, tc := range []struct {
		name  string
		ports []nlPort
		want  []string
	}{
		{
			// 80/80 supplies the second entry that forces the SET path; the
			// 1024-65535 range is the subject and must run open to the top.
			name:  "range to 65535 alongside a single port",
			ports: []nlPort{{lo: 80, hi: 80}, {lo: 1024, hi: 65535}},
			want:  []string{"0050", "0051!end", "0400"},
		},
		{
			name:  "two ranges, the second reaching 65535",
			ports: []nlPort{{lo: 1, hi: 1023}, {lo: 1024, hi: 65535}},
			want:  []string{"0001", "0400!end", "0400"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := portSetKeys(t, tc.ports)
			// LIVENESS: an empty dump means the set path was not taken and the
			// comparison below would be vacuous.
			if len(got) == 0 {
				t.Fatalf("no set elements emitted — the fixture did not reach the set path, " +
					"so this cell measures nothing (a single range compiles to expr.Range)")
			}
			if len(got) != len(tc.want) {
				t.Fatalf("got %d elements %v, want %d %v — a top-of-range port must emit NO "+
					"end element rather than a wrapped one at the bottom of the key space "+
					"(#9005, the port twin of #8597)", len(got), got, len(tc.want), tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("element %d = %q, want %q (full: %v)", i, got[i], tc.want[i], got)
				}
			}
		})
	}
}

// NON-VACUITY: an ordinary range must still get its end element, so the fix
// cannot be passing by suppressing every end.
func TestOrdinaryPortRangesStillGetTheirEnd_9005(t *testing.T) {
	got := portSetKeys(t, []nlPort{{lo: 80, hi: 80}, {lo: 1024, hi: 2048}})
	want := []string{"0050", "0051!end", "0400", "0801!end"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v — suppressing the end for an ordinary range would open the "+
			"interval to the top of the key space, matching far more than configured", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("element %d = %q, want %q (full: %v)", i, got[i], want[i], got)
		}
	}
}
