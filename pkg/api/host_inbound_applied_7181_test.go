package api

import "testing"

// #7181: the tri-state must not collapse.
//
// WHY A TABLE AND NOT TWO CELLS. `Established` is sticky-true: a failed render
// does NOT clear it, because the retained generation may still be protecting.
// So the two ends — never-established and established-and-healthy — are passed
// by a renderer that simply returns `Established`. Only the MIDDLE row
// (Established AND LastApplyFailed) separates a correct implementation from
// that one, and it is the row an operator most needs, because it is the box
// whose latest render failed while a stale table still stands.
func TestHostInboundAppliedIsTriState7181(t *testing.T) {
	cases := []struct {
		name string
		snap HostInboundAppliedSnapshot
		want string
	}{
		{
			name: "never established — a configured default-deny is NOT in force",
			snap: HostInboundAppliedSnapshot{Known: true},
			want: HostInboundAppliedNotEstablished,
		},
		{
			// THE MIDDLE ROW. Established is true and stays true; the latest
			// render failed. A renderer keyed on Established alone says
			// "current" here and is wrong in the direction that matters.
			name: "established but the latest render FAILED — stale, not current",
			snap: HostInboundAppliedSnapshot{Known: true, Established: true, LastApplyFailed: true, Generation: 3},
			want: HostInboundAppliedStale,
		},
		{
			name: "established and current",
			snap: HostInboundAppliedSnapshot{Known: true, Established: true, Generation: 4},
			want: HostInboundAppliedCurrent,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := hostInboundAppliedInfo(tc.snap)
			if got.State != tc.want {
				t.Errorf("state = %q, want %q.\nA sticky Established rendered as a health verdict is the "+
					"exact conflation #7181 exists to remove: it reports a box whose latest render failed "+
					"as enforcing, and the operator has no other surface that would tell them otherwise.",
					got.State, tc.want)
			}
		})
	}
}

// The evidence fields must survive into the projection, not just the verdict.
// A verdict with no generation is unfalsifiable from the operator's side —
// they cannot tell a box that re-rendered a second ago from one that has been
// standing on the same generation since boot.
func TestHostInboundAppliedCarriesItsEvidence7181(t *testing.T) {
	got := hostInboundAppliedInfo(HostInboundAppliedSnapshot{
		Known: true, Established: true, LastApplyFailed: true,
		Generation: 7, LastFailureUnixSec: 1690000000, GapFenceActive: true,
	})
	if got.Generation != 7 {
		t.Errorf("Generation = %d, want 7", got.Generation)
	}
	if got.LastFailureUnixSec != 1690000000 {
		t.Errorf("LastFailureUnixSec = %d, want 1690000000", got.LastFailureUnixSec)
	}
	if !got.GapFenceActive {
		t.Error("GapFenceActive lost. A box enforcing through the additive gap fence " +
			"is in a different state from one whose main table covers everything, and an " +
			"operator diagnosing reachability needs to know which table is answering")
	}
}
