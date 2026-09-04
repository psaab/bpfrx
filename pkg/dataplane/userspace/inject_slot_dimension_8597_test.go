package userspace

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// #8597: the inject helper-seam bound is on the SLOT dimension.
//
// It compared against BindingArrayMaxEntries (1048576), which bounds the
// COMPOSED INDEX into userspace_bindings. `req.Slot` is not that — the helper
// resolves it by lookup in maps keyed by the planner's dense slot, bounded by
// BindingSlotMapMaxEntries (4096), and applyUserspaceHelperStatusLocked
// fail-closes on any binding at or above it. constants.go warns against exactly
// this substitution.
//
// DEFENSIVE and currently unreachable: the helper returns "unknown binding
// slot" for anything not live, and a live slot is always below 4096. This buys
// an earlier refusal with a truthful ceiling.
//
// It is NOT the K79 finding, which is REFUTED. K79 claimed uint16(req.Slot)
// truncates the emit-on-wire source port for "legal high binding slots"; slots
// at that magnitude are not legal, which is why the truncation is unreachable.
// Reading the old constant on this line as the definition of "legal" is what
// made the row look live, so the two changes are kept apart deliberately.

func TestInjectSeamBoundsTheSlotDimension8597(t *testing.T) {
	// The distinction only exists in the gap between the two constants. A cell
	// that used a value outside BOTH would pass against either bound.
	if dataplane.BindingSlotMapMaxEntries >= dataplane.BindingArrayMaxEntries {
		t.Fatalf("fixture: the two constants must differ for this cell to discriminate "+
			"(slot=%d array=%d)", dataplane.BindingSlotMapMaxEntries, dataplane.BindingArrayMaxEntries)
	}
	between := dataplane.BindingSlotMapMaxEntries + 1 // >= slot bound, << array bound

	err := validateInjectPacketRequestForHelper(
		InjectPacketRequest{Slot: between},
		ProcessStatus{},
	)
	if err == nil {
		t.Fatalf("#8597: slot %d sits above the slot-map ceiling (%d) and below the "+
			"composed-index ceiling (%d), and was accepted. The helper cannot address "+
			"it: no live binding carries a slot that high, so the request reaches the "+
			"helper only to be refused there as an unknown slot",
			between, dataplane.BindingSlotMapMaxEntries, dataplane.BindingArrayMaxEntries)
	}
	if !strings.Contains(err.Error(), "out of range") {
		t.Fatalf("slot %d rejected for the wrong reason: %v", between, err)
	}
}

// CONTROL. A slot the helper CAN address must still pass this seam — a bound
// that rejected everything would satisfy the cell above completely, and would
// break every real inject.
func TestInjectSeamStillAcceptsAnAddressableSlot8597(t *testing.T) {
	for _, slot := range []uint32{0, 1, dataplane.BindingSlotMapMaxEntries - 1} {
		err := validateInjectPacketRequestForHelper(
			InjectPacketRequest{Slot: slot},
			ProcessStatus{},
		)
		if err != nil {
			t.Fatalf("CONTROL: slot %d is addressable (< %d) and must pass the seam: %v",
				slot, dataplane.BindingSlotMapMaxEntries, err)
		}
	}
}
