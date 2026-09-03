package userspace

import (
	"strings"
	"testing"

	"github.com/cilium/ebpf"

	"github.com/psaab/xpf/pkg/dataplane"
)

// #7497 blocker 8. applyPrimaryBindingRowsLocked bounded the COMPOSED index
// (#814) and the queue dimension (#4894), then wrote binding.Slot into the row
// with no validation at all. Slot is what indexes userspace_heartbeat and
// userspace_xsk_map — maps 256x smaller than BindingArrayMaxEntries — so a
// composed-index guard does not stand in for a slot guard.
//
// These drive the apply helpers DIRECTLY with fakes rather than through
// applyHelperStatusLocked against real BPF maps. The first draft did the
// latter, and every case skipped on `RemoveMemlock: operation not permitted`
// while the package still reported `ok` — one of them even printed `--- PASS`
// because only its subtests skipped. A guard whose test skips wherever it runs
// is not a guard, so the level was moved to where it executes unprivileged.

// recordingBindingsMap7497 satisfies ctrlMapUpdater and records what the apply
// path actually wrote, so a test can assert a row was NEVER written rather than
// only that an error came back.
type recordingBindingsMap7497 struct {
	writes []recordedBindingWrite7497
}

type recordedBindingWrite7497 struct {
	Idx uint32
	Val userspaceBindingValue
}

func (r *recordingBindingsMap7497) Lookup(_, _ interface{}) error { return ebpf.ErrKeyNotExist }

func (r *recordingBindingsMap7497) Update(key, value interface{}, _ ebpf.MapUpdateFlags) error {
	idx, ok := key.(uint32)
	if !ok {
		return nil
	}
	val, ok := value.(userspaceBindingValue)
	if !ok {
		return nil
	}
	r.writes = append(r.writes, recordedBindingWrite7497{Idx: idx, Val: val})
	return nil
}

func (r *recordingBindingsMap7497) wrote(idx uint32) (userspaceBindingValue, bool) {
	for _, w := range r.writes {
		if w.Idx == idx {
			return w.Val, true
		}
	}
	return userspaceBindingValue{}, false
}

func applyPrimary7497(t *testing.T, m *Manager, bindings []BindingStatus) (*recordingBindingsMap7497, error) {
	t.Helper()
	rec := &recordingBindingsMap7497{}
	status := &ProcessStatus{
		Enabled:      true,
		Workers:      1,
		Capabilities: UserspaceCapabilities{ForwardingSupported: true},
		Bindings:     bindings,
	}
	_, err := m.applyPrimaryBindingRowsLocked(
		status, &fakeCtrlMap{}, rec, userspaceCtrlValue{},
		map[uint32]bool{}, nil, map[uint32]struct{}{})
	return rec, err
}

// A slot at or above the slot-keyed map capacity is refused and never written.
//
// The fixture straddles the boundary: capacity-1 must be ACCEPTED and capacity
// refused. Without the accepted case the test cannot see a guard that rejects
// valid slots — the failure direction that takes forwarding down rather than
// leaving it unprotected.
func TestApplyRejectsBindingSlotBeyondSlotMapCapacity7497(t *testing.T) {
	const ifindexN = 3
	idx := uint32(ifindexN) * bindingQueuesPerIface

	t.Run("at-capacity-refused", func(t *testing.T) {
		rec, err := applyPrimary7497(t, New(), []BindingStatus{{
			Slot: dataplane.BindingSlotMapMaxEntries, QueueID: 0, Ifindex: ifindexN,
			Registered: true, Armed: true, Bound: true, Ready: true,
		}})
		if err == nil {
			t.Fatal("apply accepted slot == capacity, want fail-closed error")
		}
		if _, written := rec.wrote(idx); written {
			t.Fatalf("row idx=%d was written before failing closed; the guard runs after the Update", idx)
		}
		// The message must name the limit and the maps it protects — an
		// operator has to learn what the ceiling is, not just that one exists.
		if !strings.Contains(err.Error(), "7497") || !strings.Contains(err.Error(), "userspace_xsk_map") {
			t.Fatalf("error does not identify the slot-capacity guard: %v", err)
		}
		if !strings.Contains(err.Error(), "4096") {
			t.Fatalf("error does not name the capacity value: %v", err)
		}
	})

	t.Run("below-capacity-accepted", func(t *testing.T) {
		want := dataplane.BindingSlotMapMaxEntries - 1
		rec, err := applyPrimary7497(t, New(), []BindingStatus{{
			Slot: want, QueueID: 0, Ifindex: ifindexN,
			Registered: true, Armed: true, Bound: true, Ready: true,
		}})
		if err != nil {
			t.Fatalf("apply rejected the highest VALID slot (%d): %v", want, err)
		}
		v, written := rec.wrote(idx)
		if !written {
			t.Fatalf("highest valid slot was not written at idx=%d", idx)
		}
		if v.Slot != want {
			t.Fatalf("row slot = %d, want %d", v.Slot, want)
		}
	})
}

// Two rows resolving to the same (ifindex, queue) are refused rather than
// silently last-wins. Before this guard the second Update overwrote the first
// and the first row's XSK was orphaned — registered and heartbeating, but
// unreachable by any redirect, and counted nowhere.
func TestApplyRejectsDuplicateIfindexQueue7497(t *testing.T) {
	const ifindexN = 4
	rec, err := applyPrimary7497(t, New(), []BindingStatus{
		{Slot: 10, QueueID: 2, Ifindex: ifindexN, Registered: true, Armed: true, Bound: true, Ready: true},
		{Slot: 11, QueueID: 2, Ifindex: ifindexN, Registered: true, Armed: true, Bound: true, Ready: true},
	})
	if err == nil {
		t.Fatal("apply accepted a duplicate (ifindex, queue), want fail-closed error")
	}
	if !strings.Contains(err.Error(), "duplicate") || !strings.Contains(err.Error(), "orphan") {
		t.Fatalf("error does not identify the duplicate-coordinate guard: %v", err)
	}
	// Asserting the surviving VALUE, not merely that an error came back: this
	// is what distinguishes "refused" from "overwrote, then errored".
	idx := uint32(ifindexN)*bindingQueuesPerIface + 2
	if v, written := rec.wrote(idx); written && v.Slot == 11 {
		t.Fatalf("the duplicate row overwrote idx=%d with slot=11 before failing closed", idx)
	}
}

// One slot claimed by two DIFFERENT coordinates is refused. This is invisible
// downstream — both redirects succeed and the packets are adjudicated — but one
// of the two queues has no socket of its own and the plan is not what it says.
func TestApplyRejectsDuplicateSlotAcrossCoordinates7497(t *testing.T) {
	_, err := applyPrimary7497(t, New(), []BindingStatus{
		{Slot: 7, QueueID: 0, Ifindex: 5, Registered: true, Armed: true, Bound: true, Ready: true},
		{Slot: 7, QueueID: 1, Ifindex: 6, Registered: true, Armed: true, Bound: true, Ready: true},
	})
	if err == nil {
		t.Fatal("apply accepted one slot on two coordinates, want fail-closed error")
	}
	if !strings.Contains(err.Error(), "claimed twice") {
		t.Fatalf("error does not identify the slot-uniqueness guard: %v", err)
	}
}

// A plan of several distinct, valid rows is accepted whole. Without this the
// three rejection cases above are equally satisfied by a guard that refuses
// everything.
func TestApplyAcceptsDistinctValidBindings7497(t *testing.T) {
	rec, err := applyPrimary7497(t, New(), []BindingStatus{
		{Slot: 0, QueueID: 0, Ifindex: 5, Registered: true, Armed: true, Bound: true, Ready: true},
		{Slot: 1, QueueID: 1, Ifindex: 5, Registered: true, Armed: true, Bound: true, Ready: true},
		{Slot: 2, QueueID: 0, Ifindex: 6, Registered: true, Armed: true, Bound: true, Ready: true},
	})
	if err != nil {
		t.Fatalf("apply rejected three distinct valid bindings: %v", err)
	}
	if len(rec.writes) != 3 {
		t.Fatalf("wrote %d rows, want 3", len(rec.writes))
	}
}

// THE CONTROL THAT MATTERS: a VLAN alias legitimately REUSES its parent's slot
// at a different index, and must still be accepted.
//
// applyAliasBindingRowsLocked mirrors each child ifindex onto its parent's
// binding rows with `Slot: binding.Slot` — the parent's slot — so the same slot
// is written at several indices BY DESIGN. A slot-uniqueness check scoped
// across both passes, or one keyed off the shared newBindingIndexSet
// accumulator, would reject every VLAN-aliased config. That mistake scores a
// clean mutation sweep and breaks the product, so it gets a test, not an
// argument.
func TestAliasedVLANChildMayReuseParentSlot7497(t *testing.T) {
	const parentIfindex = 8
	const childIfindex = 9
	m := New()
	m.lastSnapshot = &ConfigSnapshot{
		Generation: 1,
		Interfaces: []InterfaceSnapshot{
			{Name: "ge-0-0-1", Zone: "trust", Ifindex: parentIfindex},
			{Name: "ge-0-0-1.50", Zone: "trust", Ifindex: childIfindex, ParentIfindex: parentIfindex},
		},
	}
	bindings := []BindingStatus{{
		Slot: 3, QueueID: 0, Ifindex: parentIfindex,
		Registered: true, Armed: true, Bound: true, Ready: true,
	}}
	status := &ProcessStatus{
		Enabled:      true,
		Workers:      1,
		Capabilities: UserspaceCapabilities{ForwardingSupported: true},
		Bindings:     bindings,
	}
	rec := &recordingBindingsMap7497{}
	set := map[uint32]struct{}{}

	idxs, err := m.applyPrimaryBindingRowsLocked(
		status, &fakeCtrlMap{}, rec, userspaceCtrlValue{}, map[uint32]bool{}, nil, set)
	if err != nil {
		t.Fatalf("primary pass rejected the parent binding: %v", err)
	}
	if _, err = m.applyAliasBindingRowsLocked(
		status, &fakeCtrlMap{}, rec, userspaceCtrlValue{}, map[uint32]bool{}, idxs, set); err != nil {
		t.Fatalf("a VLAN child reusing its parent's slot was rejected: %v", err)
	}

	parentIdx := uint32(parentIfindex) * bindingQueuesPerIface
	childIdx := uint32(childIfindex) * bindingQueuesPerIface
	pv, okP := rec.wrote(parentIdx)
	cv, okC := rec.wrote(childIdx)
	if !okP {
		t.Fatalf("parent row idx=%d was not written", parentIdx)
	}
	if !okC {
		t.Fatalf("alias row idx=%d was not written — the alias pass did not run or was rejected", childIdx)
	}
	// The shared slot IS the alias: the child steers into the parent's XSK.
	// If these ever differ, the alias has stopped aliasing.
	if pv.Slot != cv.Slot {
		t.Fatalf("alias slot %d != parent slot %d; the child no longer steers into the parent's socket", cv.Slot, pv.Slot)
	}
}
