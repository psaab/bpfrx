package userspace

import (
	"errors"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

// TestApplyHelperStatusRejectsQueueIDBeyondStride is the #4894 fail-on-revert
// guard. The flat userspace_bindings index is idx = ifindex*stride + queue
// with stride == bindingQueuesPerIface (16). A queue-id EQUAL to the stride on
// ifindex N computes idx = N*16 + 16 == (N+1)*16 + 0 — the queue-0 slot of the
// ADJACENT ifindex N+1. The dense-cap guard (#814) does NOT catch this because
// the aliased index is in range, so without the queue-dimension bound the apply
// path would overwrite the neighbouring interface's binding slot.
//
// The load-bearing assertion is that the adjacent ifindex queue-0 slot is NOT
// written: if the bound is removed the apply loop writes the aliasing slot
// before any later step, so the lookup finds it and this test fails.
func TestApplyHelperStatusRejectsQueueIDBeyondStride(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("RemoveMemlock: %v", err)
	}
	m := New()
	m.bpfShim.SelectUserspaceXDPShimEntryProgram()
	ctrlMap, bindingsMap := injectCtrlAndBindingMaps(t, m)
	injectUserspaceSessionMap(t, m)
	m.neighborsPrewarmed = true
	m.xskLivenessProven = true
	m.publishedSnapshot = 1

	const ifindexN = 3
	const aliasSlotValue = 42
	// idx for the aliased adjacent ifindex queue-0 slot:
	// (ifindexN+1)*stride + 0 == ifindexN*stride + stride.
	aliasIdx := uint32(ifindexN+1) * bindingQueuesPerIface

	status := ProcessStatus{
		Enabled:                true,
		Workers:                1,
		LastSnapshotGeneration: 1,
		NeighborGeneration:     1,
		Capabilities: UserspaceCapabilities{
			ForwardingSupported: true,
		},
		Bindings: []BindingStatus{{
			Slot:       aliasSlotValue,
			QueueID:    bindingQueuesPerIface, // == stride: the aliasing boundary
			Ifindex:    ifindexN,
			Registered: true,
			Armed:      true,
			Bound:      true,
			Ready:      true,
		}},
	}

	err := m.applyHelperStatusLocked(&status)

	// Load-bearing anti-aliasing assertion (decisive on revert): the adjacent
	// ifindex queue-0 slot must never have been written. On revert (bound
	// removed) the apply loop writes {Slot: aliasSlotValue} at aliasIdx before
	// any later step, so this lookup succeeds and fails the test regardless of
	// what the overall apply return value ends up being.
	var v userspaceBindingValue
	lookupErr := bindingsMap.Lookup(aliasIdx, &v)
	if lookupErr == nil {
		t.Fatalf("aliased slot idx=%d was written (slot=%d flags=%d): queue-id==stride overwrote the adjacent ifindex queue-0 binding (#4894)",
			aliasIdx, v.Slot, v.Flags)
	}
	if !errors.Is(lookupErr, ebpf.ErrKeyNotExist) {
		t.Fatalf("unexpected lookup error for aliased slot idx=%d: %v", aliasIdx, lookupErr)
	}

	// Fail-closed posture: the apply path must reject the out-of-stride binding
	// with a legible aliasing/#4894 error rather than publish it.
	if err == nil {
		t.Fatal("applyHelperStatusLocked returned nil for queue-id==stride binding, want fail-closed error")
	}
	if !strings.Contains(err.Error(), "alias") || !strings.Contains(err.Error(), "4894") {
		t.Fatalf("error missing aliasing/#4894 explanation: %v", err)
	}

	// Fail-closed posture: userspace_ctrl must not be left enabled.
	var ctrl userspaceCtrlValue
	if le := ctrlMap.Lookup(uint32(0), &ctrl); le == nil && ctrl.Enabled != 0 {
		t.Fatalf("userspace_ctrl.Enabled = %d after out-of-stride binding, want disabled", ctrl.Enabled)
	} else if le != nil && !errors.Is(le, ebpf.ErrKeyNotExist) {
		t.Fatalf("lookup userspace_ctrl after out-of-stride binding: %v", le)
	}
}
