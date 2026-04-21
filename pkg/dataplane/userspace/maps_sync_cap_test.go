package userspace

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/cilium/ebpf/rlimit"
	"github.com/psaab/xpf/pkg/dataplane"
)

// TestApplyHelperStatusRejectsOverCapIfindex verifies that a binding
// whose ifindex overflows the userspace_bindings Array cap is caught
// at the call site with a legible error rather than bubbling up the
// kernel's generic "argument list too long" from bpf_map_update_elem.
// See issue #814.
func TestApplyHelperStatusRejectsOverCapIfindex(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("RemoveMemlock: %v", err)
	}
	m := New()
	m.inner.XDPEntryProg = "xdp_userspace_prog"
	injectCtrlAndBindingMaps(t, m)
	injectUserspaceSessionMap(t, m)
	m.neighborsPrewarmed = true
	m.xskLivenessProven = true
	m.publishedSnapshot = 1

	// Any ifindex >= MaxInterfaces overflows the flat
	// idx = ifindex*BindingQueuesPerIface + queue_id formula.
	overCapIfindex := int(dataplane.MaxInterfaces) + 7

	status := ProcessStatus{
		Enabled:                true,
		Workers:                1,
		LastSnapshotGeneration: 1,
		NeighborGeneration:     1,
		Capabilities: UserspaceCapabilities{
			ForwardingSupported: true,
		},
		Bindings: []BindingStatus{{
			Slot:       1,
			QueueID:    0,
			Ifindex:    overCapIfindex,
			Registered: true,
			Armed:      true,
			Bound:      true,
		}},
	}

	err := m.applyHelperStatusLocked(&status)
	if err == nil {
		t.Fatal("applyHelperStatusLocked returned nil for over-cap ifindex, want error")
	}
	// Error must be legible — name the cap and the remediation path.
	if !strings.Contains(err.Error(), "exceeds cap") {
		t.Fatalf("error missing cap message: %v", err)
	}
	if !strings.Contains(err.Error(), "MAX_INTERFACES") {
		t.Fatalf("error missing remediation pointer: %v", err)
	}
}

// TestApplyHelperStatusAcceptsIfindexWithinCap exercises the happy path
// to confirm the new cap guard does not spuriously reject valid
// ifindexes. Any small ifindex (< MaxInterfaces) must still succeed.
func TestApplyHelperStatusAcceptsIfindexWithinCap(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("RemoveMemlock: %v", err)
	}
	m := New()
	m.inner.XDPEntryProg = "xdp_userspace_prog"
	injectCtrlAndBindingMaps(t, m)
	injectUserspaceSessionMap(t, m)
	m.neighborsPrewarmed = true
	m.xskLivenessProven = true
	m.publishedSnapshot = 1

	status := ProcessStatus{
		Enabled:                true,
		Workers:                1,
		LastSnapshotGeneration: 1,
		NeighborGeneration:     1,
		Capabilities: UserspaceCapabilities{
			ForwardingSupported: true,
		},
		Bindings: []BindingStatus{{
			Slot:       1,
			QueueID:    0,
			Ifindex:    5,
			Registered: true,
			Armed:      true,
			Bound:      true,
		}},
	}
	if err := m.applyHelperStatusLocked(&status); err != nil {
		t.Fatalf("applyHelperStatusLocked with in-cap ifindex returned %v, want nil", err)
	}
}

// TestVerifyBindingsWatchdogSkipsOverCapIfindex exercises the
// watchdog's log-and-skip branch when a reported binding has an
// ifindex that would overflow BindingArrayMaxEntries. The watchdog
// must NOT unwind (it's repair-only) — it logs and keeps going.
func TestVerifyBindingsWatchdogSkipsOverCapIfindex(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("RemoveMemlock: %v", err)
	}
	m := New()
	m.inner.XDPEntryProg = "xdp_userspace_prog"
	injectCtrlAndBindingMaps(t, m)
	m.ctrlWasEnabled = true
	// verifyBindingsMapLocked early-returns on m.proc == nil or
	// m.proc.Process == nil — give it a non-nil *exec.Cmd with a
	// harmless pointer to our own PID so the guard passes.
	m.proc = &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}

	overCapIfindex := int(dataplane.MaxInterfaces) + 42
	m.lastStatus.Bindings = []BindingStatus{
		{Slot: 1, QueueID: 0, Ifindex: overCapIfindex, Registered: true, Armed: true, Bound: true},
		{Slot: 2, QueueID: 1, Ifindex: 7, Registered: true, Armed: true, Bound: true},
	}

	// Must not panic, must not return repaired=true for the over-cap
	// entry. The in-cap entry may or may not be "repaired" depending
	// on whether the map has any entries yet — what matters here is
	// the watchdog did not die on the over-cap ifindex.
	_ = m.verifyBindingsMapLocked()
}

// TestBindingArrayMaxEntriesMirrorsRustSide pins the Go-visible
// constant to its derivation. If MaxInterfaces or
// BindingQueuesPerIface drift vs userspace-xdp/src/lib.rs, the
// load-time assertion in loader_ebpf.go catches it — but this test
// fails at compile/unit-test time before you get that far.
func TestBindingArrayMaxEntriesMirrorsRustSide(t *testing.T) {
	if dataplane.BindingQueuesPerIface != bindingQueuesPerIface {
		t.Fatalf("bindingQueuesPerIface in maps_sync.go (%d) differs from dataplane.BindingQueuesPerIface (%d); one side of the mirror drifted",
			bindingQueuesPerIface, dataplane.BindingQueuesPerIface)
	}
	if dataplane.BindingArrayMaxEntries != dataplane.MaxInterfaces*dataplane.BindingQueuesPerIface {
		t.Fatalf("BindingArrayMaxEntries (%d) != MaxInterfaces * BindingQueuesPerIface (%d * %d)",
			dataplane.BindingArrayMaxEntries, dataplane.MaxInterfaces, dataplane.BindingQueuesPerIface)
	}
}
