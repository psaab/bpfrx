package userspace

import (
	"os"
	"os/exec"
	"testing"
	"time"
)

// #7497 blocker 5.
//
// `hasBusyBindingsWedgeLocked` required `bound == 0 && ready == 0` — every
// binding down. That was reasonable when the planner bound `min(rx)` queues
// across all candidates: the binding set was small and a bind failure
// plausibly hit all of it at once. With `Σ min(rx, 16)` bindings the realistic
// failure is PARTIAL — fifteen bind, one returns EBUSY — so `bound != 0` and
// auto-rebind recovery never ran at all.
//
// The predicate did not become wrong. The distribution of failures in front of
// it moved.

func wedgeManager7497(bindings []BindingStatus) *Manager {
	return &Manager{
		proc: &exec.Cmd{Process: &os.Process{Pid: 1}},
		lastStatus: ProcessStatus{
			ForwardingArmed: true,
			Bindings:        bindings,
		},
	}
}

func boundBinding7497(ifindex int, queue uint32) BindingStatus {
	return BindingStatus{
		Ifindex: ifindex, QueueID: queue,
		Registered: true, Armed: true, Ready: true, Bound: true,
	}
}

func busyUnboundBinding7497(ifindex int, queue uint32) BindingStatus {
	return BindingStatus{
		Ifindex: ifindex, QueueID: queue,
		Registered: true, Armed: true, Ready: false, Bound: false,
		LastError: "libxdp xsk_socket__create_shared: Device or resource busy",
	}
}

// THE fail-on-revert cell: fifteen bound, one wedged. Under the old predicate
// `bound == 0` is false, so this returned false and recovery never fired.
//
// The fixture needs BOTH kinds of binding present — a single-binding fixture
// (which is what the pre-existing wedge test uses) cannot express a partial
// wedge at all, so it stays green under either predicate.
func TestWedgeFiresOnPartialBindFailure7497(t *testing.T) {
	bindings := make([]BindingStatus, 0, 16)
	for q := uint32(0); q < 15; q++ {
		bindings = append(bindings, boundBinding7497(6, q))
	}
	bindings = append(bindings, busyUnboundBinding7497(6, 15))

	m := wedgeManager7497(bindings)
	if !m.hasBusyBindingsWedgeLocked(false) {
		t.Fatal("15 bound + 1 EBUSY did not register as a wedge; recovery will " +
			"never fire for the realistic post-#7497 failure mode")
	}

	// Control: with every binding bound there is nothing to recover, and a
	// predicate that fired here would rebind the whole dataplane on a healthy
	// box. Without this the cell above is satisfied by "always true".
	m.lastStatus.Bindings[15].Bound = true
	m.lastStatus.Bindings[15].Ready = true
	if m.hasBusyBindingsWedgeLocked(false) {
		t.Fatal("a fully bound set registered as a wedge; recovery would tear " +
			"down a healthy dataplane")
	}
}

// The busy-error term still gates. A binding can be unbound for reasons a
// rebind cannot fix, and firing on those turns an unrelated fault into a
// repeated global teardown.
func TestWedgeStillRequiresBusyError7497(t *testing.T) {
	unboundNotBusy := busyUnboundBinding7497(6, 3)
	unboundNotBusy.LastError = "some other failure"
	m := wedgeManager7497([]BindingStatus{boundBinding7497(6, 0), unboundNotBusy})

	if m.hasBusyBindingsWedgeLocked(false) {
		t.Fatal("a partial wedge with a non-EBUSY error fired; the busy term " +
			"must still gate")
	}
	// ...and the `repaired` argument is the documented second route in.
	if !m.hasBusyBindingsWedgeLocked(true) {
		t.Fatal("repaired=true must still admit a partial wedge")
	}
}

// #7497: consecutive failed auto-rebinds are capped.
//
// The predicate now fires on a DURABLE fault — a transient EBUSY never reaches
// it, since the bind itself retries "Device or resource busy" for
// BIND_RETRY_ATTEMPTS x BIND_RETRY_DELAY = 5s first. So a global rebind that
// immediately re-EBUSYs would re-satisfy the predicate every cycle, which is
// the EBUSY/rebind loop `handlers/rebind.rs` warns about.
func TestAutoRebindGivesUpAfterCap7497(t *testing.T) {
	m := wedgeManager7497([]BindingStatus{
		boundBinding7497(6, 0),
		busyUnboundBinding7497(6, 1),
	})

	now := time.Now()
	fired := 0
	// Drive well past the cap. Each iteration advances past both the 5s dwell
	// and the 15s rate limit so neither of those is what stops it — otherwise
	// this cell would pass with no cap at all.
	for i := 0; i < maxConsecutiveAutoRebinds*3; i++ {
		now = now.Add(30 * time.Second)
		if m.shouldAutoRebindBusyBindingsLocked(now, false) {
			fired++
		}
	}
	if fired != maxConsecutiveAutoRebinds {
		t.Fatalf("auto-rebind fired %d times for an unclearing wedge, want exactly %d "+
			"(the cap); an unbounded count is the EBUSY/rebind loop", fired, maxConsecutiveAutoRebinds)
	}
}

// Clearing the wedge restores the budget: the cap is per-wedge, not per-process.
// Without this, one exhausted wedge would disable recovery for the lifetime of
// the daemon — trading a loop for a permanently dead recovery path, which is
// the defect this change exists to fix.
func TestAutoRebindBudgetResetsWhenWedgeClears7497(t *testing.T) {
	m := wedgeManager7497([]BindingStatus{
		boundBinding7497(6, 0),
		busyUnboundBinding7497(6, 1),
	})

	now := time.Now()
	for i := 0; i < maxConsecutiveAutoRebinds*2; i++ {
		now = now.Add(30 * time.Second)
		m.shouldAutoRebindBusyBindingsLocked(now, false)
	}

	// Wedge clears.
	m.lastStatus.Bindings[1].Bound = true
	m.lastStatus.Bindings[1].Ready = true
	m.lastStatus.Bindings[1].LastError = ""
	now = now.Add(30 * time.Second)
	if m.shouldAutoRebindBusyBindingsLocked(now, false) {
		t.Fatal("fired with no wedge present")
	}

	// A NEW wedge must get a fresh budget.
	m.lastStatus.Bindings[1] = busyUnboundBinding7497(6, 1)
	fired := 0
	for i := 0; i < maxConsecutiveAutoRebinds*2; i++ {
		now = now.Add(30 * time.Second)
		if m.shouldAutoRebindBusyBindingsLocked(now, false) {
			fired++
		}
	}
	if fired != maxConsecutiveAutoRebinds {
		t.Fatalf("after the wedge cleared, a new wedge got %d attempts, want %d; "+
			"the cap must be per-wedge or recovery dies permanently", fired, maxConsecutiveAutoRebinds)
	}
}
