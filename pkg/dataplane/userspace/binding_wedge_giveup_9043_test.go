package userspace

import (
	"os"
	"os/exec"
	"testing"
	"time"
)

// wedgedManager9043 builds the minimal manager state that a REAL wedge
// produces: a live helper, forwarding armed, XSK liveness neither proven nor
// failed, and one binding the helper registered and armed but could not bind
// with EBUSY. Modelled on TestHasBusyBindingsWedgeLocked so this cell cannot
// drift from the predicate it depends on.
//
// The first version of this cell used a bare &Manager{} and measured NOTHING:
// hasBusyBindingsWedgeLocked returned false on the nil proc, which RESETS
// consecutiveFailedAutoRebinds to 0 and returns before the give-up branch. It
// failed loudly rather than passing vacuously, which is the only reason the
// gap was visible.
func wedgedManager9043() *Manager {
	return &Manager{
		proc: &exec.Cmd{Process: &os.Process{Pid: 1}},
		lastStatus: ProcessStatus{
			ForwardingArmed: true,
			Bindings: []BindingStatus{{
				Ifindex:    6,
				QueueID:    0,
				Registered: true,
				Armed:      true,
				Bound:      false,
				LastError:  "libxdp xsk_socket__create_shared: Device or resource busy",
			}},
		},
	}
}

// #9043: the give-up arm had no counter, and per #8384 binding readiness cannot
// see a bound-but-dead queue — so once auto-rebind stops, a single
// once-per-wedge log line was the entire signal that a box is forwarding with
// queues nobody is repairing any more.
//
// The counter must move EXACTLY ONCE per wedge, in lockstep with that message:
// the branch logs once by design (it steps the counter past the cap so the
// message does not repeat every poll), and a metric that fired on every poll
// would report a rate rather than an event.
//
// Fail-on-revert: drop `noteBindingWedgeGiveup()` and the first assertion goes
// RED at 0-want-1.
func TestAutoRebindGiveUpIsCounted9043(t *testing.T) {
	before := BindingWedgeGiveups()

	m := wedgedManager9043()
	m.consecutiveFailedAutoRebinds = maxConsecutiveAutoRebinds

	// PRECONDITION: the fixture must actually present a wedge, or everything
	// below measures the predicate declining rather than the give-up arm.
	if !m.hasBusyBindingsWedgeLocked(false) {
		t.Fatal("fixture does not present a busy-binding wedge; the give-up " +
			"branch is unreachable and this cell would assert nothing")
	}

	if m.shouldAutoRebindBusyBindingsLocked(time.Now(), false) {
		t.Fatal("at the cap the manager must not attempt another rebind")
	}
	if got := BindingWedgeGiveups() - before; got != 1 {
		t.Fatalf("give-up count moved by %d, want 1 — the give-up state is "+
			"unobservable without it, because readiness cannot see a "+
			"bound-but-dead queue (#8384)", got)
	}

	// NARROWNESS: polling again while still wedged must NOT count again. The
	// log is emitted once per wedge on purpose; a counter that advanced on
	// every poll would turn one event into a rate and could not answer "how
	// many wedges has this box given up on".
	for i := 0; i < 3; i++ {
		m.shouldAutoRebindBusyBindingsLocked(time.Now(), false)
	}
	if got := BindingWedgeGiveups() - before; got != 1 {
		t.Errorf("count moved by %d across repeated polls of ONE wedge, want 1", got)
	}
}

// REFERENCE ARM: a manager below the cap must not count. Without this, the
// assertion above is satisfied by a counter that increments unconditionally —
// which carries the same information as one that never increments.
func TestBelowTheCapDoesNotCountAGiveUp9043(t *testing.T) {
	before := BindingWedgeGiveups()

	m := wedgedManager9043()
	m.consecutiveFailedAutoRebinds = maxConsecutiveAutoRebinds - 1
	m.shouldAutoRebindBusyBindingsLocked(time.Now(), false)

	if got := BindingWedgeGiveups() - before; got != 0 {
		t.Errorf("a manager below the give-up cap counted %d give-ups, want 0", got)
	}
}
