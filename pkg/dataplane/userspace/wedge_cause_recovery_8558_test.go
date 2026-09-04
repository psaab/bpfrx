package userspace

import (
	"path/filepath"
	"testing"
	"time"
)

// #8558: the auto-rebind wedge predicate keys on a field the fail-closed
// teardown erased, so recovery for the fault it exists for never fired.
//
// The helper-side half — that a fail-closed bring-up now publishes the bind
// cause and keeps publishing it across every subsequent status refresh — is
// measured in `userspace-dp` (`afxdp::coordinator::tests`):
// `bind_failure_cause_survives_the_failclosed_teardown_8558` and its two
// siblings. The half BELOW is the manager's: given that published shape, does a
// `rebind` actually reach the helper?
//
// That was untested. Every existing cell in `partial_wedge_recovery_7497_test.go`
// calls `hasBusyBindingsWedgeLocked` directly and asserts a bool, so the whole
// path from the predicate through `requestLocked` to the wire had no guard at
// all — which is one reason a predicate that could never be satisfied in
// production looked healthy for as long as it did.

func wedgeBinding8558(slot uint32, queue uint32, bound bool, lastErr string) BindingStatus {
	return BindingStatus{
		Slot: slot, Ifindex: 6, QueueID: queue,
		Registered: true, Armed: true, Bound: bound, Ready: bound,
		LastError: lastErr,
	}
}

// failClosedStatus8558 is the shape the helper publishes after a fail-closed
// bind-incomplete reconcile, and it is deliberately NOT the fifteen-bound
// -one-wedged shape the older cells use: the #5143 readiness barrier stops
// every worker, so nothing is bound (measured in #8388 /
// `bind_incomplete_leaves_no_bound_sibling_8388`). `busy` selects whether the
// bind cause survived the teardown — false is master's behaviour.
func failClosedStatus8558(busy bool) ProcessStatus {
	cause := ""
	if busy {
		cause = "libxdp private bind(flags=0x0004): Device or resource busy"
	}
	return ProcessStatus{
		PID:             4242,
		Workers:         3,
		ForwardingArmed: true,
		Bindings: []BindingStatus{
			wedgeBinding8558(1, 0, false, cause),
			wedgeBinding8558(2, 1, false, ""),
			wedgeBinding8558(3, 2, false, ""),
		},
	}
}

func newWedgeRecoveryManager8558(t *testing.T, busy bool) (*Manager, *leaseControlServer) {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "control.sock")
	m := newLinkCycleProcessOnlyManager(t, sock)
	status := failClosedStatus8558(busy)
	srv := startLeaseControlServer(t, sock, status)
	// The manager's view of the helper, as the 1 Hz poll would have left it.
	m.lastStatus = status
	// Past the 5s dwell: this cell is about whether the wedge reaches the wire,
	// not about the debounce, which `TestShouldAutoRebindBusyBindingsLockedDebounces`
	// already owns. Left at zero the first call would only ARM the dwell and
	// return false, and the cell would pass for the wrong reason in the negative
	// control below.
	m.bindingsBusySince = time.Now().Add(-time.Minute)
	return m, srv
}

func countRebinds8558(reqs []string) int {
	n := 0
	for _, r := range reqs {
		if r == "rebind" {
			n++
		}
	}
	return n
}

// THE WIRING CELL. A wedge whose cause survived the teardown must put a real
// `rebind` on the control socket — not merely make a predicate return true.
//
// Fail-on-revert: revert the helper-side #8558 fix and the status this manager
// polls carries an empty `LastError` on every slot, which is exactly the
// negative control below — no `rebind` is sent, and this cell reds.
func TestWedgeWithSurvivingCauseSendsRebind8558(t *testing.T) {
	m, srv := newWedgeRecoveryManager8558(t, true)

	m.mu.Lock()
	m.maybeAutoRebindBusyBindingsLocked(time.Now(), false)
	m.mu.Unlock()

	if n := countRebinds8558(srv.requests()); n != 1 {
		t.Fatalf("auto-rebind sent %d rebind requests, want 1; requests=%v",
			n, srv.requests())
	}
}

// THE NEGATIVE CONTROL, and the reproduction of the defect. Identical fixture
// with the bind cause erased — which is precisely what master's fail-closed
// teardown published, since `zero_unbound_slot` ends with
// `last_error.clear()`. Nothing reaches the wire: `busyErr` is false, and
// `repaired` cannot rescue it because it needs a forwarding-live (`Ready`)
// binding and a fail-closed reconcile leaves none.
//
// Without this cell the one above would be satisfied by a predicate that fired
// on any wedge at all, which is a rebind storm rather than a fix.
func TestWedgeWithErasedCauseSendsNothing8558(t *testing.T) {
	m, srv := newWedgeRecoveryManager8558(t, false)

	m.mu.Lock()
	m.maybeAutoRebindBusyBindingsLocked(time.Now(), false)
	m.mu.Unlock()

	if n := countRebinds8558(srv.requests()); n != 0 {
		t.Fatalf("a wedge with no cause sent %d rebind requests, want 0; "+
			"requests=%v", n, srv.requests())
	}
}

// THE HEALTHY CONTROL. Same cause text present on a box whose bindings are all
// bound: nothing is wedged, so nothing is sent. This is the state a wrong fix
// breaks silently — a cause that outlived its worker set would rebind a
// forwarding dataplane on the next poll.
func TestNoRebindWhenNothingIsWedged8558(t *testing.T) {
	m, srv := newWedgeRecoveryManager8558(t, true)
	m.mu.Lock()
	for i := range m.lastStatus.Bindings {
		m.lastStatus.Bindings[i].Bound = true
		m.lastStatus.Bindings[i].Ready = true
	}
	m.maybeAutoRebindBusyBindingsLocked(time.Now(), false)
	m.mu.Unlock()

	if n := countRebinds8558(srv.requests()); n != 0 {
		t.Fatalf("a fully bound dataplane got %d rebind requests, want 0; a "+
			"stale cause on a healthy box is a rebind storm", n)
	}
}

// THE MIDDLE STATE: a fault that self-clears must spend no recovery budget.
//
// Poll 1 sees the wedge and rebinds. Poll 2 — the retry landed, every slot is
// bound and the cause is gone, which is what the helper-side
// `a_recovered_reconcile_leaves_no_stale_bind_failure_cause_8558` proves it
// publishes — must send nothing AND reset the consecutive-attempt budget, so
// the NEXT fault gets the full allowance rather than inheriting a spent one.
//
// Fail-on-revert: drop the `m.consecutiveFailedAutoRebinds = 0` reset in
// `shouldAutoRebindBusyBindingsLocked`'s cleared-wedge branch and the budget
// assertion reds.
func TestTransientWedgeSpendsNoBudget8558(t *testing.T) {
	m, srv := newWedgeRecoveryManager8558(t, true)

	m.mu.Lock()
	m.maybeAutoRebindBusyBindingsLocked(time.Now(), false)
	if n := countRebinds8558(srv.requests()); n != 1 {
		m.mu.Unlock()
		t.Fatalf("poll 1: got %d rebinds, want 1", n)
	}
	if m.consecutiveFailedAutoRebinds != 1 {
		m.mu.Unlock()
		t.Fatalf("poll 1: consecutiveFailedAutoRebinds = %d, want 1",
			m.consecutiveFailedAutoRebinds)
	}

	// The fault cleared: the helper now reports every slot bound with no cause.
	recovered := failClosedStatus8558(false)
	for i := range recovered.Bindings {
		recovered.Bindings[i].Bound = true
		recovered.Bindings[i].Ready = true
	}
	m.lastStatus = recovered
	m.maybeAutoRebindBusyBindingsLocked(time.Now().Add(30*time.Second), false)
	m.mu.Unlock()

	if n := countRebinds8558(srv.requests()); n != 1 {
		t.Fatalf("poll 2 (recovered) sent another rebind: total %d, want 1", n)
	}
	if m.consecutiveFailedAutoRebinds != 0 {
		t.Fatalf("a self-clearing fault left consecutiveFailedAutoRebinds = %d, "+
			"want 0; the next fault would start with a spent budget",
			m.consecutiveFailedAutoRebinds)
	}
}
