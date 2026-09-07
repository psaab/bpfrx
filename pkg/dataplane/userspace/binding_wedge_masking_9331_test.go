package userspace

import (
	"os"
	"os/exec"
	"testing"
	"time"
)

// #9331: `xskLivenessProven` is BOX-WIDE, so one live queue disabled wedge
// detection for every OTHER queue. Combined with #8384 — binding readiness
// cannot see a bound-but-dead queue — a masked queue had no detection, no
// recovery and no readiness signal: the box reports healthy and silently drops
// whatever RSS hashes to it.
//
// The gate is reset only by a rebind, a link cycle or a process restart, so on
// a stable box the blind spot is the entire uptime. That is the common case,
// not the corner.

// maskedWedgeManager9331 is the shape the issue names: one binding LIVE and
// BOUND, another registered+armed+unbound with a durable EBUSY. `livenessProven`
// models the box-wide flag a healthy sibling sets.
func maskedWedgeManager9331(livenessProven bool) *Manager {
	return &Manager{
		proc:              &exec.Cmd{Process: &os.Process{Pid: 1}},
		xskLivenessProven: livenessProven,
		lastStatus: ProcessStatus{
			ForwardingArmed: true,
			Bindings: []BindingStatus{
				{
					Ifindex:    6,
					QueueID:    0,
					Registered: true,
					Armed:      true,
					Bound:      true,
					Ready:      true,
					RXPackets:  1234,
				},
				{
					Ifindex:    6,
					QueueID:    1,
					Registered: true,
					Armed:      true,
					Bound:      false,
					LastError:  "libxdp xsk_socket__create_shared: Device or resource busy",
				},
			},
		},
	}
}

// THE DEFECT. A live sibling must not disable detection for a wedged queue.
//
// RED at master: `xskLivenessProven` short-circuits the whole predicate, so the
// wedged queue 1 is invisible however durable its EBUSY is.
//
// Both arms are asserted, and the pair is the point: the `false` arm shows the
// fixture really does present a wedge, so a `true` arm that also detects is
// reporting the sibling no longer masks — not that the predicate says yes to
// everything.
func TestALiveSiblingDoesNotMaskAWedgedBinding9331(t *testing.T) {
	for _, provenByASibling := range []bool{false, true} {
		m := maskedWedgeManager9331(provenByASibling)
		if !m.hasBusyBindingsWedgeLocked(false) {
			t.Errorf("xskLivenessProven=%v: the wedged queue was NOT detected. "+
				"Queue 1 is registered+armed+unbound with a durable EBUSY while "+
				"queue 0 is live; per #8384 nothing else reports it, so masking "+
				"here means no detection, no recovery and no readiness signal",
				provenByASibling)
		}
	}
}

// `xskLivenessFailed` STAYS box-wide, and that is a different claim: XSK is
// proven broken for this box, so a rebind cannot repair anything and firing one
// only tears down whatever still works.
//
// Without this arm, #9331 reads as "delete the gate", and the next reader has
// no way to tell which half was deliberate.
func TestProvenBrokenXSKStillSuppressesRecovery9331(t *testing.T) {
	m := maskedWedgeManager9331(false)
	if !m.hasBusyBindingsWedgeLocked(false) {
		t.Fatal("fixture: the wedge must be detectable before xskLivenessFailed " +
			"is set, or the assertion below passes for the wrong reason")
	}
	m.xskLivenessFailed = true
	if m.hasBusyBindingsWedgeLocked(false) {
		t.Error("with XSK proven BROKEN box-wide, recovery must stay suppressed: " +
			"a rebind cannot repair it and would tear down whatever still works")
	}
}

// TRAP 1 from the issue: do not re-arm detection on a legitimately idle
// standby.
//
// It is avoided by terms that were already there rather than by a new
// box-wide substitute, and this cell proves that rather than asserting it. A
// standby's queues receive nothing by design, and
// `shouldAutoProveIdleStandbyXSKLocked` requires `allBindingsBound` — so a
// healthy idle standby has NO registered+armed+unbound binding, `wedged` is 0,
// and the predicate is false whatever the liveness flag says.
//
// GREEN at master. It constrains what the fix must NOT do.
func TestAnIdleStandbyIsStillNotChurned9331(t *testing.T) {
	for _, provenByIdleAutoProve := range []bool{false, true} {
		m := &Manager{
			proc:              &exec.Cmd{Process: &os.Process{Pid: 1}},
			xskLivenessProven: provenByIdleAutoProve,
			lastStatus: ProcessStatus{
				ForwardingArmed: true,
				Bindings: []BindingStatus{
					{Ifindex: 6, QueueID: 0, Registered: true, Armed: true, Bound: true, Ready: true},
					{Ifindex: 6, QueueID: 1, Registered: true, Armed: true, Bound: true, Ready: true},
				},
			},
		}
		if m.hasBusyBindingsWedgeLocked(false) {
			t.Errorf("xskLivenessProven=%v: an idle standby with every binding BOUND "+
				"and no error was reported as wedged — auto-rebind would churn a "+
				"healthy standby", provenByIdleAutoProve)
		}
	}
}

// A durable EBUSY is still required. Removing the box-wide gate must not make
// every transiently-unbound binding a wedge.
//
// GREEN at master; it is the second half of "what the fix must not do".
func TestAnUnboundBindingWithNoDurableErrorIsNotAWedge9331(t *testing.T) {
	m := maskedWedgeManager9331(true)
	m.lastStatus.Bindings[1].LastError = ""
	if m.hasBusyBindingsWedgeLocked(false) {
		t.Error("an unbound binding with no EBUSY and no repair signal was reported " +
			"as a wedge; the bind already retried 20x250ms before reporting, so " +
			"the durable-error term is what separates a wedge from bring-up")
	}
}

// ANTI-REGRESSION for the trap the issue's own proposed shape would have
// created.
//
// The issue proposed per-binding liveness so the gate asks "has THIS queue ever
// been live". MEASURED, both readings are wrong: `zero_unbound_slot`
// (userspace-dp coordinator/refresh_bindings.rs) sets `rx_packets = 0` on every
// unbound slot, so a REPORTED-RX term is vacuous; and a REMEMBERED term would
// exclude exactly the binding that was live and went RX-dead — the case #9331
// exists to detect — re-creating the mask in a new place.
//
// This cell pins the consequence: a registered+armed+unbound binding is a wedge
// REGARDLESS of what RX it reports. If anyone later adds a liveness exclusion
// keyed on RX, remembered or reported, this reds.
func TestAWedgedBindingIsAWedgeWhateverRXItReports9331(t *testing.T) {
	for _, rx := range []uint64{0, 1, 1 << 40} {
		m := maskedWedgeManager9331(true)
		m.lastStatus.Bindings[1].RXPackets = rx
		if !m.hasBusyBindingsWedgeLocked(false) {
			t.Errorf("a registered+armed+unbound binding reporting RX=%d was NOT "+
				"counted as wedged. An RX-keyed liveness exclusion re-masks the "+
				"bound-then-RX-dead queue, which is the defect #9331 fixes", rx)
		}
	}
}

// The #9043 give-up counter must move for a wedge that was previously MASKED,
// so the new detection stays observable all the way to its terminal state.
//
// RED at master: the predicate returns false on the live sibling, which resets
// the attempt counter and returns before the give-up branch, so the counter
// never moves.
func TestTheGiveupCounterMovesForAPreviouslyMaskedWedge9331(t *testing.T) {
	before := BindingWedgeGiveups()

	m := maskedWedgeManager9331(true)
	m.consecutiveFailedAutoRebinds = maxConsecutiveAutoRebinds
	if !m.hasBusyBindingsWedgeLocked(false) {
		t.Fatal("fixture does not present a wedge; the give-up branch is " +
			"unreachable and this cell would assert nothing")
	}
	if m.shouldAutoRebindBusyBindingsLocked(time.Now(), false) {
		t.Fatal("at the cap the manager must not attempt another rebind")
	}
	if got := BindingWedgeGiveups() - before; got != 1 {
		t.Fatalf("give-up count moved by %d, want 1 — a masked wedge that is now "+
			"detected must remain observable when recovery stops", got)
	}
}
