// Busy-binding wedge detection and bounded auto-rebind recovery.
//
// Extracted from maps_sync.go by #7497 blocker 5, which pushed that file past
// the 2000 LOC modularity floor. Pure code motion plus this header — the unit
// was already self-contained: it reads `m.lastStatus.Bindings` and owns the
// three pieces of recovery state (`bindingsBusySince`,
// `lastBindingsAutoRebind`, `consecutiveFailedAutoRebinds`), all under the
// manager mutex like the rest of the ...Locked surface.
//
// What lives here is the answer to one question: when the helper reports a
// binding it registered and armed but could not bind, should the manager tear
// the dataplane down and rebuild it, and how many times.

package userspace

import (
	"log/slog"
	"strings"
	"time"
)

func (m *Manager) hasBusyBindingsWedgeLocked(repaired bool) bool {
	if m.proc == nil || m.proc.Process == nil {
		return false
	}
	if !m.lastStatus.ForwardingArmed || m.deferWorkers {
		return false
	}
	// #9331: `m.xskLivenessProven` used to sit in this condition, and it is
	// BOX-WIDE. On any box where at least ONE queue ever proved live — every
	// healthy box — wedge detection was therefore off for EVERY queue, so a
	// queue that binds and then goes RX-dead, or one of sixteen that never
	// bound while the other fifteen did, was never detected and never
	// repaired. The tree already stated the masking in two places written for
	// other work (`pkg/api/metrics_dataplane_silent_skips_9019.go`,
	// `process_napi.go`). Combined with #8384 — binding readiness cannot see a
	// bound-but-dead queue — a masked queue had NO detection, NO recovery and
	// NO readiness signal: the box reports healthy and silently drops whatever
	// RSS hashes to it.
	//
	// THE ISSUE PROPOSED PER-BINDING LIVENESS HERE. It is not implemented,
	// because measuring it showed both readings are wrong:
	//
	//   * REPORTED per-binding RX is VACUOUS. `zero_unbound_slot`
	//     (userspace-dp coordinator/refresh_bindings.rs) sets
	//     `binding.rx_packets = 0` on every unbound slot, so a binding that is
	//     registered+armed+unbound ALWAYS reports RX 0. A "has this binding
	//     received" term would be false for every binding this predicate can
	//     count, i.e. dead code.
	//   * REMEMBERED per-binding liveness is HARMFUL. A map that survives the
	//     unbind would exclude precisely the binding that WAS live and went
	//     RX-dead — the exact case #9331 exists to detect — turning the fix
	//     into a new mask with the same shape as the old one.
	//
	// What actually answers "is this queue live" is already in the loop below
	// and is per-binding by construction: `Registered && Armed && !Bound`. An
	// unbound binding is not receiving; no extra liveness term can say more.
	//
	// `xskLivenessFailed` STAYS, and stays box-wide, because it is a different
	// claim: XSK is proven broken for this box, so a rebind cannot repair
	// anything and firing one only tears down whatever still works.
	if m.xskLivenessFailed {
		return false
	}
	bindings := m.lastStatus.Bindings
	if len(bindings) == 0 {
		return false
	}
	registeredArmed := 0
	wedged := 0
	bound := 0
	busyErr := false
	for _, binding := range bindings {
		if binding.Ifindex <= 0 {
			continue
		}
		if binding.Registered && binding.Armed {
			registeredArmed++
			if !binding.Bound {
				wedged++
			}
		}
		if binding.Bound {
			bound++
		}
		if strings.Contains(strings.ToLower(binding.LastError), "resource busy") {
			busyErr = true
		}
	}
	// #7497 blocker 5: fire on a PARTIAL wedge, not only a total one.
	//
	// This used to require `bound == 0 && ready == 0` — every binding down.
	// Widening it is right, but #8388 measured the justification blocker 5 was
	// written with and it does not hold, so it is corrected here rather than
	// left to be re-derived. The claim was: with `Sum min(rx, 16)` bindings the
	// realistic failure is PARTIAL — fifteen bind and one returns EBUSY — so
	// `bound != 0` and recovery never ran.
	//
	// A BIND failure never produces that shape. The helper's reconcile is a
	// transaction: the #5143 startup readiness barrier requires `bound ==
	// planned` for every spawned worker, and on any shortfall
	// `bring_up_workers` calls `stop_inner(false)`, which stops and joins EVERY
	// worker — the fifteen that bound included — before the closing
	// `refresh_bindings` publishes anything. So one EBUSY is reported to this
	// predicate as `bound == 0` with every registered+armed slot wedged, which
	// the OLD predicate already fired on. Measured by
	// `bind_incomplete_leaves_no_bound_sibling_8388` (userspace-dp
	// `afxdp::coordinator::tests`).
	//
	// The shape that IS partial, and the reason to keep the widened predicate,
	// is the other post-teardown failure class: a #4952 worker-thread SPAWN
	// failure (`pthread_create` EAGAIN/ENOMEM) at worker K returns WITHOUT
	// `stop_inner`, so workers `0..K-1` stay live and bound while worker K's
	// slots are registered+armed and unbound — `bound != 0` with a real wedge,
	// which the old predicate could not see. Measured by the sibling positive
	// control `spawn_failure_does_leave_bound_siblings_8388`. Note what is
	// missing at those slots is a worker THREAD, not a socket, which is why
	// #8388's proposed per-slot `rebind_slot` verb was closed rather than built:
	// the global rebind re-runs the whole plan and spawns the missing worker,
	// and in the bind-failure case above there is nothing healthy left for a
	// targeted rebind to spare.
	//
	// `wedged` counts bindings the helper registered and armed but could not
	// bind. `!Bound` subsumes `!Ready`, since Ready requires Bound
	// (`refresh_bindings.rs`), so there is no separate ready term.
	//
	// #8558: the `busyErr` term below reads a field the helper's fail-closed
	// teardown used to ERASE. `stop_inner(false)` empties `workers.live`, so
	// `refresh_bindings` routes every slot through `zero_unbound_slot`, whose
	// last act is `last_error.clear()` — and `repaired` cannot stand in,
	// because it needs a forwarding-live (`Ready`) binding and a fail-closed
	// reconcile leaves none. So for the DOMINANT outcome of a bind EBUSY this
	// predicate could not be satisfied at all, and neither could the
	// `auto-rebind GAVE UP` log that would have reported the gap, since it is
	// inside the same predicate. The helper now carries the terminal per-slot
	// cause across the teardown on `Coordinator::last_bind_failures` and
	// re-publishes it on every refresh (`bind_failure_cause_survives_the_
	// failclosed_teardown_8558`), so `LastError` is populated for as long as
	// the fault lasts.
	//
	// One shortfall is still invisible: the barrier TIMEOUT case, where a
	// worker never reported and there is no per-slot cause to attribute.
	// Recovery does not fire for it, deliberately — see the cap derivation
	// below, which assumes the rebind is being fired for a teardown race.
	//
	// Note what does NOT need filtering here: a TRANSIENT EBUSY never reaches
	// this predicate. The bind itself retries "Device or resource busy"
	// specifically, BIND_RETRY_ATTEMPTS (20) x BIND_RETRY_DELAY (250ms) = 5s,
	// before reporting failure (userspace-dp/src/afxdp/bind.rs). Anything
	// visible here already survived that, and then `bindingsBusySince` requires
	// it to persist another 5s. Adding further dwell would only delay recovery
	// of a fault already proven durable.
	return registeredArmed > 0 && wedged > 0 && (busyErr || repaired)
}

// maxConsecutiveAutoRebinds bounds how many times auto-rebind will fire for a
// wedge it is not clearing (#7497 blocker 5).
//
// Needed because the predicate above now fires on a DURABLE fault. A global
// rebind that immediately re-EBUSYs would re-satisfy it every cycle — the
// EBUSY/rebind loop `handlers/rebind.rs` warns about, rate-limited to one per
// 15s but otherwise indefinite.
//
// Three, because of what a rebind can legitimately fix. Its repairable failure
// is a teardown race: sockets recreated while the kernel's previous xsk_pool
// teardown is still pending return EBUSY, and the next cycle succeeds once the
// quiesce completes. That resolves within one retry, so the first retry is the
// one that matters and the second is margin for a slow teardown. Beyond that a
// rebind is repeating an action that has already failed twice for a fault it
// evidently cannot repair, and continuing buys nothing while tearing down every
// healthy binding on each attempt.
//
// #9331 RE-DERIVED THIS RATHER THAN INHERITING IT, because removing the
// box-wide liveness gate widens when the predicate can fire — it can now be
// true on a box that has proven live, which it never could before.
//
// The derivation survives, and its cost term gets STRONGER. What a rebind can
// repair is unchanged: a teardown race, which resolves within one retry. What
// changes is what an attempt costs. Before #9331 the predicate could only fire
// while the box had proven nothing, so a rebind tore down bindings that were
// not yet known to work. Now it can fire on a box with fifteen healthy queues
// and one wedged one, and the rebind is GLOBAL (`handlers/rebind.rs`) — it
// tears down all sixteen. So "beyond that a rebind is repeating an action that
// has already failed twice" now costs proven-good forwarding, and three is if
// anything generous rather than tight.
//
// The budget is per-BOX and per-EPISODE, not per-wedge, and that is deliberate
// under per-binding detection: the rebind is one global action whatever set of
// bindings is wedged, so N simultaneous wedges still consume one attempt per
// cycle, not N. `consecutiveFailedAutoRebinds` resets when the predicate goes
// false, so a cleared wedge restores the full budget for the next one.
//
// What per-binding detection DOES change is how often the predicate stays
// true: a single durable single-queue wedge now holds it true indefinitely
// instead of being masked, so the counter reaches the cap, gives up once, and
// stays given-up until the wedge clears. That is the intended behaviour and it
// is observable — the give-up arm bumps the #9043 counter.
//
// THAT DERIVATION IS NOT ENFORCED BY ANY TEST. The cells read this constant on
// both sides of their assertions — deliberately, so a legitimate retune does
// not red them — which means changing 3 to 30 keeps the suite green and leaves
// the reasoning above describing a value the code no longer uses. Anyone
// changing it is overriding an argument, not adjusting a knob: re-derive it
// from what a rebind can repair, and rewrite this comment to match.
const maxConsecutiveAutoRebinds = 3

func (m *Manager) shouldAutoRebindBusyBindingsLocked(now time.Time, repaired bool) bool {
	if !m.hasBusyBindingsWedgeLocked(repaired) {
		m.bindingsBusySince = time.Time{}
		// The wedge is gone — either an attempt worked or it cleared on its
		// own. Either way the budget is spent on the NEXT wedge, not this one.
		m.consecutiveFailedAutoRebinds = 0
		return false
	}
	if m.consecutiveFailedAutoRebinds >= maxConsecutiveAutoRebinds {
		if m.consecutiveFailedAutoRebinds == maxConsecutiveAutoRebinds {
			// Step past the cap so this logs exactly once per wedge rather
			// than every poll. Loudly, and naming the consequence: per #8384
			// binding readiness cannot see a queue that is bound-but-dead, so
			// if automatic recovery stops there is no other signal that
			// anything is wrong.
			m.consecutiveFailedAutoRebinds++
			// #9043: count it in the SAME branch as the message, so the
			// counter and the log can never describe different conditions.
			noteBindingWedgeGiveup()
			slog.Error("userspace: auto-rebind GAVE UP on stuck XSK bindings",
				"attempts", maxConsecutiveAutoRebinds,
				"wedged_bindings", m.countWedgedBindingsLocked(),
				"remedy", "restart xpfd or investigate the interface's RX queues; "+
					"the affected queues will not forward and no readiness signal reports them")
		}
		return false
	}
	if m.bindingsBusySince.IsZero() {
		m.bindingsBusySince = now
		return false
	}
	if now.Sub(m.bindingsBusySince) < 5*time.Second {
		return false
	}
	if !m.lastBindingsAutoRebind.IsZero() && now.Sub(m.lastBindingsAutoRebind) < 15*time.Second {
		return false
	}
	m.lastBindingsAutoRebind = now
	m.consecutiveFailedAutoRebinds++
	return true
}

// countWedgedBindingsLocked reports how many registered+armed bindings are not
// bound, for the give-up message. Recomputed rather than carried on the struct:
// the count is only needed on a path that runs at most once per wedge.
func (m *Manager) countWedgedBindingsLocked() int {
	n := 0
	for _, binding := range m.lastStatus.Bindings {
		if binding.Ifindex > 0 && binding.Registered && binding.Armed && !binding.Bound {
			n++
		}
	}
	return n
}

func (m *Manager) maybeAutoRebindBusyBindingsLocked(now time.Time, repaired bool) {
	if !m.shouldAutoRebindBusyBindingsLocked(now, repaired) {
		return
	}
	var status ProcessStatus
	m.neighborsPrewarmed = false
	m.xskLivenessProven = false
	m.xskLivenessFailed = false
	m.xskProbeStart = time.Time{}
	m.lastXSKRX = 0
	if err := m.requestLocked(ControlRequest{Type: "rebind"}, &status); err != nil {
		slog.Warn("userspace: auto-rebind for stuck XSK bindings failed", "err", err)
		return
	}
	if err := m.applyHelperStatusLocked(&status); err != nil {
		slog.Warn("userspace: auto-rebind status sync failed", "err", err)
	}
	slog.Warn("userspace: auto-rebind initiated for stuck XSK bindings",
		"bindings", len(status.Bindings),
		"forwarding_armed", status.ForwardingArmed)
	m.bootstrapNAPIQueuesAsyncLocked("busy-xsk-wedge")
}
