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
	if m.xskLivenessProven || m.xskLivenessFailed {
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
	// This used to require `bound == 0 && ready == 0` — every binding down. That
	// was a reasonable precondition when the planner bound `min(rx)` queues
	// across all candidates, because the binding set was small and a bind
	// failure plausibly hit all of them at once. It is not reasonable now: with
	// `Sum min(rx, 16)` bindings the realistic failure is PARTIAL — fifteen bind
	// and one returns EBUSY — so `bound != 0` and recovery never ran at all.
	// The predicate did not become wrong; the distribution of failures in front
	// of it moved.
	//
	// `wedged` counts bindings the helper registered and armed but could not
	// bind. `!Bound` subsumes `!Ready`, since Ready requires Bound
	// (`refresh_bindings.rs`), so there is no separate ready term.
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
