package eventengine

import (
	"log/slog"
)

// queue.go — ACTION QUEUE ADMISSION (#7636, split out of engine.go).
//
// A self-contained bounded-channel admission policy: what gets queued, what
// supersedes what, and what happens to a remediation that cannot be admitted.
// Its concurrency contract is its own — #5062 producer serialization, #5853
// early dedup, #2869 FIFO ordering, #6810 the admission verdict and the edge
// latch that depends on it.
//
// LOCK ORDER, and it is the reason this split is safe to make at all:
// e.mu (evaluation and runtime state, engine.go / evaluate.go) and enqueueMu
// (admission, this file) are NEVER NESTED. enqueue returns before anything
// takes e.mu, which is what lets releaseEdgeLatch below take e.mu at all —
// #6810's latch rollback would deadlock against a held enqueueMu.
//
// Splitting these into separate files makes that invariant easier to violate
// by accident, because the two locks are no longer visible on one screen. It
// is therefore stated on BOTH sides: see the matching note in engine.go on the
// Engine struct.

// actionQueueDepth bounds the worker's pending-action channel. Dedup-by-policy
// (a newer trigger supersedes an older queued one) keeps at most one pending
// action per policy, so this is also an upper bound on distinct policies with
// a remediation in flight while the config lock is held. #5853: the dedup runs
// on EVERY enqueue (not only when the channel is full), so a burst from ONE
// policy occupies at most ONE slot — it can never fill the queue with redundant
// duplicates and starve an unrelated policy's remediation into a queue-full drop.
const actionQueueDepth = 64

// enqueue adds an action to the bounded worker queue with dedup-by-policy: a
// newer trigger of the same policy supersedes an older queued one (there is no
// value in applying a stale remediation twice), which also bounds the queue to
// one pending action per policy. If the queue is full of OTHER policies'
// actions, the new action is dropped (counted) rather than blocking the caller
// goroutine (#2157 bounded queue).
//
// #5853: the dedup runs on EVERY enqueue via supersede, not only when the
// channel is full. The pre-#5853 fast path did an UNCONDITIONAL send first and
// only deduped in the full/`default` branch, so while the worker was blocked
// behind the config lock a burst from ONE policy filled all 64 slots with
// redundant duplicates (later discarded by cooldown/staleness) and the next
// remediation for an UNRELATED policy was dropped queue-full. Draining and
// replacing the same-policy entry up front keeps at most one pending action per
// policy, so a same-policy burst occupies a single slot and leaves the rest free
// for other policies. supersede is non-blocking (select-with-default drain +
// refill), so this never blocks the caller even mid-shutdown (e.actions is never
// closed); a genuine full-of-other-policies queue still drops the new action
// (counted) via supersede returning false.
//
// The whole body runs under enqueueMu (#5062) so concurrent producers cannot
// interleave: supersede's drain+refill must be atomic w.r.t. other producers,
// otherwise a second producer could take a slot supersede freed while draining
// and force supersede to drop an already-accepted survivor. See the enqueueMu
// field comment for the lock-ordering rationale.
// enqueue returns whether the action was ADMITTED — i.e. whether an equivalent
// action for this policy is now queued for the worker. It returns false only
// when nothing will run: a genuine capacity drop, or a shutdown fast-exit.
//
// #6810: the verdict exists because the caller has already armed the edge latch
// for this crossing by the time it gets here. Before this, enqueue returned
// nothing, so a dropped action was indistinguishable from an admitted one at
// the call site and the latch stayed armed over a remediation that never ran.
// A superseded placement still counts as admitted: the newer equivalent action
// IS queued, which is exactly what the latch is asserting.
func (e *Engine) enqueue(a plannedAction) bool {
	e.enqueueMu.Lock()
	defer e.enqueueMu.Unlock()
	// Fast exit during shutdown: don't churn the queue for an action the worker
	// will never apply. supersede would otherwise still succeed (the channel is
	// unbounded-in-shutdown only in that it is never closed), but there is no
	// consumer left to drain it.
	select {
	case <-e.stopCh:
		return false
	default:
	}
	if e.supersede(a) {
		return true
	}
	// supersede could not place `a`: the queue is full of OTHER policies'
	// actions and there was no same-policy entry to evict. This is the only
	// genuine capacity drop (an unrelated policy really did fill the queue).
	e.counters.droppedQueueFull.Add(1)
	slog.Warn("event-options: action queue full, dropping remediation",
		"policy", a.policyName)
	return false
}

// releaseEdgeLatch clears the #3756 edge latch that evaluateEvent armed for one
// crossing, when the action that crossing authorized was never admitted (#6810).
//
// evaluateEvent arms the latch under e.mu and returns; HandleEvent classifies
// and enqueues afterwards, outside that lock. If the queue is full of OTHER
// policies' actions the remediation is dropped — and because withinMatches
// suppresses every later at/above-threshold event while the latch is armed, and
// only re-arms when a clause's count falls BELOW its threshold, a transient
// queue saturation permanently consumed the crossing. For a sustained fault the
// level never drops, so the configured remediation simply never ran.
//
// Rolling the latch back restores the invariant the latch is supposed to
// express: "this crossing already fired". A crossing whose action was dropped
// did not fire.
//
// authRev is the policy's semantic revision as of the evaluate that armed the
// latch, and the guard is the same ABA defence armCooldown uses (#5311): if a
// successor generation was installed (or the policy removed) while this action
// was being classified and rejected, its latch state belongs to the successor
// and must not be cleared by a predecessor's failure. Identity check and clear
// happen in ONE critical section under e.mu so a concurrent Apply cannot swap
// the runtime between them.
//
// Lock order is safe by construction: the caller has already released
// enqueueMu (enqueue returns before this runs), so e.mu is never taken while
// enqueueMu is held.
//
// A concurrent event that lands between the drop and this rollback is still
// suppressed by the armed latch — the window is one classify+enqueue — so the
// crossing costs at most a delay to the next event rather than being consumed
// outright, which is the whole of the defect.
func (e *Engine) releaseEdgeLatch(name, eventName, authRev string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.semRev[name] != authRev {
		// Successor generation installed, or the policy removed, while this
		// action was rejected. Its latch is not ours to clear.
		return
	}
	if rt := e.runtime[name]; rt != nil {
		rt.onLatched[eventName] = false
	}
}

// supersede non-blockingly rebuilds the queue, replacing any existing
// same-policy action with a, and returns true if a was placed. It is the SOLE
// enqueue path (#5853): every enqueue drains the buffered queue, drops any
// existing same-policy entry (benign dedup, counted as superseded), re-enqueues
// the surviving OTHER-policy actions in FIFO order, and places a at the tail. It
// returns false only when the queue is full of OTHER policies and a could not be
// placed (a genuine capacity drop the caller counts as droppedQueueFull).
//
// CALLER MUST HOLD enqueueMu (#5062). That is what makes the drain->re-enqueue
// atomic w.r.t. other producers: while this runs, no other enqueue/supersede can
// take a slot the drain just freed, so every surviving other-policy action is
// re-enqueued exactly once in FIFO order (a survivor can never be dropped). The
// only concurrent actor is the consumer (actionWorker), which just REMOVES
// items, so the drain sees at most the buffered entries and the loop is bounded
// with no need to guard against a producer refilling underneath it.
func (e *Engine) supersede(a plannedAction) bool {
	drained := make([]plannedAction, 0, actionQueueDepth)
	replaced := false
	// Drain whatever is currently buffered.
	for {
		select {
		case old := <-e.actions:
			e.counters.queueDepth.Add(-1)
			if old.policyName == a.policyName {
				// Drop the stale same-policy action; it is superseded by the
				// newer trigger a. This is a benign dedup — the newer equivalent
				// action still runs — NOT a capacity loss, so count it as
				// superseded rather than droppedQueueFull (#5853). Inflating the
				// alert-worthy queue_full metric on every same-policy burst
				// (which the early dedup makes routine) would mask real capacity
				// drops.
				e.counters.superseded.Add(1)
				continue
			}
			drained = append(drained, old)
		default:
			goto refill
		}
	}
refill:
	// Test-only seam (#5062): the drain->re-enqueue boundary. In production this
	// is nil. A concurrency test sets it to drive a second producer into the
	// freed slots here and prove enqueueMu serializes it (the survivors are
	// preserved regardless of what the injected producer does).
	if e.afterDrainFn != nil {
		e.afterDrainFn()
	}
	// Re-enqueue the surviving other-policy actions in their original FIFO
	// order, then place the new (superseding) action at the TAIL (#2869).
	// Prepending `a` would jump it ahead of every already-queued action of
	// OTHER policies, converting the documented FIFO queue into LIFO for the
	// newest arrival and starving older queued remediations under sustained
	// event frequency. Supersede must only drop/replace the stale SAME-policy
	// entry (done in the drain loop above); it must not reorder unrelated
	// policies relative to the order their events were observed.
	all := append(drained, a)
	for _, item := range all {
		select {
		case e.actions <- item:
			e.counters.queueDepth.Add(1)
			if item.policyName == a.policyName {
				replaced = true
			}
		default:
			// Still no room (lost the race to another producer, or the queue
			// is full of unrelated policies and there was no stale same-policy
			// entry to evict). Count the loss for any SURVIVOR we could not
			// re-place — but NOT for the new action `a` itself: supersede
			// returns false in that case and enqueue owns `a`'s single
			// queue_full count + warn. Counting it here too would
			// double-increment xpf_event_actions_dropped_total (#2869).
			if item.policyName != a.policyName {
				e.counters.droppedQueueFull.Add(1)
			}
		}
	}
	return replaced
}
