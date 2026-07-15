package eventengine

import "testing"

// #5853: the action-queue dedup-by-policy invariant ("at most one pending action
// per policy") must hold on EVERY enqueue, not only once the channel is full.
// The pre-#5853 enqueue did an unconditional fast-path send and only deduped in
// the full/`default` branch, so while the worker was blocked behind the config
// lock a burst from ONE policy filled all 64 slots with redundant duplicates and
// the next remediation for an UNRELATED policy was dropped queue-full.

// drainPolicyNames non-destructively... no: it drains the buffered queue and
// returns the policy names in FIFO order. Used by the dedup tests to inspect the
// exact queue contents (the worker is not started by New(), so the queue is
// inert and this is race-free).
func drainPolicyNames(e *Engine) []string {
	var out []string
	for {
		select {
		case a := <-e.actions:
			out = append(out, a.policyName)
		default:
			return out
		}
	}
}

// TestQueue_SamePolicyBurstDoesNotStarveOthers_5853 pins the fix: a same-policy
// burst occupies exactly ONE slot (early dedup), so an unrelated policy's action
// still enqueues instead of being dropped queue-full.
//
// New(nil, nil) does NOT start the actionWorker, so the queue is inert and the
// producer-side dedup is exercised deterministically without a consumer draining
// underneath (same seam as TestSupersede_PreservesFIFOPlacesNewAtTail).
//
// FAIL-ON-REVERT: revert enqueue to the fast-path-send-then-dedup-only-when-full
// form and BOTH assertions go RED — the burst fills all actionQueueDepth slots
// (depth != 1) and the unrelated action is dropped queue-full (absent from the
// drained queue).
func TestQueue_SamePolicyBurstDoesNotStarveOthers_5853(t *testing.T) {
	e := New(nil, nil)
	defer e.Close()

	// Burst == actionQueueDepth same-policy events. The pre-fix fast path
	// fast-sends each (there is room until the 64th), so it NEVER hits the
	// full/`default` branch, no supersede runs, and all 64 slots hold redundant
	// 'flapping' duplicates. With the fix each enqueue supersedes the queued
	// entry, so exactly one slot is ever used.
	for i := 0; i < actionQueueDepth; i++ {
		e.enqueue(plannedAction{policyName: "flapping"})
	}
	if got := int(e.counters.queueDepth.Load()); got != 1 {
		t.Fatalf("same-policy burst of %d occupied %d queue slots; want 1 — dedup "+
			"must run on EVERY enqueue, not only when full (#5853; pre-fix fills all %d slots)",
			actionQueueDepth, got, actionQueueDepth)
	}
	if st := e.Stats(); st.Superseded != uint64(actionQueueDepth-1) {
		t.Fatalf("Superseded=%d; want %d (every redundant same-policy duplicate is a benign dedup)",
			st.Superseded, actionQueueDepth-1)
	}
	if st := e.Stats(); st.DroppedQueueFull != 0 {
		t.Fatalf("DroppedQueueFull=%d after a same-policy burst; a dedup is benign, "+
			"NOT a capacity drop — it must not inflate the queue_full alert metric (#5853)", st.DroppedQueueFull)
	}

	// The whole point: an UNRELATED policy's remediation must STILL enqueue.
	// Pre-fix the queue is full of 'flapping', and supersede can only evict a
	// SAME-policy entry (none matches 'unrelated'), so this action is dropped
	// queue-full — the starvation the issue describes.
	e.enqueue(plannedAction{policyName: "unrelated"})

	got := drainPolicyNames(e)
	if len(got) != 2 || got[0] != "flapping" || got[1] != "unrelated" {
		t.Fatalf("queue = %v; want [flapping unrelated] — the unrelated remediation must "+
			"not be starved/dropped by the same-policy burst (#5853)", got)
	}
	if st := e.Stats(); st.DroppedQueueFull != 0 {
		t.Fatalf("DroppedQueueFull=%d; the unrelated policy must have been queued, not dropped (#5853)",
			st.DroppedQueueFull)
	}
}

// TestQueue_InterleavedPoliciesEachKeepOneSlot_5853 proves the invariant holds
// across MANY policies interleaved with duplicates: N distinct policies each
// firing repeatedly must leave exactly N queued entries (one per policy), FIFO
// by first appearance, never N×duplicates.
func TestQueue_InterleavedPoliciesEachKeepOneSlot_5853(t *testing.T) {
	e := New(nil, nil)
	defer e.Close()

	policies := []string{"a", "b", "c", "d"}
	// Fire each policy 5 times, interleaved.
	for round := 0; round < 5; round++ {
		for _, p := range policies {
			e.enqueue(plannedAction{policyName: p})
		}
	}
	if got := int(e.counters.queueDepth.Load()); got != len(policies) {
		t.Fatalf("queueDepth=%d; want %d (one pending action per policy, no duplicates)",
			got, len(policies))
	}
	// FIFO by first appearance: a, b, c, d (later duplicates supersede in place at
	// the tail, but with all four already queued each duplicate re-drops its own
	// and re-appends at the tail — the relative order of the four distinct
	// policies is preserved because a same-policy supersede only moves its OWN
	// entry). The final round fired a,b,c,d in order, so the tail order is a,b,c,d.
	got := drainPolicyNames(e)
	want := []string{"a", "b", "c", "d"}
	if len(got) != len(want) {
		t.Fatalf("queue=%v; want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("queue order=%v; want %v", got, want)
		}
	}
}
