// BindingLiveState redirect-inbox admission + overflow-counter
// tests. Split from umem/tests.rs (#4667).

use super::*;

#[test]
fn enqueue_tx_owned_increments_redirect_inbox_overflow_counter_when_soft_cap_drops_newcomer() {
    // #710 / #706: pin that a redirect-inbox overflow in
    // `enqueue_tx_owned` increments both `redirect_inbox_overflow_drops`
    // (dedicated view) and `tx_errors` (generic), regardless of
    // which request gets dropped. Post-#706 the policy is drop-
    // newest (the incoming push is discarded); pre-#706 it was
    // drop-oldest (the head of the queue was evicted). Either way,
    // every push must return `Ok(())` and both counters advance in
    // lockstep.
    let live = BindingLiveState::new();
    live.max_pending_tx.store(2, Ordering::Relaxed);

    // Fill to cap — no overflow yet.
    live.enqueue_tx_owned(test_tx_request_for_inbox(1))
        .expect("push 1");
    live.enqueue_tx_owned(test_tx_request_for_inbox(2))
        .expect("push 2");
    assert_eq!(
        live.redirect_inbox_overflow_drops.load(Ordering::Relaxed),
        0
    );
    assert_eq!(live.tx_errors.load(Ordering::Relaxed), 0);

    // Third push hits the soft cap — drop-newest, counters advance.
    live.enqueue_tx_owned(test_tx_request_for_inbox(3))
        .expect("push 3 drops newest");
    assert_eq!(
        live.redirect_inbox_overflow_drops.load(Ordering::Relaxed),
        1
    );
    assert_eq!(
        live.tx_errors.load(Ordering::Relaxed),
        1,
        "generic tx_errors stays in lockstep with the dedicated drop \
         counter on this path — the dedicated counter is a subset view"
    );

    // Fourth push, another overflow — both counters advance again.
    live.enqueue_tx_owned(test_tx_request_for_inbox(4))
        .expect("push 4 drops newest");
    assert_eq!(
        live.redirect_inbox_overflow_drops.load(Ordering::Relaxed),
        2
    );
    assert_eq!(live.tx_errors.load(Ordering::Relaxed), 2);
}

#[test]
fn take_pending_tx_into_appends_without_resetting_caller_buffer() {
    // #706: pin that `take_pending_tx_into` preserves the caller's
    // existing `VecDeque` contents. The owner-worker drain feeds its
    // `pending_tx_local` buffer through the call; if the new API ever
    // regressed to `*out = drained` or `out.clear()`, items already
    // queued locally would be dropped on every poll.
    let live = BindingLiveState::new();
    live.max_pending_tx.store(8, Ordering::Relaxed);
    live.enqueue_tx_owned(test_tx_request_for_inbox(10))
        .expect("push inbox");
    live.enqueue_tx_owned(test_tx_request_for_inbox(11))
        .expect("push inbox");

    let mut out = VecDeque::from([test_tx_request_for_inbox(1), test_tx_request_for_inbox(2)]);
    live.take_pending_tx_into(&mut out);

    let payloads: Vec<u8> = out.iter().map(|req| req.bytes[0]).collect();
    assert_eq!(
        payloads,
        vec![1, 2, 10, 11],
        "caller-provided items must come first; inbox items appended in FIFO order"
    );
    assert!(live.pending_tx_empty(), "inbox fully drained");
}

#[test]
fn enqueue_tx_owned_below_cap_does_not_touch_overflow_counter() {
    let live = BindingLiveState::new();
    live.max_pending_tx.store(8, Ordering::Relaxed);

    for payload in 0..4 {
        live.enqueue_tx_owned(test_tx_request_for_inbox(payload))
            .expect("push below cap");
    }
    assert_eq!(
        live.redirect_inbox_overflow_drops.load(Ordering::Relaxed),
        0
    );
    assert_eq!(live.tx_errors.load(Ordering::Relaxed), 0);
}

/// #6304: the admission-attempt instrument does not perturb `BindingLiveState`.
///
/// `try_acquire_pending_tx_admission` carries a `#[cfg(test)]` bump into a
/// THREAD-LOCAL counter so
/// `live_flow_cache_callsite_nonsampled_makes_no_shared_admission_attempt_6304`
/// can distinguish sample-first from reserve-first at the live call site. This
/// struct is the one whose cross-core cacheline behaviour #6114 exists to fix,
/// so the standing objection to instrumenting it is real: a test-only member
/// puts a layout under test that production never has.
///
/// A thread-local answers that objection by construction — it lives in its own
/// storage — and this cell is the measurement rather than the argument. It reads
/// the TEST configuration; the `const _: [(); N]` asserts beside the struct in
/// `binding_state/mod.rs` are what make the statement a CROSS-configuration one,
/// since they are not `cfg`-gated and must hold in the production build too.
/// Both numbers here and there are the same literals on purpose.
///
/// Why the two offsets and not just the size — measured, not assumed. A
/// `#[cfg(test)]` `AtomicU64` field declared ahead of `pending_tx_admitted`
/// leaves size and align UNCHANGED (it fits in existing tail slack) and moves
/// `pending_tx_admitted` 2152 -> 2160; declared last, after
/// `delta_loss_pending`, it leaves size, align and `pending_tx_admitted`
/// unchanged and moves `delta_loss_pending` 2280 -> 2288. A size-only guard
/// calls both of those layout-neutral, and both would be exactly the
/// perturbation #6114 cares about.
///
/// WHAT THIS CELL CAN AND CANNOT DO. It cannot FAIL. The four `const _`
/// asserts beside the struct are not `cfg`-gated, so a wrong value in the test
/// configuration is a compile error and this binary never gets built — the
/// assertions below execute, always pass, and exist as a readable mirror of the
/// numbers plus their reasoning, not as an independent check. Nor are four
/// pinned values a whole-struct fingerprint: a perturbation that moves only
/// unpinned fields satisfies all four. See the comment beside the struct for the
/// full scope, including why `repr(Rust)` plus an unpinned toolchain makes these
/// literals a build tripwire rather than a portable invariant.
#[test]
fn admission_attempt_instrument_leaves_binding_live_state_layout_unchanged_6304() {
    assert_eq!(
        std::mem::size_of::<BindingLiveState>(),
        2304,
        "#6304: the `cfg(test)` admission-attempt instrument must not change \
         `BindingLiveState`'s SIZE — the same literal is asserted at compile \
         time in `binding_state/mod.rs`, which is where the production build \
         checks it"
    );
    assert_eq!(
        std::mem::align_of::<BindingLiveState>(),
        64,
        "#6304: ...nor its ALIGNMENT"
    );
    assert_eq!(
        std::mem::offset_of!(BindingLiveState, pending_tx_admitted),
        2152,
        "#6304/#6114: ...nor the OFFSET of the admission counter whose \
         cacheline this is all about. A `cfg(test)` field ahead of it moves \
         this to 2160 while leaving the size assert above satisfied"
    );
    assert_eq!(
        std::mem::offset_of!(BindingLiveState, delta_loss_pending),
        2280,
        "#6304: ...nor the offset of the last-declared field, which is the \
         sentinel for a `cfg(test)` member appended at the END of the struct — \
         that shape moves this to 2288 and trips nothing else"
    );
}
