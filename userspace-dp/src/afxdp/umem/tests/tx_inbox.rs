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
