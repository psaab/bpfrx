// Tests for afxdp/mpsc_inbox.rs — relocated from inline
// `#[cfg(test)] mod tests` to keep mpsc_inbox.rs under the modularity-discipline
// LOC threshold. Loaded as a sibling submodule via
// `#[path = "mpsc_inbox_tests.rs"]` from mpsc_inbox.rs.

use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;

#[test]
fn push_and_pop_in_order_for_single_producer() {
    let q = MpscInbox::<u32>::new(4);
    assert_eq!(q.capacity(), 4);
    assert!(q.is_empty());
    for i in 0..4 {
        q.push(i).expect("push");
    }
    assert!(!q.is_empty());
    assert_eq!(q.len(), 4);
    for expected in 0..4 {
        let got = unsafe { q.pop() }.expect("pop");
        assert_eq!(got, expected);
    }
    assert!(q.is_empty());
    assert!(unsafe { q.pop() }.is_none());
}

#[test]
fn push_returns_err_when_ring_is_full() {
    let q = MpscInbox::<u32>::new(2);
    q.push(10).unwrap();
    q.push(11).unwrap();
    match q.push(12) {
        Err(v) => assert_eq!(v, 12),
        Ok(()) => panic!("push should have failed on full ring"),
    }
    // After draining one slot, push should succeed again.
    assert_eq!(unsafe { q.pop() }, Some(10));
    q.push(13).expect("push after drain");
    assert_eq!(unsafe { q.pop() }, Some(11));
    assert_eq!(unsafe { q.pop() }, Some(13));
    assert!(q.is_empty());
}

#[test]
fn capacity_hint_rounds_up_to_power_of_two() {
    assert_eq!(MpscInbox::<u32>::new(3).capacity(), 4);
    assert_eq!(MpscInbox::<u32>::new(5).capacity(), 8);
    assert_eq!(MpscInbox::<u32>::new(1).capacity(), 2);
    assert_eq!(MpscInbox::<u32>::new(0).capacity(), 2);
}

#[test]
fn concurrent_producers_do_not_lose_items_below_capacity() {
    // N producers each push P items; hard cap is large enough that
    // no push should fail. Consumer drains and we verify the sum.
    const PRODUCERS: usize = 4;
    const PER_PRODUCER: usize = 1024;
    let q = Arc::new(MpscInbox::<u32>::new(PRODUCERS * PER_PRODUCER));
    let consumed = Arc::new(AtomicUsize::new(0));

    let handles: Vec<_> = (0..PRODUCERS)
        .map(|p| {
            let q = Arc::clone(&q);
            thread::spawn(move || {
                for i in 0..PER_PRODUCER {
                    let v = (p * PER_PRODUCER + i) as u32;
                    q.push(v).expect("no overflow at below-cap");
                }
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }

    // Drain on the main (consumer) thread — the single consumer.
    let mut sum: u64 = 0;
    while let Some(v) = unsafe { q.pop() } {
        sum += v as u64;
        consumed.fetch_add(1, Ordering::Relaxed);
    }
    let expected_sum: u64 = (0..(PRODUCERS * PER_PRODUCER) as u64).sum();
    assert_eq!(sum, expected_sum, "lost items across concurrent producers");
    assert_eq!(consumed.load(Ordering::Relaxed), PRODUCERS * PER_PRODUCER);
    assert!(q.is_empty());
}

#[test]
fn concurrent_producers_over_capacity_drop_exactly_the_overflow() {
    // N producers each try to push P items into a ring smaller than
    // N*P. We count push failures (Err) and pop successes (Ok) and
    // verify no item is leaked or duplicated. With a concurrent
    // consumer, `pushed == popped + failed`.
    const PRODUCERS: usize = 4;
    const PER_PRODUCER: usize = 4096;
    const CAP: usize = 1024;
    let q = Arc::new(MpscInbox::<u32>::new(CAP));
    let pushed_ok = Arc::new(AtomicUsize::new(0));
    let pushed_err = Arc::new(AtomicUsize::new(0));

    let producers: Vec<_> = (0..PRODUCERS)
        .map(|p| {
            let q = Arc::clone(&q);
            let ok = Arc::clone(&pushed_ok);
            let err = Arc::clone(&pushed_err);
            thread::spawn(move || {
                for i in 0..PER_PRODUCER {
                    let v = (p * PER_PRODUCER + i) as u32;
                    match q.push(v) {
                        Ok(()) => {
                            ok.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(_) => {
                            err.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            })
        })
        .collect();

    // Consumer runs concurrently with producers.
    let q_c = Arc::clone(&q);
    let consumer = thread::spawn(move || {
        let mut popped = 0usize;
        let mut idle_spins = 0usize;
        loop {
            if let Some(_v) = unsafe { q_c.pop() } {
                popped += 1;
                idle_spins = 0;
            } else {
                idle_spins += 1;
                if idle_spins > 1_000_000 {
                    break;
                }
                std::hint::spin_loop();
            }
        }
        popped
    });

    for h in producers {
        h.join().unwrap();
    }
    let popped_mid = consumer.join().unwrap();
    // Drain anything the consumer's timeout missed.
    let mut popped_tail = 0;
    while let Some(_v) = unsafe { q.pop() } {
        popped_tail += 1;
    }
    let popped = popped_mid + popped_tail;

    let ok = pushed_ok.load(Ordering::Relaxed);
    let err = pushed_err.load(Ordering::Relaxed);
    assert_eq!(ok + err, PRODUCERS * PER_PRODUCER);
    assert_eq!(
        popped, ok,
        "every successful push should be popped exactly once \
         (popped={popped}, pushed_ok={ok}, pushed_err={err})"
    );
    assert!(q.is_empty());
}

#[test]
fn drop_runs_for_remaining_values() {
    use std::sync::atomic::AtomicUsize;
    struct DropCount<'a>(&'a AtomicUsize);
    impl<'a> Drop for DropCount<'a> {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
    let counter = AtomicUsize::new(0);
    {
        let q = MpscInbox::<DropCount<'_>>::new(8);
        q.push(DropCount(&counter)).ok().unwrap();
        q.push(DropCount(&counter)).ok().unwrap();
        q.push(DropCount(&counter)).ok().unwrap();
        // Drop the queue without popping: all three values must Drop.
    }
    assert_eq!(counter.load(Ordering::Relaxed), 3);
}
