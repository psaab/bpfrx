//! Bounded lock-free MPMC queue, safe for MPSC use.
//!
//! Backs the per-binding redirect inbox on `BindingLiveState` (see `umem.rs`):
//! N producer workers push redirected `TxRequest`s; the owner worker drains.
//! Prior to #706 this was a `Mutex<VecDeque<TxRequest>>` which serialised
//! every producer against every other producer *and* against the owner's
//! drain; the contention injected µs-scale jitter into TCP inter-arrival
//! timing on redirected flows and drove the bimodal cwnd pattern in #704.
//!
//! Algorithm: Dmitry Vyukov's bounded MPMC with per-slot sequence numbers
//! (<https://www.1024cores.net/home/lock-free-algorithms/queues/bounded-mpmc-queue>).
//! We only take the MPSC subset — all `pop` callers must be the owner worker
//! — so correctness needs only the weaker single-consumer invariant. Using
//! the MPMC algorithm keeps the push side trivially lock-free with one CAS
//! per slot acquire.
//!
//! Overflow semantics: `push` returns `Err(val)` when the ring is full. The
//! caller in `BindingLiveState` treats that as drop-newest and bumps the
//! `redirect_inbox_overflow_drops` / `tx_errors` counters. This replaces the
//! prior drop-oldest (pop-front-then-push-back) behaviour; drop-newest is
//! preferable under contention because older queued packets are closer to
//! being serviced by the owner and evicting them extends tail latency.

use std::cell::UnsafeCell;
use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicUsize, Ordering};

struct Slot<T> {
    seq: AtomicUsize,
    val: UnsafeCell<MaybeUninit<T>>,
}

pub(super) struct MpscInbox<T> {
    slots: Box<[Slot<T>]>,
    mask: usize,
    /// Producer cursor. Advanced via CAS by any pushing thread.
    head: AtomicUsize,
    /// Consumer cursor. Advanced only by the single consumer (the owner
    /// worker for this binding). Exposed atomically so producers and the
    /// `is_empty` / `len` helpers can observe it.
    tail: AtomicUsize,
}

// Safety: the queue is designed to be shared across producer threads and
// the consumer thread. `T: Send` is sufficient — values transit between
// threads but each value is owned by exactly one thread at a time via
// the head/tail sequencing.
unsafe impl<T: Send> Send for MpscInbox<T> {}
unsafe impl<T: Send> Sync for MpscInbox<T> {}

impl<T> MpscInbox<T> {
    /// Create a queue with capacity rounded up to the next power of two
    /// (minimum 2 slots).
    pub(super) fn new(capacity_hint: usize) -> Self {
        let cap = capacity_hint.max(2).next_power_of_two();
        let slots = (0..cap)
            .map(|i| Slot {
                seq: AtomicUsize::new(i),
                val: UnsafeCell::new(MaybeUninit::uninit()),
            })
            .collect::<Box<[_]>>();
        Self {
            slots,
            mask: cap - 1,
            head: AtomicUsize::new(0),
            tail: AtomicUsize::new(0),
        }
    }

    #[inline]
    pub(super) fn capacity(&self) -> usize {
        self.mask + 1
    }

    /// Approximate occupancy. Non-linearisable: producers may have
    /// claimed a slot (advanced `head`) without yet publishing a value,
    /// and the consumer may have consumed a value without readers seeing
    /// the updated `tail`. Safe for observability and soft-cap gating.
    #[inline]
    pub(super) fn len(&self) -> usize {
        let head = self.head.load(Ordering::Relaxed);
        let tail = self.tail.load(Ordering::Relaxed);
        head.wrapping_sub(tail)
    }

    #[inline]
    pub(super) fn is_empty(&self) -> bool {
        self.head.load(Ordering::Relaxed) == self.tail.load(Ordering::Relaxed)
    }

    /// Multi-producer push. Returns `Err(val)` when the ring is full.
    pub(super) fn push(&self, val: T) -> Result<(), T> {
        let mut pos = self.head.load(Ordering::Relaxed);
        loop {
            // SAFETY: `pos & mask` is in range because `mask = cap - 1`
            // and `cap = slots.len()`.
            let slot = unsafe { self.slots.get_unchecked(pos & self.mask) };
            let seq = slot.seq.load(Ordering::Acquire);
            let diff = (seq as isize).wrapping_sub(pos as isize);
            if diff == 0 {
                // Slot ready for this producer at `pos`. Try to claim.
                match self.head.compare_exchange_weak(
                    pos,
                    pos.wrapping_add(1),
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => {
                        // SAFETY: we own the slot until we publish via
                        // `seq.store(pos+1, Release)`; no other thread
                        // can read or write the value until then.
                        unsafe {
                            (*slot.val.get()).write(val);
                        }
                        slot.seq
                            .store(pos.wrapping_add(1), Ordering::Release);
                        return Ok(());
                    }
                    Err(actual) => pos = actual,
                }
            } else if diff < 0 {
                // seq is behind pos — consumer hasn't finished with the
                // slot that currently lives at `pos & mask`. Queue full.
                return Err(val);
            } else {
                // Another producer claimed this slot first; refresh and retry.
                pos = self.head.load(Ordering::Relaxed);
            }
        }
    }

    /// Single-consumer pop.
    ///
    /// SAFETY: must not be called concurrently with itself. The helper's
    /// contract is that only the owner worker for a binding pops from its
    /// inbox.
    pub(super) unsafe fn pop(&self) -> Option<T> {
        let pos = self.tail.load(Ordering::Relaxed);
        // SAFETY: `pos & mask` is in range.
        let slot = unsafe { self.slots.get_unchecked(pos & self.mask) };
        let seq = slot.seq.load(Ordering::Acquire);
        let diff = (seq as isize).wrapping_sub(pos.wrapping_add(1) as isize);
        if diff == 0 {
            // Slot holds a value published at sequence `pos+1`.
            // SAFETY: by the single-consumer invariant we are the only
            // reader, and the producer already wrote the value before
            // releasing the slot via `seq.store(pos+1, Release)`.
            let val = unsafe { (*slot.val.get()).assume_init_read() };
            // Republish slot for the next pass: producer looking at this
            // slot at position `pos + cap` will see `seq == pos + cap`
            // and be cleared to claim it.
            slot.seq.store(
                pos.wrapping_add(self.mask).wrapping_add(1),
                Ordering::Release,
            );
            self.tail
                .store(pos.wrapping_add(1), Ordering::Release);
            Some(val)
        } else {
            // seq behind pos+1: no value yet at this tail position.
            None
        }
    }
}

impl<T> Drop for MpscInbox<T> {
    fn drop(&mut self) {
        // SAFETY: &mut self gives us exclusive access, so the single-
        // consumer invariant holds trivially.
        while unsafe { self.pop() }.is_some() {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
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
}
