// #4800: process-global exclusion between the tests that READ the new-flow
// contention counters and every code path that MOVES them. Test-build only —
// the whole module is `#[cfg(test)]` and nothing here is compiled into a
// release helper.
//
// The counters (`SHARED_SESSION_PUBLISHES`,
// `SHARED_SESSION_PUBLISH_LOCK_ACQUISITIONS`,
// `SHARED_SESSION_PUBLISH_LOCK_CONTENDED`, `SESSION_REPLICATION_*`) are
// process-global statics, and cargo runs the whole unit-test suite in ONE
// process across a thread pool. A sibling test that installs or replicates a
// session between a reading test's `before` and `after` snapshots inflates the
// delta, so an exact assertion becomes a coin flip. That is measured, not
// hypothetical: the publish-side equality assertions failed 1 run in 12 at
// default parallelism, and the replication-side ones failed at iteration 74 of
// a 1500-iteration filtered loop.
//
// DERIVED, NOT INVENTORIED. The first attempt at this was a bare mutex that
// every mover had to remember to take, with the mover set written down in a
// doc comment. That inventory was WRONG — it missed
// `coordinator::sync_worker_session_tables` and
// `promote::maybe_promote_synced_session`, both of which reach
// `replicate_session_upsert` from tests that have no idea they are movers, and
// a mover without the guard defeats it exactly as thoroughly as a reader
// without it. So the shared side of this lock is taken INSIDE the two
// counter-moving functions themselves ([`publish_shared_session`] and
// [`replicate_session_upsert`]), which removes the list a caller had to
// remember to join.
//
// WHAT THIS DOES **NOT** GUARANTEE — an earlier revision of this comment
// claimed the mover set was "closed by construction". It is not, and the
// claim is withdrawn:
//
//   * The guarded atomics are `pub(crate)` (`shared_ops.rs`,
//     `session_glue/mod.rs`) and any module in the crate can `fetch_add` one
//     directly without going near either function.
//   * `worker_queue::lock_recover_counting` takes an ARBITRARY `&AtomicU64`,
//     so a future caller can move the replication contended counter from
//     somewhere else entirely.
//   * The per-binding `new_flow_installs` counter moves at
//     `poll_descriptor/mod.rs` on the transit-install path, outside both
//     functions. It is NOT part of this isolation set at all — nothing here
//     serializes it, and no test in this module reads it.
//
// So the real property is: every mover REACHABLE THROUGH TODAY'S CALL GRAPH
// goes through one of the two functions, and the guard covers those. That is a
// convention the compiler does not enforce. A new direct `fetch_add` on one of
// these statics is exactly the change this module cannot catch — review for it.
//
// Shape: movers take the SHARED side — they may still run concurrently with
// each other, which is ordinary production concurrency over atomics — and
// readers take the EXCLUSIVE side.

use std::cell::Cell;
use std::marker::PhantomData;
use std::rc::Rc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

static COUNTER_LOCK: RwLock<()> = RwLock::new(());

/// Number of threads currently PARKED on the mover side, i.e. that have
/// entered [`counter_mover_guard`] and not yet acquired the shared lock.
///
/// Exists so a test can prove exclusion is actually in force without sleeping
/// and hoping: `movers_waiting() >= 1` is a positive observation that some
/// non-exempt mover is blocked on this lock, which is the property the guard
/// claims. Without it the only available evidence is "the counter did not move
/// during a 200ms nap", which a descheduled thread satisfies just as well as a
/// correctly blocked one — so the test would pass under its own mutation.
static MOVERS_WAITING: AtomicUsize = AtomicUsize::new(0);

/// Test-visible reader for [`MOVERS_WAITING`].
pub(super) fn movers_waiting() -> usize {
    MOVERS_WAITING.load(Ordering::SeqCst)
}

thread_local! {
    /// Depth of counter-lock ownership (or exemption) held by THIS thread.
    ///
    /// Two jobs, both about re-entrancy, because `RwLock` is not reentrant:
    ///
    ///   * A reading test calls the movers itself while holding the exclusive
    ///     side. Its own thread must not then try to take the shared side.
    ///   * A mover may call another mover. `maybe_promote_synced_session`
    ///     publishes and then replicates SEQUENTIALLY — each guard is dropped
    ///     before the next is taken, so that path alone would not nest — but
    ///     the depth is what makes nesting safe if any caller ever does wrap
    ///     one mover inside another's guard scope. Only the outermost frame
    ///     takes the lock: a nested `read()` would deadlock against a writer
    ///     that queued in between, because std's `RwLock` does not let a later
    ///     reader overtake a waiting writer.
    static COUNTER_LOCK_DEPTH: Cell<u32> = const { Cell::new(0) };
}

fn enter() -> bool {
    COUNTER_LOCK_DEPTH.with(|d| {
        let held = d.get();
        d.set(held + 1);
        held == 0
    })
}

fn leave() {
    COUNTER_LOCK_DEPTH.with(|d| d.set(d.get() - 1));
}

/// Exempt the calling thread from the mover-side guard for as long as this
/// value lives.
///
/// Needed only by a reading test that drives a mover from a SPAWNED thread —
/// the two deterministic contention probes, which park on a map/queue mutex on
/// the test thread and publish/replicate from a helper. Without the exemption
/// that helper would block on the exclusive guard its parent still holds, and
/// the parent's `join()` would hang forever.
///
/// NOT `Send`/`Sync`, deliberately (`PhantomData<Rc<()>>`). The token's whole
/// state is a THREAD-LOCAL depth, so a token created on T0 and moved to T1 is
/// incoherent in both directions: T1 would still take the shared side (its own
/// depth is zero) and block behind T0's exclusive guard, deadlocking a T0 that
/// then joins it; and T1 dropping the token would subtract from a zero depth
/// while T0's stays elevated, leaking an exemption that makes every later mover
/// on T0 skip the guard silently. Both are unreachable if the value cannot
/// leave the thread that made it, so the bound is enforced by the compiler
/// rather than by the two call sites happening to construct and drop in place.
pub(super) struct CounterExempt {
    _not_send: PhantomData<Rc<()>>,
}

impl CounterExempt {
    pub(super) fn new() -> Self {
        enter();
        Self {
            _not_send: PhantomData,
        }
    }
}

/// Compile-time proof of the `!Send` bound above. Two blanket impls apply to a
/// `Send` type and only one to a non-`Send` type, so inference resolves this
/// call ONLY while `CounterExempt` stays non-`Send`; dropping the `PhantomData`
/// makes it ambiguous and this file stops compiling. A compile error is the
/// only possible red for a compile-time property.
const _: fn() = || {
    trait AmbiguousIfSend<A> {
        fn proof() {}
    }
    impl<T: ?Sized> AmbiguousIfSend<()> for T {}
    impl<T: ?Sized + Send> AmbiguousIfSend<u8> for T {}
    let _ = <CounterExempt as AmbiguousIfSend<_>>::proof;
};

impl Drop for CounterExempt {
    fn drop(&mut self) {
        leave();
    }
}

/// Exclusive access for a test that READS the counters.
///
/// Precisely: no NON-EXEMPT thread may move them while this guard lives. The
/// contention probes deliberately hand their helper thread a [`CounterExempt`]
/// so it CAN publish/replicate inside the bracket — that publish is the
/// measurement. "No other thread may move them" would be false, and false in
/// the direction that matters, since the exempt mover is the one whose effect
/// the reader is counting.
pub(super) struct CounterReaderGuard {
    // Field order is drop order: release the depth marker, then the lock.
    _lock: RwLockWriteGuard<'static, ()>,
}

impl Drop for CounterReaderGuard {
    fn drop(&mut self) {
        leave();
    }
}

/// Take the exclusive side. Poison is recovered rather than propagated: a
/// panicking sibling test has already failed on its own terms, and turning
/// that into a cascade of unrelated `unwrap` panics only obscures which test
/// actually broke.
pub(super) fn counter_reader_guard() -> CounterReaderGuard {
    let lock = COUNTER_LOCK.write().unwrap_or_else(|e| e.into_inner());
    enter();
    CounterReaderGuard { _lock: lock }
}

/// Mover-side guard, taken inside the counter-moving functions themselves.
///
/// `None` means "this thread already holds the lock (or is exempt)" — see
/// [`COUNTER_LOCK_DEPTH`]. The caller must bind the result to a NAMED
/// `let _guard = ...` so it lives to the end of the moving function; `let _ =`
/// would drop it immediately and guard nothing.
#[must_use]
pub(super) fn counter_mover_guard() -> Option<MoverGuard> {
    if !enter() {
        leave();
        return None;
    }
    MOVERS_WAITING.fetch_add(1, Ordering::SeqCst);
    let lock = COUNTER_LOCK.read().unwrap_or_else(|e| e.into_inner());
    MOVERS_WAITING.fetch_sub(1, Ordering::SeqCst);
    Some(MoverGuard { _lock: lock })
}

pub(super) struct MoverGuard {
    _lock: RwLockReadGuard<'static, ()>,
}

impl Drop for MoverGuard {
    fn drop(&mut self) {
        leave();
    }
}
