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
// [`replicate_session_upsert`]). The mover set is then closed by construction:
// moving a counter REQUIRES calling one of those two functions, and calling one
// of them takes the guard. There is no list to keep current.
//
// Shape: movers take the SHARED side — they may still run concurrently with
// each other, which is ordinary production concurrency over atomics — and
// readers take the EXCLUSIVE side.

use std::cell::Cell;
use std::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

static COUNTER_LOCK: RwLock<()> = RwLock::new(());

thread_local! {
    /// Depth of counter-lock ownership (or exemption) held by THIS thread.
    ///
    /// Two jobs, both about re-entrancy, because `RwLock` is not reentrant:
    ///
    ///   * A reading test calls the movers itself while holding the exclusive
    ///     side. Its own thread must not then try to take the shared side.
    ///   * A mover may call another mover (`maybe_promote_synced_session`
    ///     publishes and then replicates). Only the outermost frame takes the
    ///     lock: a nested `read()` would deadlock against a writer that queued
    ///     in between, because std's `RwLock` does not let a later reader
    ///     overtake a waiting writer.
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
pub(super) struct CounterExempt;

impl CounterExempt {
    pub(super) fn new() -> Self {
        enter();
        Self
    }
}

impl Drop for CounterExempt {
    fn drop(&mut self) {
        leave();
    }
}

/// Exclusive access for a test that READS the counters: no other thread may
/// move them while this guard lives.
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
    let lock = COUNTER_LOCK.read().unwrap_or_else(|e| e.into_inner());
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
