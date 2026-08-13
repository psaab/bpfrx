// #1807: shared poison-recovery helpers for the per-worker
// `Mutex<VecDeque<WorkerCommand>>` command queues.
//
// One uniform policy for every producer and consumer of a worker
// command queue (extends the #1790 coordinator-side recovery):
//
// - Poison means a thread panicked while holding the lock. The panic
//   already happened and was contained (#925 worker supervisor); the
//   deque holds the **committed prefix** of every completed push — a
//   panic between the pushes of a multi-push section (e.g. the
//   DemoteOwnerRGS + VacateAllSharedExactSlots pair in ha.rs, or the
//   forward + reverse UpsertLocal pair in tunnel.rs) leaves exactly
//   the commands pushed before the panic. Commands are individually
//   self-contained, so consumers tolerate partial batches; discarding
//   the queue instead would lose acknowledged HA/session commands.
// - `clear_poison` restores the fast unpoisoned path for subsequent
//   accesses, so the Poisoned arm stays cold after the first recovery
//   instead of taxing every later lock.
// - Every recovery bumps `WORKER_COMMAND_QUEUE_POISON_RECOVERIES`,
//   surfaced via ProcessStatus as the Prometheus counter
//   `xpf_userspace_worker_command_queue_poison_recoveries_total`.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, TryLockError};

use super::types::WorkerCommand;

/// #1807: total worker-command-queue poison recoveries across every
/// producer/consumer site (worker poll peek + apply, HA enqueues,
/// session replication, activation prewarm, tunnel install/drain-wait,
/// cross-binding CoS redirect). Read by
/// `Coordinator::worker_command_queue_poison_recoveries_total()`.
pub(in crate::afxdp) static WORKER_COMMAND_QUEUE_POISON_RECOVERIES: AtomicU64 = AtomicU64::new(0);

/// Lock a worker-command queue, recovering and CLEARING poison.
///
/// Policy (#1807, extends #1790): a panic that poisoned the queue
/// already happened and was contained ([#925] supervisor); the deque
/// holds the committed prefix of every completed push — discarding it
/// would lose acknowledged HA/session commands. `clear_poison` restores
/// the fast unpoisoned path for subsequent accesses.
#[inline]
pub(in crate::afxdp) fn lock_recover(
    m: &Mutex<VecDeque<WorkerCommand>>,
) -> MutexGuard<'_, VecDeque<WorkerCommand>> {
    match m.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            m.clear_poison();
            WORKER_COMMAND_QUEUE_POISON_RECOVERIES.fetch_add(1, Ordering::Relaxed);
            eprintln!(
                "xpf-ha: worker command queue mutex poisoned; recovering committed queue and clearing poison"
            );
            poisoned.into_inner()
        }
    }
}

/// #4800: [`lock_recover`] that reports whether it had to block, for the
/// N-way session-replication fan-out.
///
/// `try_lock` first (one CAS on an uncontended mutex — what `lock()` cost
/// anyway); on WouldBlock bump `contended` and fall through to the blocking
/// [`lock_recover`], which carries the poison policy. Kept as an explicit
/// opt-in rather than folded into `lock_recover` because that helper is
/// shared by the tunnel, TX-drain, HA and cross-binding CoS enqueues —
/// counting all of them would blur the very attribution this exists for.
#[inline]
pub(in crate::afxdp) fn lock_recover_counting<'a>(
    m: &'a Mutex<VecDeque<WorkerCommand>>,
    contended: &AtomicU64,
) -> MutexGuard<'a, VecDeque<WorkerCommand>> {
    if let Some(guard) = try_lock_recover(m) {
        return guard;
    }
    contended.fetch_add(1, Ordering::Relaxed);
    lock_recover(m)
}

/// `try_lock` variant of [`lock_recover`]: WouldBlock → `None`
/// (unchanged skip semantics — another thread holds the lock and will
/// release it shortly); Poisoned → recover + clear + `Some(guard)`,
/// same committed-prefix policy as [`lock_recover`].
#[inline]
pub(in crate::afxdp) fn try_lock_recover(
    m: &Mutex<VecDeque<WorkerCommand>>,
) -> Option<MutexGuard<'_, VecDeque<WorkerCommand>>> {
    match m.try_lock() {
        Ok(guard) => Some(guard),
        Err(TryLockError::WouldBlock) => None,
        Err(TryLockError::Poisoned(poisoned)) => {
            m.clear_poison();
            WORKER_COMMAND_QUEUE_POISON_RECOVERIES.fetch_add(1, Ordering::Relaxed);
            eprintln!(
                "xpf-ha: worker command queue mutex poisoned; recovering committed queue and clearing poison"
            );
            Some(poisoned.into_inner())
        }
    }
}

#[cfg(test)]
#[path = "worker_queue_tests.rs"]
mod tests;
