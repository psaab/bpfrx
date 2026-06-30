// Tests for afxdp/worker_queue.rs (#1807) — poison recovery on the
// per-worker Mutex<VecDeque<WorkerCommand>> command queues. Loaded as a
// sibling submodule via `#[path = "worker_queue_tests.rs"]` from
// worker_queue.rs.

use super::*;
use std::sync::Arc;
use std::sync::atomic::Ordering;

fn export_command(sequence: u64) -> WorkerCommand {
    WorkerCommand::ExportOwnerRGSessions {
        sequence,
        owner_rgs: vec![1],
    }
}

fn export_sequence(command: &WorkerCommand) -> u64 {
    match command {
        WorkerCommand::ExportOwnerRGSessions { sequence, .. } => *sequence,
        other => panic!("unexpected command {other:?}"),
    }
}

/// Poison `m` deterministically: a thread panics while holding the lock
/// and join() observes the panic, so the mutex is poisoned on return.
/// Same shape as the #1790 ha_tests regression.
fn poison(m: &Arc<Mutex<VecDeque<WorkerCommand>>>) {
    let to_poison = m.clone();
    let poisoner = std::thread::spawn(move || {
        let _guard = to_poison.lock().expect("lock before poisoning");
        panic!("poison worker command mutex");
    })
    .join();
    assert!(poisoner.is_err(), "poisoning thread must panic");
    assert!(m.is_poisoned(), "mutex must be poisoned");
}

#[test]
fn lock_recover_returns_committed_queue_and_clears_poison() {
    let m = Arc::new(Mutex::new(VecDeque::from([
        export_command(1),
        export_command(2),
    ])));
    poison(&m);
    let before = WORKER_COMMAND_QUEUE_POISON_RECOVERIES.load(Ordering::Relaxed);

    {
        let guard = lock_recover(&m);
        assert_eq!(
            guard.iter().map(export_sequence).collect::<Vec<_>>(),
            vec![1, 2],
            "recovered guard must expose the committed queue contents"
        );
    }
    // The counter is a process-global shared by every test in the
    // binary, so assert a relative bump rather than an absolute value.
    assert!(
        WORKER_COMMAND_QUEUE_POISON_RECOVERIES.load(Ordering::Relaxed) > before,
        "recovery must bump the poison-recovery counter"
    );

    // clear_poison verified: a subsequent PLAIN lock() succeeds — the
    // fast unpoisoned path is restored after one recovery.
    assert!(!m.is_poisoned(), "poison must be cleared after recovery");
    let plain = m.lock();
    assert!(plain.is_ok(), "plain lock() must be Ok after recovery");
    assert_eq!(plain.unwrap().len(), 2);
}

#[test]
fn try_lock_recover_preserves_wouldblock_skip_semantics() {
    let m = Mutex::new(VecDeque::from([export_command(7)]));
    let held = m.lock().expect("hold the lock");
    assert!(
        try_lock_recover(&m).is_none(),
        "WouldBlock must still read as None (skip), not a recovery"
    );
    drop(held);
    let guard = try_lock_recover(&m).expect("uncontended try_lock succeeds");
    assert_eq!(guard.len(), 1);
}

#[test]
fn try_lock_recover_recovers_and_clears_poison() {
    let m = Arc::new(Mutex::new(VecDeque::from([export_command(9)])));
    poison(&m);
    let before = WORKER_COMMAND_QUEUE_POISON_RECOVERIES.load(Ordering::Relaxed);

    {
        let guard = try_lock_recover(&m).expect("poisoned mutex must be recovered, not skipped");
        let sequences = guard.iter().map(export_sequence).collect::<Vec<_>>();
        assert_eq!(sequences, vec![9]);
    }
    assert!(WORKER_COMMAND_QUEUE_POISON_RECOVERIES.load(Ordering::Relaxed) > before);
    assert!(!m.is_poisoned(), "poison must be cleared after recovery");
    assert!(m.lock().is_ok(), "plain lock() must be Ok after recovery");
}

// Open question 6 from the plan: clear_poison under concurrent recovery.
// Two threads contend on a freshly poisoned mutex and drain it through
// lock_recover. The guards serialize, clear_poison is idempotent, and
// every queued command is processed exactly once (no double-processing,
// no loss).
#[test]
fn concurrent_recovery_processes_each_command_exactly_once() {
    const COMMANDS: u64 = 1000;
    let m = Arc::new(Mutex::new(
        (0..COMMANDS).map(export_command).collect::<VecDeque<_>>(),
    ));
    poison(&m);

    // Start barrier so both threads genuinely contend on the poisoned
    // mutex (Codex review on PR #1822: without it one thread can drain
    // everything before the other starts, proving only the final
    // no-loss/no-dup property, not contention-time behavior).
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let drain = |queue: Arc<Mutex<VecDeque<WorkerCommand>>>,
                 barrier: Arc<std::sync::Barrier>| {
        std::thread::spawn(move || {
            barrier.wait();
            let mut seen = Vec::new();
            loop {
                let mut guard = lock_recover(&queue);
                match guard.pop_front() {
                    Some(command) => seen.push(export_sequence(&command)),
                    None => break,
                }
                // Drop the guard each iteration (end of scope) so the
                // peer thread can interleave.
            }
            seen
        })
    };
    let a = drain(m.clone(), barrier.clone());
    let b = drain(m.clone(), barrier);
    let seen_a = a.join().expect("drain thread a");
    let seen_b = b.join().expect("drain thread b");

    // #3457: do NOT assert that BOTH threads pop at least one command. The
    // start Barrier guarantees both threads enter `lock_recover` on the
    // poisoned mutex simultaneously (the genuine recovery-time contention PR
    // #1822's review asked for), but it CANNOT guarantee balanced draining:
    // once the first recoverer clears the poison, whichever thread holds the
    // lock may drain the entire queue within a single scheduling quantum,
    // leaving its peer to observe an already-empty queue. Under CPU contention
    // (full test-suite load) that is the COMMON outcome — the prior
    // `!seen_a.is_empty() && !seen_b.is_empty()` assertion failed ~18/20 under
    // load — so an empty peer slice is a scheduler artifact, not a correctness
    // violation. The deterministic poison-recovery contract is exactly-once
    // processing with the poison cleared and the queue drained, asserted below.
    let mut all = seen_a;
    all.extend(seen_b);
    all.sort_unstable();
    assert_eq!(
        all,
        (0..COMMANDS).collect::<Vec<_>>(),
        "every command processed exactly once across both recovering threads"
    );
    assert!(!m.is_poisoned());
    assert!(m.lock().expect("plain lock after race").is_empty());
}
