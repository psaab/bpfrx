// #869: per-worker busy/idle runtime accounting.
//
// The AF_XDP worker loop publishes cumulative time spent in three states
// (Active, IdleSpin, IdleBlock) plus loop counts and sampled thread CPU
// time.  Operators use this to tell compute saturation apart from spin
// waste apart from genuine idle headroom apart from VM-scheduling loss.
//
// Hot-path design:
//
//   1. At each loop iteration's top the worker computes
//      `delta = now - last_loop_ns` and attributes the delta to the
//      PREVIOUS loop's classified state.  No per-packet work.
//
//   2. After `did_work` is known and the worker has decided whether it
//      will take the active / spin / block branch, the state for the
//      next iteration is set.
//
//   3. Worker-local counters are pure u64 math.  They are copied into a
//      cacheline-isolated atomic struct only on a ~1s cadence (same
//      cadence as existing worker_heartbeats).  `CLOCK_THREAD_CPUTIME_ID`
//      is sampled on the same cadence, NOT per iteration.
//
//   4. All atomics use Ordering::Relaxed — these are diagnostic monotonic
//      counters, not synchronization primitives.

use std::sync::atomic::{AtomicU64, Ordering};

/// Classification applied to the previous worker-loop iteration.
/// Determines which counter the elapsed delta is added to.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WorkerRuntimeState {
    /// `did_work` returned true — the loop processed at least one ring
    /// or packet.
    Active,
    /// No useful work this iteration; worker stayed in the short-spin
    /// path (idle_iters <= IDLE_SPIN_ITERS).
    IdleSpin,
    /// No useful work this iteration; worker entered interrupt-mode
    /// `poll()` or `sleep()`.
    IdleBlock,
}

/// Per-worker cumulative counters, owned exclusively by the worker
/// thread.  No atomics here — the worker only contends with itself.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct WorkerRuntimeCounters {
    pub wall_ns: u64,
    pub active_ns: u64,
    pub idle_spin_ns: u64,
    pub idle_block_ns: u64,
    pub thread_cpu_ns: u64,
    pub work_loops: u64,
    pub idle_loops: u64,
}

/// Cacheline-isolated atomic publish slot.  The worker copies its local
/// counters here on a ~1s cadence; the coordinator (or any status reader)
/// snapshots with `Ordering::Relaxed`.  One Atomic per field keeps
/// snapshots consistent within a field — cross-field tearing is
/// acceptable for diagnostic counters.
#[repr(align(64))]
pub(crate) struct WorkerRuntimeAtomics {
    pub wall_ns: AtomicU64,
    pub active_ns: AtomicU64,
    pub idle_spin_ns: AtomicU64,
    pub idle_block_ns: AtomicU64,
    pub thread_cpu_ns: AtomicU64,
    pub work_loops: AtomicU64,
    pub idle_loops: AtomicU64,
    pub tid: AtomicU64,
    /// Cacheline padding after the atomics so that adjacent workers in
    /// a `Vec<WorkerRuntimeAtomics>` don't false-share.
    _pad: [u8; 0],
}

impl WorkerRuntimeAtomics {
    pub fn new() -> Self {
        Self {
            wall_ns: AtomicU64::new(0),
            active_ns: AtomicU64::new(0),
            idle_spin_ns: AtomicU64::new(0),
            idle_block_ns: AtomicU64::new(0),
            thread_cpu_ns: AtomicU64::new(0),
            work_loops: AtomicU64::new(0),
            idle_loops: AtomicU64::new(0),
            tid: AtomicU64::new(0),
            _pad: [],
        }
    }

    /// Publish a full snapshot of the worker's local counters.  Called
    /// on the ~1s publish cadence; NOT called per iteration.
    pub fn publish(&self, c: &WorkerRuntimeCounters) {
        self.wall_ns.store(c.wall_ns, Ordering::Relaxed);
        self.active_ns.store(c.active_ns, Ordering::Relaxed);
        self.idle_spin_ns.store(c.idle_spin_ns, Ordering::Relaxed);
        self.idle_block_ns.store(c.idle_block_ns, Ordering::Relaxed);
        self.thread_cpu_ns.store(c.thread_cpu_ns, Ordering::Relaxed);
        self.work_loops.store(c.work_loops, Ordering::Relaxed);
        self.idle_loops.store(c.idle_loops, Ordering::Relaxed);
    }

    /// Snapshot for status readers.  Not atomic across fields — each
    /// field is `Relaxed`-loaded individually.
    pub fn snapshot(&self) -> WorkerRuntimeCounters {
        WorkerRuntimeCounters {
            wall_ns: self.wall_ns.load(Ordering::Relaxed),
            active_ns: self.active_ns.load(Ordering::Relaxed),
            idle_spin_ns: self.idle_spin_ns.load(Ordering::Relaxed),
            idle_block_ns: self.idle_block_ns.load(Ordering::Relaxed),
            thread_cpu_ns: self.thread_cpu_ns.load(Ordering::Relaxed),
            work_loops: self.work_loops.load(Ordering::Relaxed),
            idle_loops: self.idle_loops.load(Ordering::Relaxed),
        }
    }

    pub fn set_tid(&self, tid: u64) {
        self.tid.store(tid, Ordering::Relaxed);
    }

    pub fn tid(&self) -> u64 {
        self.tid.load(Ordering::Relaxed)
    }
}

impl Default for WorkerRuntimeAtomics {
    fn default() -> Self {
        Self::new()
    }
}

/// Sample CLOCK_THREAD_CPUTIME_ID for the calling thread.  Returns 0 on
/// syscall failure — diagnostic counters treat that as "no sample this
/// cadence" rather than propagating the error.
pub(crate) fn sample_thread_cpu_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: clock_gettime with a valid clock id + writable timespec
    // is defined behavior.
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut ts) };
    if rc != 0 {
        return 0;
    }
    (ts.tv_sec as u64).saturating_mul(1_000_000_000) + (ts.tv_nsec as u64)
}

/// Return the calling thread's kernel TID (`gettid`) as u64.  Used in
/// status output so operators can correlate telemetry with `top -H`.
/// Returns 0 on syscall failure so a wrapped -1 sentinel never escapes
/// to Prometheus or the CLI.
pub(crate) fn current_tid() -> u64 {
    // SAFETY: gettid is a pure syscall with no arguments.
    let tid = unsafe { libc::syscall(libc::SYS_gettid) };
    if tid < 0 {
        return 0;
    }
    tid as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_roundtrip() {
        let atomics = WorkerRuntimeAtomics::new();
        let c = WorkerRuntimeCounters {
            wall_ns: 10_000_000_000,
            active_ns: 9_700_000_000,
            idle_spin_ns: 250_000_000,
            idle_block_ns: 50_000_000,
            thread_cpu_ns: 9_950_000_000,
            work_loops: 1_234_567,
            idle_loops: 1_234,
        };
        atomics.publish(&c);
        let s = atomics.snapshot();
        assert_eq!(s.wall_ns, c.wall_ns);
        assert_eq!(s.active_ns, c.active_ns);
        assert_eq!(s.idle_spin_ns, c.idle_spin_ns);
        assert_eq!(s.idle_block_ns, c.idle_block_ns);
        assert_eq!(s.thread_cpu_ns, c.thread_cpu_ns);
        assert_eq!(s.work_loops, c.work_loops);
        assert_eq!(s.idle_loops, c.idle_loops);
    }

    #[test]
    fn counters_default_zero() {
        let c: WorkerRuntimeCounters = Default::default();
        assert_eq!(c.wall_ns, 0);
        assert_eq!(c.active_ns, 0);
        assert_eq!(c.idle_spin_ns, 0);
        assert_eq!(c.idle_block_ns, 0);
        assert_eq!(c.thread_cpu_ns, 0);
        assert_eq!(c.work_loops, 0);
        assert_eq!(c.idle_loops, 0);
    }

    #[test]
    fn cpu_sample_is_monotonic_or_zero() {
        let a = sample_thread_cpu_ns();
        // busy wait briefly
        let until = std::time::Instant::now() + std::time::Duration::from_millis(5);
        let mut _acc = 0u64;
        while std::time::Instant::now() < until {
            _acc = _acc.wrapping_add(1);
        }
        let b = sample_thread_cpu_ns();
        // Zero is the syscall-failure sentinel; only assert monotonicity
        // when both samples succeeded.
        if a != 0 && b != 0 {
            assert!(b >= a, "thread cpu time must be monotonic: a={a} b={b}");
        }
    }
}
