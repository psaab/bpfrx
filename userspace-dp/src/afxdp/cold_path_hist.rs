//! #1612 step-3: cold-path latency histogram primitives.
//!
//! This module provides the math + helpers consumed by
//! `worker_cold_path.rs` (counter aggregation) and the cold-path
//! sampling site in `poll_descriptor/mod.rs`. Hot-path callers see:
//!
//! - `sample_tsc_start() -> u64` / `sample_tsc_end() -> u64` —
//!   asymmetric TSC read pair: start does `LFENCE; RDTSCP`, end does
//!   `RDTSCP; LFENCE`, both with `compiler_fence` brackets. Per
//!   Intel SDM §17.17 measurement-window recipe. Wrapper baseline
//!   ~25-40 ns on the loss cluster. (Codex code-r1 finding 1 +
//!   Copilot code-r1: the prior `sample_tsc()` alias was removed
//!   to prevent foot-gun usage at the end of a window.)
//! - `bucket_index_for_ns_24(ns)` — branchless 24-bucket select. Same
//!   formula family as `bucket_index_for_ns` at `umem/mod.rs:244`;
//!   only the upper clamp changes (`.min(23)` vs `.min(15)`). Codex
//!   plan-r1 finding 3 pinned the exact formula.
//! - `splitmix64(x) -> u64` and `zone_pair_slot(from, to)` — 16-slot
//!   per-zone-pair hash. Pinned via `POLICY_COLD_PATH_ZONE_PAIR_SLOTS
//!   == 16` const assertion.
//!
//! Slot collision detection lives at the harness side per plan §3.4
//! (v3): the dataplane keeps a `first_key` + `alias_seen` pair per
//! slot. The hot path records the first packed key seen, and flips
//! `alias_seen = true` on any subsequent sample with a different
//! key. The harness publication gate excludes slots with
//! `alias_seen == true`. v1/v2 used `keys_xor` but Codex r2 proved
//! a false-pass mode (count(K) odd + count(L) even leaves
//! `keys_xor == K`), so v3 retires XOR for first_key + alias_seen.

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering, compiler_fence};

/// Number of histogram buckets per zone-pair slot.
///
/// Pinned at 24 — bucket 0 covers `[0, 1024)` ns, bucket 23 saturates
/// at any `ns ≥ 2^32` ≈ 4.295 s.
pub(in crate::afxdp) const POLICY_COLD_PATH_HIST_BUCKETS: usize = 24;
const _: () = assert!(POLICY_COLD_PATH_HIST_BUCKETS == 24);

/// Number of per-zone-pair slots in the histogram.
///
/// Pinned at 16 (4-bit splitmix mask). The cluster's active zone-pair
/// set may exceed 16, in which case the `first_key + alias_seen`
/// collision detector triggers and the harness excludes aliased
/// slots from publication (plan §3.4).
pub(in crate::afxdp) const POLICY_COLD_PATH_ZONE_PAIR_SLOTS: usize = 16;
const _: () = assert!(POLICY_COLD_PATH_ZONE_PAIR_SLOTS == 16);
const _: () = assert!(POLICY_COLD_PATH_ZONE_PAIR_SLOTS.is_power_of_two());

/// Slot index mask = `POLICY_COLD_PATH_ZONE_PAIR_SLOTS - 1`.
pub(in crate::afxdp) const ZONE_PAIR_SLOT_MASK: u64 =
    (POLICY_COLD_PATH_ZONE_PAIR_SLOTS - 1) as u64;

/// 24-bucket power-of-two ns histogram bucket selector. Branchless.
///
/// Same math family as `bucket_index_for_ns` at
/// `userspace-dp/src/afxdp/umem/mod.rs:244`; only the upper clamp
/// changes from 15 → 23. Bucket 0 covers `[0, 1024)` ns; bucket[i]
/// for i ∈ [1, 22] covers `[2^(9+i), 2^(10+i))` ns; bucket 23
/// saturates at any `ns ≥ 2^32` ≈ 4.295 s.
#[inline]
pub(in crate::afxdp) fn bucket_index_for_ns_24(ns: u64) -> usize {
    let clz = (ns | 1).leading_zeros() as i32;
    let b = (54 - clz).max(0) as usize;
    b.min(POLICY_COLD_PATH_HIST_BUCKETS - 1)
}

/// 64-bit splitmix scrambler. Single-step variant used to hash a
/// packed `(from_zone_id, to_zone_id)` key into a 4-bit slot index.
///
/// Same constants as the public splitmix64 (Steele/Vigna), one
/// xor-shift-multiply round; sufficient avalanche for the 16-slot
/// pigeonhole. NOT a cryptographic hash.
#[inline]
pub(in crate::afxdp) fn splitmix64(x: u64) -> u64 {
    let mut z = x.wrapping_add(0x9E3779B97F4A7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
    z ^ (z >> 31)
}

/// Pack zone IDs into a u64 key suitable for hashing or comparison.
///
/// **Injective encoding** (Codex r3 finding 1): `+ 1` instead of `| 1`
/// — `| 1` collapses adjacent `to_zone_id` values that share the same
/// odd parity into the same key (e.g. `(1,2)` and `(1,3)` both become
/// `65539` under `| 1`). The `+ 1` form preserves injectivity by
/// shifting the entire 32-bit packed key range by +1, which keeps
/// `(0, 0)` from collapsing to zero while keeping all other pairs
/// distinct.
///
/// The non-zero invariant is needed so that `first_key[slot] == 0`
/// remains a reliable "no sample yet" sentinel (plan §3.4).
#[inline]
pub(in crate::afxdp) fn zone_pair_packed_key(from_zone_id: u16, to_zone_id: u16) -> u64 {
    // (from << 16) | to fits in 32 bits and is injective over distinct
    // (u16, u16) pairs. Adding 1 keeps zero free as the "no sample"
    // sentinel without breaking injectivity.
    (((from_zone_id as u64) << 16) | (to_zone_id as u64)) + 1
}

/// Map a `(from_zone_id, to_zone_id)` pair to a slot index in
/// `[0, POLICY_COLD_PATH_ZONE_PAIR_SLOTS)`.
#[inline]
pub(in crate::afxdp) fn zone_pair_slot(from_zone_id: u16, to_zone_id: u16) -> usize {
    let key = zone_pair_packed_key(from_zone_id, to_zone_id);
    (splitmix64(key) & ZONE_PAIR_SLOT_MASK) as usize
}

/// Read the TSC at the **start** of a measurement window via
/// `LFENCE; RDTSCP` per Intel SDM §17.17.
///
/// Recipe rationale (Codex code-r1 finding 1):
/// - Leading `compiler_fence(SeqCst)` prevents rustc from reordering
///   prior stores past the LFENCE.
/// - `_mm_lfence` drains the load buffer so any preceding load
///   (e.g. flow-cache key reads) commits before the TSC capture.
/// - `__rdtscp` partially serializes on the prior-completion side
///   (waits for all prior instructions to complete) and provides
///   the timestamp.
///
/// **Use `sample_tsc_end()` for the closing timestamp** — RDTSCP
/// alone does NOT prevent subsequent instructions from being
/// dispatched before its retirement, so the end side needs a
/// TRAILING `_mm_lfence()`.
///
/// Returns 0 on non-x86_64 builds; the caller should branch on the
/// `ClockSource` field before using the value.
#[inline]
#[cfg(target_arch = "x86_64")]
pub(in crate::afxdp) fn sample_tsc_start() -> u64 {
    compiler_fence(Ordering::SeqCst);
    unsafe { core::arch::x86_64::_mm_lfence() };
    let mut _aux: u32 = 0;
    let tsc = unsafe { core::arch::x86_64::__rdtscp(&mut _aux) };
    compiler_fence(Ordering::SeqCst);
    tsc
}

/// Read the TSC at the **end** of a measurement window via
/// `RDTSCP; LFENCE` per Intel SDM §17.17.
///
/// Codex code-r1 finding 1 fix: the end side needs a **hardware**
/// `_mm_lfence` AFTER `__rdtscp` to prevent subsequent instructions
/// (e.g. histogram-bucket updates) from being dispatched before the
/// timestamp read retires. A `compiler_fence(SeqCst)` only keeps the
/// compiler honest; aggressive OoO cores (Skylake-X / Ice Lake /
/// Sapphire Rapids) can still hardware-reorder. Wrapper-baseline
/// calibration cannot absorb this — calibration subtracts constant
/// cost, not variable ordering noise.
///
/// Returns 0 on non-x86_64 builds.
#[inline]
#[cfg(target_arch = "x86_64")]
pub(in crate::afxdp) fn sample_tsc_end() -> u64 {
    compiler_fence(Ordering::SeqCst);
    let mut _aux: u32 = 0;
    let tsc = unsafe { core::arch::x86_64::__rdtscp(&mut _aux) };
    unsafe { core::arch::x86_64::_mm_lfence() };
    compiler_fence(Ordering::SeqCst);
    tsc
}

// Copilot code-r1 + Codex code-r1 finding 1: the prior `sample_tsc()`
// alias has been REMOVED to avoid a foot-gun where callers using it
// as an end timestamp would silently skip the trailing `_mm_lfence()`
// required by Intel SDM §17.17. All call sites must now explicitly
// use `sample_tsc_start()` (LFENCE; RDTSCP) at the START of a window
// and `sample_tsc_end()` (RDTSCP; LFENCE) at the END. Tests updated.

#[inline]
#[cfg(not(target_arch = "x86_64"))]
pub(in crate::afxdp) fn sample_tsc_start() -> u64 {
    0
}

#[inline]
#[cfg(not(target_arch = "x86_64"))]
pub(in crate::afxdp) fn sample_tsc_end() -> u64 {
    0
}

/// Per-worker clock source for cold-path latency sampling.
///
/// Worker startup probes `/proc/cpuinfo` for ALL THREE flags
/// `constant_tsc + nonstop_tsc + rdtscp` (Codex code-r1 finding 2:
/// the first two attest TSC stability; the third attests the
/// instruction is legal — x86_64 mandates SSE2 but NOT RDTSCP)
/// AND `/sys/devices/system/clocksource/clocksource0/current_clocksource
/// == tsc`. If ALL FOUR pass, `Tsc` is selected; otherwise
/// `ClockGettime` fallback. The harness gates Scale Target table
/// publication on every worker reporting `Tsc`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::afxdp) enum ClockSource {
    /// TSC unavailable, fall back to `clock_gettime(CLOCK_MONOTONIC_RAW)`.
    ClockGettime = 2,
    /// Invariant TSC available, `rdtscp` is used.
    Tsc = 1,
    /// Unset (worker not yet calibrated).
    Unset = 0,
}

impl ClockSource {
    #[inline]
    pub(in crate::afxdp) fn as_u8(self) -> u8 {
        self as u8
    }

    #[inline]
    pub(in crate::afxdp) fn from_u8(v: u8) -> Self {
        match v {
            1 => ClockSource::Tsc,
            2 => ClockSource::ClockGettime,
            _ => ClockSource::Unset,
        }
    }

    pub(in crate::afxdp) fn as_str(self) -> &'static str {
        match self {
            ClockSource::Tsc => "tsc",
            ClockSource::ClockGettime => "clock_gettime",
            ClockSource::Unset => "",
        }
    }
}

/// Probe the host for TSC invariance + RDTSCP availability. Returns
/// `Tsc` only if ALL THREE conditions hold:
/// - `/proc/cpuinfo` reports `constant_tsc` AND `nonstop_tsc` AND
///   `rdtscp` (Codex code-r1 finding 2: the first two attest TSC
///   stability; `rdtscp` attests the INSTRUCTION itself is legal —
///   x86_64 mandates SSE2 but NOT rdtscp; #UD on missing).
/// - `/sys/devices/system/clocksource/clocksource0/current_clocksource
///   == tsc` (kernel agrees TSC is usable as the active clocksource).
/// Otherwise `ClockGettime` — the sampler will skip RDTSCP entirely
/// and the harness will TSC-gate the run out of the published table.
///
/// Called once per worker at thread spawn AFTER `pthread_setaffinity_np`
/// has pinned the worker to its core (Claude SMR r1 NIT 2). The probe is
/// conservative: it only enables `Tsc` when every `/proc/cpuinfo` block
/// reports `constant_tsc`, `nonstop_tsc`, and `rdtscp`.
pub(in crate::afxdp) fn probe_clock_source() -> ClockSource {
    #[cfg(target_arch = "x86_64")]
    {
        let cpuinfo_ok = std::fs::read_to_string("/proc/cpuinfo")
            .map(|s| {
                // Codex code-r1 finding 2: rdtscp instruction support
                // is NOT implied by constant_tsc/nonstop_tsc. Check it
                // explicitly. Linux exposes the CPUID rdtscp feature
                // flag as the literal token "rdtscp" in the flags line.
                //
                // AGY code-r1 NIT 2: parse the `flags` line as
                // whitespace-separated tokens rather than a free-text
                // substring grep. A virtualized hypervisor or guest
                // admin who sets a custom CPU model name containing
                // any of these tokens would otherwise yield a false-
                // positive probe.
                let mut saw_any_block = false;
                for block in s.split("\n\n").filter(|b| !b.trim().is_empty()) {
                    saw_any_block = true;
                    let flags_line = block
                        .lines()
                        .find(|l| {
                            let trimmed = l.trim_start();
                            trimmed.starts_with("flags")
                                || trimmed.starts_with("Features")
                        })
                        .and_then(|l| l.split(':').nth(1));
                    let Some(flags) = flags_line else {
                        return false;
                    };
                    let tokens: std::collections::HashSet<&str> =
                        flags.split_ascii_whitespace().collect();
                    if !(tokens.contains("constant_tsc")
                        && tokens.contains("nonstop_tsc")
                        && tokens.contains("rdtscp"))
                    {
                        return false;
                    }
                }
                saw_any_block
            })
            .unwrap_or(false);
        let clocksource_ok = std::fs::read_to_string(
            "/sys/devices/system/clocksource/clocksource0/current_clocksource",
        )
        .map(|s| s.trim() == "tsc")
        .unwrap_or(false);
        if cpuinfo_ok && clocksource_ok {
            return ClockSource::Tsc;
        }
    }
    ClockSource::ClockGettime
}

/// Q32 fixed-point `ns_per_tsc_tick` multiplier.
///
/// `delta_ns ≈ (delta_tsc * ns_per_tsc_q32) >> 32`. Computed once at
/// worker startup by measuring TSC ticks against `std::time::Instant`
/// over a 10 ms calibration window (Codex code-r1 finding 3: prior
/// docstring claimed `CLOCK_MONOTONIC_RAW` but the impl uses Rust's
/// `Instant` which is `CLOCK_MONOTONIC`, not raw). For a one-shot
/// calibration on a constant-tsc invariant host the distinction is
/// not measurable; we use `Instant` for portability + no external
/// libc surface.
pub(in crate::afxdp) fn calibrate_ns_per_tsc_q32() -> u64 {
    #[cfg(target_arch = "x86_64")]
    {
        // Copilot code-r2: guard against RDTSCP #UD on x86_64 hosts
        // that don't expose the CPUID rdtscp feature. The probe is
        // cheap (two file reads + token-set parse) and runs once per
        // worker startup; returning 0 here makes the caller's
        // ns_per_tsc_q32 zero, which downstream code treats as
        // "TSC unavailable, use clock_gettime fallback".
        if probe_clock_source() != ClockSource::Tsc {
            return 0;
        }
        use std::time::Instant;
        let start_tsc = sample_tsc_start();
        let start_inst = Instant::now();
        std::thread::sleep(std::time::Duration::from_millis(10));
        let end_inst = Instant::now();
        let end_tsc = sample_tsc_end();
        let elapsed_ns = end_inst.duration_since(start_inst).as_nanos() as u64;
        let elapsed_tsc = end_tsc.saturating_sub(start_tsc);
        if elapsed_tsc == 0 || elapsed_ns == 0 {
            return 0;
        }
        // ns_per_tsc_q32 = (elapsed_ns << 32) / elapsed_tsc
        //
        // Operator precedence trap (Codex r3 finding 2): `<<` binds
        // LOWER than `/` in Rust, so `(elapsed_ns as u128) << 32 /
        // (elapsed_tsc as u128)` parses as `elapsed_ns << (32 /
        // elapsed_tsc)`, not as the intended `(elapsed_ns << 32) /
        // elapsed_tsc`. Parenthesize the shift explicitly.
        (((elapsed_ns as u128) << 32) / (elapsed_tsc as u128)) as u64
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        0
    }
}

/// Per-worker wrapper-baseline calibration. Runs N=4096 rdtscp/rdtscp
/// pairs (back-to-back) and returns the **median** of the deltas in
/// ns. The median is robust against scheduler jitter; the calibration
/// runs after `pthread_setaffinity_np` has pinned the worker.
///
/// Returns 0 if TSC is unavailable on this target.
pub(in crate::afxdp) fn calibrate_wrapper_baseline_ns(ns_per_tsc_q32: u64) -> u64 {
    if ns_per_tsc_q32 == 0 {
        return 0;
    }
    // Copilot code-r2: same #UD guard as calibrate_ns_per_tsc_q32.
    // A non-zero ns_per_tsc_q32 from a malformed caller (e.g. unit
    // test passing 42) shouldn't bypass the RDTSCP availability gate.
    #[cfg(target_arch = "x86_64")]
    {
        if probe_clock_source() != ClockSource::Tsc {
            return 0;
        }
    }
    const N: usize = 4096;
    let mut deltas = Vec::with_capacity(N);
    for _ in 0..N {
        // Wrapper baseline measures the round-trip between a START
        // timestamp and an END timestamp — the same fence recipe the
        // hot path will use — so the calibration absorbs the correct
        // ordering cost (Codex code-r1 finding 1).
        let a = sample_tsc_start();
        let b = sample_tsc_end();
        deltas.push(b.saturating_sub(a));
    }
    deltas.sort_unstable();
    let median_tsc = deltas[N / 2];
    ((median_tsc as u128 * ns_per_tsc_q32 as u128) >> 32) as u64
}

/// Atomic-publish view of the per-worker cold-path histogram.
///
/// Lives alongside `WorkerRuntimeAtomics` in `worker_runtime.rs`
/// but with its own dedicated `cold_window_gen` field per Codex
/// plan-r1 finding 2 — the cold-path seqlock is INDEPENDENT of the
/// runtime seqlock because the runtime's even-flip only fires inside
/// the 60s window-rotation branch, while cold-path counters must
/// publish every ~1 s tick.
///
/// Publish protocol (every ~1 s; called from `publish()` regardless
/// of whether the 60s rotation branch fires):
///   1. `cold_window_gen.fetch_add(1, AcqRel)` (even → odd).
///   2. Relaxed-store 16 × 24 = 384 bucket counts + 16 × 4 = 64
///      metadata fields (sum_ns / samples / first_key / alias_seen).
///   3. `cold_window_gen.fetch_add(1, Release)` (odd → even).
///
/// Readers Acquire-load `cold_window_gen` (s1), Relaxed-load the
/// payload, `fence(Acquire)`, Relaxed-load `cold_window_gen` (s2).
/// If `s2 == s1` and even, the payload was observed within a single
/// committed epoch.
#[repr(align(64))]
pub(in crate::afxdp) struct WorkerColdPathAtomics {
    pub(in crate::afxdp) buckets: [[AtomicU64; POLICY_COLD_PATH_HIST_BUCKETS];
        POLICY_COLD_PATH_ZONE_PAIR_SLOTS],
    pub(in crate::afxdp) sum_ns: [AtomicU64; POLICY_COLD_PATH_ZONE_PAIR_SLOTS],
    pub(in crate::afxdp) samples: [AtomicU64; POLICY_COLD_PATH_ZONE_PAIR_SLOTS],
    /// v3: first packed zone-pair key seen in this slot during the
    /// current publish window. Zero = no sample yet.
    pub(in crate::afxdp) first_key: [AtomicU64; POLICY_COLD_PATH_ZONE_PAIR_SLOTS],
    /// v3: set true if any sample's packed key differs from
    /// `first_key`. Once set, stays set for the window. The harness
    /// publication gate excludes slots with `alias_seen = true`
    /// from Tables A1/A2 per plan §3.4 (Codex r2 finding 3).
    pub(in crate::afxdp) alias_seen: [AtomicBool; POLICY_COLD_PATH_ZONE_PAIR_SLOTS],
    /// Calibration: set once at worker startup. Outside the per-tick seqlock.
    pub(in crate::afxdp) ns_per_tsc_q32: AtomicU64,
    /// Calibration: set once at worker startup. Outside the per-tick seqlock.
    pub(in crate::afxdp) wrapper_ns_baseline: AtomicU64,
    /// Calibration: set once at worker startup. Outside the per-tick seqlock.
    pub(in crate::afxdp) clock_source: AtomicU8,
    /// Per-tick seqlock generation. Separate from
    /// `WorkerRuntimeAtomics.window_gen` per Codex r1 finding 2.
    pub(in crate::afxdp) cold_window_gen: AtomicU64,
}

impl Default for WorkerColdPathAtomics {
    fn default() -> Self {
        Self::new()
    }
}

impl WorkerColdPathAtomics {
    pub(in crate::afxdp) fn new() -> Self {
        Self {
            buckets: std::array::from_fn(|_| {
                std::array::from_fn(|_| AtomicU64::new(0))
            }),
            sum_ns: std::array::from_fn(|_| AtomicU64::new(0)),
            samples: std::array::from_fn(|_| AtomicU64::new(0)),
            first_key: std::array::from_fn(|_| AtomicU64::new(0)),
            alias_seen: std::array::from_fn(|_| AtomicBool::new(false)),
            ns_per_tsc_q32: AtomicU64::new(0),
            wrapper_ns_baseline: AtomicU64::new(0),
            clock_source: AtomicU8::new(ClockSource::Unset.as_u8()),
            cold_window_gen: AtomicU64::new(0),
        }
    }

    /// Set the calibration fields. Called once per worker after thread
    /// affinity is set; samples after this call use the calibrated
    /// multiplier.
    pub(in crate::afxdp) fn install_calibration(
        &self,
        ns_per_tsc_q32: u64,
        wrapper_ns_baseline: u64,
        clock_source: ClockSource,
    ) {
        self.ns_per_tsc_q32
            .store(ns_per_tsc_q32, Ordering::Relaxed);
        self.wrapper_ns_baseline
            .store(wrapper_ns_baseline, Ordering::Relaxed);
        self.clock_source
            .store(clock_source.as_u8(), Ordering::Relaxed);
    }

    /// Publish a full snapshot of the worker's local cold-path
    /// counters under the per-tick seqlock.
    pub(in crate::afxdp) fn publish_from_local(&self, local: &WorkerColdPathCounters) {
        // 1. Bump gen even → odd. AcqRel forbids subsequent Relaxed
        //    stores from being hoisted above this point.
        self.cold_window_gen.fetch_add(1, Ordering::AcqRel);
        // 2. Relaxed-store the payload (16 slots × 24 buckets = 384
        //    bucket stores + 16 × 4 metadata = 64; total 448 stores).
        for slot in 0..POLICY_COLD_PATH_ZONE_PAIR_SLOTS {
            for b in 0..POLICY_COLD_PATH_HIST_BUCKETS {
                self.buckets[slot][b].store(local.buckets[slot][b], Ordering::Relaxed);
            }
            self.sum_ns[slot].store(local.sum_ns[slot], Ordering::Relaxed);
            self.samples[slot].store(local.samples[slot], Ordering::Relaxed);
            self.first_key[slot].store(local.first_key[slot], Ordering::Relaxed);
            self.alias_seen[slot].store(local.alias_seen[slot], Ordering::Relaxed);
        }
        // 3. Bump gen odd → even with Release.
        self.cold_window_gen.fetch_add(1, Ordering::Release);
    }

    /// Snapshot for status readers. Seqlock protocol: Acquire-load
    /// `cold_window_gen` (s1), Relaxed-load the full payload, issue
    /// `fence(Acquire)` to seal the Relaxed loads, then Relaxed-load
    /// `cold_window_gen` (s2). If s1 and s2 are equal and even the
    /// payload is coherent.
    ///
    /// AGY code-r2 finding 2: returns `Option<WorkerColdPathCounters>`.
    /// `None` indicates the retry budget exhausted (caller should treat
    /// as "stale, try again next tick"); `Some(_)` is a coherent
    /// payload. Previously `snapshot()` returned `default()` on giveup,
    /// which a Prometheus scraper or the harness could not distinguish
    /// from a legitimately-empty worker, masking retry-starvation
    /// regimes under heavy publish contention.
    ///
    /// AGY code-r2 finding 2 (continued): the retry budget is now 128
    /// (up from 16) with an exponential `std::hint::spin_loop` backoff.
    /// For a 448-field payload at ~5 ns per Relaxed load, one publish
    /// cycle takes ~2.2 µs; 128 retries × spin_loop give the writer
    /// ~10-50 µs to publish before the reader gives up.
    pub(in crate::afxdp) fn snapshot(&self) -> Option<WorkerColdPathCounters> {
        const RETRY_BUDGET: u32 = 128;
        for attempt in 0..RETRY_BUDGET {
            let s1 = self.cold_window_gen.load(Ordering::Acquire);
            if s1 & 1 != 0 {
                // Adaptive backoff: spin a few cycles on early
                // retries, longer on later ones to give a contested
                // writer time to complete its publish cycle.
                for _ in 0..(1u32 << (attempt.min(6))) {
                    std::hint::spin_loop();
                }
                continue;
            }
            let mut out = WorkerColdPathCounters::default();
            for slot in 0..POLICY_COLD_PATH_ZONE_PAIR_SLOTS {
                for b in 0..POLICY_COLD_PATH_HIST_BUCKETS {
                    out.buckets[slot][b] = self.buckets[slot][b].load(Ordering::Relaxed);
                }
                out.sum_ns[slot] = self.sum_ns[slot].load(Ordering::Relaxed);
                out.samples[slot] = self.samples[slot].load(Ordering::Relaxed);
                out.first_key[slot] = self.first_key[slot].load(Ordering::Relaxed);
                out.alias_seen[slot] = self.alias_seen[slot].load(Ordering::Relaxed);
            }
            // Seal Relaxed loads before s2 re-check.
            std::sync::atomic::fence(Ordering::Acquire);
            let s2 = self.cold_window_gen.load(Ordering::Relaxed);
            if s2 == s1 {
                out.ns_per_tsc_q32 = self.ns_per_tsc_q32.load(Ordering::Relaxed);
                out.wrapper_ns_baseline = self.wrapper_ns_baseline.load(Ordering::Relaxed);
                out.clock_source = ClockSource::from_u8(self.clock_source.load(Ordering::Relaxed));
                return Some(out);
            }
            std::hint::spin_loop();
        }
        // Retry budget exhausted — return None so the caller can
        // distinguish from a legitimately-empty worker (AGY code-r2
        // finding 2). A Prometheus scraper sees this as "stale", not
        // as "all zeros".
        None
    }
}

/// Worker-local mutable cold-path counters. Touched only by the
/// owning worker thread on the hot path. The owner writes
/// non-atomically; the publisher (same thread) `store(Relaxed)` into
/// `WorkerColdPathAtomics` under the cold_window_gen seqlock.
#[derive(Clone, Debug)]
pub(in crate::afxdp) struct WorkerColdPathCounters {
    pub(in crate::afxdp) buckets:
        [[u64; POLICY_COLD_PATH_HIST_BUCKETS]; POLICY_COLD_PATH_ZONE_PAIR_SLOTS],
    pub(in crate::afxdp) sum_ns: [u64; POLICY_COLD_PATH_ZONE_PAIR_SLOTS],
    pub(in crate::afxdp) samples: [u64; POLICY_COLD_PATH_ZONE_PAIR_SLOTS],
    /// v3 alias detector: first packed zone-pair key per slot (0 = none).
    pub(in crate::afxdp) first_key: [u64; POLICY_COLD_PATH_ZONE_PAIR_SLOTS],
    /// v3 alias detector: monotonic per-slot flag set when a sample
    /// arrives with a key different from `first_key`. Once true,
    /// stays true for the publish window.
    pub(in crate::afxdp) alias_seen: [bool; POLICY_COLD_PATH_ZONE_PAIR_SLOTS],
    /// v3 sample-phase counter: worker-local monotonic counter
    /// incremented on every session-miss path through the policy-
    /// eval site. NOT a per-poll BatchCounters accumulator. The
    /// sample gate is `phase & sample_mask == 0`.
    pub(in crate::afxdp) sample_phase: u64,
    /// Mirror of `WorkerColdPathAtomics.ns_per_tsc_q32` after snapshot;
    /// not used on the hot path.
    pub(in crate::afxdp) ns_per_tsc_q32: u64,
    pub(in crate::afxdp) wrapper_ns_baseline: u64,
    pub(in crate::afxdp) clock_source: ClockSource,
}

impl Default for WorkerColdPathCounters {
    fn default() -> Self {
        Self {
            buckets: [[0u64; POLICY_COLD_PATH_HIST_BUCKETS]; POLICY_COLD_PATH_ZONE_PAIR_SLOTS],
            sum_ns: [0u64; POLICY_COLD_PATH_ZONE_PAIR_SLOTS],
            samples: [0u64; POLICY_COLD_PATH_ZONE_PAIR_SLOTS],
            first_key: [0u64; POLICY_COLD_PATH_ZONE_PAIR_SLOTS],
            alias_seen: [false; POLICY_COLD_PATH_ZONE_PAIR_SLOTS],
            sample_phase: 0,
            ns_per_tsc_q32: 0,
            wrapper_ns_baseline: 0,
            clock_source: ClockSource::Unset,
        }
    }
}

impl WorkerColdPathCounters {
    /// Hot-path-friendly sample record. Inlined to keep the call site
    /// in `poll_descriptor/mod.rs` cheap. NOT branchless — but the
    /// caller already gated on `sample_tag` so this fn is only invoked
    /// at the sampling rate (1-in-256 unbounded; 1-in-1 bounded).
    #[inline]
    pub(in crate::afxdp) fn record_sample(
        &mut self,
        from_zone_id: u16,
        to_zone_id: u16,
        delta_ns: u64,
    ) {
        let slot = zone_pair_slot(from_zone_id, to_zone_id);
        let bucket = bucket_index_for_ns_24(delta_ns);
        self.buckets[slot][bucket] = self.buckets[slot][bucket].saturating_add(1);
        self.sum_ns[slot] = self.sum_ns[slot].saturating_add(delta_ns);
        self.samples[slot] = self.samples[slot].saturating_add(1);
        // v3 alias detector: first_key + alias_seen (Codex r2 finding 3
        // retired the v1/v2 XOR-rolling design which false-passes on
        // count(K) odd + count(L) even).
        let key = zone_pair_packed_key(from_zone_id, to_zone_id);
        if self.first_key[slot] == 0 {
            self.first_key[slot] = key;
        } else if self.first_key[slot] != key {
            self.alias_seen[slot] = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_zero_covers_sub_1024_ns() {
        for ns in [0u64, 1, 100, 500, 1000, 1023] {
            assert_eq!(bucket_index_for_ns_24(ns), 0, "ns={ns}");
        }
    }

    #[test]
    fn bucket_one_starts_at_1024_ns() {
        assert_eq!(bucket_index_for_ns_24(1024), 1);
        assert_eq!(bucket_index_for_ns_24(2047), 1);
    }

    #[test]
    fn bucket_two_starts_at_2048_ns() {
        assert_eq!(bucket_index_for_ns_24(2048), 2);
        assert_eq!(bucket_index_for_ns_24(4095), 2);
    }

    #[test]
    fn bucket_23_saturates_at_2_pow_32_ns() {
        // Lower edge of bucket 23 is 2^(9+23) = 2^32.
        assert_eq!(bucket_index_for_ns_24(1u64 << 32), 23);
        // Upper saturation: anything ≥ 2^32 lands in bucket 23.
        assert_eq!(bucket_index_for_ns_24(u64::MAX), 23);
        assert_eq!(bucket_index_for_ns_24(1u64 << 33), 23);
        assert_eq!(bucket_index_for_ns_24(1u64 << 40), 23);
    }

    #[test]
    fn bucket_22_lower_edge_is_2_pow_31_ns() {
        assert_eq!(bucket_index_for_ns_24(1u64 << 31), 22);
        assert_eq!(bucket_index_for_ns_24((1u64 << 32) - 1), 22);
    }

    #[test]
    fn bucket_formula_matches_existing_16_bucket_below_saturation() {
        // Sanity: for ns up to 2^23, the 24-bucket formula matches the
        // 16-bucket bucket_index_for_ns (which clamps at 15). The 16-
        // bucket fn lives in umem; we re-implement the math here only
        // to verify equivalence in the shared subrange.
        for power in 10..=23u32 {
            let ns = 1u64 << power;
            let b24 = bucket_index_for_ns_24(ns);
            let clz = (ns | 1).leading_zeros() as i32;
            let b16 = ((54 - clz).max(0) as usize).min(15);
            // The two formulas agree until the 16-bucket fn clamps.
            let expected_unclamped = ((54 - clz).max(0) as usize).min(23);
            assert_eq!(b24, expected_unclamped, "ns=2^{power}");
            if expected_unclamped < 16 {
                assert_eq!(b16, b24);
            }
        }
    }

    #[test]
    fn splitmix64_avalanche_low_bits_distributes_zone_id_diagonal() {
        // Copilot code-r3: prior test comment claimed 'should produce
        // 16 distinct slots' which contradicted the actual >= 8
        // assertion. Birthday-paradox on 16 uniform throws into 16
        // bins gives ~10 distinct bins in expectation, never close
        // to 16. The assertion is a statistical sanity check that
        // splitmix is roughly uniform; the harness collision detector
        // (first_key + alias_seen) handles aliasing semantics.
        let mut slots = std::collections::HashSet::new();
        for i in 0..16u16 {
            let s = zone_pair_slot(i, i);
            slots.insert(s);
        }
        assert!(
            slots.len() >= 8,
            "splitmix avalanche too tight: only {} distinct slots out of 16 throws into 16 bins (slots={slots:?})",
            slots.len()
        );
    }

    #[test]
    fn zone_pair_packed_key_nonzero_for_zero_inputs() {
        // (0, 0) must not collapse to zero per plan §3.4 first_key/
        // alias_seen collision detection (zero is the "no sample"
        // sentinel).
        assert_ne!(zone_pair_packed_key(0, 0), 0);
        assert_eq!(zone_pair_packed_key(0, 0), 1);
    }

    #[test]
    fn zone_pair_packed_key_distinguishes_from_to() {
        assert_ne!(
            zone_pair_packed_key(1, 2),
            zone_pair_packed_key(2, 1),
            "(1,2) and (2,1) must hash to distinct packed keys"
        );
    }

    /// Codex r3 finding 1: `| 1` collapsed (1,2) and (1,3) to the
    /// same packed key, breaking injectivity. v3 fix uses `+ 1`
    /// instead. This test pins the injective semantics by exhaustively
    /// checking the small (8x8) zone-id box for distinct keys per
    /// distinct pair.
    #[test]
    fn zone_pair_packed_key_is_injective_over_small_box() {
        use std::collections::HashSet;
        let mut keys = HashSet::new();
        for f in 0..8u16 {
            for t in 0..8u16 {
                let k = zone_pair_packed_key(f, t);
                assert!(keys.insert(k), "duplicate packed key for ({f},{t}) -> {k}");
            }
        }
        assert_eq!(keys.len(), 8 * 8);
    }

    /// Codex r3 finding 1 explicit counter-example: (1,2) and (1,3)
    /// MUST have distinct packed keys; the v1/v2 `| 1` form collapsed
    /// them both to 65539.
    #[test]
    fn zone_pair_packed_key_distinguishes_adjacent_to_zone_ids() {
        let k12 = zone_pair_packed_key(1, 2);
        let k13 = zone_pair_packed_key(1, 3);
        assert_ne!(k12, k13, "(1,2)={k12} (1,3)={k13} — must be distinct (Codex r3 finding 1)");
    }

    #[test]
    fn clock_source_round_trip_u8() {
        for src in [ClockSource::Tsc, ClockSource::ClockGettime, ClockSource::Unset] {
            assert_eq!(ClockSource::from_u8(src.as_u8()), src);
        }
    }

    #[test]
    fn clock_source_as_str_stable_wire_contract() {
        assert_eq!(ClockSource::Tsc.as_str(), "tsc");
        assert_eq!(ClockSource::ClockGettime.as_str(), "clock_gettime");
        assert_eq!(ClockSource::Unset.as_str(), "");
    }

    #[test]
    fn record_sample_updates_all_fields() {
        let mut c = WorkerColdPathCounters::default();
        c.record_sample(1, 2, 1500);
        let slot = zone_pair_slot(1, 2);
        let bucket = bucket_index_for_ns_24(1500);
        assert_eq!(c.buckets[slot][bucket], 1);
        assert_eq!(c.sum_ns[slot], 1500);
        assert_eq!(c.samples[slot], 1);
        // v3 alias detector: first sample sets first_key, alias_seen
        // remains false.
        assert_eq!(c.first_key[slot], zone_pair_packed_key(1, 2));
        assert!(!c.alias_seen[slot]);
    }

    #[test]
    fn record_sample_same_key_twice_no_alias() {
        let mut c = WorkerColdPathCounters::default();
        c.record_sample(1, 2, 100);
        c.record_sample(1, 2, 100);
        let slot = zone_pair_slot(1, 2);
        // Two samples with the same key: first_key set, alias_seen still false.
        assert_eq!(c.first_key[slot], zone_pair_packed_key(1, 2));
        assert!(!c.alias_seen[slot]);
        assert_eq!(c.samples[slot], 2);
    }

    #[test]
    fn record_sample_detects_alias() {
        // Find two zone-pair keys that hash to the same slot.
        let mut collisions: Option<((u16, u16), (u16, u16))> = None;
        'outer: for a_from in 0..256u16 {
            for a_to in 0..256u16 {
                if a_from == 0 && a_to == 0 {
                    continue;
                }
                let slot_a = zone_pair_slot(a_from, a_to);
                for b_from in 0..256u16 {
                    for b_to in 0..256u16 {
                        if (b_from, b_to) == (a_from, a_to)
                            || (b_from == 0 && b_to == 0)
                        {
                            continue;
                        }
                        if zone_pair_slot(b_from, b_to) == slot_a {
                            collisions = Some(((a_from, a_to), (b_from, b_to)));
                            break 'outer;
                        }
                    }
                }
            }
        }
        let ((af, at), (bf, bt)) =
            collisions.expect("must find a slot collision in 256×256 zone-id subspace");
        let mut c = WorkerColdPathCounters::default();
        c.record_sample(af, at, 100);
        // first_key set, alias_seen false.
        let slot = zone_pair_slot(af, at);
        assert!(!c.alias_seen[slot]);
        c.record_sample(bf, bt, 200);
        // alias_seen MUST be true now (different key in same slot).
        assert!(c.alias_seen[slot], "alias detector must fire on slot collision");
    }

    #[test]
    fn record_sample_codex_r2_false_pass_counter_example() {
        // Codex r2 finding 3: with XOR-rolling, count(K)=odd + count(L)=even
        // leaves final keys_xor == K, false-passing the gate. v3 first_key
        // + alias_seen MUST detect this.
        let mut collisions: Option<((u16, u16), (u16, u16))> = None;
        'outer: for k_from in 1..32u16 {
            for k_to in 1..32u16 {
                let slot_k = zone_pair_slot(k_from, k_to);
                for l_from in 1..32u16 {
                    for l_to in 1..32u16 {
                        if (l_from, l_to) == (k_from, k_to) {
                            continue;
                        }
                        if zone_pair_slot(l_from, l_to) == slot_k {
                            collisions = Some(((k_from, k_to), (l_from, l_to)));
                            break 'outer;
                        }
                    }
                }
            }
        }
        let ((kf, kt), (lf, lt)) = collisions.expect("must find K/L collision in 1..32 space");
        let mut c = WorkerColdPathCounters::default();
        // count(K) = 3 (odd), count(L) = 2 (even).
        c.record_sample(kf, kt, 100);
        c.record_sample(kf, kt, 100);
        c.record_sample(kf, kt, 100);
        c.record_sample(lf, lt, 100);
        c.record_sample(lf, lt, 100);
        let slot = zone_pair_slot(kf, kt);
        // v3 alias_seen MUST be true (would have been false-passed by
        // the retired XOR-rolling design).
        assert!(c.alias_seen[slot], "alias_seen must fire on Codex r2 false-pass counter-example");
    }

    #[test]
    fn snapshot_roundtrip() {
        let atomics = WorkerColdPathAtomics::new();
        let mut local = WorkerColdPathCounters::default();
        local.record_sample(3, 5, 4000);
        local.record_sample(3, 5, 8000);
        atomics.install_calibration(42, 30, ClockSource::Tsc);
        atomics.publish_from_local(&local);
        let snap = atomics.snapshot().expect("single-thread snapshot must succeed");
        let slot = zone_pair_slot(3, 5);
        assert_eq!(snap.samples[slot], 2);
        assert_eq!(snap.sum_ns[slot], 12000);
        assert_eq!(snap.ns_per_tsc_q32, 42);
        assert_eq!(snap.wrapper_ns_baseline, 30);
        assert_eq!(snap.clock_source, ClockSource::Tsc);
    }

    /// Single-thread sequential publish + snapshot test. Verifies
    /// the seqlock writes/reads coherently across two consecutive
    /// publish-snapshot cycles on the same thread.
    ///
    /// Copilot code-r1: the prior test was named
    /// `snapshot_concurrent_publish_does_not_tear` but actually
    /// performed no concurrent writes. Renamed to reflect what it
    /// truly exercises. A separate `snapshot_under_concurrent_writer_*`
    /// test below covers the real cross-thread tear regime.
    #[test]
    fn snapshot_sequential_publish_roundtrip() {
        let atomics = std::sync::Arc::new(WorkerColdPathAtomics::new());
        let mut local = WorkerColdPathCounters::default();
        local.record_sample(7, 11, 12345);
        atomics.publish_from_local(&local);
        let snap1 = atomics.snapshot().expect("seq snapshot 1 must succeed");
        local.record_sample(7, 11, 67890);
        atomics.publish_from_local(&local);
        let snap2 = atomics.snapshot().expect("seq snapshot 2 must succeed");
        let slot = zone_pair_slot(7, 11);
        assert_eq!(snap1.samples[slot], 1);
        assert_eq!(snap2.samples[slot], 2);
    }

    /// AGY code-r2 finding 2: snapshot() now returns Option. Verify
    /// that an in-flight publish (odd cold_window_gen) is detected
    /// and the snapshot returns None on retry exhaustion — NOT a
    /// silently-zero result that the harness would mistake for an
    /// empty worker.
    #[test]
    fn snapshot_returns_none_on_perpetually_odd_gen() {
        use std::sync::atomic::Ordering as AOrd;
        let atomics = WorkerColdPathAtomics::new();
        // Pin the seqlock at an odd generation. The snapshot retry
        // loop should exhaust its budget and return None.
        atomics.cold_window_gen.fetch_add(1, AOrd::AcqRel);
        let snap = atomics.snapshot();
        assert!(
            snap.is_none(),
            "snapshot must return None when cold_window_gen is perpetually odd"
        );
    }

    /// Cross-thread tear test: spawn a writer thread that publishes
    /// in a tight loop while the main thread snapshots. Verifies the
    /// seqlock provably never returns a torn payload (samples[slot]
    /// must monotonically increase across snapshots, never decrease
    /// or wrap).
    ///
    /// Copilot code-r1: replaces the prior misnamed test that only
    /// did back-to-back same-thread publishes.
    #[test]
    fn snapshot_under_concurrent_writer_never_tears() {
        use std::sync::atomic::{AtomicBool, Ordering as AOrd};
        let atomics = std::sync::Arc::new(WorkerColdPathAtomics::new());
        let stop = std::sync::Arc::new(AtomicBool::new(false));
        let writer_atomics = atomics.clone();
        let writer_stop = stop.clone();
        let writer = std::thread::spawn(move || {
            let mut local = WorkerColdPathCounters::default();
            let mut count = 0u64;
            while !writer_stop.load(AOrd::Relaxed) {
                local.record_sample(3, 5, 1000 + (count & 0xff));
                writer_atomics.publish_from_local(&local);
                count += 1;
                // The production writer publishes at ~1 Hz cadence
                // (see worker_runtime.rs::publish). The test writer
                // is much faster — drop to ~10 kHz with a 100 µs
                // sleep so the reader has room to observe even-gen
                // snapshots within its 16-retry budget. Without
                // this, the writer keeps the seqlock perpetually
                // odd and every reader snapshot exhausts retries
                // → returns default(zero) → test fails the
                // max_samples > 0 sanity assertion (Codex code-r3
                // NIT: the weaker oracle would have falsely passed
                // by accepting all zeros).
                std::thread::sleep(std::time::Duration::from_micros(100));
            }
            count
        });
        // Give the writer time to spin up under parallel test load.
        // Without this, on a heavily contended test run the reader can
        // finish all 1000 snapshots before the writer publishes more
        // than a handful of times, which would fail the `writer_iters
        // > 10` sanity assertion below.
        std::thread::sleep(std::time::Duration::from_millis(20));
        // Reader: take 1000 snapshots, assert monotonic samples per
        // slot AND cross-field invariants (Codex code-r3 NIT: the
        // weaker oracle would pass even if every snapshot returned
        // default zero after retry-exhaustion).
        let slot = zone_pair_slot(3, 5);
        let mut last_samples = 0u64;
        let mut max_samples = 0u64;
        let mut at_least_one_observed_increase = false;
        let mut coherent_snapshots = 0u64;
        let mut retry_exhausted_snapshots = 0u64;
        for _ in 0..1000 {
            // AGY code-r2 finding 2: snapshot() returns Option<_>.
            // None means retry budget exhausted — NOT a tear. The
            // earlier oracle conflated these two regimes by checking
            // `samples` against a zero-default that retry-exhaustion
            // returned, producing false "seqlock tore" panics under
            // heavy contention. The correct oracle skips None
            // snapshots; tear detection runs only on coherent
            // (Some) snapshots.
            let Some(snap) = atomics.snapshot() else {
                retry_exhausted_snapshots += 1;
                continue;
            };
            coherent_snapshots += 1;
            let s = snap.samples[slot];
            // Tear-1: samples must be monotonic non-decreasing if the
            // seqlock is honoring epoch boundaries. We compare only
            // against the LAST COHERENT snapshot's samples; None
            // snapshots in between don't reset the monotonicity check.
            assert!(
                s >= last_samples,
                "samples regressed: {s} < {last_samples} — seqlock tore"
            );
            if s > last_samples {
                at_least_one_observed_increase = true;
            }
            // Tear-2: cross-field invariant — total bucket counts in
            // this slot MUST equal samples count. If the seqlock tore
            // and we observed samples from one epoch + buckets from
            // another, this invariant would fail.
            let bucket_sum: u64 = snap.buckets[slot].iter().sum();
            assert_eq!(
                bucket_sum, s,
                "torn epoch: samples={s} != bucket_sum={bucket_sum} for slot {slot}"
            );
            last_samples = s;
            max_samples = max_samples.max(s);
        }
        stop.store(true, AOrd::Relaxed);
        let writer_iters = writer.join().expect("writer thread panicked");
        // Sanity-1: at least one COHERENT snapshot must have been
        // nonzero. None counts as "stale, retry" and is excluded.
        assert!(
            max_samples > 0,
            "reader observed only zero samples across {coherent_snapshots} coherent and \
             {retry_exhausted_snapshots} retry-exhausted snapshots"
        );
        // Sanity-2: at least one snapshot must show an INCREASE over
        // the prior one, proving we actually observed publishes
        // arriving during the reader loop.
        assert!(
            at_least_one_observed_increase,
            "reader observed only the same samples value — seqlock contention may have masked all writes"
        );
        // Sanity-3: the writer did actually publish (proves we exercised
        // the concurrent path, not just an idle reader).
        assert!(
            writer_iters > 10,
            "writer only published {writer_iters} times — test did not exercise concurrency"
        );
        // Sanity-4: at least 10% of snapshots must have been coherent;
        // if EVERY snapshot exhausted retries the test is meaningless.
        assert!(
            coherent_snapshots >= 100,
            "only {coherent_snapshots}/1000 snapshots coherent — retry budget may be too low"
        );
    }

    #[test]
    fn sample_tsc_monotonic_within_thread() {
        // On x86_64 with constant_tsc, back-to-back rdtscp must be
        // monotonic non-decreasing. Gate on `probe_clock_source` per
        // Codex code-r2 NIT/portability: x86_64 does not imply
        // RDTSCP — a probe-fallback host would #UD on these
        // invocations.
        #[cfg(target_arch = "x86_64")]
        {
            if probe_clock_source() != ClockSource::Tsc {
                eprintln!("skipping sample_tsc_monotonic_within_thread: host lacks RDTSCP or invariant TSC");
                return;
            }
            let a = sample_tsc_start();
            let b = sample_tsc_end();
            let c = sample_tsc_start();
            let d = sample_tsc_end();
            assert!(
                b >= a && c >= b && d >= c,
                "tsc not monotonic: a={a} b={b} c={c} d={d}"
            );
        }
    }

    /// AGY code-r1 NIT 2: probe_clock_source must parse the `flags`
    /// line as tokens to avoid false-positives from CPU model names
    /// that contain the substring. We exercise the tokenizer in
    /// isolation here because probe_clock_source itself reads
    /// /proc/cpuinfo which is host-state-dependent.
    #[test]
    fn cpuinfo_tokenization_rejects_substring_false_positives() {
        // A pathological "model name" line that contains all three
        // tokens as substrings of the model name should NOT yield a
        // positive match if the actual flags line lacks them.
        let pathological = "\
model name\t: AMD constant_tsc-nonstop_tsc-rdtscp Special Edition\n\
flags\t\t: fpu vme de pse\n";
        let block = pathological.split("\n\n").next().unwrap();
        let flags_line = block
            .lines()
            .find(|l| {
                let t = l.trim_start();
                t.starts_with("flags") || t.starts_with("Features")
            })
            .and_then(|l| l.split(':').nth(1));
        let flags = flags_line.expect("flags line must exist in fixture");
        let tokens: std::collections::HashSet<&str> =
            flags.split_ascii_whitespace().collect();
        assert!(!tokens.contains("constant_tsc"));
        assert!(!tokens.contains("nonstop_tsc"));
        assert!(!tokens.contains("rdtscp"));
    }

    /// AGY code-r1 NIT 2: the positive case — a realistic flags line
    /// with all three tokens must be detected.
    #[test]
    fn cpuinfo_tokenization_accepts_realistic_flags_line() {
        let realistic = "\
processor\t: 0\n\
flags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov constant_tsc rep_good nopl nonstop_tsc cpuid pni rdtscp\n";
        let block = realistic.split("\n\n").next().unwrap();
        let flags_line = block
            .lines()
            .find(|l| {
                let t = l.trim_start();
                t.starts_with("flags") || t.starts_with("Features")
            })
            .and_then(|l| l.split(':').nth(1))
            .expect("flags line must exist");
        let tokens: std::collections::HashSet<&str> =
            flags_line.split_ascii_whitespace().collect();
        assert!(tokens.contains("constant_tsc"));
        assert!(tokens.contains("nonstop_tsc"));
        assert!(tokens.contains("rdtscp"));
    }

    /// Codex code-r1 finding 1: verify the start/end split exists and
    /// each variant returns a monotonic non-decreasing pair, matching
    /// the Intel SDM §17.17 measurement-window recipe.
    ///
    /// Gate on `probe_clock_source` per Codex code-r2 NIT/portability.
    #[test]
    fn sample_tsc_start_end_split_monotonic() {
        #[cfg(target_arch = "x86_64")]
        {
            if probe_clock_source() != ClockSource::Tsc {
                eprintln!("skipping sample_tsc_start_end_split_monotonic: host lacks RDTSCP or invariant TSC");
                return;
            }
            let a = sample_tsc_start();
            let b = sample_tsc_end();
            assert!(b >= a, "start={a} end={b} — not monotonic");
            // Two consecutive measurement windows; ensure each
            // start/end pair is monotonic and that the second start
            // is >= the first end (TSC is monotonic across the
            // intervening cycles).
            let c = sample_tsc_start();
            let d = sample_tsc_end();
            assert!(c >= b, "second_start={c} after first_end={b} — not monotonic");
            assert!(d >= c, "second start={c} end={d} — not monotonic");
        }
    }
}
