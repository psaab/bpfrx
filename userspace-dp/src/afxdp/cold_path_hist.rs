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
//! - `bucket_index_for_ns_48(ns)` — #1635 log-linear 48-bucket select:
//!   32 linear 16-ns buckets over `[0, 512)` ns + 15 pow-2 buckets over
//!   `[512, 2^24)` ns + 1 saturate bucket. Fixes the #1622 F1
//!   bucket-0 resolution floor (a 5-10× p50 error at low rule counts).
//! - `ColdPathSlotMap` + `lookup_slot(map, from, to)` — #1635 DIRECT
//!   `(from_zone_id, to_zone_id) → slot` map (256 slots) built at
//!   config apply. Replaces the splitmix64 16-slot hash that collided
//!   at 88.2% with 8 active zone-pairs (#1622 F2).
//!
//! Each slot keeps a `first_key` + `builder_collision` pair (renamed
//! from `alias_seen` per AGY r1 [1.6]). With the direct map a
//! `builder_collision` should NEVER fire — it indicates the snapshot
//! builder produced two distinct keys for one slot and is treated as a
//! hard error in operator dashboards.

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering, compiler_fence};

/// Number of histogram buckets per zone-pair slot.
///
/// #1635: pinned at 48 (was 24). The layout is log-linear:
///   - 32 LINEAR buckets of 16-ns stride covering `[0, 512)` ns
///     (bucket `b` covers `[b*16, (b+1)*16)` for `0 ≤ b ≤ 31`).
///   - 15 EXPONENTIAL buckets covering `[512, 2^24)` ns
///     (bucket `32+i` covers `[2^(9+i), 2^(10+i))` for `0 ≤ i ≤ 14`).
///   - 1 SATURATE bucket (index 47) for `ns ≥ 2^24` (≈16.8 ms).
///
/// The linear band gives ~16-ns resolution in the operator-critical
/// 50-150 ns range that the old pow-2-from-0 layout collapsed into a
/// single 1024-ns bucket-0 (a 5-10× p50 reporting error). See #1622
/// PLAN-KILL finding F1.
pub(in crate::afxdp) const POLICY_COLD_PATH_HIST_BUCKETS: usize = 48;
const _: () = assert!(POLICY_COLD_PATH_HIST_BUCKETS == 48);

/// Number of LINEAR buckets at the low end (16-ns stride, `[0, 512)` ns).
pub(in crate::afxdp) const COLD_PATH_LINEAR_BUCKETS: usize = 32;
/// Linear-band stride in nanoseconds.
pub(in crate::afxdp) const COLD_PATH_LINEAR_STRIDE_NS: u64 = 16;
/// Pivot: first nanosecond value handled by the exponential band.
pub(in crate::afxdp) const COLD_PATH_PIVOT_NS: u64 =
    (COLD_PATH_LINEAR_BUCKETS as u64) * COLD_PATH_LINEAR_STRIDE_NS; // 512
const _: () = assert!(COLD_PATH_PIVOT_NS == 512);

/// Number of per-zone-pair slots in the histogram.
///
/// #1635: pinned at 256 (was 16). The slot map is now a DIRECT
/// `(from_zone_id, to_zone_id) → slot` assignment built at config
/// apply (see [`ColdPathSlotMap`]). 256 gives ~21× headroom over the
/// largest known deployment; wire cost is bounded by SPARSE
/// serialization (only slots with `samples > 0` ride the wire), so
/// the static cap does not impose a per-scrape byte cost.
pub(in crate::afxdp) const POLICY_COLD_PATH_ZONE_PAIR_SLOTS: usize = 256;
const _: () = assert!(POLICY_COLD_PATH_ZONE_PAIR_SLOTS == 256);

/// Maximum number of ASSIGNABLE slots. Slot index 255 (`u8::MAX`) is
/// never handed out — the accumulator arrays are 256 wide for alignment
/// and to keep slot indices identity-mapped, and reserving the top index
/// keeps a `u8` slot id unambiguous. Capacity is therefore 255 active
/// zone-pairs (~21× the largest known deployment). #3075: overflow past
/// this capacity (not zone-id magnitude) is the only `overflow_active`
/// trigger now that the slot map is keyed sparsely by the `(from, to)`
/// pair (`ColdPathSlotMap::slot_by_pair`) rather than a 65×65 flat table.
pub(in crate::afxdp) const COLD_PATH_ASSIGNABLE_SLOTS: usize =
    POLICY_COLD_PATH_ZONE_PAIR_SLOTS - 1;
const _: () = assert!(COLD_PATH_ASSIGNABLE_SLOTS == 255);

// #3075: the old 65×65 flat lookup table (`COLD_PATH_ZONE_DIM` /
// `cold_path_flat_index`, `from * 65 + to`) was removed. Zone ids are now
// stable name-hashes spanning [1,65533] (not sequential 1..MaxZones), so a
// dense table is infeasible and a flat index dropped every pair with an id
// ≥ 65 — silently dark-ing the #1635 histogram for every real config. The
// slot map is now keyed sparsely by the `(from, to)` pair itself
// (`ColdPathSlotMap::slot_by_pair`).

/// Wire/layout version stamped into the status payload (#1635).
pub(in crate::afxdp) const COLD_PATH_LAYOUT_VERSION: u32 = 3;

/// 48-bucket log-linear ns histogram bucket selector.
///
/// #1635 (replaces `bucket_index_for_ns_24`):
///   - `ns < 512`            → linear: `ns / 16` ∈ `[0, 32)`.
///   - `512 ≤ ns < 2^24`     → exponential: `32 + (floor(log2(ns)) - 9)`
///                             ∈ `[32, 47)`.
///   - `ns ≥ 2^24`           → saturate: `47`.
///
/// Branchless within each band; one predicate selects the band.
#[inline]
pub(in crate::afxdp) fn bucket_index_for_ns_48(ns: u64) -> usize {
    if ns < COLD_PATH_PIVOT_NS {
        // Linear band: 16-ns stride, indices [0, 32).
        (ns / COLD_PATH_LINEAR_STRIDE_NS) as usize
    } else {
        // Exponential band: floor(log2(ns)) ∈ [9, +) for ns ≥ 512.
        // log2 = 63 - clz(ns); bucket = 32 + (log2 - 9).
        let log2 = (63 - ns.leading_zeros()) as usize;
        let b = COLD_PATH_LINEAR_BUCKETS + (log2 - 9);
        b.min(POLICY_COLD_PATH_HIST_BUCKETS - 1)
    }
}

/// Inclusive upper boundary in nanoseconds for histogram bucket `idx`,
/// for the Prometheus `le` label. Mirrors [`bucket_index_for_ns_48`]:
///   - `idx < 32`        → `(idx + 1) * 16 - 1`  (15, 31, …, 511).
///   - `32 ≤ idx ≤ 46`   → `2^(10 + idx - 32) - 1` (1023, 2047, …).
///   - `idx ≥ 47`        → `u64::MAX` (rendered as `+Inf` on the wire).
#[inline]
pub(in crate::afxdp) fn bucket_upper_bound_ns_48(idx: usize) -> u64 {
    if idx < COLD_PATH_LINEAR_BUCKETS {
        (idx as u64 + 1) * COLD_PATH_LINEAR_STRIDE_NS - 1
    } else if idx >= POLICY_COLD_PATH_HIST_BUCKETS - 1 {
        u64::MAX
    } else {
        (1u64 << (10 + idx - COLD_PATH_LINEAR_BUCKETS)) - 1
    }
}

/// Pack zone IDs into a u64 key suitable for the slot-map `first_key`
/// collision sentinel. `+ 1` keeps `(0, 0)` from collapsing to the
/// zero "no sample yet" sentinel while preserving injectivity over
/// distinct `(u16, u16)` pairs (Codex r3 finding 1).
#[inline]
pub(in crate::afxdp) fn zone_pair_packed_key(from_zone_id: u16, to_zone_id: u16) -> u64 {
    (((from_zone_id as u64) << 16) | (to_zone_id as u64)) + 1
}

/// #1635: direct `(from_zone_id, to_zone_id) → slot` map built at
/// config-apply time. Replaces the splitmix64 16-slot hash that
/// collided at 88.2% with 8 active zone-pairs (birthday paradox), the
/// F2 finding in the #1622 PLAN-KILL.
///
/// Lookup is a sparse `(from, to) → slot` hash map (#3075: stable
/// name-hash zone ids span [1,65533], so the prior 65×65 flat table was
/// removed). A miss (pair absent) means no slot assigned (capacity
/// exhausted); the sample is dropped at the hot path.
///
/// `inverse[slot]` is the reverse map used by the status path to emit
/// per-zone-pair labels for the sparse wire encoding.
#[derive(Clone, Debug)]
pub(in crate::afxdp) struct ColdPathSlotMap {
    /// Sparse `(from_zone_id, to_zone_id) → slot` map (#3075). Replaces
    /// the old 65×65 flat table: stable name-hash ids span [1,65533], so
    /// a flat `from*65+to` index dropped every pair with an id ≥ 65. A
    /// pair absent from the map = no slot assigned.
    pub(in crate::afxdp) slot_by_pair: std::collections::HashMap<(u16, u16), u8>,
    /// `slot → Some((from, to))` for assigned slots, `None` for free.
    pub(in crate::afxdp) inverse: Vec<Option<(u16, u16)>>,
    /// True if some configured zone-pair could not be assigned a slot
    /// because the 255-slot capacity was exhausted.
    pub(in crate::afxdp) overflow_active: bool,
}

impl Default for ColdPathSlotMap {
    fn default() -> Self {
        Self::empty()
    }
}

impl ColdPathSlotMap {
    /// An empty map: every lookup misses.
    pub(in crate::afxdp) fn empty() -> Self {
        Self {
            slot_by_pair: std::collections::HashMap::new(),
            inverse: vec![None; POLICY_COLD_PATH_ZONE_PAIR_SLOTS],
            overflow_active: false,
        }
    }

    /// Build a direct slot map from a set of configured zone-pairs,
    /// optionally reusing a previous map's slot assignments so retained
    /// pairs keep their slot (and their accumulated histogram) across a
    /// config apply.
    ///
    /// Returns the new map plus the list of slots that received a NEW
    /// zone-pair (every Pass-2 assignment). The worker zeroes these
    /// slots' accumulators before recording into them so a slot never
    /// carries an EARLIER zone-pair's counts (plan §2.4 / F4).
    ///
    /// Codex code-r1 finding 1: zero-out MUST cover every newly-assigned
    /// slot, not just slots the *immediately previous* map showed as
    /// occupied. The worker-local accumulator can carry stale counts
    /// from ANY earlier config generation (e.g. A assigns slot 0, B
    /// frees it without reuse, C reassigns slot 0 — B's map shows slot 0
    /// free, but the worker never cleared A's counts). Zeroing a
    /// genuinely-fresh slot is a harmless no-op (it is already zero).
    ///
    /// `pairs` should be deduplicated and in a stable order (the caller
    /// passes a `BTreeSet`-derived `Vec`) so slot assignment is
    /// deterministic for a given config.
    pub(in crate::afxdp) fn build(
        previous: Option<&ColdPathSlotMap>,
        pairs: &[(u16, u16)],
    ) -> (Self, Vec<u8>) {
        let mut slot_by_pair: std::collections::HashMap<(u16, u16), u8> =
            std::collections::HashMap::with_capacity(pairs.len());
        let mut inverse: Vec<Option<(u16, u16)>> =
            vec![None; POLICY_COLD_PATH_ZONE_PAIR_SLOTS];
        let mut used = [false; POLICY_COLD_PATH_ZONE_PAIR_SLOTS];
        let mut slots_to_zero: Vec<u8> = Vec::new();
        let mut overflow_active = false;

        // Pass 1: retain slot assignments for pairs that survive from
        // the previous map (so their accumulated histogram is kept).
        let mut pending: Vec<(u16, u16)> = Vec::with_capacity(pairs.len());
        for &(from, to) in pairs {
            // #3075: every (u16, u16) pair is representable — the stable
            // name-hash id space [1,65533] is keyed sparsely by the pair
            // itself, so there is no id-magnitude "unrepresentable" case.
            // `overflow_active` is set only when the SLOT capacity is
            // exhausted (Pass 2).
            let retained = previous.and_then(|p| {
                let s = p.slot_by_pair.get(&(from, to)).copied()?;
                if p.inverse[s as usize] == Some((from, to)) {
                    Some(s)
                } else {
                    None
                }
            });
            match retained {
                Some(s) => {
                    used[s as usize] = true;
                    inverse[s as usize] = Some((from, to));
                    slot_by_pair.insert((from, to), s);
                }
                None => pending.push((from, to)),
            }
        }

        // Pass 2: assign the lowest free slot to each new pair. EVERY
        // newly-assigned slot is queued for zero-out (Codex finding 1) —
        // the worker-local accumulator may carry stale counts from an
        // earlier generation regardless of what `previous` shows.
        let mut next_free = 0usize;
        for &(from, to) in &pending {
            while next_free < COLD_PATH_ASSIGNABLE_SLOTS && used[next_free] {
                next_free += 1;
            }
            if next_free >= COLD_PATH_ASSIGNABLE_SLOTS {
                overflow_active = true;
                break;
            }
            let s = next_free;
            used[s] = true;
            inverse[s] = Some((from, to));
            slot_by_pair.insert((from, to), s as u8);
            // Queue zero-out for every newly-assigned slot when a
            // PREVIOUS map existed — the worker may have accumulated
            // counts for an earlier pair in this slot during any prior
            // generation (Codex finding 1). On the very first build
            // (previous == None) the worker's accumulators are still
            // default-zero, so no zero-out is needed.
            if previous.is_some() {
                slots_to_zero.push(s as u8);
            }
        }

        (
            Self {
                slot_by_pair,
                inverse,
                overflow_active,
            },
            slots_to_zero,
        )
    }
}

/// Look up the slot for `(from, to)` in the direct map. Returns `None`
/// for unmapped pairs (capacity exhausted). #3075: one sparse hash-map
/// probe keyed on the `(from, to)` pair (any u16 zone id), replacing the
/// old 65×65 flat-table index that dropped ids ≥ 65.
#[inline]
pub(in crate::afxdp) fn lookup_slot(map: &ColdPathSlotMap, from: u16, to: u16) -> Option<u8> {
    map.slot_by_pair.get(&(from, to)).copied()
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
/// #1620 plan v4 (AGY r3 [MED-1]): `#[repr(u8)]` is load-bearing.
/// Embedding a `#[repr(Rust)]` enum inside a `#[repr(C)]` struct
/// (WorkerColdPathCounters) makes the offset of subsequent fields
/// implementation-defined — the compiler may choose a 1, 2, or 4-byte
/// representation. `#[repr(u8)]` pins this to 1 byte so the layout
/// math in plan §4.1 (clock_source at offset 32, alias_seen at 33)
/// holds under the C ABI rules the rest of the struct relies on.
#[repr(u8)]
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
///
/// #1620 plan v3 Amendment A: `#[repr(C, align(64))]` is load-bearing.
/// `align(64)` was already in #1619 (cacheline isolation). The `C` is
/// added in #1620 so the hot fields (`cold_window_gen`,
/// `ns_per_tsc_q32`, `wrapper_ns_baseline`, `clock_source`) stay at
/// the top of the struct under the compiler's hand. Default
/// `#[repr(Rust)]` is free to reorder fields and would defeat the
/// cacheline-0 hot-set design.
#[repr(C, align(64))]
pub(in crate::afxdp) struct WorkerColdPathAtomics {
    // === HOT FIELDS (cacheline 0; touched on every publish) ===
    /// Per-tick seqlock generation. Separate from
    /// `WorkerRuntimeAtomics.window_gen` per Codex r1 finding 2.
    pub(in crate::afxdp) cold_window_gen: AtomicU64,
    /// #1621 plan v2 (AGY r1 F3 + Codex r1 F5 + Claude SMR r1 F4):
    /// monotonic count of snapshot() calls that exhausted their
    /// retry budget. Incremented by snapshot() ON THE READER
    /// THREAD before returning None. Surfaced as
    /// `xpf_userspace_worker_cold_path_snapshot_failed_total` so
    /// operators can distinguish "no data this scrape" from
    /// "snapshot failed under publish contention".
    pub(in crate::afxdp) snapshot_failed: AtomicU64,
    /// #1620 plan v4 (AGY r3 [HIGH-1]): per-worker monotonic
    /// session-miss counter mirrored from
    /// `WorkerColdPathCounters.sample_phase`. Without this published,
    /// #1621/Prometheus + #1622/harness cannot compute the actual
    /// sampling rate (samples / sample_phase) and cannot validate
    /// that the configured `sample_mask` is being respected.
    pub(in crate::afxdp) sample_phase: AtomicU64,
    /// Calibration: set once at worker startup. Outside the per-tick seqlock.
    pub(in crate::afxdp) ns_per_tsc_q32: AtomicU64,
    /// Calibration: set once at worker startup. Outside the per-tick seqlock.
    pub(in crate::afxdp) wrapper_ns_baseline: AtomicU64,
    /// #1620 plan v4 (AGY r3 AXIS 6 diagnostic): monotonic count of
    /// samples where `raw_ns < wrapper_ns_baseline`. Without this,
    /// `saturating_sub` silently absorbs persistent underflow
    /// (frequency scaling, OoO jitter, ultra-fast policy_eval),
    /// falsely skewing the histogram toward bucket 0.
    pub(in crate::afxdp) wrapper_underflow_count: AtomicU64,
    /// Calibration: set once at worker startup. Outside the per-tick seqlock.
    pub(in crate::afxdp) clock_source: AtomicU8,
    // === COLD FIELDS (written by publish_from_local) ===
    /// #1635 (renamed from `alias_seen`): set true if a sample's packed
    /// key differs from the slot's `first_key`. With the direct slot
    /// map this should NEVER fire; a set bit means the snapshot builder
    /// mapped two distinct zone-pairs to one slot (AGY r1 [1.6]).
    pub(in crate::afxdp) builder_collision: [AtomicBool; POLICY_COLD_PATH_ZONE_PAIR_SLOTS],
    /// First packed zone-pair key seen in this slot during the current
    /// publish window. Zero = no sample yet.
    pub(in crate::afxdp) first_key: [AtomicU64; POLICY_COLD_PATH_ZONE_PAIR_SLOTS],
    pub(in crate::afxdp) sum_ns: [AtomicU64; POLICY_COLD_PATH_ZONE_PAIR_SLOTS],
    pub(in crate::afxdp) samples: [AtomicU64; POLICY_COLD_PATH_ZONE_PAIR_SLOTS],
    pub(in crate::afxdp) buckets: [[AtomicU64; POLICY_COLD_PATH_HIST_BUCKETS];
        POLICY_COLD_PATH_ZONE_PAIR_SLOTS],
}

impl Default for WorkerColdPathAtomics {
    fn default() -> Self {
        Self::new()
    }
}

impl WorkerColdPathAtomics {
    pub(in crate::afxdp) fn new() -> Self {
        Self {
            cold_window_gen: AtomicU64::new(0),
            snapshot_failed: AtomicU64::new(0),
            sample_phase: AtomicU64::new(0),
            ns_per_tsc_q32: AtomicU64::new(0),
            wrapper_ns_baseline: AtomicU64::new(0),
            wrapper_underflow_count: AtomicU64::new(0),
            clock_source: AtomicU8::new(ClockSource::Unset.as_u8()),
            builder_collision: std::array::from_fn(|_| AtomicBool::new(false)),
            first_key: std::array::from_fn(|_| AtomicU64::new(0)),
            sum_ns: std::array::from_fn(|_| AtomicU64::new(0)),
            samples: std::array::from_fn(|_| AtomicU64::new(0)),
            buckets: std::array::from_fn(|_| {
                std::array::from_fn(|_| AtomicU64::new(0))
            }),
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
    ///
    /// #1620 plan v4 (AGY r3 [HIGH-1]): also publishes `sample_phase`
    /// and `wrapper_underflow_count` so external telemetry can
    /// compute the sampling rate (samples / sample_phase) and
    /// observe baseline drift.
    pub(in crate::afxdp) fn publish_from_local(&self, local: &WorkerColdPathCounters) {
        // 1. Bump gen even → odd. AcqRel forbids subsequent Relaxed
        //    stores from being hoisted above this point.
        self.cold_window_gen.fetch_add(1, Ordering::AcqRel);
        // 2. Relaxed-store the payload (16 slots × 24 buckets = 384
        //    bucket stores + 16 × 4 metadata = 64 + 2 monotonic = 450).
        self.sample_phase
            .store(local.sample_phase, Ordering::Relaxed);
        self.wrapper_underflow_count
            .store(local.wrapper_underflow_count, Ordering::Relaxed);
        for slot in 0..POLICY_COLD_PATH_ZONE_PAIR_SLOTS {
            for b in 0..POLICY_COLD_PATH_HIST_BUCKETS {
                self.buckets[slot][b].store(local.buckets[slot][b], Ordering::Relaxed);
            }
            self.sum_ns[slot].store(local.sum_ns[slot], Ordering::Relaxed);
            self.samples[slot].store(local.samples[slot], Ordering::Relaxed);
            self.first_key[slot].store(local.first_key[slot], Ordering::Relaxed);
            self.builder_collision[slot]
                .store(local.builder_collision[slot], Ordering::Relaxed);
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
    /// AGY code-r2 finding 2 (continued): the retry budget is now 8192
    /// with an exponential `std::hint::spin_loop` backoff. #1635 grew
    /// the payload from the old 16×24 dense surface to 256 slots × 48
    /// buckets, so one publish now writes ~13k atomics instead of ~450.
    /// The larger budget keeps status-path snapshots coherent under a
    /// concurrent publish without changing the hot path.
    pub(in crate::afxdp) fn snapshot(&self) -> Option<WorkerColdPathCounters> {
        const RETRY_BUDGET: u32 = 8192;
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
            // #1620 plan v4 (AGY r3 [HIGH-1]): load sample_phase +
            // wrapper_underflow_count so external telemetry can
            // compute sampling rate and observe baseline drift.
            out.sample_phase = self.sample_phase.load(Ordering::Relaxed);
            out.wrapper_underflow_count = self
                .wrapper_underflow_count
                .load(Ordering::Relaxed);
            for slot in 0..POLICY_COLD_PATH_ZONE_PAIR_SLOTS {
                for b in 0..POLICY_COLD_PATH_HIST_BUCKETS {
                    out.buckets[slot][b] = self.buckets[slot][b].load(Ordering::Relaxed);
                }
                out.sum_ns[slot] = self.sum_ns[slot].load(Ordering::Relaxed);
                out.samples[slot] = self.samples[slot].load(Ordering::Relaxed);
                out.first_key[slot] = self.first_key[slot].load(Ordering::Relaxed);
                out.builder_collision[slot] =
                    self.builder_collision[slot].load(Ordering::Relaxed);
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
        //
        // #1621 plan v2 (AGY r1 F3 + Codex r1 F5): also bump the
        // snapshot_failed counter so operators can DETECT this regime
        // via `xpf_userspace_worker_cold_path_snapshot_failed_total`
        // rather than only see an empty payload.
        self.snapshot_failed.fetch_add(1, Ordering::Relaxed);
        None
    }

    /// #1621 plan v2: Counter accessor for the snapshot-failed counter.
    /// Used by the coordinator status path to emit a Prometheus metric
    /// even when `snapshot()` returns None.
    pub(in crate::afxdp) fn snapshot_failed_count(&self) -> u64 {
        self.snapshot_failed.load(Ordering::Relaxed)
    }

    /// #1635 (plan §2.4): atomically zero one slot's accumulator
    /// fields. Called by the owning worker on its next tick after a
    /// config apply reassigns the slot to a new zone-pair, so the
    /// reused slot never carries the previous pair's counts. Stores are
    /// Relaxed under the same single-writer discipline as
    /// `publish_from_local`; the caller runs this inside the worker's
    /// publish path so the seqlock brackets it.
    pub(in crate::afxdp) fn zero_slot(&self, idx: usize) {
        debug_assert!(idx < POLICY_COLD_PATH_ZONE_PAIR_SLOTS);
        for b in 0..POLICY_COLD_PATH_HIST_BUCKETS {
            self.buckets[idx][b].store(0, Ordering::Relaxed);
        }
        self.sum_ns[idx].store(0, Ordering::Relaxed);
        self.samples[idx].store(0, Ordering::Relaxed);
        self.first_key[idx].store(0, Ordering::Relaxed);
        self.builder_collision[idx].store(false, Ordering::Relaxed);
    }
}

/// Worker-local mutable cold-path counters. Touched only by the
/// owning worker thread on the hot path. The owner writes
/// non-atomically; the publisher (same thread) `store(Relaxed)` into
/// `WorkerColdPathAtomics` under the cold_window_gen seqlock.
///
/// #1620 plan v3 Amendment A: `#[repr(C)]` is load-bearing. The hot
/// fields (`sample_phase`, `ns_per_tsc_q32`, `wrapper_ns_baseline`,
/// `clock_source`) are declared FIRST so the hot-path read pattern
/// (`sample_phase` + mask, `ns_per_tsc_q32` + `wrapper_ns_baseline`
/// in the q32-skip block) hits cacheline 0. Without `#[repr(C)]` the
/// default `#[repr(Rust)]` is free to reorder fields to optimize
/// packing, which would destroy the hot-cacheline isolation.
///
/// Verified layout (AGY r2 axis 2 + Claude SMR r3 cross-check; offsets
/// re-derived for the #1635 256-slot / 48-bucket sizes):
///   [0..7]      sample_phase
///   [8..15]     ns_per_tsc_q32
///   [16..23]    wrapper_ns_baseline
///   [24..31]    wrapper_underflow_count
///   [32]        clock_source (enum #[repr(u8)])
///   [33..288]   builder_collision [bool; 256] (alignment 1, no padding)
///   [288..295]  PADDING                       (to align next u64 array)
///   first_key / sum_ns / samples / buckets follow as [_; 256] arrays.
///
/// The hot-path read set (sample_phase, ns_per_tsc_q32,
/// wrapper_ns_baseline, clock_source) still lands in cacheline 0
/// ([0..63]); the cold per-slot arrays start at offset 33.
#[repr(C)]
#[derive(Clone, Debug)]
pub(in crate::afxdp) struct WorkerColdPathCounters {
    // === HOT FIELDS (cacheline 0, read on every session-miss) ===
    /// v3 sample-phase counter: worker-local monotonic counter
    /// incremented on every session-miss path through the policy-
    /// eval site. NOT a per-poll BatchCounters accumulator. The
    /// sample gate is `phase & sample_mask == 0`.
    pub(in crate::afxdp) sample_phase: u64,
    /// Mirror of `WorkerColdPathAtomics.ns_per_tsc_q32`. Read on
    /// every sampled packet inside the q32-skip block.
    pub(in crate::afxdp) ns_per_tsc_q32: u64,
    /// Calibrated wrapper baseline (sample_tsc_start/end pair cost).
    /// Subtracted from `raw_ns` per #1620 plan v3 Amendment B so the
    /// recorded delta reflects only the policy_eval body cost.
    pub(in crate::afxdp) wrapper_ns_baseline: u64,
    /// #1620 plan v4 (AGY r3 AXIS 6 diagnostic): monotonic count of
    /// samples where `raw_ns < wrapper_ns_baseline`. Worker-local
    /// mirror of `WorkerColdPathAtomics.wrapper_underflow_count`.
    pub(in crate::afxdp) wrapper_underflow_count: u64,
    /// Per-worker clock source set once at startup.
    pub(in crate::afxdp) clock_source: ClockSource,
    // === COLD FIELDS (written only when sample fires) ===
    /// #1635 (renamed from `alias_seen`): per-slot flag set when a
    /// sample arrives with a key different from `first_key`. With the
    /// direct slot map this is a builder-bug signal, not an aliasing
    /// gate. Once true, stays true for the publish window.
    pub(in crate::afxdp) builder_collision: [bool; POLICY_COLD_PATH_ZONE_PAIR_SLOTS],
    /// First packed zone-pair key per slot (0 = none).
    pub(in crate::afxdp) first_key: [u64; POLICY_COLD_PATH_ZONE_PAIR_SLOTS],
    pub(in crate::afxdp) sum_ns: [u64; POLICY_COLD_PATH_ZONE_PAIR_SLOTS],
    pub(in crate::afxdp) samples: [u64; POLICY_COLD_PATH_ZONE_PAIR_SLOTS],
    pub(in crate::afxdp) buckets:
        [[u64; POLICY_COLD_PATH_HIST_BUCKETS]; POLICY_COLD_PATH_ZONE_PAIR_SLOTS],
}

impl Default for WorkerColdPathCounters {
    fn default() -> Self {
        Self {
            sample_phase: 0,
            ns_per_tsc_q32: 0,
            wrapper_ns_baseline: 0,
            wrapper_underflow_count: 0,
            clock_source: ClockSource::Unset,
            builder_collision: [false; POLICY_COLD_PATH_ZONE_PAIR_SLOTS],
            first_key: [0u64; POLICY_COLD_PATH_ZONE_PAIR_SLOTS],
            sum_ns: [0u64; POLICY_COLD_PATH_ZONE_PAIR_SLOTS],
            samples: [0u64; POLICY_COLD_PATH_ZONE_PAIR_SLOTS],
            buckets: [[0u64; POLICY_COLD_PATH_HIST_BUCKETS]; POLICY_COLD_PATH_ZONE_PAIR_SLOTS],
        }
    }
}

impl WorkerColdPathCounters {
    /// #1635 hot-path sample record. The caller resolves `slot` via
    /// [`lookup_slot`] against the per-config `ColdPathSlotMap` and
    /// skips the call entirely on a miss, so this fn never needs to
    /// hash. `from_zone_id` / `to_zone_id` are still passed so the
    /// `first_key` / `builder_collision` invariant can detect a builder
    /// bug (two distinct pairs mapped to one slot). Inlined; only
    /// invoked at the sampling rate.
    #[inline]
    pub(in crate::afxdp) fn record_sample(
        &mut self,
        slot: u8,
        from_zone_id: u16,
        to_zone_id: u16,
        delta_ns: u64,
    ) {
        let slot = slot as usize;
        debug_assert!(slot < POLICY_COLD_PATH_ZONE_PAIR_SLOTS);
        let bucket = bucket_index_for_ns_48(delta_ns);
        self.buckets[slot][bucket] = self.buckets[slot][bucket].saturating_add(1);
        self.sum_ns[slot] = self.sum_ns[slot].saturating_add(delta_ns);
        self.samples[slot] = self.samples[slot].saturating_add(1);
        // builder_collision invariant: with the direct slot map every
        // sample in a slot MUST carry the same packed key. A mismatch
        // means the snapshot builder mapped two pairs to one slot.
        let key = zone_pair_packed_key(from_zone_id, to_zone_id);
        if self.first_key[slot] == 0 {
            self.first_key[slot] = key;
        } else if self.first_key[slot] != key {
            self.builder_collision[slot] = true;
        }
    }

    /// #1635 (plan §2.4): zero one slot's local accumulator. Called by
    /// the owning worker when a config apply reassigns the slot, before
    /// the first `record_sample` into the new zone-pair.
    #[inline]
    pub(in crate::afxdp) fn zero_slot(&mut self, slot: usize) {
        debug_assert!(slot < POLICY_COLD_PATH_ZONE_PAIR_SLOTS);
        self.buckets[slot] = [0u64; POLICY_COLD_PATH_HIST_BUCKETS];
        self.sum_ns[slot] = 0;
        self.samples[slot] = 0;
        self.first_key[slot] = 0;
        self.builder_collision[slot] = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // #1620 plan v4: pin the cacheline-0 layout of
    // WorkerColdPathCounters so a future field reorder is caught
    // by the test suite, not by a regression in the cold-path-flooder
    // microbench. v4 absorbs AGY r3 [HIGH-1] (sample_phase published)
    // + AXIS-6 diagnostic (wrapper_underflow_count).
    #[test]
    fn worker_cold_path_counters_hot_fields_fit_in_cacheline_0() {
        use std::mem::offset_of;
        // Hot fields declared first; ClockSource is #[repr(u8)] so
        // its size is 1 byte and the offset math is deterministic.
        assert_eq!(offset_of!(WorkerColdPathCounters, sample_phase), 0);
        assert_eq!(offset_of!(WorkerColdPathCounters, ns_per_tsc_q32), 8);
        assert_eq!(offset_of!(WorkerColdPathCounters, wrapper_ns_baseline), 16);
        assert_eq!(offset_of!(WorkerColdPathCounters, wrapper_underflow_count), 24);
        assert_eq!(offset_of!(WorkerColdPathCounters, clock_source), 32);
        // #1635: builder_collision [bool; 256] alignment 1: lives at
        // [33..289], no padding. All hot reads (sample_phase ..
        // clock_source) still land in cacheline 0 ([0..63]).
        assert_eq!(offset_of!(WorkerColdPathCounters, builder_collision), 33);
        // first_key [u64; 256] alignment 8: padded from 33+256=289 to 296.
        assert_eq!(offset_of!(WorkerColdPathCounters, first_key), 296);
    }

    #[test]
    fn worker_cold_path_atomics_hot_fields_at_top() {
        use std::mem::{align_of, offset_of};
        // align(64) preserved from #1619.
        assert_eq!(align_of::<WorkerColdPathAtomics>(), 64);
        // Hot fields at top — cacheline 0. v2 (#1621) inserts the
        // snapshot_failed counter at offset 8 between cold_window_gen
        // and sample_phase so the reader-thread Counter sits in
        // cacheline 0 alongside the seqlock gen it accompanies.
        assert_eq!(offset_of!(WorkerColdPathAtomics, cold_window_gen), 0);
        assert_eq!(offset_of!(WorkerColdPathAtomics, snapshot_failed), 8);
        assert_eq!(offset_of!(WorkerColdPathAtomics, sample_phase), 16);
        assert_eq!(offset_of!(WorkerColdPathAtomics, ns_per_tsc_q32), 24);
        assert_eq!(offset_of!(WorkerColdPathAtomics, wrapper_ns_baseline), 32);
        assert_eq!(offset_of!(WorkerColdPathAtomics, wrapper_underflow_count), 40);
        assert_eq!(offset_of!(WorkerColdPathAtomics, clock_source), 48);
    }

    /// #1620 plan v4 (AGY r3 [HIGH-1]): publish_from_local /
    /// snapshot must round-trip sample_phase + wrapper_underflow_count.
    #[test]
    fn sample_phase_and_underflow_round_trip_through_publish_snapshot() {
        let atomics = WorkerColdPathAtomics::new();
        let mut local = WorkerColdPathCounters::default();
        local.sample_phase = 12345;
        local.wrapper_underflow_count = 7;
        atomics.publish_from_local(&local);
        let snap = atomics.snapshot().expect("snapshot must succeed");
        assert_eq!(snap.sample_phase, 12345);
        assert_eq!(snap.wrapper_underflow_count, 7);
    }

    // === #1635 log-linear 48-bucket layout ===

    #[test]
    fn bucket_index_for_ns_48_linear_band() {
        // Linear band: 16-ns stride, indices [0, 32).
        assert_eq!(bucket_index_for_ns_48(0), 0);
        assert_eq!(bucket_index_for_ns_48(15), 0);
        assert_eq!(bucket_index_for_ns_48(16), 1);
        assert_eq!(bucket_index_for_ns_48(31), 1);
        assert_eq!(bucket_index_for_ns_48(100), 6); // 100/16 = 6
        assert_eq!(bucket_index_for_ns_48(496), 31);
        assert_eq!(bucket_index_for_ns_48(511), 31);
    }

    #[test]
    fn bucket_index_for_ns_48_pivots_at_512() {
        assert_eq!(bucket_index_for_ns_48(511), 31, "last linear bucket");
        assert_eq!(bucket_index_for_ns_48(512), 32, "first exponential bucket");
    }

    #[test]
    fn bucket_index_for_ns_48_exponential_band() {
        // bucket 32 covers [512, 1024); 33 covers [1024, 2048); ...
        assert_eq!(bucket_index_for_ns_48(512), 32);
        assert_eq!(bucket_index_for_ns_48(1023), 32);
        assert_eq!(bucket_index_for_ns_48(1024), 33);
        assert_eq!(bucket_index_for_ns_48(2047), 33);
        assert_eq!(bucket_index_for_ns_48(2048), 34);
        // i=14 → bucket 46 covers [2^23, 2^24).
        assert_eq!(bucket_index_for_ns_48(1u64 << 23), 46);
        assert_eq!(bucket_index_for_ns_48((1u64 << 24) - 1), 46);
    }

    #[test]
    fn bucket_index_for_ns_48_saturates() {
        // ns ≥ 2^24 lands in bucket 47.
        assert_eq!(bucket_index_for_ns_48(1u64 << 24), 47);
        assert_eq!(bucket_index_for_ns_48(1u64 << 33), 47);
        assert_eq!(bucket_index_for_ns_48(u64::MAX), 47);
    }

    #[test]
    fn bucket_upper_bound_ns_48_matches_layout() {
        // Linear band inclusive upper boundaries.
        assert_eq!(bucket_upper_bound_ns_48(0), 15);
        assert_eq!(bucket_upper_bound_ns_48(1), 31);
        assert_eq!(bucket_upper_bound_ns_48(31), 511);
        // Exponential band.
        assert_eq!(bucket_upper_bound_ns_48(32), 1023);
        assert_eq!(bucket_upper_bound_ns_48(33), 2047);
        assert_eq!(bucket_upper_bound_ns_48(46), (1u64 << 24) - 1);
        // Saturate bucket.
        assert_eq!(bucket_upper_bound_ns_48(47), u64::MAX);
    }

    /// Consumer criterion (#1622 F1 / plan §X): a 10-rule cold-path
    /// distribution centered at ~50-150 ns must read back a p50 within
    /// 2× of truth, NOT collapsed to the old bucket-0 512-ns midpoint.
    /// This test FAILS on the old 24-bucket pow-2-from-0 layout (which
    /// puts all of [0,1024) ns into one bucket whose midpoint is 512)
    /// and PASSES on the new log-linear layout.
    #[test]
    fn bucket_layout_resolves_low_end_within_2x() {
        // For each true latency, the bucket's INCLUSIVE upper bound is
        // the worst-case reported value for a histogram_quantile read
        // landing in that bucket. Assert it is within 2× of truth (and
        // that the lower edge is ≥ truth/2), i.e. relative error ≤ 1.0.
        for truth in [50u64, 75, 100, 125, 150, 1000, 5000, 50000] {
            let idx = bucket_index_for_ns_48(truth);
            let upper = bucket_upper_bound_ns_48(idx);
            let lower = if idx == 0 {
                0
            } else {
                bucket_upper_bound_ns_48(idx - 1) + 1
            };
            // Reported value (bucket boundary) within 2× of truth.
            assert!(
                upper <= truth.saturating_mul(2),
                "truth={truth} upper={upper} exceeds 2x (idx={idx})"
            );
            assert!(
                lower <= truth,
                "truth={truth} lower={lower} above truth (idx={idx})"
            );
        }
    }

    /// Adversarial demonstration that the OLD pow-2-from-0 layout
    /// FAILS the consumer criterion the new layout passes: a true
    /// 100 ns p50 reads as 1023 ns (>10× error) under the old bucket-0.
    #[test]
    fn old_pow2_layout_would_fail_low_end_resolution() {
        // Re-implement the retired 24-bucket formula inline to prove
        // the regression it caused.
        fn old_bucket_index_for_ns_24(ns: u64) -> usize {
            let clz = (ns | 1).leading_zeros() as i32;
            let b = (54 - clz).max(0) as usize;
            b.min(23)
        }
        // 50, 100, 150 ns all collapse into old bucket 0 = [0, 1024).
        assert_eq!(old_bucket_index_for_ns_24(50), 0);
        assert_eq!(old_bucket_index_for_ns_24(100), 0);
        assert_eq!(old_bucket_index_for_ns_24(150), 0);
        // Old bucket-0 upper bound is 1023 ns ⇒ a true 100 ns p50
        // reads up to 1023 ns: > 10× error. The new layout keeps it
        // ≤ 2× (covered by bucket_layout_resolves_low_end_within_2x).
        let old_upper = 1023u64;
        assert!(old_upper > 100 * 2, "old layout error must exceed 2x");
        // New layout: 100 ns → bucket 6 → upper 111 ns ⇒ 1.11×.
        assert_eq!(bucket_index_for_ns_48(100), 6);
        assert_eq!(bucket_upper_bound_ns_48(6), 111);
    }

    // === #1635 direct slot map ===

    #[test]
    fn direct_slot_map_assigns_sequential() {
        let pairs = [(1u16, 2u16), (3, 4), (5, 6), (7, 8), (9, 10)];
        let (map, zeroed) = ColdPathSlotMap::build(None, &pairs);
        assert!(zeroed.is_empty(), "fresh build zeroes nothing");
        // Sorted/dedup input ⇒ slots assigned 0..5 in pair order.
        for (i, &(from, to)) in pairs.iter().enumerate() {
            assert_eq!(lookup_slot(&map, from, to), Some(i as u8), "pair {from}->{to}");
            assert_eq!(map.inverse[i], Some((from, to)));
        }
        assert!(!map.overflow_active);
    }

    #[test]
    fn direct_slot_map_no_collisions_at_capacity() {
        // 255 distinct in-range pairs ⇒ unique slots [0,255), no
        // overflow. (Slot 255 is reserved as the u8::MAX sentinel.)
        let mut pairs = Vec::new();
        'outer: for from in 0u16..8 {
            for to in 0u16..32 {
                pairs.push((from, to));
                if pairs.len() == COLD_PATH_ASSIGNABLE_SLOTS {
                    break 'outer;
                }
            }
        }
        assert_eq!(pairs.len(), 255);
        let (map, _) = ColdPathSlotMap::build(None, &pairs);
        assert!(!map.overflow_active);
        let mut seen = std::collections::HashSet::new();
        for &(from, to) in &pairs {
            let s = lookup_slot(&map, from, to).expect("all 255 pairs assigned");
            assert!(s != u8::MAX, "slot 255 sentinel must never be handed out");
            assert!(seen.insert(s), "slot {s} assigned twice");
        }
        assert_eq!(seen.len(), 255);
    }

    #[test]
    fn direct_slot_map_overflow_past_capacity() {
        // 256 in-range pairs: one more than the 255 assignable slots.
        let mut pairs = Vec::new();
        'outer: for from in 0u16..16 {
            for to in 0u16..17 {
                pairs.push((from, to));
                if pairs.len() == 256 {
                    break 'outer;
                }
            }
        }
        assert_eq!(pairs.len(), 256);
        let (map, _) = ColdPathSlotMap::build(None, &pairs);
        assert!(
            map.overflow_active,
            "the 256th pair must overflow the 255-slot capacity"
        );
        // Exactly 255 slots occupied.
        let occupied = map.inverse.iter().filter(|s| s.is_some()).count();
        assert_eq!(occupied, 255);
    }

    #[test]
    fn direct_slot_map_immediate_reuse_after_removal_zeros_atomics() {
        // Build A with {(1,2),(3,4)}; record into both.
        let pairs_a = [(1u16, 2u16), (3, 4)];
        let (map_a, _) = ColdPathSlotMap::build(None, &pairs_a);
        let slot_34 = lookup_slot(&map_a, 3, 4).unwrap();
        // Build B with {(1,2),(5,6)} — drop (3,4), add (5,6).
        let pairs_b = [(1u16, 2u16), (5, 6)];
        let (map_b, zeroed) = ColdPathSlotMap::build(Some(&map_a), &pairs_b);
        // (1,2) retains its slot; (5,6) takes the freed (3,4) slot.
        assert_eq!(lookup_slot(&map_b, 1, 2), lookup_slot(&map_a, 1, 2));
        let slot_56 = lookup_slot(&map_b, 5, 6).unwrap();
        assert_eq!(slot_56, slot_34, "reused freed slot");
        assert_eq!(lookup_slot(&map_b, 3, 4), None, "(3,4) no longer mapped");
        // The reused slot is queued for zero-out.
        assert!(zeroed.contains(&slot_56), "reused slot must be zeroed");

        // Verify zero_slot actually clears local + atomic accumulators.
        let mut local = WorkerColdPathCounters::default();
        local.record_sample(slot_34, 3, 4, 5000);
        assert_eq!(local.samples[slot_34 as usize], 1);
        local.zero_slot(slot_34 as usize);
        assert_eq!(local.samples[slot_34 as usize], 0);
        assert_eq!(local.sum_ns[slot_34 as usize], 0);
        assert_eq!(local.first_key[slot_34 as usize], 0);

        let atomics = WorkerColdPathAtomics::new();
        let mut l2 = WorkerColdPathCounters::default();
        l2.record_sample(slot_34, 3, 4, 5000);
        atomics.publish_from_local(&l2);
        atomics.zero_slot(slot_34 as usize);
        let snap = atomics.snapshot().expect("snapshot");
        assert_eq!(snap.samples[slot_34 as usize], 0);
    }

    #[test]
    fn direct_slot_map_retains_assignment_for_surviving_pairs() {
        let pairs_a = [(1u16, 2u16), (3, 4), (5, 6)];
        let (map_a, _) = ColdPathSlotMap::build(None, &pairs_a);
        // Add a new pair; all original pairs survive.
        let pairs_b = [(1u16, 2u16), (3, 4), (5, 6), (7, 8)];
        let (map_b, zeroed) = ColdPathSlotMap::build(Some(&map_a), &pairs_b);
        for &(from, to) in &pairs_a {
            assert_eq!(
                lookup_slot(&map_b, from, to),
                lookup_slot(&map_a, from, to),
                "surviving pair {from}->{to} kept its slot"
            );
            // Retained pairs must NOT be zeroed (keep their histogram).
            let s = lookup_slot(&map_b, from, to).unwrap();
            assert!(
                !zeroed.contains(&s),
                "retained pair {from}->{to} (slot {s}) must NOT be zeroed"
            );
        }
        // (7,8) is a NEW pair ⇒ its slot IS queued for zero-out (every
        // newly-assigned slot is zeroed per Codex finding 1).
        let slot_78 = lookup_slot(&map_b, 7, 8).expect("(7,8) assigned");
        assert!(
            zeroed.contains(&slot_78),
            "new pair (7,8) slot {slot_78} must be zeroed; zeroed={zeroed:?}"
        );
    }

    #[test]
    fn build_assigns_slots_for_wide_stable_hash_zone_ids() {
        // #3075: zone ids are stable name-hashes spanning [1,65533], NOT
        // the old sequential 1..=64. A pair with an id >= 65 (e.g. 300,
        // 40000) MUST get a slot — the old 65×65 flat table dropped every
        // such pair, silently dark-ing the #1635 cold-path histogram for
        // every real config. RED-on-revert: against the fixed-65 table
        // these lookups return None and overflow_active is true.
        let pairs = [(300u16, 400u16), (40000, 1), (1, 65533), (65533, 65533)];
        let (map, _) = ColdPathSlotMap::build(None, &pairs);
        for &(from, to) in &pairs {
            assert!(
                lookup_slot(&map, from, to).is_some(),
                "wide stable-hash pair {from}->{to} must get a slot"
            );
        }
        assert!(
            !map.overflow_active,
            "wide ids must NOT trip overflow (overflow is now slot-capacity only)"
        );
        // Distinct wide pairs get distinct slots.
        assert_ne!(lookup_slot(&map, 300, 400), lookup_slot(&map, 40000, 1));
        // An unmapped wide pair still misses.
        assert_eq!(lookup_slot(&map, 12345, 54321), None);
    }

    #[test]
    fn build_assigns_slots_for_zone_ids_up_to_64() {
        // Regression for Codex code-r1 finding 2 (ids 32-63 dropped at
        // ceiling 32) AND Copilot code-r2 (id 64 dropped at exclusive
        // ceiling 64). The 1-based MAX_ZONES=64 means the 64th zone has
        // id 64; it MUST get a slot.
        let pairs = [(32u16, 33u16), (63, 1), (1, 63), (64, 64), (1, 64), (64, 1)];
        let (map, _) = ColdPathSlotMap::build(None, &pairs);
        for &(from, to) in &pairs {
            assert!(
                lookup_slot(&map, from, to).is_some(),
                "in-range pair {from}->{to} must get a slot"
            );
        }
        assert!(!map.overflow_active);
        // (64,64) and (1,2)-style pairs must not collide.
        assert_ne!(lookup_slot(&map, 64, 64), lookup_slot(&map, 1, 64));
        assert_ne!(lookup_slot(&map, 1, 64), lookup_slot(&map, 64, 1));
    }

    #[test]
    fn lookup_slot_returns_none_for_unmapped_pair() {
        let (map, _) = ColdPathSlotMap::build(None, &[(1u16, 2u16)]);
        assert_eq!(lookup_slot(&map, 9, 9), None);
    }

    #[test]
    fn build_flags_overflow_only_on_slot_capacity_exhaustion() {
        // #3075: overflow_active is set when the slot CAPACITY
        // (COLD_PATH_ASSIGNABLE_SLOTS) is exhausted, NOT by zone-id
        // magnitude — wide stable-hash ids are first-class now. A wide id
        // within capacity is assigned, not dropped.
        let pairs = [(1u16, 2u16), (200, 5), (3, 4)];
        let (map, _) = ColdPathSlotMap::build(None, &pairs);
        assert!(
            lookup_slot(&map, 200, 5).is_some(),
            "a wide id (200) within capacity must be assigned, not dropped"
        );
        assert!(!map.overflow_active, "no capacity pressure ⇒ no overflow");
        let occupied = map.inverse.iter().filter(|s| s.is_some()).count();
        assert_eq!(occupied, 3);

        // Exceed the slot capacity with distinct wide pairs ⇒ overflow.
        let mut many: Vec<(u16, u16)> = Vec::new();
        for i in 0..(COLD_PATH_ASSIGNABLE_SLOTS as u16 + 1) {
            many.push((1000 + i, 2000 + i));
        }
        let (full, _) = ColdPathSlotMap::build(None, &many);
        assert!(
            full.overflow_active,
            "exceeding the {COLD_PATH_ASSIGNABLE_SLOTS}-slot capacity must trip overflow_active"
        );
        let occupied_full = full.inverse.iter().filter(|s| s.is_some()).count();
        assert_eq!(
            occupied_full, COLD_PATH_ASSIGNABLE_SLOTS,
            "exactly the capacity is assigned; the surplus pair is dropped"
        );
    }

    /// Codex code-r1 finding 1: A assigns slot 0; B frees it (no reuse);
    /// C reassigns slot 0 to a NEW pair. C's `previous` (= B) shows
    /// slot 0 free, but the worker-local accumulator may still carry
    /// A's counts — so C MUST queue slot 0 for zero-out.
    #[test]
    fn build_zeros_slot_reassigned_after_intermediate_free() {
        // A: slot 0 = (1,2), slot 1 = (3,4).
        let (map_a, za) = ColdPathSlotMap::build(None, &[(1u16, 2u16), (3, 4)]);
        assert!(za.is_empty());
        let slot_12 = lookup_slot(&map_a, 1, 2).unwrap();
        // B: drop (1,2); keep (3,4). Slot for (1,2) is now free.
        let (map_b, _zb) = ColdPathSlotMap::build(Some(&map_a), &[(3u16, 4u16)]);
        assert_eq!(lookup_slot(&map_b, 1, 2), None);
        // C: keep (3,4); add NEW (5,6). It takes the lowest free slot,
        // which is the slot A used for (1,2).
        let (map_c, zc) = ColdPathSlotMap::build(Some(&map_b), &[(3u16, 4u16), (5, 6)]);
        let slot_56 = lookup_slot(&map_c, 5, 6).unwrap();
        assert_eq!(slot_56, slot_12, "(5,6) reuses the slot A gave (1,2)");
        assert!(
            zc.contains(&slot_56),
            "reassigned slot must be queued for zero-out even though B showed it free \
             (Codex finding 1) — slots_to_zero={zc:?}"
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
        let slot = 0u8;
        c.record_sample(slot, 1, 2, 1500);
        let bucket = bucket_index_for_ns_48(1500);
        assert_eq!(c.buckets[slot as usize][bucket], 1);
        assert_eq!(c.sum_ns[slot as usize], 1500);
        assert_eq!(c.samples[slot as usize], 1);
        // First sample sets first_key, builder_collision stays false.
        assert_eq!(c.first_key[slot as usize], zone_pair_packed_key(1, 2));
        assert!(!c.builder_collision[slot as usize]);
    }

    #[test]
    fn record_sample_same_key_twice_no_collision() {
        let mut c = WorkerColdPathCounters::default();
        let slot = 0u8;
        c.record_sample(slot, 1, 2, 100);
        c.record_sample(slot, 1, 2, 100);
        assert_eq!(c.first_key[slot as usize], zone_pair_packed_key(1, 2));
        assert!(!c.builder_collision[slot as usize]);
        assert_eq!(c.samples[slot as usize], 2);
    }

    #[test]
    fn record_sample_detects_builder_collision() {
        // With the direct slot map a slot should only ever see one
        // zone-pair. If the builder mistakenly maps two pairs to the
        // same slot, builder_collision must fire — this is a builder
        // bug detector, not an aliasing gate.
        let mut c = WorkerColdPathCounters::default();
        let slot = 4u8;
        c.record_sample(slot, 1, 2, 100);
        assert!(!c.builder_collision[slot as usize]);
        c.record_sample(slot, 3, 4, 200); // different key, same slot
        assert!(
            c.builder_collision[slot as usize],
            "builder_collision must fire when two distinct keys share a slot"
        );
    }

    #[test]
    fn snapshot_roundtrip() {
        let atomics = WorkerColdPathAtomics::new();
        let mut local = WorkerColdPathCounters::default();
        let slot = 9u8;
        local.record_sample(slot, 3, 5, 4000);
        local.record_sample(slot, 3, 5, 8000);
        atomics.install_calibration(42, 30, ClockSource::Tsc);
        atomics.publish_from_local(&local);
        let snap = atomics.snapshot().expect("single-thread snapshot must succeed");
        assert_eq!(snap.samples[slot as usize], 2);
        assert_eq!(snap.sum_ns[slot as usize], 12000);
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
        let slot = 11u8;
        local.record_sample(slot, 7, 11, 12345);
        atomics.publish_from_local(&local);
        let snap1 = atomics.snapshot().expect("seq snapshot 1 must succeed");
        local.record_sample(slot, 7, 11, 67890);
        atomics.publish_from_local(&local);
        let snap2 = atomics.snapshot().expect("seq snapshot 2 must succeed");
        assert_eq!(snap1.samples[slot as usize], 1);
        assert_eq!(snap2.samples[slot as usize], 2);
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
                local.record_sample(5, 3, 5, 1000 + (count & 0xff));
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
        let slot = 5usize;
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
