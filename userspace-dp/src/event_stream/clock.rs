//! Monotonic-to-wall-clock conversion for event-stream flow-export fields.
//!
//! The session table stamps creation/last-seen instants with `CLOCK_MONOTONIC`,
//! but the RT_FLOW / flow-export wire fields carry absolute Unix wall-clock
//! values. These helpers anchor a monotonic instant against a single
//! `(CLOCK_MONOTONIC, CLOCK_REALTIME)` reading so a queued/backlogged delivery on
//! the Go side cannot skew the logged event time to consumption time. Pure code
//! motion out of `mod.rs` (#6235); no logic change.

pub(super) const NS_PER_SEC: u64 = 1_000_000_000;

/// #2465: read CLOCK_MONOTONIC (ns) and the wall clock (ns since the Unix
/// epoch) in one pair so the two are anchored to the same instant. Used to
/// convert the session table's monotonic creation/last-seen instants into the
/// absolute wall-clock values the flow-export wire fields carry. On a clock
/// read failure both fall back to 0 (→ the Go-side packet-count fallback).
pub(super) fn read_mono_and_wall_clocks() -> (u64, u64) {
    let mut mono = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let mut wall = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let rc_mono = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut mono) };
    let rc_wall = unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut wall) };
    if rc_mono != 0 || rc_wall != 0 || mono.tv_sec < 0 || wall.tv_sec < 0 {
        return (0, 0);
    }
    let mono_ns = (mono.tv_sec as u64)
        .saturating_mul(NS_PER_SEC)
        .saturating_add(mono.tv_nsec.max(0) as u64);
    let wall_ns = (wall.tv_sec as u64)
        .saturating_mul(NS_PER_SEC)
        .saturating_add(wall.tv_nsec.max(0) as u64);
    (mono_ns, wall_ns)
}

/// #2465: convert a monotonic instant (`mono_ns`) to an absolute wall-clock
/// nanosecond count, anchored against a (`now_mono_ns`, `now_unix_ns`) reading.
/// `mono_ns == 0` (unknown) maps to 0. The age is clamped at the present so a
/// monotonic value slightly ahead of `now_mono_ns` (a benign cross-CPU read
/// skew) cannot push the result into the future.
pub(crate) fn monotonic_ns_to_unix_ns(mono_ns: u64, now_mono_ns: u64, now_unix_ns: u64) -> u64 {
    if mono_ns == 0 || now_mono_ns == 0 || now_unix_ns == 0 {
        return 0;
    }
    let age_ns = now_mono_ns.saturating_sub(mono_ns);
    now_unix_ns.saturating_sub(age_ns)
}

/// #2465: convert a monotonic instant to absolute wall-clock Unix SECONDS for
/// the `created` wire field (offset 108, u32). Truncates toward the epoch;
/// 0/unknown stays 0; values beyond u32 (year 2106) saturate.
pub(crate) fn monotonic_ns_to_unix_secs(mono_ns: u64, now_mono_ns: u64, now_unix_ns: u64) -> u32 {
    monotonic_ns_to_unix_secs_subnanos(mono_ns, now_mono_ns, now_unix_ns).0
}

/// #2853: convert a monotonic instant to absolute wall-clock Unix SECONDS plus
/// the sub-second NANOSECOND remainder (0..=999_999_999). The integer seconds
/// ride the `created` wire field (offset 108, u32); the sub-second nanos ride
/// the SESSION_CLOSE-unused policy_id slot (offset 44, u32) so the Go flow
/// exporters can build a MILLISECOND-accurate flow StartTime instead of one
/// truncated to the whole second (the #2853 defect: short flows — DNS, single
/// HTTP requests — all collapsed onto the same integer-second start).
///
/// 0/unknown stays `(0, 0)`; a seconds value beyond u32 (year 2106) saturates
/// to `(u32::MAX, 0)` so the saturated record carries no misleading remainder.
pub(crate) fn monotonic_ns_to_unix_secs_subnanos(
    mono_ns: u64,
    now_mono_ns: u64,
    now_unix_ns: u64,
) -> (u32, u32) {
    let unix_ns = monotonic_ns_to_unix_ns(mono_ns, now_mono_ns, now_unix_ns);
    let secs = unix_ns / NS_PER_SEC;
    if secs > u32::MAX as u64 {
        return (u32::MAX, 0);
    }
    (secs as u32, (unix_ns % NS_PER_SEC) as u32)
}

/// #2470: convert a CLOCK_MONOTONIC instant (the `now_ns`/`now_secs`-derived
/// value the worker poll loop hands to the RT_FLOW deny/screen/filter-log
/// emitters) to an absolute wall-clock Unix nanosecond count, taking a fresh
/// anchored (`mono`, `wall`) reading here. This is the emission-time
/// conversion boundary: the deny/screen/filter-log events carry the dataplane
/// DECISION instant on the wire (offset 0, LE u64, absolute Unix ns — the same
/// `timestamp_ns` format the SESSION_CLOSE frame uses and the Go decoder
/// reads), so a queued/backlogged delivery on the Go side cannot skew the
/// logged event time to consumption time. A 0 `mono_ns` (unknown) or a clock
/// read failure maps to 0 → the Go side (`pkg/logging/ringbuf.go`) falls back
/// to receive time, preserving the old behavior only when no real instant is
/// available.
///
/// These events fire on drops / denies / log-matched packets (NOT per normal
/// packet), so one anchored clock read per emit is acceptable; correctness
/// (a real decision timestamp) is preferred over saving the read.
pub(crate) fn mono_ns_to_wall_clock_unix_ns(mono_ns: u64) -> u64 {
    let (now_mono_ns, now_unix_ns) = read_mono_and_wall_clocks();
    monotonic_ns_to_unix_ns(mono_ns, now_mono_ns, now_unix_ns)
}
