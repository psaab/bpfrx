// #2472: per-reason token-bucket rate limiter for LOCALLY-GENERATED ICMP /
// RST error replies.
//
// The three locally-originated error-reply generators —
//   - TTL/Hop-Limit Exceeded (`icmp::build_local_time_exceeded_request`),
//   - Packet-Too-Big / Frag-Needed PMTUD (`icmp_ptb`),
//   - policy/filter `reject` RST or ICMP-unreachable
//     (`poll_descriptor::reject_reply`),
// each build + enqueue an error frame after the RFC-suppression and (since
// #2238/#2328) output-classification gates. None of them had a token bucket:
// an attacker that drives a flood of TTL-1 packets, oversized DF=1 packets, or
// rejected flows can make the box emit one generated error PER trigger packet,
// unbounded. That is a CPU / TX amplification sink and a reflection vector (the
// generated errors are addressed to the trigger's source, which an attacker can
// spoof). The pre-existing SYN-cookie TX-frame budget gate on the reject path
// is a queue-protection gate (it stops the reply ring from starving transit
// TX), NOT a per-reason cap — under a sustained flood it refills as fast as TX
// drains, so it does not bound the generated-error RATE.
//
// This adds the missing limiter, modelled on Linux's ICMP rate limiting
// (`net.ipv4.icmp_msgs_per_sec` — a GLOBAL per-host burst, default 1000/s —
// plus `net.ipv4.icmp_ratelimit`). We use the simple, bounded-state half of
// that model: a GLOBAL-per-reason token bucket (no per-source / per-destination
// map, so there is no attacker-driven map growth). Each reason has its own
// bucket so a TTL-exceeded flood cannot starve the PTB or reject reasons (and
// vice-versa) — per-reason isolation.
//
// Hot-path: the check is a single CAS loop over two atomics (token count +
// last-refill timestamp). It runs ONLY on the cold generated-error path (per
// TTL-exceeded / PTB / reject decision), never per forwarded packet, and never
// allocates. On bucket-empty the generated reply is DROPPED and a per-reason
// `*_rate_limited` counter (a global `AtomicU64`, surfaced via the coordinator
// status the same way as `GRE_ENCAP_DF_OVERSIZE_DROPS`) is bumped so the
// suppression is observable.

use std::sync::atomic::{AtomicU64, Ordering};

use super::neighbor::monotonic_nanos;

/// The locally-generated error reasons that share this limiter. Each variant
/// indexes an independent token bucket, so exhausting one reason never blocks
/// another (per-reason isolation, #2472).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::afxdp) enum GeneratedErrorReason {
    /// ICMPv4 Time Exceeded / ICMPv6 Hop-Limit Exceeded
    /// (`build_local_time_exceeded_request`).
    TimeExceeded,
    /// ICMPv4 Frag-Needed (type 3 code 4) / ICMPv6 Packet Too Big
    /// (the #2301/#2330 PMTUD generators).
    PacketTooBig,
    /// Policy / firewall-filter `reject` reply (TCP RST or ICMP/ICMPv6
    /// administratively-prohibited unreachable).
    Reject,
}

/// Default sustained refill rate, in tokens (= permitted generated errors) per
/// second, applied PER reason. 1000/s mirrors Linux's `icmp_msgs_per_sec`
/// default. A legitimate router emits these errors at a trickle (a real
/// PMTUD/traceroute path is a handful per flow); 1000/s per reason is far above
/// any benign rate yet caps a flood at three orders of magnitude below
/// line-rate amplification.
pub(in crate::afxdp) const DEFAULT_RATE_PER_SEC: u64 = 1000;

/// Default burst depth (bucket capacity), PER reason. Allows a short legitimate
/// burst (e.g. a traceroute fan-out or an MTU-change storm at the start of many
/// flows) to pass without being clipped, while still bounding the steady-state
/// rate to `DEFAULT_RATE_PER_SEC`.
pub(in crate::afxdp) const DEFAULT_BURST: u64 = 1000;

const NANOS_PER_SEC: u64 = 1_000_000_000;

/// A lock-free token bucket. `tokens` is stored in MILLITOKENS (tokens * 1000)
/// so that a sub-token-per-tick refill (the common case at nanosecond
/// granularity) accumulates without integer-truncation starvation. `last_ns`
/// is the monotonic timestamp of the last refill. Both are plain atomics; the
/// `try_take` CAS loop keeps them mutually consistent without a lock.
struct TokenBucket {
    /// Available tokens * 1000. Capacity is `burst * 1000`.
    millitokens: AtomicU64,
    /// Monotonic nanos at the last refill.
    last_ns: AtomicU64,
    /// Count of generated errors dropped because the bucket was empty.
    rate_limited: AtomicU64,
}

impl TokenBucket {
    const fn new() -> Self {
        // Start full (burst * 1000) so the first burst after boot is allowed.
        TokenBucket {
            millitokens: AtomicU64::new(DEFAULT_BURST * 1000),
            last_ns: AtomicU64::new(0),
            rate_limited: AtomicU64::new(0),
        }
    }

    /// Try to consume one token. Returns true when a token was available (the
    /// generated reply MAY be sent) and false when the bucket is empty (the
    /// reply MUST be dropped + the per-reason counter bumped by the caller).
    ///
    /// Refill is computed lazily from the elapsed time since `last_ns` at the
    /// configured `rate_per_sec`, capped at `burst`. The whole operation is a
    /// CAS loop over `millitokens`; `last_ns` advances monotonically.
    fn try_take(&self, now_ns: u64, rate_per_sec: u64, burst: u64) -> bool {
        let cap = burst.saturating_mul(1000);
        // A zero rate disables the bucket (unlimited) — never rate-limit. This
        // keeps the limiter opt-out-able via config without a branch at the
        // call site.
        if rate_per_sec == 0 {
            return true;
        }
        loop {
            let last = self.last_ns.load(Ordering::Relaxed);
            let cur = self.millitokens.load(Ordering::Relaxed);
            // Compute the lazily-accrued refill since `last`. Guard against a
            // non-monotonic / first-call (last == 0) sample.
            let elapsed = now_ns.saturating_sub(last);
            // refill_millitokens = elapsed_ns * rate_per_sec * 1000 / 1e9.
            // Order the multiply to stay within u128 and avoid truncation.
            let refill = ((elapsed as u128) * (rate_per_sec as u128) * 1000u128
                / (NANOS_PER_SEC as u128)) as u64;
            let refreshed = if last == 0 {
                // First use: treat the bucket as full; do not credit a huge
                // refill from the 0 epoch.
                cap
            } else {
                cur.saturating_add(refill).min(cap)
            };
            if refreshed < 1000 {
                // Less than one whole token even after refill — deny. Publish
                // the refilled level + advance the timestamp so the accrual is
                // not lost, but only when we actually moved time forward.
                if refill > 0 || last == 0 {
                    // best-effort: store refilled tokens and the new epoch.
                    let _ = self.millitokens.compare_exchange(
                        cur,
                        refreshed,
                        Ordering::Relaxed,
                        Ordering::Relaxed,
                    );
                    self.last_ns.store(now_ns, Ordering::Relaxed);
                }
                return false;
            }
            let after = refreshed - 1000;
            // Commit the consume. On contention, retry with a fresh read.
            if self
                .millitokens
                .compare_exchange(cur, after, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                // Advance the refill epoch only after a successful consume so a
                // racing thread does not lose accrued time. Storing `now_ns`
                // (not `last`) folds the just-applied refill into the epoch.
                self.last_ns.store(now_ns, Ordering::Relaxed);
                return true;
            }
            // CAS lost: another worker consumed/refilled concurrently; retry.
        }
    }
}

static TIME_EXCEEDED_BUCKET: TokenBucket = TokenBucket::new();
static PACKET_TOO_BIG_BUCKET: TokenBucket = TokenBucket::new();
static REJECT_BUCKET: TokenBucket = TokenBucket::new();

fn bucket_for(reason: GeneratedErrorReason) -> &'static TokenBucket {
    match reason {
        GeneratedErrorReason::TimeExceeded => &TIME_EXCEEDED_BUCKET,
        GeneratedErrorReason::PacketTooBig => &PACKET_TOO_BIG_BUCKET,
        GeneratedErrorReason::Reject => &REJECT_BUCKET,
    }
}

/// Returns true when a locally-generated error reply for `reason` MAY be sent
/// (a token was available), false when it MUST be dropped because the
/// per-reason bucket is empty. On a deny the per-reason `rate_limited` counter
/// is bumped so the suppression is observable via the coordinator status.
///
/// Uses the compile-time `DEFAULT_RATE_PER_SEC` / `DEFAULT_BURST`. The bucket
/// is global-per-reason (no per-source state), matching Linux's
/// `icmp_msgs_per_sec` model.
pub(in crate::afxdp) fn allow_generated_error(reason: GeneratedErrorReason) -> bool {
    allow_generated_error_at(reason, monotonic_nanos(), DEFAULT_RATE_PER_SEC, DEFAULT_BURST)
}

/// Testable core of [`allow_generated_error`] with an injected clock + rate /
/// burst, so the unit tests can drive a deterministic burst-then-refill
/// sequence without sleeping.
pub(in crate::afxdp) fn allow_generated_error_at(
    reason: GeneratedErrorReason,
    now_ns: u64,
    rate_per_sec: u64,
    burst: u64,
) -> bool {
    let bucket = bucket_for(reason);
    let allowed = bucket.try_take(now_ns, rate_per_sec, burst);
    if !allowed {
        bucket.rate_limited.fetch_add(1, Ordering::Relaxed);
    }
    allowed
}

/// Observable per-reason count of generated error replies dropped because the
/// reason's token bucket was empty. Surfaced via the coordinator status
/// (`*_rate_limited_total`).
pub(in crate::afxdp) fn rate_limited_count(reason: GeneratedErrorReason) -> u64 {
    bucket_for(reason).rate_limited.load(Ordering::Relaxed)
}

#[cfg(test)]
pub(in crate::afxdp) fn reset_bucket_for_test(reason: GeneratedErrorReason, now_ns: u64) {
    let bucket = bucket_for(reason);
    bucket
        .millitokens
        .store(DEFAULT_BURST * 1000, Ordering::Relaxed);
    bucket.last_ns.store(now_ns, Ordering::Relaxed);
    bucket.rate_limited.store(0, Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;

    // Each test uses a distinct (reason, rate, burst) so the global buckets do
    // not cross-contaminate across the parallel test runner. Where a test must
    // own a reason's bucket it resets it first under a fixed epoch.

    /// A burst up to `burst` passes; the (burst+1)th within the same instant is
    /// rate-limited (dropped + counter bumped). FAIL-ON-REVERT: without the
    /// limiter every call returns true and `rate_limited` stays 0, so the
    /// `assert!(!allowed)` + counter assertion both fail.
    #[test]
    fn burst_beyond_capacity_is_rate_limited() {
        let reason = GeneratedErrorReason::TimeExceeded;
        let t0 = 1_000_000_000u64;
        reset_bucket_for_test(reason, t0);
        let before = rate_limited_count(reason);
        // burst=5, rate=1000/s. At a frozen instant only 5 tokens are
        // available.
        for i in 0..5 {
            assert!(
                allow_generated_error_at(reason, t0, 1000, 5),
                "token {i} within burst must pass"
            );
        }
        // The 6th at the same instant: bucket empty → rate-limited.
        assert!(
            !allow_generated_error_at(reason, t0, 1000, 5),
            "beyond-burst generated error must be rate-limited"
        );
        assert_eq!(
            rate_limited_count(reason),
            before + 1,
            "the dropped generated error must bump the per-reason counter"
        );
    }

    /// Tokens refill over wall-clock time: after exhausting the burst, advancing
    /// the clock by enough to accrue >= 1 token at the configured rate restores
    /// capacity.
    #[test]
    fn refill_over_time_restores_capacity() {
        let reason = GeneratedErrorReason::PacketTooBig;
        let t0 = 5_000_000_000u64;
        reset_bucket_for_test(reason, t0);
        // burst=2, rate=1000/s → one token accrues every 1ms.
        assert!(allow_generated_error_at(reason, t0, 1000, 2));
        assert!(allow_generated_error_at(reason, t0, 1000, 2));
        assert!(
            !allow_generated_error_at(reason, t0, 1000, 2),
            "burst exhausted at the frozen instant"
        );
        // Advance 2ms → 2 tokens refill (capped at burst=2).
        let t1 = t0 + 2_000_000;
        assert!(
            allow_generated_error_at(reason, t1, 1000, 2),
            "a token must be available after the refill interval elapses"
        );
        assert!(
            allow_generated_error_at(reason, t1, 1000, 2),
            "second refilled token available"
        );
        assert!(
            !allow_generated_error_at(reason, t1, 1000, 2),
            "refill is capped at the burst depth"
        );
    }

    /// Per-reason isolation: exhausting the TimeExceeded bucket must not affect
    /// the Reject bucket. FAIL-ON-REVERT for a single-shared-bucket regression.
    #[test]
    fn reasons_are_isolated() {
        let te = GeneratedErrorReason::TimeExceeded;
        let rj = GeneratedErrorReason::Reject;
        let t0 = 9_000_000_000u64;
        reset_bucket_for_test(te, t0);
        reset_bucket_for_test(rj, t0);
        // Drain TimeExceeded (burst=1).
        assert!(allow_generated_error_at(te, t0, 1000, 1));
        assert!(
            !allow_generated_error_at(te, t0, 1000, 1),
            "TimeExceeded exhausted"
        );
        // Reject is untouched — still has its own capacity.
        assert!(
            allow_generated_error_at(rj, t0, 1000, 1),
            "Reject bucket must be independent of TimeExceeded exhaustion"
        );
    }

    /// A zero rate disables the limiter (opt-out): always allowed, counter
    /// never moves.
    #[test]
    fn zero_rate_disables_limiter() {
        let reason = GeneratedErrorReason::Reject;
        let t0 = 12_000_000_000u64;
        reset_bucket_for_test(reason, t0);
        let before = rate_limited_count(reason);
        for _ in 0..10_000 {
            assert!(
                allow_generated_error_at(reason, t0, 0, 1),
                "rate 0 means unlimited"
            );
        }
        assert_eq!(
            rate_limited_count(reason),
            before,
            "a disabled limiter must never bump the rate-limited counter"
        );
    }
}
