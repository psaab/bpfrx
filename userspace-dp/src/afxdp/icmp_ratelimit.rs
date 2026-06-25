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
// Hot-path: the check is a single CAS loop over ONE atomic word (a GCRA
// theoretical-arrival-time; #2955 collapsed the prior split token-count +
// timestamp pair into this single CAS so refill and consume commit together
// and concurrent workers cannot double-credit / over-admit). It runs ONLY on
// the cold generated-error path (per TTL-exceeded / PTB / reject decision),
// never per forwarded packet, and never allocates. On bucket-empty the
// generated reply is DROPPED and a per-reason
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

/// A lock-free GCRA (Generic Cell Rate Algorithm) token bucket. #2955: the
/// state is a SINGLE atomic word — the "theoretical arrival time" (TAT) in
/// monotonic nanos — so refill and consume commit together in one CAS. The
/// previous implementation split the state into two independent atomics
/// (`millitokens` + `last_ns`) and CAS-committed only `millitokens`, then
/// published `last_ns` as a separate relaxed store. Two workers could observe
/// the new (lower) token count with the OLD timestamp and credit the same
/// refill interval twice (double-credit), or both observe the `last_ns == 0`
/// first-use branch and each refill to full burst — over-admitting generated
/// error replies past the configured rate and corrupting the
/// `rate_limited_total` counters on the DoS boundary.
///
/// GCRA encodes the bucket as one number: as long as `tat - burst_horizon <=
/// now`, a token is available, and a successful consume advances `tat` by one
/// `interval`. Because `tat` is the entire state, there is no second field to
/// tear against — the single CAS atomically refills AND consumes. This is the
/// same single-TAT pattern used by `event_stream/producer.rs`.
struct TokenBucket {
    /// Theoretical arrival time (monotonic nanos). The whole limiter state.
    /// Initialised to 0 so the first `burst` calls after boot pass (an
    /// effectively-full bucket: `0 - horizon` saturates to 0 <= any `now`).
    theoretical_arrival_ns: AtomicU64,
    /// Count of generated errors dropped because the bucket was empty.
    rate_limited: AtomicU64,
}

impl TokenBucket {
    const fn new() -> Self {
        TokenBucket {
            theoretical_arrival_ns: AtomicU64::new(0),
            rate_limited: AtomicU64::new(0),
        }
    }

    /// Try to consume one token. Returns true when a token was available (the
    /// generated reply MAY be sent) and false when the bucket is empty (the
    /// reply MUST be dropped + the per-reason counter bumped by the caller).
    ///
    /// GCRA: `interval_ns = 1e9 / rate_per_sec` is the steady-state spacing
    /// between admitted replies; `burst_horizon_ns = (burst - 1) * interval`
    /// is how far ahead of `now` the TAT may run while still admitting a
    /// burst. The refill (advancing the admissible window as `now` grows) and
    /// the consume (advancing `tat` by one interval) are committed TOGETHER in
    /// a single `compare_exchange` over the one state word, so concurrent
    /// workers can never double-credit or over-admit (#2955).
    fn try_take(&self, now_ns: u64, rate_per_sec: u64, burst: u64) -> bool {
        // A zero rate disables the bucket (unlimited) — never rate-limit. This
        // keeps the limiter opt-out-able via config without a branch at the
        // call site.
        if rate_per_sec == 0 {
            return true;
        }
        // interval = nanos between admitted tokens at the steady rate. Round up
        // so a high rate never collapses to a zero interval (which would admit
        // unboundedly). A burst of 0 is treated as 1 (no negative horizon).
        let interval_ns =
            (NANOS_PER_SEC.saturating_add(rate_per_sec - 1) / rate_per_sec).max(1);
        let burst_horizon_ns = interval_ns.saturating_mul(burst.saturating_sub(1));

        let mut tat = self.theoretical_arrival_ns.load(Ordering::Relaxed);
        loop {
            // Bucket empty: the next admission would push the TAT more than the
            // burst horizon ahead of the current time. Deny WITHOUT mutating
            // state (a denied call must not advance the epoch — sibling tests
            // and the far-future-drain pattern in reject_reply.rs rely on this).
            if tat.saturating_sub(burst_horizon_ns) > now_ns {
                return false;
            }
            // Refill + consume in ONE value: clamp the TAT forward to `now`
            // (this is the lazy refill — never let the bucket accrue more than
            // `burst` worth of credit) and add one interval (the consume).
            let next_tat = tat.max(now_ns).saturating_add(interval_ns);
            match self.theoretical_arrival_ns.compare_exchange_weak(
                tat,
                next_tat,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                // Single CAS committed refill AND consume atomically.
                Ok(_) => return true,
                // CAS lost: another worker advanced the TAT concurrently. Retry
                // with the observed value — never with stale split state.
                Err(actual) => tat = actual,
            }
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

/// #2955: serialises every test that drives the GLOBAL per-reason buckets.
/// The buckets are process-wide statics shared across modules (this module's
/// unit tests AND `poll_descriptor::reject_reply`'s tests), and the GCRA TAT
/// advances monotonically and never travels backwards. So a
/// `reset_bucket_for_test` from one test interleaved with a TAT advance / drain
/// from another can starve a sibling (e.g. a drain-to-far-future leaves the
/// Reject bucket denied for a concurrent success-path test). The old
/// millitoken reset-to-full was order-independent and hid this; the
/// race-immune single-word limiter is order-SENSITIVE under the cargo parallel
/// runner, so the *tests* must serialise their reset→drive→assert window over
/// the shared statics. Every global-bucket test holds this guard for its whole
/// body. (Tests using a LOCAL `TokenBucket` — the #2955 concurrency guards —
/// touch no shared state and do not take the lock.)
#[cfg(test)]
pub(in crate::afxdp) fn global_bucket_test_lock()
-> std::sync::MutexGuard<'static, ()> {
    use std::sync::Mutex;
    static LOCK: Mutex<()> = Mutex::new(());
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

#[cfg(test)]
pub(in crate::afxdp) fn reset_bucket_for_test(reason: GeneratedErrorReason, now_ns: u64) {
    let bucket = bucket_for(reason);
    // GCRA: a full bucket at epoch `now_ns` is `tat == now_ns` (the next
    // `burst` admissions all satisfy `tat - horizon <= now`). Tests that pin a
    // FAR-FUTURE epoch then drain rely on this: after draining at `now_ns`,
    // `tat` runs `burst * interval` ahead, and a later call at a SMALLER clock
    // value stays denied (the GCRA window never travels backwards).
    bucket
        .theoretical_arrival_ns
        .store(now_ns, Ordering::Relaxed);
    bucket.rate_limited.store(0, Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A burst up to `burst` passes; the (burst+1)th within the same instant is
    /// rate-limited (dropped + counter bumped). FAIL-ON-REVERT: without the
    /// limiter every call returns true and `rate_limited` stays 0, so the
    /// `assert!(!allowed)` + counter assertion both fail.
    #[test]
    fn burst_beyond_capacity_is_rate_limited() {
        let _g = global_bucket_test_lock();
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
        let _g = global_bucket_test_lock();
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
        let _g = global_bucket_test_lock();
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

    /// #2955 FAIL-ON-REVERT: under heavy multi-thread contention at a FROZEN
    /// first-use instant, the limiter must admit AT MOST `burst` tokens — never
    /// more — regardless of interleaving. The pre-#2955 split-atomic
    /// implementation (CAS `millitokens`, then a SEPARATE relaxed `last_ns`
    /// store) let every worker that read while `last_ns == 0` (the boot epoch)
    /// take the first-use branch and force `refreshed = cap`, each granting
    /// itself a full burst — admitting MORE than `burst` total (a torn
    /// refill/double-credit). With the GCRA single-CAS word, refill and consume
    /// commit together, so the admitted count is hard-capped at `burst`.
    ///
    /// This mirrors the demonstrated race vector exactly: each trial starts from
    /// `TokenBucket::new()` (TAT == 0, the boot/first-use state) and a start
    /// barrier maximises the simultaneous-read window. Every call uses the SAME
    /// frozen `now_ns`, so no real time elapses and the only legitimately
    /// admissible tokens are the initial burst — any `total > burst` is the bug.
    /// Verified RED against the split-atomic revert (admitted 51 > burst 50).
    #[test]
    fn concurrent_hammer_never_over_admits() {
        use std::sync::atomic::AtomicU64;
        use std::sync::{Arc, Barrier};
        use std::thread;

        let now = 100_000_000_000u64;
        let rate = 1000u64;
        let burst = 50u64;
        let threads = 16;
        let calls_per_thread = 200u64;

        for trial in 0..2000 {
            let bucket = Arc::new(TokenBucket::new()); // TAT == 0 (boot/first-use)
            let admitted = Arc::new(AtomicU64::new(0));
            let barrier = Arc::new(Barrier::new(threads));
            let handles: Vec<_> = (0..threads)
                .map(|_| {
                    let bucket = Arc::clone(&bucket);
                    let admitted = Arc::clone(&admitted);
                    let barrier = Arc::clone(&barrier);
                    thread::spawn(move || {
                        barrier.wait();
                        for _ in 0..calls_per_thread {
                            if bucket.try_take(now, rate, burst) {
                                admitted.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    })
                })
                .collect();
            for h in handles {
                h.join().unwrap();
            }
            let total = admitted.load(Ordering::Relaxed);
            assert!(
                total <= burst,
                "trial {trial}: at a frozen first-use instant the limiter must \
                 admit AT MOST the burst ({burst}); admitted {total} means a \
                 split-atomic double-credit over-admit (the #2955 race)"
            );
        }
    }

    /// #2955 deterministic atomicity guard: a single successful `try_take`
    /// advances the WHOLE state word by exactly one interval. If the refill and
    /// consume were ever split back into two atomics, a reader between them
    /// could observe an inconsistent (consumed-but-not-timestamped) state. Here
    /// we assert the GCRA invariant directly: from a full bucket at `now`, after
    /// `burst` admissions the TAT is exactly `now + burst * interval`, and the
    /// next admission is denied without further advancing the word.
    #[test]
    fn single_word_state_advances_atomically() {
        let now = 7_000_000_000u64;
        let rate = 1000u64; // interval = 1ms
        let burst = 8u64;
        let interval = NANOS_PER_SEC / rate;

        let bucket = TokenBucket::new();
        bucket.theoretical_arrival_ns.store(now, Ordering::Relaxed);

        for i in 0..burst {
            assert!(bucket.try_take(now, rate, burst), "burst token {i}");
            assert_eq!(
                bucket.theoretical_arrival_ns.load(Ordering::Relaxed),
                now + (i + 1) * interval,
                "each admit advances the single state word by exactly one \
                 interval — refill+consume committed together"
            );
        }
        // Bucket empty at the frozen instant.
        assert!(!bucket.try_take(now, rate, burst), "burst exhausted");
        assert_eq!(
            bucket.theoretical_arrival_ns.load(Ordering::Relaxed),
            now + burst * interval,
            "a denied call must NOT advance the state word"
        );
    }

    /// A zero rate disables the limiter (opt-out): always allowed, counter
    /// never moves.
    #[test]
    fn zero_rate_disables_limiter() {
        let _g = global_bucket_test_lock();
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
