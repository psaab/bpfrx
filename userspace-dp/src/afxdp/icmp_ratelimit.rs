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
// that model: a per-reason token bucket (no per-source / per-destination map,
// so there is no attacker-driven map growth). Each reason has its own bucket so
// a TTL-exceeded flood cannot starve the PTB or reject reasons (and vice-versa)
// — per-reason isolation.
//
// #3618: the Reject reason is further split PER INGRESS (from) ZONE — one
// bucket per configured zone, held in `ForwardingState::reject_buckets` and
// resolved at the reject call site (`poll_descriptor::reject_reply`), with a
// process-global `REJECT_FALLBACK_BUCKET` for an unzoned/unknown zone. This
// removes the cross-zone starvation the single global Reject bucket had: a
// rejected-flow flood ingressing one zone can no longer drain the bucket and
// suppress a legitimate reject in another zone. TimeExceeded / PacketTooBig
// keep their single global-per-reason bucket (their generator sites lack a
// clean ingress zone id — see `docs/generated-reply-rate-limit.md`). The
// observable aggregate `reject_rate_limited_total` stays a SINGLE atomic
// (`REJECT_RATE_LIMITED_TOTAL`) bumped on any per-zone deny, so the coordinator
// status / Prometheus metric format is unchanged. Cardinality is
// config-bounded (configured zones, Go-capped ≤ 65533), so there is still no
// attacker-driven map growth.
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
use crate::afxdp::types::ForwardingState;

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
///
/// #3618: exposed as `pub(in crate::afxdp)` so `ForwardingState` can hold a
/// per-zone map of these for the Reject reason (`reject_buckets`). The fields
/// stay private to this module; the only cross-module entry points are
/// `TokenBucket::new()` (to build a fresh per-zone bucket at config apply) and
/// the `allow_generated_reject*` gates below (which do the `try_take` +
/// counter bump). Held behind an `Arc` in `ForwardingState` so the shared
/// atomics survive `ForwardingState::clone()` (fabric refresh re-stores a
/// clone at runtime cadence — see `forwarding.rs`).
#[derive(Debug)]
pub(in crate::afxdp) struct TokenBucket {
    /// Theoretical arrival time (monotonic nanos). The whole limiter state.
    /// Initialised to 0 so the first `burst` calls after boot pass (an
    /// effectively-full bucket: `0 - horizon` saturates to 0 <= any `now`).
    theoretical_arrival_ns: AtomicU64,
    /// Count of generated errors dropped because the bucket was empty.
    rate_limited: AtomicU64,
}

impl TokenBucket {
    pub(in crate::afxdp) const fn new() -> Self {
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
        let interval_ns = (NANOS_PER_SEC.saturating_add(rate_per_sec - 1) / rate_per_sec).max(1);
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

/// #3618: shared fallback Reject bucket used when a reject's ingress (from)
/// zone has NO per-zone bucket — an unzoned (id 0) or otherwise-unknown zone
/// id. It is a REAL bucket (never a fail-open skip), so an unzoned/unknown
/// reject is still rate-limited; such rejects all share this one budget (the
/// rare/degenerate case, not a per-zone diagnostic). This replaces the former
/// single global `REJECT_BUCKET`: the per-zone buckets now live in
/// `ForwardingState::reject_buckets` (built from the configured zone set), so a
/// rejected-flow flood on one zone can no longer drain a single global bucket
/// and starve reject-generation in another zone.
static REJECT_FALLBACK_BUCKET: TokenBucket = TokenBucket::new();

/// #3618: process-global aggregate count of Reject replies dropped because the
/// (per-zone OR fallback) bucket was empty. A SINGLE atomic bumped on ANY
/// per-zone deny — NOT a sum over the per-zone buckets' `rate_limited` fields —
/// so `rate_limited_count(Reject)` stays an O(1) atomic load and the
/// coordinator status / Prometheus `reject_rate_limited_total` wire contract is
/// UNCHANGED by the per-zone split. Each per-zone `TokenBucket` keeps its own
/// `rate_limited` field for OPTIONAL future per-zone attribution; the aggregate
/// metric never reads those fields.
static REJECT_RATE_LIMITED_TOTAL: AtomicU64 = AtomicU64::new(0);

/// TE / PTB keep their single global-per-reason bucket. For the Reject reason
/// this returns the shared `REJECT_FALLBACK_BUCKET`: it is the bucket the
/// non-zone-keyed `allow_generated_error(Reject)` back-compat entry point and
/// the test reset/drain helpers operate on. The zone-keyed reject path
/// (`allow_generated_reject*`) resolves a per-zone bucket first and falls back
/// to this same static, so both stay consistent.
fn bucket_for(reason: GeneratedErrorReason) -> &'static TokenBucket {
    match reason {
        GeneratedErrorReason::TimeExceeded => &TIME_EXCEEDED_BUCKET,
        GeneratedErrorReason::PacketTooBig => &PACKET_TOO_BIG_BUCKET,
        GeneratedErrorReason::Reject => &REJECT_FALLBACK_BUCKET,
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
    allow_generated_error_at(
        reason,
        monotonic_nanos(),
        DEFAULT_RATE_PER_SEC,
        DEFAULT_BURST,
    )
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
        // #3618: keep the aggregate Reject counter authoritative regardless of
        // which entry point denied. `rate_limited_count(Reject)` now reads the
        // dedicated `REJECT_RATE_LIMITED_TOTAL`, so this back-compat entry point
        // (still reachable via `allow_generated_error(Reject)` + the test
        // drain/reset helpers, which operate on `REJECT_FALLBACK_BUCKET`) must
        // bump it too. TE/PTB keep their per-bucket field as the aggregate.
        if reason == GeneratedErrorReason::Reject {
            REJECT_RATE_LIMITED_TOTAL.fetch_add(1, Ordering::Relaxed);
        }
    }
    allowed
}

/// #3618: zone-scoped variant of the Reject gate. Returns true when a
/// locally-generated reject reply whose ingress (from) zone is `from_zone_id`
/// MAY be sent (its per-zone bucket had a token), false when it MUST be dropped
/// because that zone's bucket is empty. The per-zone bucket comes from
/// `forwarding.reject_buckets` (built from the configured zone set at config
/// apply); an unzoned (id 0) or otherwise-unknown zone id falls back to the
/// shared process-global `REJECT_FALLBACK_BUCKET` — a real bucket, so the gate
/// is NEVER fail-open and never panics on a missing key. On a deny the single
/// aggregate `REJECT_RATE_LIMITED_TOTAL` is bumped (metric unchanged) alongside
/// the bucket's own `rate_limited` field (optional per-zone attribution).
///
/// TimeExceeded / PacketTooBig stay on the global-per-reason
/// `allow_generated_error` — they lack a clean ingress zone at their generator
/// sites (see `docs/generated-reply-rate-limit.md`).
pub(in crate::afxdp) fn allow_generated_reject(
    forwarding: &ForwardingState,
    from_zone_id: u16,
) -> bool {
    allow_generated_reject_at(
        forwarding,
        from_zone_id,
        monotonic_nanos(),
        DEFAULT_RATE_PER_SEC,
        DEFAULT_BURST,
    )
}

/// Testable core of [`allow_generated_reject`] with an injected clock + rate /
/// burst, so the unit tests can drive a deterministic per-zone burst-then-drain
/// sequence without sleeping.
pub(in crate::afxdp) fn allow_generated_reject_at(
    forwarding: &ForwardingState,
    from_zone_id: u16,
    now_ns: u64,
    rate_per_sec: u64,
    burst: u64,
) -> bool {
    let bucket = forwarding
        .reject_bucket(from_zone_id)
        .unwrap_or(&REJECT_FALLBACK_BUCKET);
    let allowed = bucket.try_take(now_ns, rate_per_sec, burst);
    if !allowed {
        // Per-zone attribution (optional future accessor).
        bucket.rate_limited.fetch_add(1, Ordering::Relaxed);
        // Aggregate metric — a single atomic, bumped on every per-zone deny.
        REJECT_RATE_LIMITED_TOTAL.fetch_add(1, Ordering::Relaxed);
    }
    allowed
}

/// Observable per-reason count of generated error replies dropped because the
/// reason's token bucket was empty. Surfaced via the coordinator status
/// (`*_rate_limited_total`). #3618: the Reject reason reads the dedicated
/// process-global aggregate (`REJECT_RATE_LIMITED_TOTAL`), which is bumped on
/// every per-zone (and fallback) deny — an O(1) atomic load, never a sum over
/// the per-zone buckets, so the wire/metric format is unchanged. TE/PTB still
/// read their single bucket's `rate_limited` field.
pub(in crate::afxdp) fn rate_limited_count(reason: GeneratedErrorReason) -> u64 {
    match reason {
        GeneratedErrorReason::Reject => REJECT_RATE_LIMITED_TOTAL.load(Ordering::Relaxed),
        _ => bucket_for(reason).rate_limited.load(Ordering::Relaxed),
    }
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
pub(in crate::afxdp) fn global_bucket_test_lock() -> std::sync::MutexGuard<'static, ()> {
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
    // #3618: also clear the dedicated aggregate so a test that asserts an exact
    // `rate_limited_count(Reject)` starts from a clean slate (the Reject
    // aggregate is a separate atomic from the fallback bucket's field).
    if reason == GeneratedErrorReason::Reject {
        REJECT_RATE_LIMITED_TOTAL.store(0, Ordering::Relaxed);
    }
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

    use crate::afxdp::types::FastMap;
    use std::sync::Arc;

    /// Build a `ForwardingState` carrying a fresh per-zone Reject bucket for
    /// each given zone id (#3618 test helper).
    fn forwarding_with_reject_zones(zone_ids: &[u16]) -> ForwardingState {
        let mut reject_buckets: FastMap<u16, Arc<TokenBucket>> = FastMap::default();
        for &id in zone_ids {
            reject_buckets.insert(id, Arc::new(TokenBucket::new()));
        }
        ForwardingState {
            reject_buckets,
            ..ForwardingState::default()
        }
    }

    /// #3618 HEADLINE fail-on-revert: a rejected-flow flood that drains ZONE A's
    /// per-zone Reject bucket must NOT prevent ZONE B from generating its
    /// reject. Reverting to a SINGLE global Reject bucket makes draining A empty
    /// the one shared bucket, so B is then denied and this assertion goes RED.
    /// This is the direct proof of the #3618 per-zone isolation fix — one
    /// ingress zone can no longer starve another's reject-generation.
    #[test]
    fn reject_per_zone_flood_does_not_starve_other_zone_3618() {
        let _g = global_bucket_test_lock();
        // Sparse, realistic stable-name-hash zone ids (NOT dense 1,2).
        let zone_a = 41_337u16;
        let zone_b = 9_002u16;
        let t0 = 3_000_000_000u64;
        let forwarding = forwarding_with_reject_zones(&[zone_a, zone_b]);
        // Drain zone A at a frozen instant (burst = 4).
        for i in 0..4 {
            assert!(
                allow_generated_reject_at(&forwarding, zone_a, t0, 1000, 4),
                "zone A token {i} within burst must pass"
            );
        }
        assert!(
            !allow_generated_reject_at(&forwarding, zone_a, t0, 1000, 4),
            "zone A bucket must be drained after its burst"
        );
        // Zone B, under no load, still generates its reject at the SAME instant.
        assert!(
            allow_generated_reject_at(&forwarding, zone_b, t0, 1000, 4),
            "zone B must NOT be starved by zone A's flood (per-zone isolation)"
        );
    }

    /// #3618: an unzoned (id 0) or otherwise-unknown from-zone id has no
    /// per-zone bucket, so the gate falls back to the shared process-global
    /// `REJECT_FALLBACK_BUCKET` — a real bucket (never fail-open) that still
    /// rate-limits and never panics on the absent key. Both an unknown id and
    /// id 0 SHARE the one fallback budget.
    #[test]
    fn reject_unknown_and_unzoned_share_fallback_bucket_3618() {
        let _g = global_bucket_test_lock();
        let t0 = 6_000_000_000u64;
        // Reset the fallback bucket (+ aggregate) to full at epoch t0.
        reset_bucket_for_test(GeneratedErrorReason::Reject, t0);
        // Empty map: every zone id resolves to the fallback.
        let forwarding = ForwardingState::default();
        let unknown = 55_555u16;
        // burst = 2 on the shared fallback: an unknown-id reject and an
        // unzoned (id 0) reject each take one token; the third is denied.
        assert!(allow_generated_reject_at(&forwarding, unknown, t0, 1000, 2));
        assert!(allow_generated_reject_at(&forwarding, 0, t0, 1000, 2));
        assert!(
            !allow_generated_reject_at(&forwarding, unknown, t0, 1000, 2),
            "unknown / unzoned rejects share and are bounded by the fallback bucket"
        );
    }

    /// #3618 metric-preservation fail-on-revert: the aggregate
    /// `reject_rate_limited_total` (a SINGLE global atomic, NOT a per-zone sum)
    /// is bumped on EVERY per-zone deny, so the coordinator status / Prometheus
    /// contract is unchanged by the per-zone split. Drain two zones by K1 and K2
    /// and assert the aggregate advanced by exactly K1 + K2.
    #[test]
    fn reject_aggregate_counter_sums_across_zones_3618() {
        let _g = global_bucket_test_lock();
        let t0 = 8_000_000_000u64;
        reset_bucket_for_test(GeneratedErrorReason::Reject, t0); // aggregate -> 0
        let zone_a = 111u16;
        let zone_b = 222u16;
        let forwarding = forwarding_with_reject_zones(&[zone_a, zone_b]);
        let before = rate_limited_count(GeneratedErrorReason::Reject);
        let k1 = 3u64;
        let k2 = 5u64;
        // burst = 1 per zone: one pass, then K denies each.
        assert!(allow_generated_reject_at(&forwarding, zone_a, t0, 1000, 1));
        for _ in 0..k1 {
            assert!(!allow_generated_reject_at(&forwarding, zone_a, t0, 1000, 1));
        }
        assert!(allow_generated_reject_at(&forwarding, zone_b, t0, 1000, 1));
        for _ in 0..k2 {
            assert!(!allow_generated_reject_at(&forwarding, zone_b, t0, 1000, 1));
        }
        assert_eq!(
            rate_limited_count(GeneratedErrorReason::Reject),
            before + k1 + k2,
            "aggregate reject_rate_limited_total must sum every per-zone deny (metric unchanged)"
        );
    }

    /// #3618: per-zone Reject buckets stay isolated from the TimeExceeded /
    /// PacketTooBig reasons (reason isolation, #2472). Draining a zone's Reject
    /// bucket must not affect the TE/PTB global buckets, and vice-versa.
    #[test]
    fn reject_per_zone_isolated_from_other_reasons_3618() {
        let _g = global_bucket_test_lock();
        let t0 = 10_000_000_000u64;
        reset_bucket_for_test(GeneratedErrorReason::TimeExceeded, t0);
        let zone_a = 700u16;
        let forwarding = forwarding_with_reject_zones(&[zone_a]);
        // Drain zone A's Reject bucket (burst = 1).
        assert!(allow_generated_reject_at(&forwarding, zone_a, t0, 1000, 1));
        assert!(!allow_generated_reject_at(&forwarding, zone_a, t0, 1000, 1));
        // TimeExceeded (a different reason, global bucket) is untouched.
        assert!(
            allow_generated_error_at(GeneratedErrorReason::TimeExceeded, t0, 1000, 1),
            "TE bucket must be independent of a zone's Reject exhaustion"
        );
    }
}
