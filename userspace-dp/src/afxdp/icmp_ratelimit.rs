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
// #3618 / #5856: ALL THREE reasons are split PER INGRESS (from) ZONE — one
// bucket per configured zone, held in `ForwardingState::{reject_buckets,
// time_exceeded_buckets, packet_too_big_buckets}` and resolved at each
// generator call site from the ingress ifindex, with a process-global
// per-reason fallback bucket (`{REJECT,TIME_EXCEEDED,PACKET_TOO_BIG}_
// FALLBACK_BUCKET`) for an unzoned/unknown zone. This removes the cross-zone
// starvation the single global buckets had: a flood ingressing one zone can
// no longer drain the bucket and suppress a legitimate generated error in
// another zone.
//
// #3618 split ONLY Reject (the reject call site carried `from_zone_id`);
// #5856 extends the IDENTICAL per-zone mechanism to TimeExceeded (resolved
// from `ingress_ident.ifindex` in `icmp::build_local_time_exceeded_request`)
// and PacketTooBig (resolved from `ingress_ident.ifindex` in the TX dispatch
// PTB path) — closing the cross-zone denial that let one zone flood
// TTL=1/hop-limit=1 or oversized-DF traffic and suppress legitimate
// traceroute / PMTUD replies for every OTHER zone. The generator sites always
// carried ingress identity; the missing zone key was an API omission, not
// absence of attribution (see `docs/generated-reply-rate-limit.md`).
//
// The observable aggregate `*_rate_limited_total` stays a SINGLE atomic per
// reason (`{REJECT,TIME_EXCEEDED,PACKET_TOO_BIG}_RATE_LIMITED_TOTAL`) bumped on
// any per-zone deny, so the coordinator status / Prometheus metric format is
// unchanged. Cardinality is config-bounded for every reason (configured zones,
// Go-capped ≤ 65533), so there is still no attacker-driven map growth.
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
/// #3618/#5856: exposed as `pub(in crate::afxdp)` so `ForwardingState` can hold
/// per-zone maps of these for EVERY reason (`reject_buckets`,
/// `time_exceeded_buckets`, `packet_too_big_buckets`). The fields stay private
/// to this module; the only cross-module entry points are `TokenBucket::new()`
/// (to build a fresh per-zone bucket at config apply) and the
/// `allow_generated_*` gates below (which do the `try_take` + counter bump).
/// Held behind an `Arc` in `ForwardingState` so the shared atomics survive
/// `ForwardingState::clone()` (fabric refresh re-stores a clone at runtime
/// cadence — see `forwarding.rs`).
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
    /// #7174 M04 test observable. `theoretical_arrival_ns` IS the limiter state:
    /// consuming a token advances it, declining to consume leaves it alone. So
    /// "did this path spend a token?" is exactly "did this value move?", which
    /// is a precise question a burst-exhaustion probe can only approximate.
    #[cfg(test)]
    pub(in crate::afxdp) fn arrival_ns(&self) -> u64 {
        self.theoretical_arrival_ns.load(Ordering::Relaxed)
    }

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

/// #3618/#5856: shared per-reason fallback bucket used when a generated error's
/// ingress (from) zone has NO per-zone bucket — an unzoned (id 0) or
/// otherwise-unknown zone id. Each is a REAL bucket (never a fail-open skip),
/// so an unzoned/unknown error is still rate-limited; such errors all share the
/// reason's one fallback budget (the rare/degenerate case, not a per-zone
/// diagnostic). The per-zone buckets now live in `ForwardingState`
/// (`reject_buckets` #3618; `time_exceeded_buckets` / `packet_too_big_buckets`
/// #5856), built from the configured zone set, so a flood on one zone can no
/// longer drain a single global bucket and starve error-generation in another
/// zone.
static REJECT_FALLBACK_BUCKET: TokenBucket = TokenBucket::new();
static TIME_EXCEEDED_FALLBACK_BUCKET: TokenBucket = TokenBucket::new();
static PACKET_TOO_BIG_FALLBACK_BUCKET: TokenBucket = TokenBucket::new();

/// #3618/#5856: process-global aggregate count, PER reason, of generated error
/// replies dropped because the (per-zone OR fallback) bucket was empty. A
/// SINGLE atomic per reason bumped on ANY per-zone deny — NOT a sum over the
/// per-zone buckets' `rate_limited` fields — so `rate_limited_count(reason)`
/// stays an O(1) atomic load and the coordinator status / Prometheus
/// `*_rate_limited_total` wire contract is UNCHANGED by the per-zone split.
/// Each per-zone `TokenBucket` keeps its own `rate_limited` field for OPTIONAL
/// future per-zone attribution; the aggregate metric never reads those fields.
static REJECT_RATE_LIMITED_TOTAL: AtomicU64 = AtomicU64::new(0);
static TIME_EXCEEDED_RATE_LIMITED_TOTAL: AtomicU64 = AtomicU64::new(0);
static PACKET_TOO_BIG_RATE_LIMITED_TOTAL: AtomicU64 = AtomicU64::new(0);

/// The reason's shared fallback bucket: the bucket the non-zone-keyed
/// `allow_generated_error_at` back-compat/test entry point and the test
/// reset/drain helpers operate on. The zone-keyed gates
/// (`allow_generated_error_zoned*`) resolve a per-zone bucket first and fall
/// back to this same static, so both stay consistent.
fn bucket_for(reason: GeneratedErrorReason) -> &'static TokenBucket {
    match reason {
        GeneratedErrorReason::TimeExceeded => &TIME_EXCEEDED_FALLBACK_BUCKET,
        GeneratedErrorReason::PacketTooBig => &PACKET_TOO_BIG_FALLBACK_BUCKET,
        GeneratedErrorReason::Reject => &REJECT_FALLBACK_BUCKET,
    }
}

/// The reason's process-global aggregate rate-limited counter. A SINGLE atomic
/// per reason, bumped on every per-zone (and fallback) deny, read O(1) by
/// `rate_limited_count`. This is what keeps the observable `*_rate_limited_total`
/// wire contract unchanged across the per-zone split (#3618/#5856).
fn rate_limited_total(reason: GeneratedErrorReason) -> &'static AtomicU64 {
    match reason {
        GeneratedErrorReason::TimeExceeded => &TIME_EXCEEDED_RATE_LIMITED_TOTAL,
        GeneratedErrorReason::PacketTooBig => &PACKET_TOO_BIG_RATE_LIMITED_TOTAL,
        GeneratedErrorReason::Reject => &REJECT_RATE_LIMITED_TOTAL,
    }
}

/// Non-zone-keyed testable core: try one token against `reason`'s FALLBACK
/// bucket with an injected clock + rate / burst, so the unit tests can drive a
/// deterministic burst-then-refill sequence without sleeping. On a deny it
/// bumps BOTH the fallback bucket's own `rate_limited` field and the reason's
/// aggregate `*_RATE_LIMITED_TOTAL`, so `rate_limited_count(reason)` (which
/// reads the aggregate) stays authoritative regardless of entry point.
///
/// Test-only: production TE/PTB/Reject gates all go through the zone-keyed
/// [`allow_generated_error_zoned_at`] (which itself falls back to this reason's
/// FALLBACK bucket for an unzoned/unknown zone), so the pure-fallback path is
/// exercised directly only by the unit tests.
#[cfg(test)]
pub(in crate::afxdp) fn allow_generated_error_at(
    reason: GeneratedErrorReason,
    now_ns: u64,
    rate_per_sec: u64,
    burst: u64,
) -> bool {
    take_and_account(bucket_for(reason), reason, now_ns, rate_per_sec, burst)
}

/// #3618/#5856: zone-scoped generated-error gate. Returns true when a
/// locally-generated error reply for `reason` whose ingress (from) zone is
/// `from_zone_id` MAY be sent (its per-zone bucket had a token), false when it
/// MUST be dropped because that zone's bucket is empty. The per-zone bucket
/// comes from `ForwardingState` (`reject_buckets` / `time_exceeded_buckets` /
/// `packet_too_big_buckets`, built from the configured zone set at config
/// apply); an unzoned (id 0) or otherwise-unknown zone id falls back to the
/// reason's shared process-global `*_FALLBACK_BUCKET` — a real bucket, so the
/// gate is NEVER fail-open and never panics on a missing key. On a deny the
/// reason's single aggregate `*_RATE_LIMITED_TOTAL` is bumped (metric
/// unchanged) alongside the bucket's own `rate_limited` field (optional
/// per-zone attribution).
pub(in crate::afxdp) fn allow_generated_error_zoned(
    forwarding: &ForwardingState,
    reason: GeneratedErrorReason,
    from_zone_id: u16,
) -> bool {
    allow_generated_error_zoned_at(
        forwarding,
        reason,
        from_zone_id,
        monotonic_nanos(),
        DEFAULT_RATE_PER_SEC,
        DEFAULT_BURST,
    )
}

/// Testable core of [`allow_generated_error_zoned`] with an injected clock +
/// rate / burst, so the unit tests can drive a deterministic per-zone
/// burst-then-drain sequence without sleeping.
pub(in crate::afxdp) fn allow_generated_error_zoned_at(
    forwarding: &ForwardingState,
    reason: GeneratedErrorReason,
    from_zone_id: u16,
    now_ns: u64,
    rate_per_sec: u64,
    burst: u64,
) -> bool {
    let bucket = forwarding
        .generated_error_bucket(reason, from_zone_id)
        .unwrap_or_else(|| bucket_for(reason));
    take_and_account(bucket, reason, now_ns, rate_per_sec, burst)
}

/// #3618: reject-reason convenience wrapper over the generic zone-keyed gate.
/// Kept as a named entry point for `poll_descriptor::reject_reply` and the
/// existing reject unit tests; behaviour is identical to
/// `allow_generated_error_zoned(_, Reject, _)`.
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

/// Testable core of [`allow_generated_reject`] — delegates to the generic
/// zone-keyed gate with the Reject reason.
pub(in crate::afxdp) fn allow_generated_reject_at(
    forwarding: &ForwardingState,
    from_zone_id: u16,
    now_ns: u64,
    rate_per_sec: u64,
    burst: u64,
) -> bool {
    allow_generated_error_zoned_at(
        forwarding,
        GeneratedErrorReason::Reject,
        from_zone_id,
        now_ns,
        rate_per_sec,
        burst,
    )
}

/// Consume one token from `bucket` and, on a deny, bump BOTH the bucket's own
/// per-zone/fallback `rate_limited` field (optional attribution) and the
/// reason's single aggregate `*_RATE_LIMITED_TOTAL` (the observable metric).
/// This is the ONE accounting site shared by the zone-keyed and fallback gates,
/// so every deny — per-zone or fallback — advances the aggregate exactly once.
fn take_and_account(
    bucket: &TokenBucket,
    reason: GeneratedErrorReason,
    now_ns: u64,
    rate_per_sec: u64,
    burst: u64,
) -> bool {
    let allowed = bucket.try_take(now_ns, rate_per_sec, burst);
    if !allowed {
        bucket.rate_limited.fetch_add(1, Ordering::Relaxed);
        rate_limited_total(reason).fetch_add(1, Ordering::Relaxed);
    }
    allowed
}

/// Observable per-reason count of generated error replies dropped because the
/// reason's token bucket was empty. Surfaced via the coordinator status
/// (`*_rate_limited_total`). #3618/#5856: EVERY reason now reads its dedicated
/// process-global aggregate (`{REJECT,TIME_EXCEEDED,PACKET_TOO_BIG}_RATE_
/// LIMITED_TOTAL`), which is bumped on every per-zone (and fallback) deny — an
/// O(1) atomic load, never a sum over the per-zone buckets, so the wire/metric
/// format is unchanged by the per-zone split.
pub(in crate::afxdp) fn rate_limited_count(reason: GeneratedErrorReason) -> u64 {
    rate_limited_total(reason).load(Ordering::Relaxed)
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
    // #3618/#5856: also clear the reason's dedicated aggregate so a test that
    // asserts an exact `rate_limited_count(reason)` starts from a clean slate
    // (the aggregate is a separate atomic from the fallback bucket's field).
    rate_limited_total(reason).store(0, Ordering::Relaxed);
}

#[cfg(test)]
#[path = "icmp_ratelimit_tests.rs"]
mod tests;
