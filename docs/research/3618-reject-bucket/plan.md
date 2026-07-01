# #3618 — per-zone fairness for the generated reject-reply rate limiter

## 1. Status

DRAFT v1 — pending adversarial plan review (Codex + AGY + Claude SMR).

Research base: worktree off `origin/master` at `bd2443c5e` (fetched at start).
Coordinator noted current master had advanced to `ad4d9afb5`; the two files this
plan touches (`userspace-dp/src/afxdp/icmp_ratelimit.rs`,
`userspace-dp/src/afxdp/poll_descriptor/reject_reply.rs`) are unchanged between
those SHAs for the code this plan cites — re-verify the exact line numbers at
`/engineer` time against then-current master.

## 2. Issue framing

Locally-generated **active reject** replies — a policy `then reject`, a
firewall-filter / lo0 `then reject`, and a zone `tcp-rst` deny — are synthesized
as a TCP RST or an ICMP/ICMPv6 administratively-prohibited unreachable and
rate-limited by a **single, process-global, per-reason** GCRA token bucket
(`REJECT_BUCKET`). There is no per-zone / per-RG / per-worker scoping of the
Reject reason.

Consequence: a rejected-flow flood arriving on **one** (untrusted) zone drains
the shared Reject bucket, so a legitimate policy/filter reject in a **different**
zone fails closed to a silent drop even though that zone is not under attack. The
aggregate cap is being asked to also deliver per-zone fairness, and it cannot.

The bucket model was deliberately chosen (#2472) to mirror Linux
`icmp_msgs_per_sec` (bounded state, no attacker-driven map growth). The research
question: is a single aggregate cap acceptable for a *diagnostic* reply, or does
per-zone fairness matter enough to justify per-zone buckets — and if so, what
cardinality is safe?

This is a DIFFERENT limiter from #3607 (screen flood `RateCounter`
over-throttle). #3607 is `userspace-dp/src/screen/rate.rs`; this is
`userspace-dp/src/afxdp/icmp_ratelimit.rs`. See §12 for the coordination note.

## 3. Honest scope / value framing

The win is **operational observability + fairness of a diagnostic reply**, not
throughput and not a security-critical drop. Concretely:

- The reject reply is a *courtesy*: the trigger packet is dropped
  fail-closed **regardless** of whether the RST/ICMP-unreachable is emitted
  (`reject_reply.rs:179-182`, `:189-194`, `:222-231` — every failure leg still
  returns `false` and the caller silently drops). So this bug never lets bad
  traffic through and never drops good *transit* traffic. It only suppresses the
  *peer-facing failure signal* (fast connection reset instead of a timeout) and
  the operator-facing troubleshooting signal.
- Blast radius of the win: on a box with a busy untrusted zone (constant
  scan/flood → constant rejects) the global 1000/s bucket can sit perpetually
  drained, so an operator troubleshooting a policy misconfiguration in a
  *trusted/internal* zone never sees that zone's reject diagnostic. The fix
  restores it.
- Memory cost of the recommended fix is ~1 KiB total (64 zones × 16 B, one
  process-global array — see §5). Hot-path cost is one array index added to an
  already-cold (`#[cold] #[inline(never)]`) path. There is no per-forwarded-
  packet cost.

**If reviewers conclude the aggregate cap is acceptable for a diagnostic reply
and the added surface is not worth it, PLAN-KILL is an acceptable verdict** (the
issue explicitly sanctions "PLAN-KILL-acceptable-if-the-aggregate-cap-is-fine").
The counter-argument the plan must defeat is in §4/§5: per-zone buckets do **not**
weaken the realistic reflection cap, so the "keep it global for amplification
safety" objection is weaker than it first appears.

## 4. Current behavior — the single global bucket + its consumers (file:line)

Base `bd2443c5e`.

**The single bucket:**
- `icmp_ratelimit.rs:163-165` — three process-global statics, one per reason:
  ```
  static TIME_EXCEEDED_BUCKET: TokenBucket = TokenBucket::new();
  static PACKET_TOO_BIG_BUCKET: TokenBucket = TokenBucket::new();
  static REJECT_BUCKET: TokenBucket = TokenBucket::new();
  ```
- `icmp_ratelimit.rs:167-173` — `bucket_for(reason)` maps
  `GeneratedErrorReason::Reject → &REJECT_BUCKET` for **every** caller, with no
  zone key.
- `icmp_ratelimit.rs:183-185` — `allow_generated_error(reason)` uses the
  compile-time `DEFAULT_RATE_PER_SEC = 1000` / `DEFAULT_BURST = 1000`
  (`:65`, `:71`), no zone key.
- `TokenBucket` (`:92-99`) is a GCRA single-atomic-word (`theoretical_arrival_ns:
  AtomicU64`) + a `rate_limited: AtomicU64` counter → **16 bytes** per bucket.

**The Reject consumer (single shared path):**
- `reject_reply.rs:179-182` — `enqueue_reject_reply` gates on
  `allow_generated_error(GeneratedErrorReason::Reject)`; on empty it
  `return false` (fail-closed) after bumping the global counter inside
  `allow_generated_error` (`icmp_ratelimit.rs:198-201`).
- Both **policy reject** and **filter reject** funnel through this ONE call:
  `enqueue_policy_reject_reply` (`:39-58`) and `enqueue_filter_reject_reply`
  (`:70-89`) both delegate to `enqueue_reject_reply` (`:151`), and
  `enqueue_deny_reply` (`:112-146`, the #3071 zone-`tcp-rst` path) routes back
  through `enqueue_policy_reject_reply`. So policy reject, filter/lo0 reject, and
  zone tcp-rst all share `REJECT_BUCKET`.

**Reject call sites (all in `poll_descriptor/mod.rs`):**
- `:180` `enqueue_deny_reply(... from_zone_id ...)` — flow-backed host-bound
  deny. `from_zone_id` in scope.
- `:2876`, `:3877` `enqueue_deny_reply(... from_zone_id ...)` — transit
  policy-deny / zone-tcp-rst arms. `from_zone_id` in scope.
- `:800`, `:905`, `:1393`, `:1779` `enqueue_filter_reject_reply(... binding.ifindex ...)`
  — input-filter / lo0 filter reject. Zone available via
  `forwarding.ifindex_to_zone_id.get(&binding.ifindex)`.

**Cross-zone starvation proof (mechanical):**
1. A flood of rejected flows arrives on zone A (say the untrust WAN zone). Each
   hits `enqueue_reject_reply` → `allow_generated_error(Reject)` →
   `REJECT_BUCKET.try_take(now, 1000, 1000)`.
2. Within the first ~1 ms the burst (1000) is spent; the GCRA TAT
   (`icmp_ratelimit.rs:146`) advances `burst * interval` ahead of `now`. From
   then on, sustained at ≥1000 rejects/s, `try_take` returns `false` for the
   whole bucket because `tat - burst_horizon > now` (`:140-142`).
3. A legitimate policy reject in zone B now calls the SAME
   `allow_generated_error(Reject)` → SAME `REJECT_BUCKET` (`bucket_for` ignores
   zone, `:171`) → `false` → `reject_reply.rs:180-182` fail-closes to a silent
   drop and bumps the single global counter.
4. There is no per-zone state anywhere on this path, so zone B's diagnostic is
   collateral-suppressed for as long as zone A's flood sustains. QED.

**Observability today:** the only signal is the single aggregate
`reject_rate_limited_total` (`coordinator/status.rs:281-287` →
`server/helpers.rs:123` → Prometheus `xpf_userspace_reject_rate_limited_total`,
protocol field `protocol/control.rs:350-351`). It says "some rejects were
suppressed" but not **which zone drained the bucket** nor that another zone was
the victim.

## 5. Concrete design

### Recommended: per-zone Reject buckets, process-global array, MAX_ZONES=64

Zone identity is **config-defined, not attacker-defined**. `MAX_ZONES = 64`
(`bpf/headers/xpf_common.h:142`); zone ids are `u16` (widened in #3075) but
practically bounded to `[0, 64)`. So a fixed-size array indexed by zone id has
**bounded cardinality with no attacker-driven growth** — it satisfies the exact
constraint that motivated the global model in #2472. Precedent already exists:
`screen/syn_rate.rs` runs per-zone, per-worker limiter state sized by a Go
commit-time memory advisory (#3315).

**Data structure change (`icmp_ratelimit.rs`):**

Replace the single `REJECT_BUCKET` static with a fixed array. TimeExceeded /
PacketTooBig stay global for now (see §10 — their generator sites do not carry a
clean zone id; out of scope):

```rust
const MAX_ZONES: usize = 64; // mirror bpf/headers/xpf_common.h MAX_ZONES

// One Reject bucket per zone id. Process-global (shared across workers) so the
// aggregate-per-zone cap semantics are exact and memory is trivial (64 * 16 B).
static REJECT_BUCKETS: [TokenBucket; MAX_ZONES] =
    [const { TokenBucket::new() }; MAX_ZONES];
```

`TokenBucket::new()` is already `const` (`:102`), so the inline-const array
initializer is valid on the pinned toolchain (confirm at /engineer time; fall
back to a `once_cell`/manual macro if the const-array form is rejected).

**API change:** thread a `zone_id: u16` through the Reject path only.

```rust
pub(in crate::afxdp) fn allow_generated_reject(zone_id: u16) -> bool {
    allow_generated_reject_at(zone_id, monotonic_nanos(),
                              DEFAULT_RATE_PER_SEC, DEFAULT_BURST)
}

fn reject_bucket_for(zone_id: u16) -> &'static TokenBucket {
    // Fail-safe clamp: an out-of-range / unknown zone (0 or >= MAX_ZONES) maps
    // to bucket[0]. Zone 0 is the "unknown/unzoned" sentinel already
    // (forwarding treats zone_id == 0 as none), so collapsing unknown → 0 is
    // consistent and keeps the index in-bounds without a panic.
    REJECT_BUCKETS[(zone_id as usize).min(MAX_ZONES - 1)]  // see note below
}
```

Note: the `.min(MAX_ZONES-1)` maps an out-of-range id to the LAST bucket, which
would merge distinct high ids; prefer a `if (zone_id as usize) < MAX_ZONES { id }
else { 0 }` clamp so all out-of-range ids share bucket[0] with the unzoned
sentinel. Final form decided at /engineer; the invariant is **in-bounds, no
panic, deterministic**.

Keep `GeneratedErrorReason::{TimeExceeded, PacketTooBig}` on
`allow_generated_error(reason)` unchanged; the Reject variant moves to the
zone-keyed entry point. (Alternative: keep one `allow_generated_error(reason,
zone_id)` where zone_id is ignored for TE/PTB — decide at /engineer for the
smaller diff. Either preserves TE/PTB behavior exactly.)

**Consumer change (`reject_reply.rs`):** thread `from_zone_id` into
`enqueue_reject_reply`.
- `enqueue_deny_reply` already has `from_zone_id: u16` (`:121`) — pass it down.
- `enqueue_policy_reject_reply` / `enqueue_filter_reject_reply` gain a
  `from_zone_id: u16` parameter.
- At the four filter-reject call sites (`mod.rs:800/905/1393/1779`) resolve the
  ingress zone: `forwarding.ifindex_to_zone_id.get(&binding.ifindex).copied()
  .unwrap_or(0)` (field `types/forwarding.rs:75`). Unzoned → 0 → bucket[0].
- The gate becomes `if !allow_generated_reject(from_zone_id) { ... }`
  (`reject_reply.rs:179`).

**Observability:** two options, pick one at /engineer (recommend both if cheap):
- Keep the existing aggregate `reject_rate_limited_total` as
  `sum(REJECT_BUCKETS[z].rate_limited)` so the Prometheus metric and the wire
  field (`protocol/control.rs:350`) are unchanged (no protocol break, additive-
  safe). `rate_limited_count(Reject)` becomes a sum loop over 64 buckets.
- OPTIONAL per-zone attribution: a `reject_rate_limited_by_zone(zone_id) -> u64`
  accessor for a future labeled metric / `show` command. Not required to fix the
  bug; deferrable. If shipped, it must be additive on the wire.

### Why this does NOT weaken the reflection/amplification cap

The #2472 limiter exists to bound reflected backscatter (the reply is addressed
to the trigger's — spoofable — source). Objection: 64 zones × 1000/s = 64000/s
worst-case backscatter vs 1000/s today. Rebuttal: an attacker can only trigger a
reject in a zone their packets **ingress on**. The realistic reflection attacker
floods ONE ingress path (the WAN zone); per-zone buckets cap that path at 1000/s
— **identical** to today. Reaching 64000/s requires being simultaneously on-link
to 64 distinct zones, which is not the reflection threat model. So per-zone
buckets preserve the realistic per-ingress-zone cap while removing the cross-zone
starvation. This rebuttal is the crux the reviewers should attack.

### Rejected alternatives (see §11 open questions)

- **Per-zone-per-worker buckets** (like syn_rate): removes cross-worker CAS
  contention, but the reject path is cold (not per-packet), the GCRA CAS is
  already lock-free, and per-worker multiplies the effective cap by num_workers
  (6 → 6000/s per zone), muddying the semantics. Rejected: no hot-path benefit,
  worse cap clarity. Memory would be 64 × workers × 16 B (~6 KiB @ 6 workers) —
  still small, but not worth the semantic cost.
- **Weighted / hierarchical (per-zone sub-quota under a global cap)** — true
  fairness under a shared global cap needs reserved per-zone floors (DRR/WFQ).
  That is real scheduler complexity for a diagnostic reply. Rejected as
  over-engineering; the per-ingress-zone-cap analysis above shows the flat
  per-zone bucket already gives the fairness that matters.
- **Global + zone attribution only** (the issue's KILL-adjacent option): keep one
  bucket, add per-zone suppression counters so the operator sees which zone
  drained it. This makes the starvation *observable* but does NOT *fix* it — zone
  B's diagnostic is still gone. Acceptable only if reviewers decide the aggregate
  cap is fine (→ PLAN-KILL the fix, ship attribution as a small separate
  enhancement). Recorded as the fallback.

## 6. Public API preservation

Rust module-internal API only — nothing crosses the Go/Rust wire or the gRPC
surface, so no proto/bindings churn required for the core fix.

- `pub(in crate::afxdp)` items only; no `pub` API leaves the crate.
- `allow_generated_error(reason)` signature preserved for TE/PTB callers
  (`icmp.rs:191`, `tx/dispatch/mod.rs:577`). Reject moves to a new
  `allow_generated_reject(zone_id)` (or a 2-arg overload — decided at /engineer).
- `rate_limited_count(reason)` preserved (Reject variant returns the sum).
- Coordinator status accessor `reject_rate_limited_total()`
  (`coordinator/status.rs:284`) preserved — its body changes to a sum but the
  signature and the Prometheus metric name are unchanged.
- Wire/protocol field `reject_rate_limited_total`
  (`protocol/control.rs:350-351`) unchanged. If per-zone attribution ships, it
  is a NEW additive field — the existing field stays.
- `enqueue_policy_reject_reply` / `enqueue_filter_reject_reply` gain a
  `from_zone_id: u16` param (module-internal, `pub(super)`); all call sites are
  in `poll_descriptor/mod.rs` and updated in the same change.

## 7. Hidden invariants the change must preserve

- **Fail-closed on every failure leg.** Bucket-empty, budget-exhausted,
  unparseable, output-filter-drop all still `return false` and the caller still
  silently drops (`reject_reply.rs:162-165`, `:180-182`, `:189-194`,
  `:222-231`). The zone key must not introduce a fail-open path (e.g. an
  out-of-range zone must map to a real bucket, never skip the gate).
- **No panic on zone index.** `zone_id` is `u16`; the array is 64. The clamp
  must be branch-safe and in-bounds for any `u16` (0..=65535 → 0..=63). A
  compile-time `assert!(MAX_ZONES == 64)` mirroring the C header keeps the two
  in sync.
- **GCRA atomicity (#2955) preserved per bucket.** Each per-zone bucket keeps the
  single-word CAS refill+consume; the array does not reintroduce split state.
  The `concurrent_hammer_never_over_admits` invariant must still hold per zone.
- **Reason isolation (#2472) preserved.** Reject per-zone must not touch TE/PTB
  buckets; `reasons_are_isolated` must still pass.
- **Counter semantics.** The aggregate `reject_rate_limited_total` must remain
  monotonic and equal to the sum of per-zone drops so the existing metric and
  the `protocol/tests.rs:403-434` round-trip stay valid.
- **Cold-path placement.** The zone lookup must not pull `enqueue_reject_reply`
  or `allow_generated_reject` out of `.text.unlikely`; keep `#[cold]
  #[inline(never)]` on the reject bodies.
- **HA / worker portability.** Buckets are process-global (not per-worker), so
  there is no per-worker sync concern and no HA session-sync interaction (the
  limiter is local anti-amplification state, not synced). The test-only
  `global_bucket_test_lock` + `reset_bucket_for_test` must be extended to the
  array (reset a given zone's bucket) so the existing serialized bucket tests
  still work.

## 8. Risk assessment (4-class)

| Class | Level | Notes |
|-------|-------|-------|
| Behavioral regression | LOW | Fail-closed legs unchanged; only the bucket *selection* changes. Reject semantics (RST/ICMP, counters) identical. The one behavior change is intended: one zone no longer starves another. |
| Lifetime / borrow-checker | LOW | `&'static TokenBucket` from a `static` array; threading a `u16` param. No new borrows, no lifetimes. Const-array init is the only toolchain risk (fallback noted in §5). |
| Performance regression | LOW | Reject path is cold (`#[cold] #[inline(never)]`), fires only on policy/filter deny — never per forwarded packet. Adds one array index + clamp. No new allocation. Aggregate counter read becomes a 64-iter sum (called ~1/s from status poll, negligible). |
| Architectural mismatch | LOW | Mirrors the existing per-zone `screen/syn_rate.rs` precedent and the existing per-reason `bucket_for` dispatch. Not a dead-end: the array generalizes cleanly to TE/PTB later, or to per-zone-per-worker if ever needed. |

Security note: the change does not weaken the realistic reflection cap (§5) and
keeps bounded, config-driven cardinality (no attacker-driven map growth).

## 9. Test plan

**Unit (Rust, `icmp_ratelimit.rs` + `reject_reply.rs`):**
- **Cross-zone isolation (the headline fail-on-revert):** drain zone A's Reject
  bucket to empty at a frozen instant; assert zone B's `allow_generated_reject`
  still returns `true`. Reverting to a single bucket makes zone B `false` → RED.
  This is the direct proof "one zone can't starve another's rejects."
- Per-zone burst-then-rate-limit: within a zone, burst passes, the (burst+1)th
  is denied and bumps that zone's counter (port the existing
  `burst_beyond_capacity_is_rate_limited`).
- Refill over time per zone (port `refill_over_time_restores_capacity`).
- Aggregate counter = sum: drain two zones by K1 and K2 drops; assert
  `reject_rate_limited_total() == K1 + K2`.
- Out-of-range / zone-0 clamp: `allow_generated_reject(u16::MAX)` and
  `allow_generated_reject(0)` are in-bounds, fail-closed on empty, never panic.
- Preserve `concurrent_hammer_never_over_admits` (per-zone bucket), `reasons_are_isolated`
  (Reject-per-zone vs TE/PTB), `zero_rate_disables_limiter`.
- Call-site fail-on-revert (`reject_reply.rs`): extend
  `reject_reply_rate_limited_when_bucket_empty` to drain a SPECIFIC zone and
  drive `enqueue_policy_reject_reply(... from_zone_id = that zone ...)` → denied;
  then a DIFFERENT zone → still enqueues. Filter-reject variant resolves zone via
  `ifindex_to_zone_id`.
- Extend `global_bucket_test_lock` / `reset_bucket_for_test` to take a `zone_id`
  for the Reject reason.

**Build / suite gates (per triple-review):** `cargo build` clean; full
`cargo test` (userspace-dp) green incl. the ported bucket tests; 5/5 flake run of
the new cross-zone test; `go test ./...` (30 pkgs) — no Go change expected, so
this is a no-regression check; `go vet`.

**Smoke (loss userspace cluster) — evidence the two-zone scenario:**
- Config a `then reject` policy in TWO zones. Flood zone A (untrust WAN) with
  rejected flows (e.g. hping/`nping` to a denied port at > 1000/s). Concurrently
  send a low-rate denied flow in zone B (LAN). Capture on the zone-B source: a
  TCP RST / ICMP unreachable is STILL received for zone B while zone A is
  flooded. Pre-fix: zone B gets silence. Post-fix: zone B gets its reset.
- Confirm `xpf_userspace_reject_rate_limited_total` climbs (zone A drops) while
  zone B's rejects succeed (`policy_reject_sent` advances).
- Deploy wipes CoS — re-apply per project runbook; not relevant to this test but
  noted.

## 10. Out of scope (explicitly)

- **TimeExceeded / PacketTooBig per-zone scoping.** Their generator sites
  (`icmp.rs:191`, `tx/dispatch/mod.rs:577`) do not cleanly carry an ingress zone
  id (TE is generated deep in the ICMP builder; PTB in the TX dispatch path).
  Scoping them per-zone is a separate change with its own zone-plumbing; file a
  follow-up issue. They keep the current global-per-reason bucket.
- **A configurable per-zone reject rate knob** (`set ...` grammar + Go compile +
  wire). The fix keeps the compile-time `DEFAULT_RATE_PER_SEC`/`DEFAULT_BURST`.
  A knob is a future enhancement; not needed to fix fairness.
- **Per-zone labeled Prometheus metric / `show` command.** Optional attribution
  accessor may ship, but a full labeled metric surface is deferrable.
- **Per-zone-per-worker or hierarchical/WFQ schemes** (§5 rejected alternatives).
- **#3607 changes.** Coordinated only (§12), not modified here.

## 11. Open questions for adversarial review (each invitable to PLAN-KILL)

1. **Is the aggregate cap actually fine?** Reject replies are diagnostic and the
   trigger is dropped either way. Is the cross-zone starvation of a *diagnostic
   courtesy reply* a real operational problem, or is "which-zone attribution on
   the global bucket" (the cheaper KILL-adjacent option) sufficient? If the
   former is not real, PLAN-KILL and ship attribution only.
2. **Does per-zone weaken anti-amplification?** The §5 rebuttal claims the
   realistic reflection attacker floods one ingress zone so the per-ingress cap
   is unchanged. Is there a realistic vector where an attacker drives rejects in
   many zones at once (e.g. an internal multi-VLAN trunk, an east-west attacker)
   that makes 64×1000/s a real backscatter regression? If yes, we need a global
   ceiling too (two-level) or PLAN-KILL.
3. **Global vs per-worker.** Process-global buckets mean cross-worker CAS
   contention on a hot zone's bucket. On the cold reject path is that ever a
   throughput concern under a flood, or is per-worker (× num_workers cap)
   actually the right call despite the cap-clarity cost?
4. **Zone-id clamp correctness.** Zone ids are `u16` but MAX_ZONES=64. Is
   collapsing out-of-range ids to bucket[0] (shared with the unzoned sentinel)
   the right fail-safe, or does merging distinct-but-out-of-range zones onto one
   bucket reintroduce a (smaller) starvation? Can a real config ever produce a
   zone id ≥ 64 (is MAX_ZONES enforced at commit)? — must verify the Go
   commit-time zone cap.
5. **Counter/metric compatibility.** Turning `reject_rate_limited_total` into a
   64-bucket sum: any risk to the `protocol/tests.rs` round-trip, the Prometheus
   contract, or monotonicity? Should the aggregate be a separate always-summed
   accumulator instead of a live sum to avoid a torn read across 64 relaxed
   loads?
6. **Scope creep.** Should TE/PTB be done in the same change for consistency
   (near-zero extra memory) despite the messier zone plumbing, or is
   Reject-only the right minimal fix?

## 12. Coordination with #3607 (the other rate-limiter research)

- **Different limiter, different module, different algorithm.** #3607 =
  `screen/rate.rs` two-bucket sliding window (screen flood detection, already
  per-zone by threshold). #3618 = `afxdp/icmp_ratelimit.rs` GCRA token bucket
  (generated-error amplification cap). Do NOT couple the two PRs.
- **Shared type opportunity, not a dependency.** #3607's own suggested fix says
  it may "replace the whole-second two-bucket carry with ... a token bucket
  (burst = threshold, refill = threshold/sec)." That is EXACTLY the GCRA
  `TokenBucket` in `icmp_ratelimit.rs:92-161`. If #3607 chooses the token-bucket
  path, it could reuse this `TokenBucket` type (promote it to a shared
  `pub(crate)` limiter module) rather than writing a second one. Flag for
  whoever engineers #3607; this plan does not require it and does not block on
  it.
- **Ordering:** #3618 and #3607 are independent; either can ship first. If both
  ship, a later consolidation PR could unify the token-bucket substrate — a
  separate, optional refactor.
```
