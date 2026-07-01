# #3618 — per-zone fairness for the generated reject-reply rate limiter

## 1. Status

PLAN-DEFER v3 — Claude SMR converged (r1→r2, see §13/§14). Recommendation:
per-zone Reject buckets via a config-keyed sparse map. Companion (Codex/AGY)
results did not surface — infra-block documented in §14; verdict rests on the two
hostile SMR rounds per the 2-of-3 rule. Awaiting manual `/engineer` approval.

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
- Memory cost of the recommended fix is config-bounded: one 16 B GCRA bucket per
  configured zone (e.g. 30 zones ≈ 480 B; the implausible 65533-zone cap ≈ 1 MiB,
  gated by the Go zone-count cap — see §5/§8). Hot-path cost is one hashmap
  lookup added to an already-cold (`#[cold] #[inline(never)]`) path. There is no
  per-forwarded-packet cost.

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

### Recommended: per-zone Reject buckets in a CONFIG-KEYED MAP (not a dense array)

**Critical correction (SMR r1 change 4 verification → v3):** zone ids are NOT
dense in `[0, 64)`. `MAX_ZONES = 64` (`bpf/headers/xpf_common.h:142`) is a legacy
eBPF-map/direct-table constant, but the userspace path does not use those maps
for zone identity. Post-#3075:
- Zone ids are a **stable name-hash in a u16 space**, sparse across `[0, 65533]`
  (`pkg/config/compiler_validate_strict.go:3327` `MaxUsableZoneID = 65533`;
  `pkg/config/zoneid.go:16` `ZoneIDReservedMin = 0xFFFE`; the top two ids are the
  global / host sentinels). A config with 3 zones can hold ids like 41337, 9002,
  60123 — NOT 1, 2, 3.
- The Rust zone maps are already sparse hashmaps: `zone_name_to_id:
  FastMap<String, u16>` / `zone_id_to_name: FastMap<u16, String>` /
  `ifindex_to_zone_id: FastMap<i32, u16>` (`types/forwarding.rs:76-77,75`).
- A dense `[TokenBucket; 64]` indexed by zone id is therefore **WRONG**: it would
  collapse almost every real zone id onto bucket[0] (clamp-to-0), giving no
  fairness at all. The v1/v2 dense-array design is retracted.

Cardinality is still **config-defined, not attacker-defined** (a reject only ever
carries a `from_zone_id` from `zone_id_to_name` / `ifindex_to_zone_id`, both
config-derived), so a per-zone structure keyed by the configured zone set has
bounded cardinality = number of configured zones (≤ 65533, realistically dozens).
This is exactly the `screen/syn_rate.rs` precedent (#3315): per-zone limiter
state allocated at config time for the zones that need it.

**Data structure (v3): a per-zone Reject bucket map owned by `ForwardingState`,
rebuilt each config apply.**

```rust
// In ForwardingState (types/forwarding.rs), built alongside zone_id_to_name at
// config apply. One GCRA Reject bucket per configured zone id. Cardinality =
// configured zones. ~16 B/zone (e.g. 30 zones ≈ 480 B).
reject_buckets: FastMap<u16, TokenBucket>,   // key = zone id
```

- Built in the forwarding-build path (`forwarding_build/interfaces.rs` /
  wherever `zone_id_to_name` is populated): for each configured zone id, insert a
  fresh `TokenBucket::new()`.
- Lookup on the cold reject path:
  ```rust
  let bucket = forwarding.reject_buckets
      .get(&from_zone_id)
      .unwrap_or(&REJECT_FALLBACK_BUCKET);   // process-global static
  ```
  `REJECT_FALLBACK_BUCKET` is a single process-global `TokenBucket` static used
  for an unzoned (id 0) or otherwise-unknown zone id — a real bucket, so the gate
  is never fail-open. It is shared, so unzoned/unknown rejects share ONE budget
  (acceptable: they are the rare/degenerate case, not a per-zone diagnostic).

**Placement decision — ForwardingState (reset-on-commit) vs process-global lazy
map.** Two viable homes:
- (Recommended) **ForwardingState-owned**, rebuilt on each config apply. Workers
  share `Arc<ForwardingState>` so they share the same per-zone atomics (VERIFY at
  /engineer that `worker_ctx.forwarding` is one shared Arc, not a per-worker
  clone — if per-worker, hoist the map into its own `Arc` or make it
  process-global). Downside: the reject limiter RESETS on `commit`. This is
  acceptable — a commit is rare and operator-initiated, not attacker-triggerable,
  and a fresh burst allowance right after a commit is benign for a diagnostic
  reply.
- (Alternative) **Process-global lazily-populated concurrent map** (a
  `Mutex<FastMap<u16, Box<TokenBucket>>>` or sharded map, insert-on-first-use).
  Survives commits; keys still bounded by configured zones. Costs a mutex on the
  cold path (fine) and more complexity. Choose this only if reset-on-commit is
  judged undesirable.

**TE / PTB unchanged.** With a map design there is no 2D array; TimeExceeded and
PacketTooBig keep their existing single global statics
(`icmp_ratelimit.rs:163-164`) and the existing `allow_generated_error(reason)`
entry point. Only the Reject reason moves to the zone-keyed map via a new
`allow_generated_reject(forwarding, from_zone_id)` (or a `bucket: &TokenBucket`
passed in). The SMR-r1 "uniform 2D dispatch" (change 2) is moot under the map
design — the asymmetry is now TE/PTB-static vs Reject-map, which is inherent and
documented, not an accidental bifurcation.

- TE call site `icmp.rs:191`, PTB `tx/dispatch/mod.rs:577`: unchanged.
- Reject: `reject_reply.rs:179` calls the zone-keyed variant with the resolved
  `from_zone_id`.

**Consumer change (`reject_reply.rs`):** thread `from_zone_id` into
`enqueue_reject_reply`.
- `enqueue_deny_reply` already has `from_zone_id: u16` (`:121`) — pass it down.
- `enqueue_policy_reject_reply` / `enqueue_filter_reject_reply` gain a
  `from_zone_id: u16` parameter.
- At the four filter-reject call sites (`mod.rs:800/905/1393/1779`) resolve the
  ingress zone: `forwarding.ifindex_to_zone_id.get(&binding.ifindex).copied()
  .unwrap_or(0)` (field `types/forwarding.rs:75`). Unzoned → 0 → `[Reject][0]`.
- The gate becomes `if !allow_generated_error(GeneratedErrorReason::Reject,
  from_zone_id) { ... }` (`reject_reply.rs:179`).

**Observability — aggregate counter is a SINGLE atomic, NOT a 64-load sum
(SMR r1 change 1):** keep one process-global `AtomicU64` per reason
(`REJECT_RATE_LIMITED_TOTAL` etc.) bumped on ANY per-zone deny, exactly where
`allow_generated_error` bumps today. `rate_limited_count(reason)` stays a single
atomic load — exact, atomic, O(1), and the `protocol/tests.rs:403-434`
round-trip + Prometheus contract are untouched. The per-zone `TokenBucket` keeps
its own `rate_limited` field ONLY for optional per-zone attribution (a future
`reject_rate_limited_by_zone(zone_id)` accessor / labeled metric); the AGGREGATE
metric never sums the 64 fields. This removes the torn-read concern entirely.

### Why this does NOT weaken the reflection/amplification cap (SMR r1 change 3)

The #2472 limiter exists to bound reflected backscatter (the reply is addressed
to the trigger's — spoofable — source). Objection: with N configured zones the
worst-case aggregate rises to N × 1000/s vs 1000/s today.

**North-south (the reflection threat model):** an attacker can only trigger a
reject in a zone their packets **ingress on**. The realistic reflection attacker
floods ONE ingress path (the WAN zone); per-zone buckets cap that path at 1000/s
— **identical** to today. So per-zone buckets preserve the realistic
per-ingress-zone cap while removing the cross-zone starvation.

**East-west (SMR r1 pressed this):** reaching the N× worst case requires an
attacker who can inject rejected flows across many zones AT ONCE — e.g. a
compromised internal host bridged onto several zone subinterfaces, or a trunk
carrying many zone VLANs to one physical port with a source that can drive each.
Assessment: (a) this attacker is already inside the trust boundary and can emit
far more damaging traffic than reflected RST/ICMP backscatter, so the marginal
N× backscatter is not the dominant risk; (b) the number of zones one physical
ingress can drive is bounded by the configured VLAN/zone count on that port (the
Go zone-count cap ceilings N at 65533, but a real port carries a handful), not
unbounded; (c) each zone is still individually capped at 1000/s, so no single
zone is amplified beyond today.

**Decision — flat per-zone, NO mandatory global second gate; keep it as a
documented OPTIONAL knob.** A global second gate (admit only if BOTH the per-zone
bucket AND a global cap have a token) would bound the aggregate at 1000/s again,
but it re-introduces a limited global-drain: the global gate is first-come-first-
served, so a busy zone can still consume the shared global tokens and partially
starve others — i.e. it trades some of the fairness we came here to fix. For a
DIAGNOSTIC reply, bounding each ingress path at 1000/s (north-south safe) while
accepting a bounded east-west aggregate from an already-inside attacker is the
right call. If a deployment’s threat model genuinely includes an east-west
multi-zone amplifier, the two-level gate is a small, well-understood follow-up
(one extra `try_take` on a global bucket) — filed, not built. Reviewers should
rule on whether flat-per-zone is acceptable or the two-level gate must ship in v1.

### Rejected alternatives (see §11 open questions)

- **Per-zone-per-worker buckets** (like syn_rate): removes cross-worker CAS
  contention, but the reject path is cold (not per-packet), the GCRA CAS is
  already lock-free, and per-worker multiplies the effective cap by num_workers
  (6 → 6000/s per zone), muddying the semantics. Rejected: no hot-path benefit,
  worse cap clarity. Memory would be num_zones × workers × 16 B — still small,
  but not worth the semantic cost.
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
  (`coordinator/status.rs:284`) preserved — its body reads a single global
  `AtomicU64` (SMR r1 change 1), signature and Prometheus metric name unchanged.
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
  `:222-231`). The zone key must not introduce a fail-open path — a missing
  zone-id must map to the `REJECT_FALLBACK_BUCKET`, never skip the gate.
- **No panic on unknown zone.** The `reject_buckets.get(&id)` returns `None` for
  an unmapped id; the `.unwrap_or(&REJECT_FALLBACK_BUCKET)` guarantees a real
  bucket for any `u16`. No indexing, so no bounds panic.
- **GCRA atomicity (#2955) preserved per bucket.** Each per-zone bucket keeps the
  single-word CAS refill+consume; the map holds independent `TokenBucket`s and
  does not reintroduce split state. `concurrent_hammer_never_over_admits` must
  still hold per zone.
- **Reason isolation (#2472) preserved.** Reject per-zone must not touch TE/PTB
  buckets (which stay their own statics); `reasons_are_isolated` must still pass.
- **Counter semantics.** The aggregate `reject_rate_limited_total` is a single
  global `AtomicU64` bumped on any per-zone deny — monotonic, atomic, and the
  `protocol/tests.rs:403-434` round-trip stays valid unchanged.
- **Cold-path placement.** The zone lookup must not pull `enqueue_reject_reply`
  or the zone-keyed allow-fn out of `.text.unlikely`; keep `#[cold]
  #[inline(never)]` on the reject bodies.
- **Shared per-zone atomics across workers.** All workers must gate against the
  SAME per-zone bucket (one `Arc<ForwardingState>`), else the cap becomes
  per-worker. VERIFY the forwarding sharing model at /engineer (§8).
- **Test helpers.** `global_bucket_test_lock` + `reset_bucket_for_test` extend to
  reset a given zone's bucket (or a test-built map) so the existing serialized
  bucket tests still work under the parallel runner (#2955).

## 8. Risk assessment (4-class)

| Class | Level | Notes |
|-------|-------|-------|
| Behavioral regression | LOW-MED | Fail-closed legs unchanged; the bucket *selection* changes and the limiter now RESETS on config apply (reset-on-commit, §5) if the ForwardingState-owned home is chosen. Intended behavior change: one zone no longer starves another. |
| Lifetime / borrow-checker | LOW-MED | The reject bucket is borrowed from `Arc<ForwardingState>` for the duration of the cold call — must not outlive the borrow; the fallback is a `&'static`. VERIFY forwarding is one shared Arc across workers (else per-worker clones would give per-worker buckets = cap × num_workers). Flagged as the key /engineer check. |
| Performance regression | LOW | Reject path is cold (`#[cold] #[inline(never)]`), fires only on policy/filter deny — never per forwarded packet. Adds one hashmap `get`. No per-forwarded-packet cost. Aggregate counter is a single atomic load (SMR r1 change 1), not a sum. |
| Architectural mismatch | LOW | Mirrors the existing sparse zone maps (`zone_name_to_id`, `ifindex_to_zone_id`) and the per-zone `screen/syn_rate.rs` precedent. Not a dead-end. |

Memory / DoS note: cardinality is bounded by the configured zone set (the Go
zone-count cap enforces ≤ 65533 distinct zones —
`pkg/config/compiler_validate_strict.go:3327` + `validateZoneCountStrict`), and a
reject only ever keys on a config-derived zone id, so there is no attacker-driven
map growth. Security: the change does not weaken the realistic per-ingress-zone
reflection cap (§5).

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
- Aggregate counter: drain two zones by K1 and K2 drops; assert the single
  global `reject_rate_limited_total() == K1 + K2` (it is bumped on every per-zone
  deny).
- Unmapped / unzoned zone: a reject with a `from_zone_id` not in the map uses
  `REJECT_FALLBACK_BUCKET`, fail-closes on empty, never panics; a zone-0 reject
  is handled the same way.
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
4. **RESOLVED — zone-id space.** Verified: zone ids are sparse u16 stable
   name-hashes over `[0, 65533]` (NOT dense `[0,64)`), enforced by the Go
   zone-count cap (`compiler_validate_strict.go:3327` `MaxUsableZoneID = 65533`,
   `validateZoneCountStrict`). The dense-64 array is retracted (§5); the design
   is now a config-keyed sparse map. Remaining sub-question: is the shared
   `REJECT_FALLBACK_BUCKET` for unzoned/unknown ids acceptable, or should an
   unzoned reject simply skip the per-zone limiter (still bounded by the TX
   budget gate)?
5. **Placement / reset-on-commit.** ForwardingState-owned buckets reset on every
   `commit`; the process-global lazy map survives. Is reset-on-commit acceptable
   for a diagnostic reply limiter, or does the added complexity of a
   process-global concurrent map earn its keep? And is `worker_ctx.forwarding` a
   single shared `Arc` (so workers share the per-zone atomics) or a per-worker
   clone (which would make the cap per-worker)? — must verify at /engineer.
6. **Scope creep.** TE/PTB stay global (they lack a clean zone id at their
   generator sites — §10). Is Reject-only the right minimal fix, or should TE/PTB
   also become per-zone (needs zone plumbing into `icmp.rs` / `tx/dispatch`)?

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

## 13. Changelog

- **v1 (d190d4a5f):** initial plan — per-zone Reject buckets as a process-global
  dense `[TokenBucket; 64]` array, aggregate counter as a 64-bucket sum.
- **v2:** folded Claude SMR r1. Change 1: aggregate counter → single global
  `AtomicU64` (not a 64-load sum). Change 2: uniform 2D `[[TokenBucket;64];3]`
  dispatch. Change 3: east-west amplification analysis + global-second-gate
  decision (flat per-zone, optional two-level as a filed follow-up).
- **v3 (this revision):** **major correction from SMR r1 change-4 verification.**
  Zone ids are sparse u16 stable name-hashes over `[0, 65533]` (NOT dense
  `[0,64)`); `MAX_ZONES=64` is a legacy eBPF-map constant, not the userspace zone
  id space. The dense-array design (v1/v2) is RETRACTED — it would collapse
  almost every real zone id onto bucket[0] and give no fairness. Replaced with a
  **config-keyed sparse map** (`FastMap<u16, TokenBucket>`) owned by
  `ForwardingState`, built from the configured zone set, with a process-global
  `REJECT_FALLBACK_BUCKET` for unzoned/unknown ids. Updated memory (config-
  bounded), risk (borrow from `Arc<ForwardingState>`, reset-on-commit, shared-Arc
  verification), invariants, and open questions accordingly.

## 14. Reviewer status (companion infra note)

Claude SMR ran two hostile rounds (r1 → this convergence). r1 forced the three
v2 folds AND its change-4 "verify MAX_ZONES enforcement" directive is what
surfaced the sparse-zone-id correction (v3) — the single most important finding,
caught by hostile self-review before any code was written.

Codex + AGY companions were dispatched (agents `codex-3618-r1`, `agy-3618-r1`)
but their results did not surface: the shared AGY job queue repeatedly returned a
stale, unrelated `#3616` review (a known AGY result-routing infra-drop), and the
Codex job list came back empty. Per the `/research` 2-of-3 rule
(`feedback_codex_infra_must_retry`) this is documented as a companion infra-block;
the verdict rests on the two hostile Claude SMR rounds. At `/engineer` time the
implementation PR gets the full 4-way (Codex + AGY + Claude SMR + Copilot) on
real code, which is the higher-value review surface for this change.
