# Claude SMR — #3618 plan review, round 2 (convergence, HOSTILE)

Reviewing `docs/research/3618-reject-bucket/plan.md` @ v3.

## Did v2/v3 actually fold r1's three required changes?

- **Change 1 (aggregate counter ≠ 64-load sum): FOLDED.** §5 now specifies a
  single process-global `AtomicU64` bumped on any per-zone deny;
  `rate_limited_count`/`reject_rate_limited_total()` is an O(1) atomic load. §7
  invariant + §6 API updated. The torn-read open question is gone. Good.
- **Change 2 (uniform dispatch): SUPERSEDED by v3.** The 2D-array idea was moot
  once the dense-array design was retracted (see below). TE/PTB stay their own
  statics; only Reject moves to the map. The residual asymmetry (static TE/PTB
  vs mapped Reject) is inherent and documented, not accidental. Acceptable.
- **Change 3 (east-west amplification): FOLDED.** §5 now separates north-south
  (unchanged per-ingress cap) from east-west (already-inside attacker, bounded
  by configured zones per port), and makes an explicit decision: flat per-zone,
  no mandatory global second gate, two-level gate filed as an optional follow-up.
  The tradeoff (a global gate re-introduces a limited global-drain) is stated
  honestly. Good — and it correctly leaves the "must the two-level gate ship in
  v1?" call open for the /engineer reviewers rather than pretending it's settled.

## The r1 change-4 directive paid off — this is the round's real finding

r1 refused to leave "is MAX_ZONES enforced at commit?" as an open question and
demanded verification. Verifying it broke the design: zone ids are **sparse u16
stable name-hashes over [0, 65533]** (`compiler_validate_strict.go:3327`
`MaxUsableZoneID = 65533`; `zoneid.go:16` `ZoneIDReservedMin = 0xFFFE`), and the
Rust zone maps are already sparse hashmaps (`zone_name_to_id`, `ifindex_to_zone_id`
= `FastMap<_, u16>`). `MAX_ZONES=64` is a **legacy eBPF-map constant**, not the
userspace zone-id space. A dense `[TokenBucket; 64]` indexed by zone id would
clamp almost every real zone id onto bucket[0] → zero fairness. v3 correctly
RETRACTS the dense array and moves to a config-keyed sparse map
(`FastMap<u16, TokenBucket>` in `ForwardingState` + a `REJECT_FALLBACK_BUCKET`
static). This is exactly the value of a hostile self-review: it killed a plausible
but wrong design before any code was written.

## Re-attack on v3

- **Fail-open?** No. `reject_buckets.get(&id).unwrap_or(&REJECT_FALLBACK_BUCKET)`
  always yields a real bucket; every failure leg still `return false` +
  silent-drop. Confirmed against `reject_reply.rs:162-231`.
- **Cardinality/DoS?** Keys are config-derived (a reject's `from_zone_id` comes
  from `zone_id_to_name`/`ifindex_to_zone_id`), and the Go zone-count cap bounds
  the config at 65533 zones. No attacker-driven growth. The 65533-zone worst-case
  memory (~1 MiB) is implausible and Go-capped; realistic is <1 KiB.
- **New risk introduced by v3:** the buckets now live in `Arc<ForwardingState>`,
  so (a) they reset on `commit` and (b) correctness depends on forwarding being
  ONE shared Arc across workers. Both are correctly surfaced as §8 risks + §11
  open questions + a hard /engineer verification. Reset-on-commit is benign for a
  diagnostic limiter (operator-initiated, rare, not attacker-triggerable). The
  shared-Arc question is the one genuine implementation hazard and is flagged
  loudly — acceptable for a research plan to defer to /engineer with the seam
  named. If forwarding turns out to be per-worker-cloned, the fallback (hoist the
  map into its own `Arc` or a process-global lazy map) is already documented.
- **Counter monotonicity / protocol:** single atomic → `protocol/tests.rs`
  round-trip and the Prometheus contract untouched. Good.
- **Coordination with #3607:** correctly decoupled (different module/algorithm)
  with a shared-`TokenBucket`-type opportunity flagged, not a dependency. Good.

## Is PLAN-KILL still on the table?

Yes, honestly. The fix is for a *diagnostic courtesy reply* and the fallback
(global bucket + per-zone attribution counters) is cheaper. But the fix is small
(config-bounded map, cold path, no protocol break) and the operational blind-spot
(a busy untrust zone perpetually starving a trust zone's reject diagnostics) is
real on a production multi-zone box. I recommend the fix over KILL, but a reviewer
who weights "diagnostic-only, don't add surface" could land KILL and I would not
call that wrong.

## Verdict

**PLAN-DEFER (PLAN-READY, awaiting manual /engineer approval).** The design is
sound and now correct (sparse-map, single-atomic counter, honest amplification
analysis, fallback bucket, all major hazards surfaced with named /engineer
verifications). Recommend Path B (per-zone Reject buckets via a config-keyed
sparse map owned by ForwardingState) over the global+attribution fallback and
over PLAN-KILL. Companion (Codex/AGY) results did not surface (infra-block, §14);
converging 2-of-3 on the two hostile SMR rounds, with the full 4-way to run on
the real code at /engineer.
