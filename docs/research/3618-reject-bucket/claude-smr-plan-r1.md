# Claude SMR — #3618 plan review, round 1 (HOSTILE)

Reviewing `docs/research/3618-reject-bucket/plan.md` @ v1 (commit d190d4a5f).

Stance: hostile. I tried to kill the plan and to find the fail-open hole. It
survives as a *concept*, but v1 has three concrete weaknesses I will not
soft-pass. Verdict at the bottom: **NEEDS-REVISION** (converges to READY once the
three required changes land).

## What holds up

- The starvation proof (§4) is mechanically correct. `bucket_for` (icmp_ratelimit.rs:167-173)
  returns the one `REJECT_BUCKET` for every caller; `reject_reply.rs:179` gates
  policy+filter+deny+lo0+zone-tcp-rst all through it. One zone's flood drains it;
  another zone's reject then fail-closes. Confirmed against source.
- The "diagnostic reply, dropped either way" framing is TRUE and load-bearing:
  every failure leg in `enqueue_reject_reply` returns false and the caller drops
  the trigger regardless (`reject_reply.rs:162-165,180-182,189-194,222-231`). So
  this is never a good-traffic-drop or a security-bypass — it is exactly a
  fairness-of-diagnostic problem. That keeps the severity Medium and makes
  PLAN-KILL a legitimate landing spot, which the plan correctly concedes.
- The anti-amplification rebuttal (§5) is the strongest part: per-zone buckets
  keep the per-ingress-zone cap at 1000/s, so the realistic single-ingress-path
  reflection attacker sees no change. The 64× worst case needs on-link presence
  to 64 zones — not the reflection model. I could not break this for the
  north-south WAN reflection case. (I do want the reviewers to press the
  east-west case — see required change 3.)
- Cardinality safety: zone id is config-defined, MAX_ZONES=64 (xpf_common.h:142),
  array is fixed — no attacker-driven growth. This is the property #2472 wanted
  and the plan preserves it.

## Required change 1 — aggregate counter must NOT be a 64-load live sum

§5/§11.5 propose making `reject_rate_limited_total()` a sum over 64 per-zone
`rate_limited` atomics. That is a torn read across 64 relaxed loads and makes the
status accessor O(64) per poll for no reason. Worse, it couples the metric's
correctness to "all 64 buckets summed consistently," which is fragile.

Cleaner and required: keep a SINGLE process-global `AtomicU64`
`REJECT_RATE_LIMITED_TOTAL` that is bumped on ANY per-zone deny (in the same
place `allow_generated_reject` currently bumps), and let the per-zone buckets
carry ONLY the GCRA word for gating. Then `reject_rate_limited_total()` is a
single atomic load — exact, atomic, O(1), and the `protocol/tests.rs:403-434`
round-trip + Prometheus contract are untouched. Per-zone attribution (if ever
shipped) becomes a SEPARATE optional per-zone counter, not the source of the
aggregate. This removes the whole §11.5 open question.

## Required change 2 — collapse to a 2D `[[TokenBucket; 64]; 3]` OR justify the asymmetry

v1 leaves TE/PTB on the single-static `bucket_for(reason)` and moves only Reject
to an array, producing two dispatch shapes and a bifurcated `bucket_for`. Two
cleaner options — the plan must pick one and defend it, not leave it implicit:

(a) A single 2D array `REASON_ZONE_BUCKETS: [[TokenBucket; MAX_ZONES]; 3]`. TE/PTB
    generator sites (icmp.rs:191, tx/dispatch/mod.rs:577) pass `zone_id = 0`
    (they lack a clean zone id — verified), which collapses them to
    `[reason][0]` — a single bucket per reason, byte-identical to today's
    behavior. Reject passes the real zone. One uniform dispatch, 3 KiB total,
    and TE/PTB become trivially per-zone-upgradeable later. This is my
    preference: it removes the asymmetry AND the §10 "TE/PTB messier plumbing"
    debt shrinks to "pass a real zone id when one is available."

(b) Keep Reject-only as an array and TE/PTB as scalars, but then `bucket_for`
    must be split into `reject_bucket_for(zone)` and
    `error_bucket_for(reason∈{TE,PTB})` with a compile-time guarantee the Reject
    variant can never reach the scalar path. v1's single `bucket_for` that
    returns `&REJECT_BUCKET` for Reject is exactly what we are removing, so the
    plan must state the replacement shape.

Either is fine; leaving it unspecified is not. I lean (a).

## Required change 3 — the east-west amplification vector is under-analyzed

§5's rebuttal only rigorously covers the north-south WAN reflection attacker. The
plan must explicitly address the internal attacker on a multi-VLAN trunk / an
east-west compromised host that CAN drive rejected flows into several zones at
once (e.g. a host bridged onto multiple zone subinterfaces, or a trunk carrying
many zone VLANs to one physical port). If that attacker can realistically reach K
zones, worst-case backscatter is K×1000/s. The plan should either (i) argue K is
small/bounded in practice, or (ii) add an OPTIONAL global ceiling as a second
gate (admit only if BOTH the per-zone bucket AND a global cap have a token) so
the aggregate is still bounded while per-zone fairness holds for the common case.
Note (ii) reintroduces a limited global-drain (the global gate is FCFS), so it is
a genuine tradeoff, not a free win — hence it belongs in the design discussion,
not silently omitted. I want the reviewers to rule on whether (ii) is needed or
whether flat per-zone at 1000/s is acceptable given the diagnostic nature.

## Minor / non-blocking

- §5 zone clamp: prefer `if (id as usize) < MAX_ZONES { id } else { 0 }` over
  `.min(63)` so out-of-range ids share bucket[0] (the unzoned sentinel) rather
  than colliding onto bucket[63] (a real zone). v1 already flags this; make it
  the decided form, and add a compile-time `assert!(MAX_ZONES == 64)` mirroring
  the C header.
- §11.4 asks whether MAX_ZONES is enforced at commit so zone_id ≥ 64 is
  impossible. This must be VERIFIED (Go compiler / zone id assignment), not left
  open — if the Go side can emit a zone id ≥ 64, the clamp is load-bearing and
  the plan must say so. Move from "open question" to "verified fact" in v2.
- Test plan (§9) is strong; add an explicit 5/5 flake requirement on the new
  cross-zone test and confirm the ported per-zone tests still hold the
  `global_bucket_test_lock` (now parameterized by zone) so the process-global
  statics don't cross-contaminate under the parallel runner (#2955 lesson).

## Verdict

**NEEDS-REVISION (r1).** The core design (per-zone Reject buckets, ~1-3 KiB,
cold path, config-bounded cardinality, no anti-amplification regression for the
realistic vector) is sound and I recommend it OVER the global+attribution
fallback. But v1 must (1) make the aggregate counter a single atomic, not a
64-load sum; (2) specify the exact bucket-dispatch shape (recommend the 2D
array); and (3) rigorously address the east-west multi-zone amplification vector
and rule explicitly on whether a global second-gate ceiling is needed. With those
three, this converges to PLAN-READY. PLAN-KILL remains defensible only if the
reviewers judge the diagnostic reply not worth ANY new surface — I do not, given
the fix is ~1-3 KiB on an already-cold path.
