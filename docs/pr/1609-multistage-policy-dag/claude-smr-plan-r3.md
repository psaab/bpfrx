# Claude SMR plan-review r3 — #1609 v2 (Multi-Book LPM + staged)

**Role**: domain SMR (network firewall semantics + Junos policy
order + data-structure algorithms + CPU microarchitecture + AF_XDP
ZC cold-path budgets).

**Target**: `docs/pr/1609-multistage-policy-dag/plan.md` v2
(rewritten from Multi-Book LPM architectural pivot, staged delivery
acknowledged).

**Verdict (round 3 / v2 round 1): PLAN-READY-WITH-NITS.**

## Why v2 passes hostile self-review

The v2 plan resolves every round-1 convergent fatal:

1. **Stage 3 memory blow-up (CONVERGENT FATAL in r1+r2)** — eliminated.
   v2 has NO bitsets, NO per-/24 RuleBitSet. The Multi-Book LPM
   stores `Arc<[u16]>` book indices per /24 (not per rule), and
   per-book sorted citation arrays carry the rule indices. Memory at
   1M rules: ~120-160 MB per snapshot. With ≤ 6 in-flight snapshots,
   stays well under the 1 GB acceptance criterion.
2. **First-match-wins across stages (CONVERGENT MAJOR)** — galloping
   merge over sorted-ascending `Arc<[u32]>` slices preserves rule
   order structurally (§2.6). Proof sketch is sound: rule_idx is
   dense parse-order so ascending = first-match.
3. **Stage 2 src-port/ICMP semantics (CONVERGENT)** — §2.2 spells
   out the ICMP carve-out (id in src_port, 0 in dst_port → exact_dport
   bucket or any_port_rules) + `any_port_rules` per-proto fall-through.
   Stage 4's `try_match_rule` re-runs `compiled_apps.matches` to close
   ICMP id matching.
4. **Construction cost (CONVERGENT)** — two-pass exact allocator.
   Phase A is naturally sorted (rule_idx ascending). Phase B/C count
   then allocate. ~1-1.5 sec at 1M rules. Junos commit budget
   acknowledged in §12 R3.
5. **DIR-24-8 vs Poptrie (CONVERGENT)** — v4 picks DIR-24-8 with
   rationale (L2 cache hit on level-0); v6 picks per-/48-hash +
   sub-LPM with rationale (2^48 table infeasible). The choice is
   parameterized via the LPM trait so #1612 measurement can drive a
   stride change without re-architecting. This is exactly the right
   level of uncertainty acknowledgement.
6. **K_bucket structural bound (CONVERGENT-NOT-CONVERGENT in r2)** —
   v2 drops the structural claim per Codex F6 tiebreak. Honest
   framing: well-behaved configs accelerate ≥10× (pending #1612);
   pathological configs are no-worse-than-master inside the
   surviving slice. Soft Prometheus diagnostic at >64 surfaces
   pathology. AGY's "no silent rule drops" and Codex's "no false
   structural claim" both honored.
7. **Ship-now-vs-BLOCK (NOT CONVERGENT in r2, user-override
   resolved)** — v2 ships behind feature flag default-OFF +
   staged delivery (Step 1 primitive + scaffold; Step 2 hot path;
   Step 3 knob+enablement). This honors both Codex F7 ("no
   production framing without #1612") and AGY F6 ("ship the
   architecture now") via the feature flag.
8. **Allocation-free hot path (Codex F8 NEW)** — §2.5 explicit code
   sketch + per-worker scratch + Arc-borrow discipline. No per-packet
   alloc.
9. **Strict 5-tuple cache-key invariant (CONVERGENT)** — Stage 2:
   (proto, src_port, dst_port). Stage 3: (src_ip, dst_ip). All
   non-5-tuple selectors in Stage 4 via `try_match_rule`. Documented.
10. **No `roaring` crate (Codex F10)** — confirmed. `Arc<[u32]>`
    + galloping merge.

## Nits (non-blocking)

### N1 — §2.5 scratch.gather_src/dst is hand-waved

The code sketch at §2.5 has `scratch.gather_src(state, src_books)`
and `scratch.gather_dst(state, dst_books)` as commented-out lines.
The actual gather mechanism — how do we union the per-book citation
arrays into a single sorted slice without allocation? — is
deferred to Step 2.

The answer is: galloping k-way merge over up to ~8 borrowed Arc<[u32]>
slices (since typical realistic configs have 2-4 books per side per
zone-pair), writing dedup'd ascending u32 into a per-worker scratch
`&mut [u32; STAGE3_SCRATCH_LEN]`. Stage 4 then 3-way merges {Stage 2
candidates, Stage 3 scratch_src, Stage 3 scratch_dst}.

**Not blocking** because Step 1 only ships the LPM primitive +
flag-scaffold; the gather mechanism is part of Step 2.

### N2 — v6 stride choice rationale could be sharper

§2.3 says "per-/48 FxHashMap + sub-LPM" for v6 with "IPv6 sparsity
makes a 2^48 top-level table infeasible". True, but the realistic
prefix distribution on customer firewalls is **/64 dominant** (host
routes), not /48. A per-/48 hash buckets all /64s under the same /48
into one sub-LPM — fine for IPv6 site-level address books, but for
host-density books may collapse most lookups onto a single sub-LPM.

Mitigation: §12 R2 acknowledges per-stride back-pressure via the LPM
trait. v6 measurement (deferred to #1612) drives the choice. The
plan should call out this v6-host-density risk more explicitly —
add to §14 v2-Q1.

**Not blocking** but worth a §14 sharpening.

### N3 — §5 wire-shape change needs a both-sides note

§5 adds `policy_dag_enable: bool` to `ConfigSnapshot` on the Rust
side and emits `false` on the Go side. Per
`feedback_wire_protocol_both_sides`, every wire field change must
grep BOTH sides. The plan does Go-side emit; it should also explicitly
say "no Junos-config knob in this PR; Go-side emit is hard-wired
false until Step 3 ships the knob". Step 5 §5 says this in prose,
but the file list at §9 should add the explicit Go file path
(`pkg/dataplane/userspace/snapshot.go` or wherever the snapshot
emission lives — the plan should grep this in implementation).

**Not blocking** — it's an implementation diligence item, not a plan
correctness issue.

### N4 — Module layout refactor in Step 1 PR is scope creep risk

§10 Step 1 starts with "Refactor policy.rs into directory layout".
That's a pure code-motion PR by itself; combining it with the new
LPM primitive in one PR risks Copilot/Codex review confusion
("where did the function go, did the semantics change?"). Two
options:

- **Option A**: ship the module-layout refactor as a separate
  pre-cursor PR first, then this PR's Step 1 adds the LPM module
  + flag.
- **Option B**: keep them in one PR but commit them as two separate
  commits with clear messages so reviewers can `git diff
  prev-commit..ref` cleanly.

I lean toward Option B for this size — the refactor is mechanical
(file move + module path rewrite) and combining keeps the PR count
manageable. But reviewers will likely flag this.

**Not blocking**; a heads-up to the implementer.

### N5 — Step 1 stub `evaluate_via_dag` is a "feature flag wired but useless" smell

§14 v2-Q3 acknowledges this. Step 1 wires the flag but the
`evaluate_via_dag` body just falls back to linear scan. Reviewer
optic: "you're shipping a flag that does nothing".

Counter-argument: it exercises the flag plumbing end-to-end +
proves the flag-off → flag-on transition is semantically identical
+ unblocks Step 2 from worrying about wire compatibility. This is a
valid scaffold pattern.

**Not blocking** but worth being honest in the PR body that "this
PR ships the primitive, not the productized hot path".

### N6 — Per-/48 hashmap on hot path is not allocation-free

Subtle: §2.3 v6 design says "per-/48 FxHashMap + sub-LPM". `FxHashMap`
lookup is allocation-free (read-only) — fine. But if the v6 lookup
ever needs to insert (it doesn't, since the DAG is frozen) the
amortized-O(1) realloc would break the no-alloc invariant. The plan
should be explicit that the v6 hashmap is built once at config-apply,
sealed via Arc, and only `get(&key)` is called on the hot path. (It
already says this implicitly via §2.3 + §3 two-pass build, but the
v2-Q1 reviewer hook could call it out.)

**Not blocking**.

## Verdict

**PLAN-READY-WITH-NITS** for Step 1 (this PR's scope: Multi-Book LPM
v4 primitive + feature-flag scaffold + property tests).

The nits N1-N6 are all non-blocking. N1 and N6 are clarifications of
how Step 2 will close out the hot path; N2-N3 are documentation
hygiene; N4-N5 are implementation strategy notes.

The v2 plan is on the correct architectural axis (Multi-Book LPM
single-global-LPM + per-book citation arrays + sorted-postings +
galloping merge), addresses all round-1 convergent fatals, and the
staged delivery + feature-flag scaffold honors both the "ship the
architecture now" and "no production framing without #1612"
positions from r1+r2.

## Process notes

Round 3 (v2 round 1) verdict: **PLAN-READY-WITH-NITS** from Claude
SMR. Awaiting Codex + AGY independent v2 reviews to confirm the
architectural pivot resolves their respective fatals.

Sandbox-infra-blocked-Codex exception (per
`feedback_codex_infra_must_retry`) applies if Codex hits a third
infra failure on v2; we proceed on AGY + Claude SMR + Copilot
attestation.
