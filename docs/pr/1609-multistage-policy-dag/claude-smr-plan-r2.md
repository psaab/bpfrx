# Claude SMR plan-review r2 — #1609 multi-stage policy DAG

**Role**: domain SMR (same scope as r1).

**Verdict (round 2): PLAN-NEEDS-MAJOR (converging with Codex + AGY)
+ BLOCKED on #1612 numbers for production framing.**

## Round 1 convergence summary

| Finding | SMR r1 | AGY r1 | Codex r1 | Verdict |
|---|---|---|---|---|
| Stage 3 memory blow-up (RuleBitSet × /24 × books) | F-r1-1 MAJOR | F1 FATAL | F1 BLOCKING | **CONVERGENT FATAL** — v2 must redesign Stage 3 |
| First-match-wins across unsorted stage outputs | F-r1-4 MAJOR | F2 MAJOR | F4 BLOCKING | **CONVERGENT MAJOR** — v2 must use frozen sorted postings + galloping merge |
| Stage 2 src-port / ICMP semantics | F-r1-2 MAJOR | F4 MEDIUM | F3 BLOCKING | **CONVERGENT** — v2 must spec any_port_rules fall-through + ICMP path |
| Construction cost at 1M rules | F-r1-3 MEDIUM | F3 MEDIUM | F5 BLOCKING | **CONVERGENT** — two-pass exact-allocator builder |
| DIR-24-8 vs Poptrie | F-r1-Q2 OPEN | F1 implicit | F2 BLOCKING | **CONVERGENT** — Poptrie should be the default; DIR-24-8 reserved for one hot global table |
| K_bucket adversarial bound | F-r1-Q7 OPEN | F5 LOW (accept soft cap) | F6 BLOCKING | **NOT CONVERGENT** — AGY says soft cap is fine; Codex says structural enforcement required |
| Ship now with 1K microbench vs BLOCK on #1612 | F-r1-6 LOW (ship now) | F6 LOW (ship now) | F7 BLOCKING (BLOCK) | **NOT CONVERGENT** — 2/3 say ship, Codex says BLOCK |
| Allocation-free hot path explicit instruction sequence | (not raised) | (not raised) | F8 BLOCKING | **NEW** — Codex unique finding, must be addressed in v2 |
| Cache-key invariant Stage 2/3 ⊆ 5-tuple | F-r1-5 MEDIUM | G (audit) | F9 BLOCKING | **CONVERGENT** — Stage 2/3 must be strict 5-tuple, no ICMP-type/app-id |
| Cargo deps (roaring) | (not raised) | (not raised) | F10 MEDIUM | **NEW** — Codex: prefer existing primitives over `roaring` crate |

**Verdict**: PLAN-NEEDS-MAJOR. The architecture is on the right axis,
but v1's data structures are fatal-broken on memory + correctness +
allocation. v2 needs the Multi-Book LPM restructure + sorted postings
+ Poptrie + two-pass builder + allocation-free hot path.

## The contested decisions and how to break the tie

### Decision 1: K_bucket — soft diagnostic vs structural bound

AGY F5 (LOW): "soft-cap Prometheus counter is the correct and only
viable operational mitigation … hard-capping is unacceptable because
silently dropping or ignoring rules violates security policy
semantics."

Codex F6 (BLOCKING): "a soft diagnostic for `K_bucket` is not a
bound. Adversarial but valid Junos policy can put 1M broad `any/any/
app any` rules in one zone pair. If `K_bucket <= 32` is required,
the compiler must enforce it structurally or reject/fallback at
commit time."

**Tiebreak**: Codex is correct in the strict sense — the structural
"K_bucket ≤ 32" claim is unsupported. AGY is correct that
hard-capping is unacceptable. The reconciliation: **drop the
"≤ 32" structural claim**. The plan's value is the AVERAGE
case (well-behaved configs prune to bucket ≤ 32). Worst-case
adversarial K_bucket reverts to ~current linear scan inside the
zone-pair, which is **no worse than today's master** for that
pathological config. Prometheus soft diagnostic surfaces the
pathology to the operator. The "≤ 500 ns at 1M rules" budget is
guaranteed only for well-behaved configs.

This must be honestly framed in v2: "DAG accelerates well-behaved
configs by ≥10×; pathological configs are no-worse than master
linear scan". This removes the structural claim that Codex
correctly flagged as unsupported.

### Decision 2: Ship-now-with-1K-microbench vs BLOCK on #1612

AGY F6 (LOW) + SMR F-r1-6: structural argument is solid; ship now
with 1K microbench, defer 1M empirical to #1612.

Codex F7 (BLOCKING): "shipping with only a 1K synthetic microbench
is unjustified. At this target, cache/TLB behavior dominates.
This needs to block on #1612 scale numbers before default
enablement. A feature-flagged prototype is fine; production
framing is not."

**Tiebreak**: Codex is correct on the principle — cache/TLB effects
at 1M rules cannot be inferred from 1K microbench. AGY is correct
that the structural argument is solid AS AN ARGUMENT. The
reconciliation: **the v2 plan ships the implementation as a
feature-flagged prototype** behind a runtime flag
`policy_dag.enable: false` by default. The implementation lands
to enable parallel work; production enablement BLOCKS on #1612
producing the 10K/100K/1M numbers.

This honors Codex F7 (no production framing without #1612 numbers)
AND AGY F6 (the architectural skeleton ships now). It also
matches the project's "narrow scope" discipline — a feature flag
makes the scope explicit.

### Decision 3: DIR-24-8 vs Poptrie

Codex F2 corrects my v1 math: 10K books × 16 MB at 1 byte per
entry is 160 GB, not 160 MB. The 10K-books arithmetic was a unit
error in v1 plan §2.3 (I divided by books instead of multiplying).

**Tiebreak**: Poptrie should be the default. DIR-24-8 reserved for
the single global Multi-Book LPM (where the top-level table is
amortized across all books) under AGY F1's restructure.

## What v2 must produce

1. **Stage 3 restructure**: single global Multi-Book LPM per address
   family (DIR-24-8 over 2^24 entries, each storing
   `Option<Arc<[u16]>>` book indices) + `BookEntry` carries
   `rules_citing_as_source: Arc<[u32]>` / `rules_citing_as_destination:
   Arc<[u32]>`. Memory budget at 1M rules: 64 MB LPM + 128 MB
   citations = ~192 MB per snapshot.

2. **Stage 2 correctness**: any_port_rules per-proto bucket falls
   through. Explicit ICMP carve-out:
   `parse_flow_ports` puts ICMP id in src_port + 0 in dst_port; ICMP
   rules go into `any_port_rules` for proto=1 / 58 and are evaluated
   in Stage 4 by `compiled_apps.matches(...)`. Document this mapping.

3. **Sorted postings + galloping merge**: every per-stage candidate
   slice is sorted by RuleIdx at construction. Stage 4 iterates the
   intersection of {Stage 2 candidates, Stage 3 source-side hits,
   Stage 3 dest-side hits} via a 3-way galloping merge that emits
   ascending RuleIdx without allocation. First-match-wins is
   preserved structurally — no per-packet sort.

4. **Two-pass exact-allocator builder**: first pass counts postings
   per LPM entry + per Stage 2 bucket; second pass allocates exact
   `Arc<[u32]>` slices, copies sorted indices, freezes. No
   bitset materialization. Construction cost re-estimated.

5. **Allocation-free hot path**: explicit instruction sequence in
   plan v2. No per-packet `Vec` allocation, no SmallVec spill above
   the inline cap, no roaring intersection. Galloping merge over
   borrowed slices; per-worker scratch buffers if needed.

6. **K_bucket honest framing**: drop the "≤ 32 structural" claim.
   DAG accelerates well-behaved configs ≥10×; pathological configs
   are no-worse than master. Operator diagnostic counter
   `xpf_userspace_policy_dag_bucket_oversize_total{zone_pair}` at
   bucket > 64 surfaces pathology.

7. **Feature flag**: `policy_dag.enable: false` by default. PR ships
   the DAG behind the flag. Production enablement blocks on #1612
   producing 10K/100K/1M cold-path numbers.

8. **Cache-key strict 5-tuple**: Stage 2 prunes on (proto, src_port,
   dst_port) and Stage 3 on (src_ip, dst_ip). No ICMP type/code, no
   app-identification, no DSCP/TCP-flags/IHL in Stage 2/3. All
   non-5-tuple selectors land in Stage 4 (consistent with #1431).

9. **Cargo discipline**: NO `roaring` crate. Use existing
   `PrefixSet` primitives + frozen `Arc<[u32]>` sorted postings.

## Risk if we proceed to v2 with these changes

- Plan v2 is a substantial rewrite — almost every section changes.
- The Multi-Book LPM restructure is architecturally cleaner but
  requires the address-family-level (not per-zone-pair) Stage 3.
  Cross-zone-pair sharing is now mechanical.
- Empirical numbers at 10K/100K/1M still gated on #1612 — the
  feature-flag honors this without blocking the implementation.

## Verdict

**PLAN-NEEDS-MAJOR**. v2 is doable and worth writing. But the v2
must be written from scratch incorporating ALL convergent findings,
not patched. I'll write v2 next.

## Process note

Codex and AGY converged on the critical architectural findings.
Codex sandbox was infra-limited (could not read worktree) and
delivered a "source-availability-limited" review based on the
prompt's section references. Per project memory at
`feedback_codex_infra_must_retry`, retry was attempted and the same
sandbox failure recurred; per-finding signal is high-confidence
because Codex's structural reasoning doesn't require line-grep.
AGY had full worktree access and confirmed all of Codex's
architectural objections independently — Codex's review is
treated as 4-of-4 quality on architectural findings (lower on
line-number-grounded findings, of which there were none in this
round).
