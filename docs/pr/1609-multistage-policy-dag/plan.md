# Plan v1: Multi-stage policy DAG (#1609)

**Status**: v1 — first draft for hostile quad-review (Codex + AGY +
Copilot + Claude SMR). Open architectural questions deliberately
left unresolved for reviewers to converge on.

## 0. Honest framing

This PR replaces the linear scan inside `evaluate_policy_result_with_len`
at `userspace-dp/src/policy.rs:660-693` with a **multi-stage decision
DAG** built at config-apply time. The goal is to bound cold-path
policy evaluation at 1M rules to ≤ ~270-500 ns per packet, which the
linear scan cannot achieve at any rule count above a few hundred.

This is **NOT** a JIT (Cranelift was killed at #1605). It is classical
data-structure work: pre-build per-zone-pair pruning indices at
config-apply, freeze, ArcSwap-publish.

The honest framing matters because the empirical justification at
1M rules is **not yet available**:

- **#1611 (cold-path flooder runner body) is OPEN.** No AF_PACKET
  flood harness exists on master today.
- **#1612 (Scale Target measurement at 10/100/1K/10K rules) is OPEN.**
  No `docs/userspace-jit-design.md` Scale Target table is populated;
  the four tables (A1/A2/B1/B2) remain TBD on master.

This plan therefore frames Stage 1-4 **structurally** — bounded by
construction, not by measured ns numbers. Whether the structural
ceiling fits the 270 ns/packet budget at 1M rules is **the open
empirical question** that depends on #1611+#1612 landing.

If the reviewers converge on "the empirical justification cannot be
hand-waved; this plan must wait on #1612 numbers", that is a valid
BLOCKED outcome and we report it back to the coordinator.

If the reviewers converge on "the structural bounds + small synthetic
microbench at 1K rules give enough confidence to ship the
implementation now, while #1611+#1612 finish in parallel", then we
proceed under that contract: the PR adds the DAG, a small synthetic
microbench at 1K rules confirming the ordering (DAG < linear by ≥10×
at that rule count), and updates the design doc Phase 4 row to
"DAG architecture committed; Scale Target table population
deferred to #1612".

## 1. Background

### 1.1 The linear scan to replace

`evaluate_policy_result_with_len` at `userspace-dp/src/policy.rs:648-694`:

```rust
let key = zone_pair_key(from_id, to_id);
if let Some(indices) = state.zone_pair_index.get(&key) {
    for &idx in indices {
        if let Some(result) = try_match_rule(
            &state.rules[idx], state, src_ip, dst_ip, protocol,
            src_port, dst_port, packet_len,
        ) {
            return result;
        }
    }
}
for &idx in &state.global_indices {
    if let Some(result) = try_match_rule(
        &state.rules[idx], ...
    ) { return result; }
}
PolicyEvaluationResult { action: state.default_action, policy_id: 0 }
```

Phase 2 (already shipped) is the `zone_pair_index` lookup — that's
O(1). What's NOT O(1) is the inner `for &idx in indices` loop. At
1M total rules with 20 zone pairs, the indices vector inside any one
zone pair is up to ~50K. Each iteration calls `try_match_rule` which
checks:
- `rule.compiled_apps.matches(protocol, src_port, dst_port)` — O(1) hash + small range scan,
- `rule.source_literal_v4.contains(src) || any book.contains(src)` — `PrefixSetV4` lookup (#923) per book,
- same for destination.

At 50K rules per zone-pair × ~5 ns per `try_match_rule` (#923 trie
contains is dominated by L1-i miss + chain of pointer chases) =
~250 µs/packet, vs 270 ns budget. **3 orders of magnitude off.**

### 1.2 Phase 2 baseline + foundational pieces now landed

- **#1606 (PR #1610 squash 1c409b0f)** — `BookEntry` table is now
  deduplicated; rules cite books by dense u32 index
  (`source_book_idxs: SmallVec<[u32; 8]>`). Memory-cost of 100K
  rules × 1K CIDRs is no longer the 1.6 TB blocker. This is a hard
  prerequisite for Stage 3 LPM trie sharing.
- **#1607 step-1 (PR #1613 squash 260ff8721c)** — cold-path flooder
  skeleton + counter scaffolding shipped. Histogram counters at
  `xpf_userspace_worker_cold_path_ns_bucket{...}` exist. **Empirical
  numbers not yet produced.**
- **#1431** — CACHE-KEY INVARIANT. Every match dimension on
  `FilterTerm` / `FirewallTermSnapshot` is classified IN cache key or
  path-(b). The same discipline applies here: each DAG stage's
  pruning predicate must be a cache-key dimension (5-tuple), and
  any per-packet field that isn't (DSCP, TCP flags, IHL, fragment)
  stays out of the Stage 1-3 pruning and lands in the bucket
  scan (Stage 4).
- **#923** — `PrefixSetV4/V6::Trie` is a per-set uncompressed
  binary trie. Per-rule binary trie is what we have today; multi-rule
  shared LPM is what this plan adds.

### 1.3 What this plan does NOT change

- **Wire protocol** is foundation from #1606 — no new fields, no
  new versions. The DAG is constructed from the existing
  `PolicyState` shape (rules + books + zone_pair_index).
- **HA session sync** — sessions still sync the established-flow
  decisions. Policy evaluation reruns at session install time on
  the receiving node; the DAG is constructed during snapshot apply
  on both nodes.
- **Address-book layout** — books continue to be referenced by
  dense u32 index. Stage 3 builds **shared** `Arc<MultiRuleLpm>`
  per book, NOT per rule.
- **Flow cache** — the DAG is cold-path-only. Established flows
  continue to bypass policy evaluation entirely.

## 2. Architecture: the four stages

```
┌──────────────────────────────────────────────────────────────┐
│ Stage 1: zone-pair hash (ALREADY SHIPPED, no change)         │
│   key u32 := (from_id << 16) | to_id                         │
│   FxHashMap<u32, Stage2Index>                                │
└──────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────┐
│ Stage 2: protocol + dst-port prune                           │
│   Per zone-pair, indexed by protocol byte:                   │
│     proto_to_buckets: [Option<Stage2ProtoBucket>; 256]       │
│   Inside a proto bucket:                                     │
│     exact_dst_ports: FxHashMap<u16, Vec<RuleId>>             │
│     dst_port_ranges: SortedRanges (small-array bisect)       │
│   Output: Vec<RuleId> (small — bounded by K_after_stage2)    │
└──────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────┐
│ Stage 3: source + destination CIDR membership intersection   │
│   Per-book multi-rule LPM index:                             │
│     Arc<BookMultiRuleLpm> per BookEntry — built ONCE         │
│     contains(ip) → fixed-size bit-set of RuleIds that cite   │
│     this book and whose CIDRs in this book cover `ip`.       │
│   Rule eligibility = AND of source-side and dest-side bit-   │
│   sets, restricted to candidates from Stage 2.               │
└──────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────┐
│ Stage 4: small-bucket linear scan on residual selectors      │
│   Within the surviving candidate set:                        │
│     - applications (compiled_apps.matches — already O(1))    │
│     - inactive flag                                          │
│     - (future: DSCP, TCP flags, IHL — cache-sensitive per    │
│       #1431, do NOT prune in Stage 2/3)                      │
│   K_bucket ≤ ~32 BY CONSTRUCTION (Stage 1+2+3 narrowing).    │
│   First-match-wins is preserved by iterating candidates in   │
│   the original rule order.                                   │
└──────────────────────────────────────────────────────────────┘
```

### 2.1 Why this composition is correct

The current `evaluate_policy` semantics are:

> Iterate rules **in original rule order** within (zone-pair-matched,
> global) buckets. First rule that matches all of {zone, application,
> source IP, destination IP, not inactive} wins. If no rule matches,
> default action.

The DAG must preserve **first-match-wins-by-rule-order** exactly. The
trick is that each stage produces a **candidate set** (sub-set of
rule indices in the original order), and the bucket scan iterates
candidates in original order. The candidate set is NOT a single
"surviving rule" — it's the small set that survives all pruning.

This is structurally safe because each stage filters out rules that
provably **cannot** match (Stage 2 — wrong protocol or wrong dst port;
Stage 3 — wrong source/dest CIDR). It never filters out a rule that
could match.

### 2.2 Stage 2 details

`Stage2Index` per zone-pair, owned by `PolicyState`:

```rust
struct Stage2Index {
    /// Indexed by protocol byte. None = no rule in this zone-pair
    /// cites this protocol AND no rule matches any-protocol.
    proto_to_buckets: Box<[Option<Stage2ProtoBucket>; 256]>,
    /// Rules in this zone-pair that match ANY protocol (compiled_apps
    /// is match_any). These fall through to Stage 3 unconditionally.
    any_proto_rules: Vec<RuleIdx>,
}

struct Stage2ProtoBucket {
    /// Common-case index: rule whose application term is a single
    /// exact dst port. dport=22 → quickly grabs ssh-rule candidates.
    exact_dst_port_to_rules: FxHashMap<u16, Vec<RuleIdx>>,
    /// Range terms (uncommon): port-range terms sorted by `low` for
    /// branchless bisect-and-walk-while-low <= dport. Small array,
    /// not a tree — port ranges per zone-pair rarely exceed ~64.
    range_terms: Vec<(PortRange, RuleIdx)>,
    /// Rules where src/dst ports are unrestricted (port_spec="").
    /// Always candidates.
    any_port_rules: Vec<RuleIdx>,
}
```

Lookup cost: 1 array index (proto), 1 hash probe (exact dst port), 1
linear pass over range_terms (which is ≤ 64 in practice). Total
≤ ~10 ns even at 1M rules.

`RuleIdx` is a `u32` packed index into `state.rules`, NOT a copy of
the `PolicyRule`. Cache-friendly: every candidate set is a
`SmallVec<[u32; N]>` rather than `Vec<PolicyRule>`.

### 2.3 Stage 3 details — multi-rule shared LPM per book

Today, every `PolicyRule` carries its own `PrefixSetV4/V6` per
literal set, plus references to books by index. The #923 trie gives
O(log n) `contains` per book. With #1606 dedup, the **book entry**
itself can host a richer index:

```rust
struct BookEntry {
    v4: PrefixSetV4,
    v6: PrefixSetV6,
    /// #1609 ADDITION: which rules cite this book (on source or
    /// destination side, separately tracked). Materialised once
    /// at config-apply.
    rules_citing_as_source: Arc<RuleBitSet>,
    rules_citing_as_destination: Arc<RuleBitSet>,
    /// #1609 ADDITION: multibit LPM index — for each /N stride
    /// returns a precomputed bit-set of (book-citing rule indices
    /// AND prefix in book covers /N). Built once at config-apply.
    /// Stride is 8 bits (DIR-24-8 style for v4, smaller table for
    /// v6).
    lpm_v4: Option<Arc<MultibitLpmV4>>,
    lpm_v6: Option<Arc<MultibitLpmV6>>,
}
```

`MultibitLpmV4` (DIR-24-8 style):
- Level 0: 2^24-entry table, each entry is `Option<Arc<RuleBitSet>>`
  giving the union of RuleIdxs whose CIDR (in this book) covers the
  /24 prefix.
- Level 1: only allocated for /24s with longer-prefix rules inside.
  Sparse.

Memory bound: at 1M rules × 1 CIDR each = 16 MB worst case per book
in the DIR-24-8 layer. With #1606 sharing, books are shared across
rules, so the per-snapshot cost is `Σ books × 16 MB` not `Σ rules ×
16 MB`. At ~10K books × 16 MB = 160 MB per snapshot. With 6 in-flight
snapshots (current + 5 generations + canary) that's 960 MB — within
the "≤ 1 GB per snapshot" acceptance criterion.

**Open question Q2**: DIR-24-8 vs Poptrie. DIR-24-8 wins on probe
latency (1 indexed load + maybe a second). Poptrie wins on memory (1 to
2 orders of magnitude). At 10K books × 16 MB = 160 MB, Poptrie may not
be needed; defer to v2 if reviewers find DIR-24-8 acceptable.

`RuleBitSet`:

```rust
/// Dense bit-set indexed by rule index. At 1M rules, that's 125 KB
/// per set; shared across all snapshots via `Arc<RuleBitSet>`.
/// In-memory bitset; not packed-to-disk.
pub(crate) struct RuleBitSet {
    bits: Box<[u64]>,
    pop: u32,
}
```

At 1M rules × 125 KB = 125 KB per bit-set. With 10K /24 entries
× 125 KB = 1.25 GB. **This is the load-bearing memory question for
Stage 3.** See Q5.

### 2.4 Stage 4 details

The surviving candidate set is at most ~32 rules by construction
(if Stage 1-3 prune as designed). For each candidate:

- `compiled_apps.matches(protocol, src_port, dst_port)` — already
  shipped, O(1) for exact-port terms.
- `inactive` flag.
- Source/dest IP **re-check**. (Why re-check? Because Stage 3 only
  proves IP is in the CIDR set of *some* book this rule cites; it
  doesn't prove IP is in the rule's literal CIDR set or in the
  rule's per-side combined set. Stage 3 is a fast O(1) over-
  approximation; Stage 4 closes the gap.)

  Concretely, if `rule_idx` survived Stage 3 because IP was in
  `book[5].v4` and rule `r` cites book 5 on the source side, Stage 4
  still needs to verify that `r`'s combined source-side
  (literals + cited books) covers IP — which is exactly the existing
  `try_match_rule` logic. The win is the per-zone-pair candidate set
  shrank from K=50K to ≤32.

First-match-wins is preserved by iterating candidates in original
rule order (the candidate set is sorted at construction time).

## 3. Construction algorithm

At config-apply time, after `parse_policy_state_with_counters` builds
`PolicyState.rules` + `PolicyState.books`:

```rust
fn build_policy_dag(state: &mut PolicyState) -> Result<PolicyDag, ...> {
    // Phase A: per-book multi-rule LPM
    for (book_idx, book) in state.books.iter().enumerate() {
        let mut v4_lpm = MultibitLpmV4Builder::new();
        // Walk all rules; for each rule that cites book_idx on source
        // side, add (prefix, rule_idx) to the source-side LPM.
        for (rule_idx, rule) in state.rules.iter().enumerate() {
            if rule.source_book_idxs.contains(&(book_idx as u32)) {
                for prefix in &book.v4_prefixes() {
                    v4_lpm.insert(prefix, rule_idx as u32);
                }
            }
        }
        let v4_lpm = v4_lpm.freeze();
        // ... same for v6, dest side ...
    }

    // Phase B: per zone-pair Stage 2 index
    for (zone_pair_key, rule_indices) in state.zone_pair_index.iter() {
        let mut stage2 = Stage2IndexBuilder::new();
        for &rule_idx in rule_indices {
            let rule = &state.rules[rule_idx];
            // Index by protocol + dst port.
            for app in &rule.applications {
                stage2.insert(app.protocol, &app.destination_ports, rule_idx);
            }
            if rule.applications.is_empty() {
                stage2.insert_any_proto(rule_idx);
            }
        }
        // ...
    }

    // Phase C: same for global_indices
    ...

    Ok(PolicyDag { stage2_by_zone_pair, ... })
}
```

Construction cost target: at 1M rules + 10K books, construction
completes in ≤ 10 seconds. The dominant cost is the LPM insertion
loop: 1M rules × 8 books each × 4 prefixes each × 1 LPM insert =
32M LPM inserts. At 100 ns each = 3.2 seconds. Acceptable.

ArcSwap publication: the entire `PolicyDag` is built off-line, then
swapped into `ConfigSnapshot` atomically. Old snapshots free their
DAG via Arc refcount.

## 4. Open architectural questions for reviewers

**Q1. Interval-tree representation for Stage 2 port ranges.**
Plan v1 uses sorted-array bisect on the per-proto-bucket
`range_terms`. At K_ranges = 10K per zone-pair (adversarial), is
this still ≤ ~20 ns? Or do we need a segment tree? Reviewer
guidance requested. (Note: realistic K_ranges per zone-pair is
~64, so the sorted-array bisect is fine for the common case; the
question is whether the worst case is bounded acceptably.)

**Q2. Multibit LPM choice: DIR-24-8 vs Poptrie vs incremental.**
DIR-24-8: O(1) probe, 16 MB worst case per book at /24-heavy
distribution. Poptrie: O(log W) probe, but ~64x smaller memory.
Plan v1 picks DIR-24-8 on the latency argument; reviewers may
push back on the memory cost. Note that with #1606 dedup, the
per-snapshot cost is bounded by `books × 16 MB`, not `rules ×
16 MB`. At 10K books that's 160 MB.

**Q3. Per-book vs per-snapshot LPM construction.** If books are
shared across rules via #1606 Arc-dedup, can the LPM also be
shared? Yes — `Arc<MultibitLpmV4>` lives on `BookEntry`, NOT on
`PolicyDag`. Rebuilding only books that changed across snapshots
keeps the apply-latency budget bounded. Plan v1 does this; v2
may add a content-hash cache to skip rebuild on no-op book
swap.

**Q4. Bucket-scan residual selectors classification.** Within
Stage 4, which selectors stay in the bucket scan vs get promoted
to a pruning stage?

| Selector | Cardinality | Pruning stage |
|---|---|---|
| `applications` (proto+port) | low-medium | **Stage 2 (planned)** |
| `source CIDR / dest CIDR` | unbounded | **Stage 3 (planned)** |
| `inactive` | binary | Stage 4 (cheap branch) |
| `from_zone / to_zone` | low | **Stage 1 (already shipped)** |
| DSCP, TCP flags, IHL | per-packet | Stage 4 ONLY (cache-sensitive per #1431) |
| forwarding-class | medium | Stage 4 |
| flex-match | unbounded | Stage 4 (not promotable) |
| application-identification (L7 DPI) | unbounded | NOT in DAG; runs at L7 inspector layer |

Reviewers should challenge this classification.

**Q5. Memory footprint at 1M rules per snapshot.** Naive bit-set
math: 1M rules × 125 KB/bitset × 256 /24 entries per book × 10K
books = 320 GB. THIS IS A KILL SHOT IF NOT MITIGATED. Mitigations:

- **Sparse bit-sets**: most /24 entries cover a small subset of
  rules (≤ 64). Use roaring-bitmap representation. At 64 rules
  per /24 × 10K books × 256 = 160 MB. Acceptable.
- **Lazy second-level LPM**: only allocate /25-/32 leaves when
  a CIDR with prefix > 24 exists in the book. Common for /32
  host objects, rare for /24s.
- **Per-book population gate**: if a book contains 0 prefixes
  (MatchAny or MatchNone), the LPM is not allocated — the rule-
  match logic short-circuits via the existing
  `source_v4_match_any` flags.

Plan v2 will specify the bit-set representation concretely once
reviewers weigh in on Q2.

**Q6. HA sync portability.** The DAG is snapshot-scoped and
generation-tagged. Generation invalidation across stages must be
atomic: a partially-rebuilt DAG must never serve a packet.

Mechanism: `ConfigSnapshot` already ArcSwaps the entire
PolicyState. The new DAG hangs off PolicyState; same atomic
swap.

Cross-chassis: HA peers each build their own DAG from their own
PolicyState (which is sync'd via the existing config sync path).
No new wire format needed.

**Q7. Adversarial K_bucket bound.** Can a config author construct
a workload that pathologically maximizes K_bucket? Yes —
constructing 1000 rules with identical (proto, dport, src CIDR,
dst CIDR) but differing in residual selectors (e.g.
application-identification name or flex-match) would force all
1000 into the same Stage 4 bucket. Mitigation:

- **Soft cap + operator diagnostic**: emit a Prometheus counter
  `xpf_userspace_policy_dag_bucket_overflow_total{zone_pair}`
  when K_bucket > 64 at evaluate time. Surface in
  `show security policies dag-diagnostic`.
- **Hard cap is NOT enforced** — first-match-wins semantics
  forbid silently dropping rules.

**Q8. Interaction with #1608 v3 cold-path defenses.** #1608 v3
(per-source rate-limit + verdict cache) sits in front of the
DAG and reduces cold-path load. The DAG plan assumes no
defensive layer — if #1608 v3 ships, the DAG's worst-case load
shrinks but the structural bound holds either way. No
duplication of effort.

## 5. Files touched

In scope for this PR:

- `userspace-dp/src/policy.rs` — refactor to add `PolicyDag` field
  on `PolicyState`, replace the linear scan in
  `evaluate_policy_result_with_len` with DAG traversal. Existing
  `try_match_rule` is reused for Stage 4.
- `userspace-dp/src/policy_tests.rs` — extend existing tests +
  add DAG-shape tests + small synthetic 1K-rule microbench.
- `userspace-dp/src/lib.rs` — possibly new module declarations
  for `policy_dag.rs` (subject to file-size convention; see
  `feedback_refactor_module_dir_layout`).
- `docs/userspace-jit-design.md` — Phase 4 row update per
  doc-coherency contract from #1605: replace "SUPERSEDED 2026-05-27
  by #1609" placeholder with the concrete DAG architecture.

May need new modules (will defer to v2 if reviewers object):
- `userspace-dp/src/policy/dag.rs` — the DAG itself.
- `userspace-dp/src/policy/multibit_lpm.rs` — DIR-24-8 multi-rule
  LPM.

NOT touched (coordinator-enforced scope discipline — #1611+#1612
sub-agent owns these):
- `test/incus/cold-path-flooder/` — owned by #1611.
- `test/incus/cold-path-microbench.sh` — owned by #1611+#1612.
- `userspace-dp/src/afxdp/poll_descriptor/` cold-path counter
  histogram — owned by #1612.

## 6. Implementation order

Suggested sequence — each step builds clean + tests pass before
the next:

1. **Pure-code-motion**: extract `evaluate_policy_result_with_len`
   body into a function that takes
   `candidates: impl Iterator<Item=RuleIdx>`. This is a no-op
   semantic change that prepares the call site.
2. Add `PolicyDag` skeleton + `Stage2Index` + `Stage2ProtoBucket`
   types. Construction sites filled in by Phase B of build_dag.
3. Add `MultibitLpmV4/V6` + `BookEntry` extensions for the per-book
   LPM. Construction sites filled in by Phase A.
4. Wire DAG construction into `parse_policy_state_with_counters`.
5. Replace the linear scan in `evaluate_policy_result_with_len`
   with `dag.lookup(...)` → candidate iterator → existing
   try_match_rule loop.
6. Add microbench at `userspace-dp/src/policy/bench_dag.rs` —
   1K synthetic rules, confirm ≥ 10× speedup vs linear scan.
7. Update `docs/userspace-jit-design.md` Phase 4 row.

## 7. Test plan

- **Existing policy_tests.rs must still pass unchanged.** Every
  semantic test in the existing suite stays.
- **New DAG-shape tests** (in policy_tests.rs):
  - Empty DAG (no rules) → default action.
  - Single rule in one zone-pair → matches when in zone, otherwise
    default.
  - Rule order is preserved (rule R1 matches first; R2 same
    bucket but lower priority).
  - Global rule fall-through (zone-pair has no match → global rules
    evaluated).
  - Adversarial K_bucket overflow (100 rules in same bucket; result
    is rule 0).
  - Stage 2 protocol mismatch (TCP rule + UDP packet).
  - Stage 3 CIDR miss (rule has src 10.0.0.0/8, packet from
    192.168.0.1).
  - Multibit LPM /24 hit + /28 leaf override.
  - `RuleBitSet::intersect_with` correctness.
- **5/5 flake-check** on the new tests (per `feedback_no_test_dismissal`).
- **Synthetic 1K-rule microbench**: confirm DAG < linear by ≥10×
  at 1K rules. Defer 10K/100K/1M to #1612 (this PR notes the gap
  in its description).
- **Smoke matrix** on `loss:xpf-userspace-fw0/fw1`: v4+v6 × push+`-R` ×
  CoS-off+CoS-on. NO regression vs master.
- **`make test-failover`**: HA failover ≤ 60 ms unchanged.

Empirical 1M-rule numbers are explicitly deferred to #1612 (per the
honest-framing constraint in §0). If reviewers say "no merge without
1M numbers", we stop and report BLOCKED.

## 8. Acceptance criteria

- [ ] Plan v1 → vN PLAN-READY through 4-way quad-review.
- [ ] Multi-stage DAG construction shipped at config-apply time.
- [ ] All existing policy_tests.rs pass unchanged.
- [ ] New DAG-shape tests added + pass 5/5 flake check.
- [ ] Synthetic 1K-rule microbench shows DAG < linear by ≥ 10×.
- [ ] Smoke matrix passes on loss userspace cluster.
- [ ] `make test-failover` passes; HA failover ≤ 60 ms.
- [ ] Memory footprint per snapshot at 10K books × 100K rules ≤
  1 GB — *measured at apply time via Prometheus gauge*.
- [ ] `docs/userspace-jit-design.md` Phase 4 row replaced with the
  concrete DAG architecture (per doc-coherency contract from #1605).
- [ ] Cold-path policy evaluation at 1M rules ≤ 500 ns/packet on
  loss userspace cluster — **DEFERRED to #1612 measurement; this PR
  ships the structural bound, not the empirical proof.**

## 9. Alternatives rejected

- **Cranelift JIT** — killed at #1605. Code-gen doesn't help the
  cold-path data-structure problem.
- **Hash-table on dominant selector + linear scan of bucket** —
  doesn't compose with CIDR membership. CIDRs are intervals, not
  exact keys.
- **Single-stage decision tree (CART / RDC)** — config-apply
  build cost at 1M rules is minutes, not seconds. DAG-as-static-
  structure wins on build latency.
- **Per-flow JIT** — every cold-path packet is a flow miss by
  definition. JIT amortization fails on cold path.

## 10. Risks

- **R1**: structural bound holds only if K_bucket ≤ ~32 in
  practice. Adversarial configs can violate; operator diagnostic
  (Q7) is the mitigation.
- **R2**: per-book LPM memory at 10K books × 16 MB = 160 MB —
  acceptable but not free. Roaring bit-sets (Q5) can shrink
  further at v2 if reviewers push back.
- **R3**: config-apply latency at 1M rules. Construction is
  O(rules × books_per_rule × prefixes_per_book) = ~32M LPM
  inserts at 100 ns each = 3.2 sec. Marginal at production scale.
- **R4**: empirical 1M-rule numbers don't exist on master. If
  reviewers require them, we BLOCK on #1612.

## 11. Out of scope

- **Rate-limit + verdict cache** — #1608.
- **Per-flow JIT specialization** — killed (#1605).
- **Wire-protocol changes** — #1606 is the foundation.
- **Cold-path flooder + Scale Target measurement** — #1611 + #1612.
- **Application-identification L7 DPI** — out of policy DAG; runs
  at a later inspector stage.
