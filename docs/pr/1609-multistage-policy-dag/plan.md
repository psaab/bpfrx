# Plan v3: Multi-Book LPM policy DAG (#1609)

**Status**: v3 — starts from the v2 Multi-Book LPM architectural
axis (which remains sound) + the 5 fixable fatals the v2 round-1
3-of-3 PLAN-NEEDS-MAJOR convergence identified. v1 is killed
(per-/24 RuleBitSet → 320 GB memory bomb). v2 is killed (literal/any
rule drop + v6 DoS + global ordering invariant + broad-prefix /0
blow-up + BookEntry-not-buildable). v3 supersedes both.

**User overrides** (2026-05-27):
- Memory budget RELAXED. The 1.5 GiB level-0 footprint from v2 r4
  is acceptable on this hardware (8-16 GB VMs). The constraint is
  CPU/cache/TLB pressure for the 270 ns/packet cold-path budget,
  NOT memory footprint. v3 §6 captures this explicitly.
- Proceed with v3 implementation even though #1612 has not yet
  ratified the structural ≥10× speedup claim. #1612 measurement
  engineer was spawned in parallel; ≥10× verification deferred to
  acceptance round, NOT plan-review round.

**Staged delivery** (preserved from v2): v3 ships in stages.
**Step 1 (this PR)** = Multi-Book LPM v4 primitive (single global
DIR-24-8 over book indices) + per-book sorted citation arrays +
MatchAny side-channels + feature-flag scaffold + property tests at
10/100/1K/10K rule counts. **Step 2** (separate follow-up) = full
multi-stage hot path (Stage 2/3/4 + galloping merge + per-worker
scratch + per-zone-pair ordering preservation). **Step 3**
(separate follow-up) = Junos `cos.policy.lookup` knob + production
default-flip gated on #1612.

## 0. Honest framing

This work replaces the linear scan inside `evaluate_policy_result_with_len`
at `userspace-dp/src/policy.rs:648-694` with a **multi-stage decision
DAG** built at config-apply time. Goal: bound cold-path policy
evaluation at 1M rules to within the per-packet budget that the
linear scan cannot achieve above a few hundred rules.

This is NOT a JIT (Cranelift killed at #1605). Classical data
structure work.

**Empirical-grounding gap** (acknowledged): the ≥10× cold-path
speedup claim at 1M rules is the v3 goal but is NOT empirically
verified by Step 1's primitive. #1611 (cold-path flooder runner) +
#1615 (multi-thread, 2.96 Mpps generator) MERGED; #1612 (Scale
Target measurement) in flight. v3 ships behind `cos.policy.lookup`
knob default-OFF; production enablement gated on #1612 numbers.

## 1. Background

### 1.1 The linear scan to replace

`evaluate_policy_result_with_len` at `userspace-dp/src/policy.rs:648-694`:

```rust
let key = zone_pair_key(from_id, to_id);
if let Some(indices) = state.zone_pair_index.get(&key) {
    for &idx in indices {
        if let Some(result) = try_match_rule(&state.rules[idx], ...) {
            return result;
        }
    }
}
for &idx in &state.global_indices {
    if let Some(result) = try_match_rule(&state.rules[idx], ...) {
        return result;
    }
}
PolicyEvaluationResult { action: state.default_action, policy_id: 0 }
```

The two-phase structure (zone-pair THEN global) is **load-bearing
semantics** that v3 preserves structurally (not by accident of
rule_idx ordering — see §2.5 ordering invariant fix).

### 1.2 Foundational pieces now landed

- **#1606 (PR #1610)** — `BookEntry` dedup; rules cite books by
  dense u32 index. **`BookEntry.v4` / `.v6` are `PrefixSetV4/V6`**,
  which are trie-compressed and do NOT expose original prefixes
  by default. v3 §2.4 fixes this by carrying the original prefix
  Vec alongside the PrefixSet (one-time apply-cost; zero hot-path
  cost).
- **#1611 (PR #1616)** — cold-path flooder runner body.
- **#1615 (PR #1617)** — flooder multi-thread, 2.96 Mpps gate met;
  #1612 unblocked.
- **#1431** — CACHE-KEY INVARIANT. Strict 5-tuple per Stage 2/3;
  all non-5-tuple selectors → Stage 4.

### 1.3 What v3 does NOT change

- Wire protocol — no version bump; `policy_dag_enable: bool` is a
  v3-additive serde-default field.
- HA session sync — unchanged. DAG built per-snapshot on each node.
- Address-book layout — books referenced by dense u32 index.
- Flow cache — DAG is cold-path-only.

## 2. Architecture — 5-fix v3

### 2.0 Round-2 kill axis resolution (v2 r4 fatals → v3 fixes)

| v2 r4 fatal | v3 fix |
|---|---|
| **F1 Level-0 memory math (256 MiB level-0 × 6 snapshots = 1.5 GiB)** | RELAXED per user override. §6 §Y captures the relaxed memory budget explicitly. Stride remains DIR-24-8 v4. |
| **F2 Literal-only / `source any` rules dropped by Stage 3** | §2.1 MatchAny side-channel: per-side `match_any_v4_rules: Arc<[u32]>` + `match_any_v6_rules: Arc<[u32]>` sorted by `(zone_pair_group, local_rule_idx)`. Rules with `*_match_any == true` (already computed at policy.rs:468-483) land here. §2.2 PseudoBooks cover rules with literal-only CIDRs. |
| **F3 IPv6 per-/48 FxHashMap DoS vector** | §2.3 v6 design: **bounded multibit trie with 8-bit strides** (DIR-(8,8,8,8,8,8)) capped at depth=6 = /48 effective stride. No hashing on attacker-controlled keys; deterministic O(6) probe. |
| **F4 Global-vs-zone ordering invariant violated by flat rule_idx** | §2.5 **per-zone-pair ordering** + explicit two-phase evaluation: every candidate slice is per-(zone_pair_key, local_rule_idx) or per-(global, local_rule_idx). Stage 4 evaluates zone-pair phase first, then global phase. |
| **F5 Broad-prefix /0 blows up level-0 build** | §2.6 **/0 short-circuit**: build skips level-0 population for /0 prefixes; sets `book.covers_all_v4 = true`. Stage 3 lookup unions `books_covering_all_v4` into the result implicitly via galloping merge. |
| **F6 LPM cannot be built from PrefixSet** | §2.4 store **`prefixes_v4: Arc<[PrefixV4]>` + `prefixes_v6: Arc<[PrefixV6]>` on `BookEntry`** alongside existing PrefixSet (one-time apply cost; zero hot-path cost). Plus `PrefixSetV4/V6::iter_prefixes()` for PseudoBook construction. |

Plus the 6 MAJORs from v2 r4 are addressed in §2.8 / §2.9 / §2.10 / §3 / §5 below.

### 2.1 MatchAny side-channels — fixing v2 r4 F2

The v2 design only routed rules through the LPM. A rule with
`source any` (no books, no literals → `source_v4_match_any = true`,
empty `source_book_idxs`, empty `source_literal_v4` set to MatchAny)
never appeared in any LPM leaf and was silently dropped from the
candidate set.

**Fix**: every rule's Stage 3 contribution is the UNION of two paths:
- **LPM path**: if rule cites ≥1 book on this side, that side's
  `book.rules_citing_as_{source,destination}` array gives the
  Stage 3 hit when the LPM returns the book index.
- **PseudoBook path** (§2.2): if rule has non-empty literal CIDRs on
  this side, those literal prefixes are injected into the global LPM
  as a "rule-private pseudo-book".
- **MatchAny path**: if the rule has `source_v4_match_any == true`,
  its (composite-key) rule index is appended to
  `match_any_v4_src_rules`. Same for v6 / dst.

```rust
struct PolicyDag {
    // Real books + rule-private pseudo-books, same LPM:
    multi_book_lpm_v4: Arc<MultiBookLpmV4>,
    multi_book_lpm_v6: Arc<MultiBookLpmV6>,
    book_src_citations: BookCitations,  // see §2.5
    book_dst_citations: BookCitations,
    // MatchAny side-channels (v2 r4 F2 fix):
    match_any_v4_src_rules_per_zone_pair: FxHashMap<ZonePairKey, Arc<[u32]>>,
    match_any_v4_dst_rules_per_zone_pair: FxHashMap<ZonePairKey, Arc<[u32]>>,
    match_any_v4_src_rules_global: Arc<[u32]>,
    match_any_v4_dst_rules_global: Arc<[u32]>,
    match_any_v6_src_rules_per_zone_pair: FxHashMap<ZonePairKey, Arc<[u32]>>,
    match_any_v6_dst_rules_per_zone_pair: FxHashMap<ZonePairKey, Arc<[u32]>>,
    match_any_v6_src_rules_global: Arc<[u32]>,
    match_any_v6_dst_rules_global: Arc<[u32]>,
    // Broad-prefix all-covering books (v2 r4 F5 fix):
    books_covering_all_v4: Arc<[u32]>,  // sorted book ids whose v4 has /0
    books_covering_all_v6: Arc<[u32]>,
    // Stage 2 per-zone-pair + global indices (v2 r4 F4 fix):
    zone_pair_stage2: FxHashMap<ZonePairKey, Stage2Index>,
    global_stage2: Stage2Index,
}
```

Stage 4 input on the v4 path per-phase becomes:
1. `stage2_candidates` (Stage 2 output for this packet's proto/port)
2. `lpm_src_rules` from `multi_book_lpm_v4.lookup(src_ip)` → union of
   `book_src_citations[book_id]` for each returned book_id (incl.
   books_covering_all_v4 via §2.6 implicit merge)
3. `lpm_dst_rules` same for dst
4. `match_any_v4_src_rules_for_phase`
5. `match_any_v4_dst_rules_for_phase`

Stage 4 galloping merge intersects:
`stage2_candidates ∩ (lpm_src_rules ∪ match_any_v4_src) ∩
(lpm_dst_rules ∪ match_any_v4_dst)`, then re-runs `try_match_rule`
on each survivor to close any Stage 3 over-approximation. First
match wins within the phase.

### 2.2 PseudoBooks for literal rules — completing the fix

For a rule with `source_literal_v4 = Linear([10.0.0.0/24,
192.168.1.0/28])` and `source_book_idxs = []`, v2 would only route
the rule through cited books — none here, so silently dropped.

**Fix**: at build time, allocate a PseudoBook per rule per side
with non-empty literal prefixes. PseudoBooks live at indices
`real_book_count..real_book_count + pseudo_book_count` in the same
`MultiBookLpm` book-id space (u32 indices — see §2.10).

```rust
struct PseudoBook {
    prefixes_v4: Arc<[PrefixV4]>,
    prefixes_v6: Arc<[PrefixV6]>,
    citing_rule: u32,
}

fn build_pseudo_books(state: &PolicyState) -> (Vec<PseudoBook>, Vec<PseudoBook>) {
    let mut src_pseudos = Vec::new();
    let mut dst_pseudos = Vec::new();
    for (rule_idx, rule) in state.rules.iter().enumerate() {
        let lits_v4: Vec<_> = rule.source_literal_v4.iter_prefixes().collect();
        let lits_v6: Vec<_> = rule.source_literal_v6.iter_prefixes().collect();
        if !lits_v4.is_empty() || !lits_v6.is_empty() {
            src_pseudos.push(PseudoBook {
                prefixes_v4: lits_v4.into(),
                prefixes_v6: lits_v6.into(),
                citing_rule: rule_idx as u32,
            });
        }
        // Same for dst…
    }
    (src_pseudos, dst_pseudos)
}
```

Pseudo-book count bounded by `rules` (≤1M). Per-PseudoBook citation
array is `Arc<[u32]>` of length exactly 1 (the citing rule). Storage
overhead: 1M × Arc<[PrefixV4]> + Arc<[u32]> of len 1 ≈ 30 MB
pointers + actual prefix bytes (small per pseudo-book since each
rule typically has ≤8 literals). Acceptable under relaxed budget.

`iter_prefixes()` is a new method on `PrefixSetV4/V6` — see §2.4.

### 2.3 v6 bounded multibit trie — fixing v2 r4 F3 DoS

v2's per-/48 `FxHashMap` is DoS-vulnerable because `fxhash` is
non-cryptographic and attacker can construct colliding /48s. v3
replaces with a **bounded multibit trie at fixed 8-bit strides**,
depth-capped at 6 (covering /48); deeper prefixes use a bounded
longer-prefix list (capped at `MAX_V6_LEAF_PREFIXES = 64`).

```rust
struct MultiBookLpmV6 {
    // Depth-0 (8-bit stride over upper /8): 256 entries.
    root: Box<[V6Node; 256]>,
}

enum V6Node {
    Empty,
    Leaf(Arc<[u32]>),                  // sorted book_ids
    Descend(Box<MultiBookLpmV6Sub>),
}

struct MultiBookLpmV6Sub {
    depth: u8,                          // 1..=5
    entries: Box<[V6Node; 256]>,
}

// Depth-6 terminal:
struct MultiBookLpmV6Leaf48 {
    books_covering_48: Arc<[u32]>,      // books with prefix ≤ /48 here
    longer_prefixes: SmallVec<[(PrefixV6, u32); 8]>,  // /49..=/128, ≤64 cap
}
```

Probe cost: deterministic O(6) descends (one cache line per node
fetched) + 1 leaf walk capped at `MAX_V6_LEAF_PREFIXES`. No hashing
on attacker-controlled keys; no bucket-collision DoS.

Memory: depth-0 is 256 entries × 24 B (enum + ptr + len) ≈ 6 KB.
Worst case at 100K populated /48s, depth-1..6 sub-tables = ~100K ×
6 KB ≈ 600 MB. Acceptable under relaxed budget; realistic 10K /48s
≈ 60 MB.

**Cap policy**: at config-apply time, if any /48's
`longer_prefixes` exceeds `MAX_V6_LEAF_PREFIXES = 64`, emit warning
+ Prometheus counter `xpf_userspace_policy_dag_v6_leaf_overflow_total
{subnet}`. Excess prefixes route to a per-snapshot "fallback v6
linear scan" list (still O(N) at /48 granularity, but bounded by
the number of /48s with >64 deep prefixes — typically zero in
realistic configs).

### 2.4 BookEntry prefix iteration — fixing v2 r4 F6

`BookEntry.v4` is `PrefixSetV4` enum (`MatchAny | MatchNone |
Linear(Vec) | Trie(_)`). Today the Trie variant doesn't expose
original prefixes.

**Fix**: extend `BookEntry` to ALSO carry the canonical prefix list
alongside the PrefixSet:

```rust
pub(crate) struct BookEntry {
    pub(crate) v4: PrefixSetV4,         // unchanged: hot-path contains()
    pub(crate) v6: PrefixSetV6,
    /// #1609 v3: canonical original prefix list. Used at config-apply
    /// time only to build the MultiBookLpm. Hot-path code does NOT
    /// touch this; PrefixSet.contains() owns the hot path.
    pub(crate) prefixes_v4: Arc<[PrefixV4]>,
    pub(crate) prefixes_v6: Arc<[PrefixV6]>,
}
```

One extra Arc<[Prefix]> per book at config-apply time (~100 KB
extra per snapshot at realistic book counts). Zero hot-path cost.

PrefixSet keeps full ownership of `contains()`; the prefix list is
a build-time helper.

For PseudoBooks (§2.2) the literal prefixes come from
`rule.source_literal_v4 / .source_literal_v6`. We add:

```rust
impl PrefixSetV4 {
    pub(crate) fn iter_prefixes(&self) -> impl Iterator<Item = PrefixV4> + '_ {
        // MatchAny → single PrefixV4(0.0.0.0/0)
        // MatchNone → empty
        // Linear(v) → v.iter().copied()
        // Trie(t) → walk
    }
}
```

For Step 1, `iter_prefixes()` is only called at config-apply time
(build_pseudo_books + build_multi_book_lpm — both one-time).

### 2.5 Per-zone-pair ordering — fixing v2 r4 F4

v2 used flat ascending `rule_idx` and claimed first-match-wins.
v2 r4 fatal #4: current `evaluate_policy` does two-phase (zone-pair
THEN global). A global rule with LOWER rule_idx than a zone-pair
rule would evaluate FIRST under flat ordering — wrong.

**Fix 1**: candidate slices are per-(zone_pair_key, local_rule_idx)
or per-(global, local_rule_idx). Each book carries:

```rust
struct BookCitations {
    /// Phase 1: zone-pair-scoped. Outer map: book_id → inner map.
    /// Inner: zone_pair_key → sorted local_rule_idxs.
    /// Lazy-allocated only for (zone_pair_key, book) pairs with
    /// actual citations.
    per_zone_pair: Vec<FxHashMap<ZonePairKey, Arc<[u32]>>>,
    /// Phase 2: global-only citations. Outer indexed by book_id.
    global: Vec<Arc<[u32]>>,
}
```

**Fix 2**: Stage 4 evaluation is two-phase **explicitly**:

```rust
fn evaluate_via_dag(...) -> PolicyEvaluationResult {
    let zp_key = zone_pair_key(from_id, to_id);

    // Phase 1: zone-pair scan
    if let Some(stage2) = dag.zone_pair_stage2.get(&zp_key) {
        if let Some(result) = stage4_eval_phase(
            dag, state, stage2, zp_key, EvalPhase::ZonePair, ...
        ) {
            return result;
        }
    }
    // Phase 2: global scan
    if let Some(result) = stage4_eval_phase(
        dag, state, &dag.global_stage2, ZP_GLOBAL_SENTINEL,
        EvalPhase::Global, ...
    ) {
        return result;
    }
    PolicyEvaluationResult { action: state.default_action, policy_id: 0 }
}
```

Within each phase, the galloping merge over sorted-ascending rule
slices preserves the operator's intended order. No cross-phase
ordering claim is made.

Memory cost at 1M rules × 10K books × ~100 zone-pairs: worst case
1M Arc<[u32]> entries. Realistic ~10 MB.

### 2.6 Broad-prefix /0 short-circuit — fixing v2 r4 F5

When a book contains a /0, v2 would populate all 2^24 level-0
entries with that book's id (256 MiB write per /0 book). v3
short-circuits at build time:

```rust
fn build_multi_book_lpm_v4(
    books: &[BookEntry], pseudo_books: &[PseudoBook],
) -> (MultiBookLpmV4, Vec<u32>) {
    let mut lpm = MultiBookLpmV4Builder::new();
    let mut covers_all = Vec::new();
    for (book_id, entry) in iter_all_books(books, pseudo_books).enumerate() {
        let mut has_zero_prefix = false;
        for prefix in entry.iter_prefixes_v4() {
            if prefix.prefix_len() == 0 {
                has_zero_prefix = true;
                continue;  // skip LPM insertion for /0
            }
            lpm.insert(prefix, book_id as u32);
        }
        if has_zero_prefix {
            covers_all.push(book_id as u32);
        }
    }
    covers_all.sort();
    (lpm.freeze(), covers_all)
}
```

At Stage 3 hot-path lookup, returned `src_books` is implicitly
unioned with `books_covering_all_v4` at galloping-merge time (1
extra slice, typically very short).

### 2.7 Allocation-free hot path

```rust
#[inline]
fn evaluate_via_dag(
    dag: &PolicyDag, state: &PolicyState,
    from_id: u16, to_id: u16,
    src_ip: IpAddr, dst_ip: IpAddr,
    protocol: u8, src_port: u16, dst_port: u16,
    packet_len: u64,
    scratch: &mut Stage4Scratch,
) -> PolicyEvaluationResult {
    let zp_key = zone_pair_key(from_id, to_id);
    if let Some(stage2) = dag.zone_pair_stage2.get(&zp_key) {
        if let Some(result) = evaluate_phase(
            stage2, dag, state, zp_key,
            src_ip, dst_ip, protocol, src_port, dst_port, packet_len,
            scratch, EvalPhase::ZonePair,
        ) { return result; }
    }
    if let Some(result) = evaluate_phase(
        &dag.global_stage2, dag, state, ZP_GLOBAL_SENTINEL,
        src_ip, dst_ip, protocol, src_port, dst_port, packet_len,
        scratch, EvalPhase::Global,
    ) { return result; }
    PolicyEvaluationResult { action: state.default_action, policy_id: 0 }
}
```

`Stage4Scratch` is owned by the dataplane binding worker
(allocated once at worker startup; reused across packets). All hot
paths read borrowed `Arc<[u32]>` slices into scratch pointer arrays —
no per-packet allocation.

### 2.8 Stage 4 buffer overflow → master-fallback — fixing v2 r4 MAJOR #9

If galloping merge produces > `STAGE4_BUFFER_SIZE = 64` candidates in
a phase, drop that phase's evaluation to the **master linear scan**
for this packet (existing `try_match_rule` over
`state.zone_pair_index[zp_key]` or `state.global_indices`). This
preserves first-match-wins semantics without rule drops, panics, or
hot-path allocation.

Operator counter: `xpf_userspace_policy_dag_stage4_overflow_total
{phase}`.

```rust
const STAGE4_BUFFER_SIZE: usize = 64;

fn galloping_merge_evaluate(...) -> Option<PolicyEvaluationResult> {
    let mut emitted = 0u32;
    while let Some(rule_idx) = merge_iter.next() {
        if emitted >= STAGE4_BUFFER_SIZE as u32 {
            STAGE4_OVERFLOW_COUNTER.inc();
            return master_linear_scan_fallback_for_phase(state, ...);
        }
        emitted += 1;
        if let Some(result) = try_match_rule(&state.rules[rule_idx as usize], ...) {
            return Some(result);
        }
    }
    None
}
```

### 2.9 Stage 2 details (refined; v2 r4 MAJORs #7-#8 fixes)

```rust
struct Stage2Index {
    proto_to_buckets: Box<[Option<Stage2ProtoBucket>; 256]>,
    any_proto_rules: Arc<[u32]>,
}

struct Stage2ProtoBucket {
    exact_dst_port_to_rules: FxHashMap<u16, Arc<[u32]>>,
    range_terms: Box<[(PortRange, Arc<[u32]>)]>,
    any_port_rules: Arc<[u32]>,
}

impl Stage2Index {
    fn candidate_slices<'a>(&'a self, proto: u8, _src_port: u16,
                            dst_port: u16) -> SmallVec<[&'a [u32]; 6]> {
        let mut out = SmallVec::new();
        // ALWAYS include any_proto_rules (v2 r4 MAJOR #7 fix).
        out.push(self.any_proto_rules.as_ref());
        if let Some(bucket) = &self.proto_to_buckets[proto as usize] {
            if let Some(slice) = bucket.exact_dst_port_to_rules.get(&dst_port) {
                out.push(slice.as_ref());
            }
            // ALL range terms covering dst_port — not just first
            // (v2 r4 MAJOR #7 fix).
            for (range, slice) in bucket.range_terms.iter() {
                if dst_port >= range.low && dst_port <= range.high {
                    out.push(slice.as_ref());
                }
            }
            out.push(bucket.any_port_rules.as_ref());
        }
        out
    }
}
```

**ICMP carve-out**: ICMP rules land in `any_port_rules` for proto=1
or 58 (parse_port_spec rejects port 0 — see policy.rs:863 — so no
`exact_dport=0` entries). Stage 4's `try_match_rule` re-runs
`compiled_apps.matches` which handles ICMP id matching at
policy.rs:306.

### 2.10 u32 book indices — fixing v2 r4 MAJOR #8

LPM leaves carry `Arc<[u32]>` book_ids (not `u16`). At 1M-rule
scale, >65K books is plausible; u16 cap is unacceptable. Per-leaf
memory cost doubles vs v2 (`u32` = 4 B vs `u16` = 2 B); budget
relaxed.

## 3. Construction algorithm — two-pass exact allocator

```rust
fn build_policy_dag(state: &PolicyState) -> PolicyDag {
    // Phase 0: PseudoBooks for per-rule literal prefixes (§2.2).
    let (src_pseudos, dst_pseudos) = build_pseudo_books(state);

    // Phase 1: per-book + per-pseudo-book citation arrays.
    // Two-pass: count, then allocate per-(zone_pair, side) Arc<[u32]>.
    let (book_src_citations, book_dst_citations) =
        build_citations(state, &src_pseudos, &dst_pseudos);

    // Phase 2: Multi-Book LPM v4 + v6 with /0 short-circuit.
    let (lpm_v4, covers_all_v4) =
        build_multi_book_lpm_v4(&state.books, &src_pseudos, &dst_pseudos);
    let (lpm_v6, covers_all_v6) =
        build_multi_book_lpm_v6(&state.books, &src_pseudos, &dst_pseudos);

    // Phase 3: MatchAny side-channels.
    let match_any = build_match_any_channels(state);

    // Phase 4: Stage 2 indexes (per zone-pair + global).
    let (zone_pair_stage2, global_stage2) = build_stage2_indexes(state);

    PolicyDag {
        multi_book_lpm_v4: Arc::new(lpm_v4),
        multi_book_lpm_v6: Arc::new(lpm_v6),
        book_src_citations,
        book_dst_citations,
        match_any_v4_src_rules_per_zone_pair: match_any.v4_src_per_zp,
        match_any_v4_dst_rules_per_zone_pair: match_any.v4_dst_per_zp,
        match_any_v4_src_rules_global: match_any.v4_src_global.into(),
        match_any_v4_dst_rules_global: match_any.v4_dst_global.into(),
        match_any_v6_src_rules_per_zone_pair: match_any.v6_src_per_zp,
        match_any_v6_dst_rules_per_zone_pair: match_any.v6_dst_per_zp,
        match_any_v6_src_rules_global: match_any.v6_src_global.into(),
        match_any_v6_dst_rules_global: match_any.v6_dst_global.into(),
        books_covering_all_v4: covers_all_v4.into(),
        books_covering_all_v6: covers_all_v6.into(),
        zone_pair_stage2,
        global_stage2,
    }
}
```

Construction cost at 1M rules + 10K books (estimated):
- Phase 0 PseudoBooks: ~1M × ~8 literals × `iter_prefixes` ≈ 800 ms.
- Phase 1 citations: ~1M × ~8 books × per-zone-pair grouping ≈ 1 sec.
- Phase 2 LPM v4 (DIR-24-8): 10K books × ~10 prefixes each ≈ 1-2 sec
  (excluding /0s which short-circuit per §2.6).
- Phase 3 MatchAny: 1M-rule scan ≈ 100 ms.
- Phase 4 Stage 2: 1M rule × ~5 apps each ≈ 500 ms.

Total: ~3-5 sec at 1M rules. Inside Junos commit budget; #1612
measurement will give the actual.

## 4. Step 1 (this PR) scope

**Implement only the LPM primitive + helpers + feature-flag scaffold
+ tests.** Step 2 wires the full hot path. Step 3 adds the Junos
knob.

In scope:
- `userspace-dp/src/policy/mod.rs` (refactor from policy.rs).
- `userspace-dp/src/policy/multi_book_lpm.rs` — MultiBookLpmV4
  DIR-24-8 builder + lookup; MultiBookLpmV6 bounded multibit trie +
  lookup.
- `userspace-dp/src/policy/pseudo_book.rs` — PseudoBook builder.
- `userspace-dp/src/policy/match_any_channel.rs` — MatchAny
  side-channel builder.
- `userspace-dp/src/policy/book_citations.rs` — per-book per-phase
  citation arrays.
- `userspace-dp/src/policy/tests.rs` — property tests with in-Rust
  synthetic policy generator (`#[cfg(test)]`).
- `userspace-dp/src/prefix_set.rs` — add `iter_prefixes()` method
  on PrefixSetV4/V6.
- `userspace-dp/src/policy/mod.rs` — extend `BookEntry` with
  `prefixes_v4 / prefixes_v6: Arc<[Prefix]>`.
- `userspace-dp/src/protocol/snapshot.rs` — add `policy_dag_enable:
  bool` (serde default false).
- `PolicyState` — add `dag: Option<Arc<PolicyDag>>` + `dag_enabled:
  bool`.
- `evaluate_policy_result_with_len` — branch to `evaluate_via_dag`
  if flag on; STUB body falls back to `evaluate_linear` (existing
  master path, factored out).

Out of scope (Step 2 follow-up):
- Stage 2 / Stage 3 / Stage 4 full hot path.
- Galloping merge.
- Per-worker `Stage4Scratch`.
- master_linear_scan_fallback for buffer overflow.

Out of scope (Step 3 follow-up):
- Junos `cos.policy.lookup` CLI knob.
- Go-side wire emit of `PolicyDagEnable`.
- Default-flip gated on #1612.

## 5. Feature flag wiring — fixing v2 r4 MAJOR #10

Flag + DAG live on `PolicyState` (which IS in scope of
`evaluate_policy_result_with_len`):

```rust
pub(crate) struct PolicyState {
    pub(crate) default_action: PolicyAction,
    pub(crate) rules: Vec<PolicyRule>,
    zone_pair_index: FxHashMap<ZonePairKey, Vec<usize>>,
    global_indices: Vec<usize>,
    pub(crate) books: Vec<BookEntry>,
    book_id_to_idx: FxHashMap<u32, u32>,
    /// #1609 v3: DAG-side state. Optional because the DAG is only
    /// built when the wire flag policy_dag_enable is true. Hot path
    /// reads this directly — no ConfigSnapshot access needed.
    pub(crate) dag: Option<Arc<PolicyDag>>,
    pub(crate) dag_enabled: bool,
}

pub(crate) fn evaluate_policy_result_with_len(
    state: &PolicyState, ...,
) -> PolicyEvaluationResult {
    if state.dag_enabled {
        if let Some(dag) = state.dag.as_ref() {
            return evaluate_via_dag(dag, state, ...);
        }
    }
    evaluate_linear(state, ...)
}
```

**Step 1's `evaluate_via_dag` is a stub** that immediately falls
back to `evaluate_linear`. This exercises the flag plumbing
end-to-end without yet shipping the hot path; Step 2 replaces the
stub with the full §2.7 implementation.

`evaluate_linear` is the existing `evaluate_policy_result_with_len`
body factored out — pure refactor, no semantic change.

`parse_policy_state_with_counters` reads `policy_dag_enable` from
`ConfigSnapshot` and stores it on `PolicyState.dag_enabled`. When
the flag is true, build the DAG; otherwise leave `dag = None`.

## 6. §Y Memory budget — RELAXED per user override (2026-05-27)

The v2 r4 fatal #1 ("256 MiB level-0 × 6 snapshots = 1.5 GiB") is
**dismissed**. The previously self-imposed ≤1 GB-per-snapshot budget
was conservative; production hardware is 8-16 GB VMs and the DAG
memory cost is amortized across at most ~6 snapshots in flight.

Relaxed v3 budget:
- Level-0 v4 table: ~128 MiB per snapshot (DIR-24-8 × 8 B/entry
  enum slot — or ~256 MiB with Arc<[u32]> fat pointer leaves; either
  way, well within capacity).
- Per-book citation arrays: ~10-40 MB per snapshot at 1M rules.
- PseudoBooks per rule: ~30 MB pointers + ~50 MB prefix bytes at
  1M rules.
- MatchAny side-channels: ~16 MB at 1M rules.
- v6 bounded multibit trie: ~60 MB realistic, up to ~600 MB
  pathological at 100K populated /48s.
- Total per snapshot: ~300-500 MB realistic; up to ~1.5 GB
  pathological.
- ≤6 snapshots: ~2-3 GB resident realistic; ~9 GB pathological.

**Constraint is CPU/cache/TLB pressure, not RSS.** Per-packet cost
target: ≤270 ns at 1M rules. Per #1612 measurement, if level-0
cold-cache hits exceed budget, stride reduction (DIR-16-8 or
DIR-20-4-8) can be revisited as follow-up tuning — not a Step 1
blocker.

If v3 consumes >5 GiB resident across the policy DAG, that's still
well within hardware capacity. The answer is "tune stride for cache,
not memory".

## 7. Test plan — Step 1

Property tests in `userspace-dp/src/policy/tests.rs` (`#[cfg(test)]`):

- **LPM v4 correctness at 10/100/1K/10K rules**:
  - In-Rust synthetic generator emits N rules with random /24-/32
    src/dst prefixes + zero-or-more books per rule + random `any`
    flag (per side).
  - For each test address, LPM lookup result must be EXACTLY the
    set of book_ids whose prefix list covers the address
    (ground-truth: brute-force `book.v4.contains(addr)`).
  - **Equality, not subset** (v2 r4 MAJOR #11 fix).
- **/0 short-circuit**: a book with `0.0.0.0/0` appears in
  `books_covering_all_v4` and NOT in any LPM leaf. Lookup for any
  v4 returns no match from LPM but the covers_all_v4 includes the
  book.
- **PseudoBook correctness**: rule with `source_literal_v4 =
  Linear([10.0.0.0/24])` has its rule_idx surfaceable via LPM
  lookup of an address in 10.0.0.0/24.
- **MatchAny side-channel correctness**: rule with `source any`
  (source_v4_match_any = true, empty source_book_idxs,
  source_literal_v4 = MatchAny) appears in
  `match_any_v4_src_rules_*` and is NOT injected as a PseudoBook.
- **`any` on dst, literal on src**: rule BOTH in
  match_any_v4_dst_rules AND has a PseudoBook on src.
- **Per-zone-pair ordering**: a global rule with low rule_idx and a
  zone-pair rule with higher rule_idx are correctly placed: the
  zone-pair rule appears in the zone-pair phase ONLY, the global
  rule appears in the global phase ONLY.
- **v6 bounded multibit trie correctness**: same as v4 LPM but with
  v6 prefixes incl. ::/0, /48, /64, /128.
- **v6 leaf overflow cap**: 100 /128 prefixes in one /48 trigger
  `MAX_V6_LEAF_PREFIXES = 64`; excess routes to fallback list;
  warning emitted.
- **u32 book_id**: snapshot with > 65K books still works; no
  truncation.
- **5/5 flake check** on the new tests.
- **Criterion microbench** at `userspace-dp/benches/multi_book_lpm.rs`:
  LPM v4 lookup p50/p99 + LPM construction wall-clock at 1K/10K.

Existing `policy_tests.rs` must still pass with flag default-OFF.

- **Smoke matrix** on `loss:xpf-userspace-fw0/fw1`: v4 + v6 × push
  + `-R` × CoS-off + CoS-on. No regression vs master.
- **`make test-failover`**: HA failover ≤ 60 ms unchanged.

## 8. Acceptance criteria — Step 1

- [ ] Plan v3 → vN PLAN-READY through 4-way quad-review.
- [ ] Multi-Book LPM v4 + v6 primitives in
  `userspace-dp/src/policy/multi_book_lpm.rs`.
- [ ] PseudoBook builder + MatchAny side-channel builder + per-book
  citation arrays in their respective modules.
- [ ] `BookEntry` carries `prefixes_v4 / prefixes_v6: Arc<[Prefix]>`.
- [ ] `PrefixSetV4/V6::iter_prefixes()` method.
- [ ] Feature flag `policy_dag_enable: bool` on `ConfigSnapshot`
  (serde default).
- [ ] `PolicyState.dag: Option<Arc<PolicyDag>>` + `dag_enabled:
  bool`.
- [ ] Stub `evaluate_via_dag` that falls back to `evaluate_linear`.
- [ ] All existing policy_tests.rs pass unchanged (flag OFF).
- [ ] Property tests at 10/100/1K/10K rules pass 5/5 flake check.
- [ ] Criterion bench: LPM v4 lookup ≤ 50 ns p50 at 10K books;
  LPM construction ≤ 200 ms at 10K rules.
- [ ] Smoke matrix passes on loss userspace cluster.
- [ ] `make test-failover` passes.
- [ ] `docs/userspace-jit-design.md` Phase 4 row updated.
- [ ] PR body explicitly states the ≥10× claim is deferred to
  Step 2 + #1612 measurement + Step 3.

## 9. Risks (Step 1)

- **R1**: Step 1 ships scaffolding only; ≥10× claim is end-to-end
  (Step 1 + Step 2 + Step 3). Step 2 + Step 3 tracked as follow-ups.
- **R2**: v6 bounded multibit trie depth-6 fixed-stride may not be
  optimal for realistic v6 distributions. #1612 measurement guides.
- **R3**: PseudoBook allocation at 1M rules × 8 literals ≈ 8M
  iter_prefixes calls during build. ~800 ms.
- **R4**: Construction cost at 1M rules ~3-5 sec — eats most of
  Junos commit budget.
- **R5**: Cache/TLB pressure on the 128 MiB level-0 table is the
  real performance constraint. Mitigation: stride tuning in a
  follow-up (#1612 measurement).
- **R6**: Stage 4 buffer-overflow → master-fallback is rare in
  realistic configs but exists; operator counter surfaces pathology.

## 10. Out of scope

- Step 2: full multi-stage DAG hot path + galloping merge.
- Step 3: Junos CLI knob + default-flip.
- Rate-limit + verdict cache (#1608).
- Per-flow JIT specialization (killed #1605).
- Application-identification L7 DPI.
- Cold-path microbench (#1612).

## 11. Alternatives rejected (carried forward)

- **Cranelift JIT** — killed #1605.
- **v1 Per-rule LPM** — killed by 320 GB memory bomb.
- **v2 per-/48 FxHashMap** — killed by DoS vector.
- **v2 u16 book idx cap** — killed by realistic >65K-book scale.
- **Stage 4 silent rule drop / panic / heap-Vec on overflow** —
  killed by AGY F1.4; v3 master-fallback is the right answer.
- **Flat ascending rule_idx ordering** — killed by zone-pair vs
  global two-phase semantics.
- **`roaring` crate** — killed by Codex F10.

## 12. Open architectural questions for reviewers

**v3-Q1**: v6 bounded multibit trie at fixed depth-6 / 8-bit stride
— is worst-case 600 MB at 100K /48s acceptable? Realistic case is
60 MB. #1612 will guide.

**v3-Q2**: `MAX_V6_LEAF_PREFIXES = 64` is arbitrary. Operator
visibility via Prometheus counter is the mitigation. Reviewer
preference on cap value?

**v3-Q3**: PseudoBook allocation per rule with literals — at 1M
rules that's up to 1M Arc<[Prefix]> per side. Memory: ~30 MB
pointers + ~50 MB prefix bytes. Acceptable under relaxed budget;
reviewer may suggest pooled-arena allocation.

**v3-Q4**: Step 1 stub `evaluate_via_dag` — same v2 question. Worth
shipping a flag whose code path stubs out? Position: yes, exercises
plumbing + decouples Step 2 from wire compat.

**v3-Q5**: Module layout — combining `policy.rs` (881 LOC) →
`policy/` directory move with the new modules in one PR. Should
the refactor be a precursor PR? Position: keep one PR, two clean
commits (refactor commit + new-modules commit).

## v1/v2 historical record

- v1: per-/24 RuleBitSet → 320 GB memory bomb. KILLED at SMR-r1 +
  Codex-r1 + AGY-r1.
- v2: Multi-Book LPM with single global DIR-24-8. KILLED at SMR-r4 +
  Codex-r3 + AGY-r3 on 6 fatals (memory math, literal/any drop, v6
  DoS, global ordering, broad-prefix /0, BookEntry not buildable)
  + 6 majors. Memory math fatal RELAXED per user override 2026-05-27.
- v3: this plan. Multi-Book LPM with §2.1 MatchAny side-channels +
  §2.2 PseudoBooks + §2.3 v6 bounded multibit trie + §2.4 BookEntry
  prefix-list extension + §2.5 per-zone-pair ordering + §2.6 /0
  short-circuit + §2.8 Stage 4 master-fallback.

v3 review record preserved at:
- `claude-smr-plan-r1.md` (v1 r1)
- `claude-smr-plan-r2.md` (v1 r2)
- `claude-smr-plan-r3.md` (v2 r1 soft-pass)
- `claude-smr-plan-r4.md` (v2 r1 reversal)
- `claude-smr-plan-r5.md` (v3 r1 — this round)
- `reviewer-ids.md`
