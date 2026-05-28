# Plan v2: Multi-Book LPM policy DAG (#1609)

**Status**: v2 — starts from the convergent Multi-Book LPM
architectural pivot AGY r1 delivered in plan-review round 1. v1
PLAN-NEEDS-MAJOR + BLOCKED determination is preserved at the bottom
of this file for historical reference. v2 supersedes v1 entirely.

**User override** (2026-05-28): proceed with the architectural work
even though #1612 (Scale Target measurement) has not yet ratified
the structural ≥10× speedup claim at 1M rules. Plan v2 ships the
architecture behind a feature flag defaulting OFF; production
enablement remains gated on #1612 once that measurement lands.

**Staged delivery** (acknowledged risk-management): this v2 ships
in stages. **Step 1 (this PR)** is the Multi-Book LPM v4 primitive
+ feature-flag wiring + property tests at 10/100/1K/10K rule
counts. **Step 2** (separate follow-up issue) wires the full
multi-stage decision DAG (Stage 2 protocol/port prune, Stage 3
multi-book LPM intersection, Stage 4 bucket scan with galloping
merge). **Step 3** (separate follow-up) is the Junos
`cos.policy.lookup` knob + production enablement gated on #1612.
This is to keep the PR reviewable and the smoke-test surface
small. The "structural ≥10× speedup" claim is the goal of the full
stack; Step 1 alone delivers only the LPM primitive.

## 0. Honest framing (kept from v1, updated)

This work replaces the linear scan inside
`evaluate_policy_result_with_len` at `userspace-dp/src/policy.rs:648-694`
with a **multi-stage decision DAG** built at config-apply time. The
goal is to bound cold-path policy evaluation at 1M rules to within
the per-packet budget that the linear scan cannot achieve at any
rule count above a few hundred.

This is **NOT** a JIT (Cranelift was killed at #1605). It is
classical data-structure work.

**Empirical-grounding deferral** (Codex F7 + user override):

- **#1611** (cold-path flooder runner body) — ✓ MERGED (PR #1616
  squash `6c26c40e6`).
- **#1612** (Scale Target measurement at 10/100/1K/10K rules) —
  ⏳ blocked on #1615 (container generator caps at ~870K pps; needs
  ≥2.5M pps to measure cold-path correctly).
- **#1615** (flooder multi-thread + virtio) — ⏳ in flight.

The architecture ships now under a feature flag (`policy_dag_enable`
field on the wire, default `false`). Production enablement requires
#1612 numbers to ratify the ≥10× claim before flipping the default.
The PR body MUST state this explicitly.

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
        ) { return result; }
    }
}
for &idx in &state.global_indices {
    if let Some(result) = try_match_rule(&state.rules[idx], ...) {
        return result;
    }
}
PolicyEvaluationResult { action: state.default_action, policy_id: 0 }
```

Phase 2 (already shipped) is the `zone_pair_index` lookup — that's
O(1). What's NOT O(1) is the inner per-`try_match_rule` walk through
50K candidate rules at 1M total rule scale. Each `try_match_rule`
checks application port/proto + per-book PrefixSet contains for src
and dst IPs. The result is ~250 µs/packet vs the project's ~270 ns
budget. 3 orders of magnitude off.

### 1.2 Phase 2 baseline + foundational pieces now landed

- **#1606 (PR #1610 squash 1c409b0f)** — `BookEntry` table is now
  deduplicated; rules cite books by dense u32 index
  (`source_book_idxs: SmallVec<[u32; 8]>`). Memory cost of 100K
  rules × 1K CIDRs is no longer the 1.6 TB blocker. This is a hard
  prerequisite for the Multi-Book LPM.
- **#1611 (PR #1616 squash 6c26c40e6)** — cold-path flooder
  runner body shipped. AF_PACKET + sendmmsg + QDISC_BYPASS path
  works at ~870K pps. Multi-thread + virtio work in #1615 to push
  past 2.5M pps.
- **#1431** — CACHE-KEY INVARIANT. Every match dimension on
  `FilterTerm` / `FirewallTermSnapshot` is classified IN cache key
  or path-(b). The same discipline applies to the DAG: Stage 2/3
  pruning predicates must be strict 5-tuple; any per-packet field
  that isn't (DSCP, TCP flags, IHL, fragment) stays out of Stage 2/3
  and lands in Stage 4.

### 1.3 What this plan does NOT change

- **Wire protocol** is foundation from #1606 — no new fields on
  `AddressBookSnapshot`, no version bump. The DAG is constructed
  from the existing snapshot shape.
- **HA session sync** — sessions still sync established-flow
  decisions. Policy evaluation reruns at session install time on
  the receiving node; the DAG is constructed during snapshot apply
  on both nodes from the synchronized config.
- **Address-book layout** — books continue to be referenced by
  dense u32 index. Shared Multi-Book LPM is built ONCE per snapshot,
  not per book.
- **Flow cache** — the DAG is cold-path-only. Established flows
  continue to bypass policy evaluation entirely.

## 2. Architecture: Multi-Book LPM + 4 stages

```
┌──────────────────────────────────────────────────────────────┐
│ Stage 1: zone-pair hash (ALREADY SHIPPED, no change)         │
│   key u32 := (from_id << 16) | to_id                         │
│   FxHashMap<u32, Stage2Index>                                │
└──────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────┐
│ Stage 2: protocol + dst-port prune (per zone-pair)           │
│   proto_to_buckets: [Option<Stage2ProtoBucket>; 256]         │
│   inside a proto bucket:                                     │
│     exact_dst_port_to_rules: FxHashMap<u16, Arc<[u32]>>      │
│     range_terms: Vec<(PortRange, Arc<[u32]>)> sorted-by-low  │
│     any_port_rules: Arc<[u32]>  // any-src + any-dst         │
│   any_proto_rules: Arc<[u32]>                                │
│   Output: 1-3 sorted ascending `&[u32]` slices               │
└──────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────┐
│ Stage 3: Multi-Book LPM intersection                         │
│   Global per-address-family Multi-Book LPM:                  │
│     MultiBookLpmV4 (DIR-24-8): each level-0 / level-1 entry  │
│       stores Arc<[u16]> book_indices (sorted ascending).     │
│     MultiBookLpmV6 (Poptrie or DIR-24-8 over /48):           │
│       same shape but over u128 → Arc<[u16]> book_indices.    │
│   Per-book sorted citation arrays:                           │
│     book.rules_citing_as_source:      Arc<[u32]>  (sorted)   │
│     book.rules_citing_as_destination: Arc<[u32]>  (sorted)   │
│   Lookup:                                                    │
│     1. src LPM(src_ip) → &[u16] src_books                    │
│     2. dst LPM(dst_ip) → &[u16] dst_books                    │
│     3. Union per-book citation arrays via galloping k-way    │
│        merge into per-worker scratch (sorted ascending,      │
│        no per-packet allocation).                            │
│   Output: 2 sorted ascending `&[u32]` slices: src_rules and  │
│           dst_rules (NOT a precise contains-check yet —      │
│           Stage 4 re-verifies CIDR membership against rule's │
│           literal + cited books to close any over-approxi-   │
│           mation).                                           │
└──────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────┐
│ Stage 4: galloping merge + residual try_match_rule           │
│   3-way galloping merge of {Stage 2 candidates ∩             │
│     src_rules ∩ dst_rules} emitting ascending RuleIdx.       │
│   For each surviving candidate (avg ≤ ~32 by construction    │
│   for well-behaved configs; pathological configs degrade to  │
│   no-worse-than-master linear scan):                         │
│     - try_match_rule (existing path) re-verifies:            │
│        - inactive flag                                       │
│        - compiled_apps.matches (closes ICMP carve-out gap)   │
│        - source-side literal + cited books (closes Stage 3   │
│          over-approximation)                                 │
│        - dest-side literal + cited books (same)              │
│     First match wins (galloping merge emits ascending,       │
│     which IS original rule order since rule_idx is dense).   │
└──────────────────────────────────────────────────────────────┘
```

### 2.1 Why this composition is correct

The existing `evaluate_policy` semantics:

> Iterate rules **in original rule order** within (zone-pair-matched,
> global) buckets. First rule that matches all of {zone,
> application, source IP, destination IP, not inactive} wins. If no
> rule matches, default action.

The DAG must preserve **first-match-wins-by-rule-order** exactly.
Each stage produces a **candidate slice** (sub-set of rule indices,
sorted ascending). Stage 4's galloping merge intersects the
candidate slices and re-runs `try_match_rule` on survivors. Since
candidate slices are sorted ascending and rule_idx assignment is
dense in original parse order, the merge emits in original rule
order — first match wins is preserved structurally.

The reason Stage 3 returns an over-approximation (not a precise
contains-check) is that the global LPM operates per address family,
not per rule. A rule citing books `{5, 9, 17}` on the source side
gets a Stage 3 hit if src_ip falls in ANY book's LPM coverage, even
if the matching book is not one this rule cites. Stage 4's existing
`try_match_rule` closes the gap: it re-checks the rule's actual
literal + cited-books membership.

This is structurally safe: Stage 2/3 only filter out rules that
provably **cannot** match (Stage 2 — wrong protocol; Stage 3 — no
book in the entire snapshot covers src or dst). Rules that survive
Stage 2/3 may still fail Stage 4, but no rule that COULD match is
ever filtered out.

### 2.2 Stage 2 details

`Stage2Index` per zone-pair, owned by `PolicyDag`:

```rust
struct Stage2Index {
    /// Indexed by protocol byte. None = no rule in this zone-pair
    /// cites this protocol AND no any-proto rule covers it.
    proto_to_buckets: Box<[Option<Stage2ProtoBucket>; 256]>,
    /// Rules whose compiled_apps.match_any == true (application
    /// "any"). Fall through to Stage 3 unconditionally.
    any_proto_rules: Arc<[u32]>,
}

struct Stage2ProtoBucket {
    /// Single-exact-dst-port hot path (e.g. ssh-rule on dport=22).
    exact_dst_port_to_rules: FxHashMap<u16, Arc<[u32]>>,
    /// Port-range terms, sorted ascending by `low` for bisect.
    range_terms: Box<[(PortRange, Arc<[u32]>)]>,
    /// Rules where dst_port is unrestricted (any-dport) AND src_port
    /// is unrestricted-OR-range-restricted. These get the additional
    /// src-port test at Stage 4 via try_match_rule, but Stage 2
    /// emits them unconditionally for this proto.
    any_port_rules: Arc<[u32]>,
}
```

Lookup cost: 1 array index (proto byte), 1 hash probe (exact dport),
1 binary search over `range_terms` (typically ≤ 64 entries). Total
≤ ~10 ns even at 1M rules.

**ICMP carve-out** (Codex F3 + AGY F4 + SMR F-r1-2 convergent):
`parse_flow_ports` at `frame/inspect.rs:212-232` puts ICMP id in
src_port and 0 in dst_port. ICMP rules in `compiled_apps` are keyed
by `protocol = PROTO_ICMP (1) | PROTO_ICMPV6 (58)`. At Stage 2:
ICMP rules go into either `exact_dst_port_to_rules[0]` (if rule
restricts dport to 0) or `any_port_rules` (the common case). Either
way they end up as a candidate slice for proto=1/58. Stage 4's
`compiled_apps.matches(protocol, src_port, dst_port)` re-verifies
the application term — including src_port range matching for ICMP
identifier-based rules. No silent drops.

**any_port_rules fall-through**: rules with no port constraint (or
src-port-only constraint) on a given proto live in
`any_port_rules` of that proto's bucket. Stage 2 emits this slice
**in addition to** any exact-dport / range hits for the same proto.
Stage 4 galloping merge dedup-merges them.

### 2.3 Stage 3 details — Multi-Book LPM

The architectural pivot from v1 (per-book multi-rule LPMs) is to a
**single global per-address-family LPM over book indices**.

```rust
/// DIR-24-8 multibit LPM where every entry stores the sorted list
/// of book indices whose v4 PrefixSet contains a CIDR covering this
/// prefix.
struct MultiBookLpmV4 {
    /// Level-0: 2^24 entries indexed by the upper 24 bits of the
    /// IPv4 address. Each entry is either:
    ///   - LpmLeafV4::Books(Arc<[u16]>) — leaf with sorted book idxs
    ///   - LpmLeafV4::DescendInto(u32)  — index into `level_1[]`
    level_0: Box<[LpmLeafV4; 1 << 24]>,
    /// Level-1: sparse vector of /25–/32 sub-tables.
    level_1: Vec<Stage3SubTableV4>,
}

enum LpmLeafV4 {
    Books(Arc<[u16]>),     // sorted ascending; empty Arc = no books
    DescendInto(u32),
}

/// 256-entry sub-table for /25–/32 lookups inside one /24.
struct Stage3SubTableV4 {
    entries: Box<[Arc<[u16]>; 256]>,
}
```

**Memory bound at 1M rules**:

- Level-0: 16 MB pointer table (Box<[LpmLeafV4; 1<<24]> at 8 B/entry
  with niche optimization — `Arc<[u16]>` and `u32` both fit in 8 B
  via tagged enum). Same as DIR-24-8 baseline.
- Level-1 sub-tables: only allocated for /24s with /25-/32 rules
  inside; for a realistic config that's ≤ 10K /24s with sub-prefixes
  × 2 KB each = 20 MB.
- Book index arrays: ~10K books × Arc<[u16]> × avg 4 books/leaf ×
  ~1M populated leaves = 80 MB upper bound; with Arc dedup
  (many leaves share the same sorted book list), realistic ~40 MB.
- Per-book citation arrays: 1M rules × ~8 citations each × 4 B =
  32 MB.

Total ~120-160 MB per snapshot at 1M rules. With 6 in-flight
snapshots that's ≤ 1 GB.

**IPv6**: v6 uses a smaller stride (DIR-24-8 over the first /48 or
Poptrie). Stage 1 of this Plan opts for **per-/48 hash + per-/48
sub-LPM** because IPv6 sparsity makes a 2^48 top-level table
infeasible. Memory bound: ~10K populated /48s × 1 KB sub-LPM each =
10 MB. Same Arc<[u16]> leaf shape.

**Construction cost at 1M rules**: per-prefix insert touches at most
256 level-0 entries (covers /24-aligned prefixes; sub-/24 prefixes
touch 1 entry + 1 sub-table). For a realistic distribution of /24
host prefixes + /16 corporate networks, ~10M LPM insertions total,
~100 ns each = ~1 second construction. Plus per-book citation array
build (sorted Vec → freeze to Arc) at 1M rules ≈ 100 ms. Total
construction ~1-1.5 seconds. Acceptable.

### 2.4 Stage 4 details

Three sorted-ascending `&[u32]` slices come into Stage 4 from
Stage 2 (zone-pair candidates) + Stage 3 (src_rules + dst_rules).
A 3-way galloping merge emits ascending RuleIdx values to a
per-worker scratch `&mut [u32; STAGE4_BUFFER_SIZE]`. For each
emitted index, the existing `try_match_rule` is called inline.
First `Some(result)` wins.

`STAGE4_BUFFER_SIZE = 64` chosen so the entire buffer fits in 256 B
(4 cache lines, hot in L1). Configs that produce > 64 survivors in
Stage 4 emit a Prometheus counter
`xpf_userspace_policy_dag_bucket_oversize_total{zone_pair}` and
continue processing without truncation (no silent rule drops). The
soft diagnostic surfaces operator pathology; the structural bound
is "no worse than master linear scan within the surviving slice"
(Codex F6 + AGY F5 tiebreak in SMR r2).

### 2.5 Allocation-free hot path (Codex F8)

```rust
#[inline]
fn evaluate_policy_dag(
    dag: &PolicyDag,
    state: &PolicyState,
    from_id: u16, to_id: u16,
    src_ip: IpAddr, dst_ip: IpAddr,
    protocol: u8, src_port: u16, dst_port: u16,
    packet_len: u64,
    scratch: &mut Stage4Scratch,  // per-worker, NOT allocated here
) -> PolicyEvaluationResult {
    let key = zone_pair_key(from_id, to_id);
    let stage2: &Stage2Index = match dag.stage2_by_zone_pair.get(&key) {
        Some(s) => s,
        None => return evaluate_global_fallback(dag, state, ...),
    };
    // Stage 2: gather candidate slices (no alloc — borrowed Arcs).
    let proto_bucket: &Stage2ProtoBucket = match &stage2.proto_to_buckets[protocol as usize] {
        Some(b) => b,
        None => return PolicyEvaluationResult::default_for(state),
    };
    let any_proto: &[u32] = &stage2.any_proto_rules;
    let exact_hit: &[u32] = proto_bucket.exact_dst_port_to_rules
        .get(&dst_port).map(|a| a.as_ref()).unwrap_or(&[]);
    let any_port: &[u32] = &proto_bucket.any_port_rules;
    // Stage 3: LPM lookup → &[u16] book indices (borrowed; no alloc).
    let src_books: &[u16] = dag.multi_book_lpm_v4.lookup_v4(src_ip);
    let dst_books: &[u16] = dag.multi_book_lpm_v4.lookup_v4(dst_ip);
    // Gather per-book citation slices into scratch (no alloc).
    // scratch.gather_src(state, src_books);  // borrowed Arc refs
    // scratch.gather_dst(state, dst_books);
    // Stage 4: galloping merge over {stage2_candidates, src_rules,
    // dst_rules}, call try_match_rule on survivors.
    galloping_merge_evaluate(
        &[exact_hit, any_port, any_proto], // sorted slices
        scratch.src_rules_slice(),
        scratch.dst_rules_slice(),
        state, src_ip, dst_ip, protocol, src_port, dst_port,
        packet_len,
    )
}
```

Every per-packet operation is either:
1. A pointer chase + index (Arc deref, slice index).
2. A borrow of an Arc<[u32]> (no clone, no refcount bump — Arc::as_ref).
3. A read/write into per-worker scratch (`&mut [u32; STAGE4_BUFFER_SIZE]`).

No `Vec` allocation. No `SmallVec` spill. No `roaring` intersection.
No string formatting. Per-worker scratch is owned by the dataplane
binding worker (allocated once at worker startup).

### 2.6 First-match-wins-by-rule-order proof sketch

Lemma: galloping merge over k sorted-ascending sequences emits all
values in ascending order, without duplicates if dedup is applied.

Lemma: `rule_idx` in `state.rules` is assigned in original parse
order (see `parse_policy_state_with_counters` at policy.rs:508 —
`let idx = state.rules.len();` immediately before push, so indices
are dense 0..N in parse order).

Corollary: the galloping merge emits rule indices in ascending order,
which IS original parse order, which IS the Junos first-match-wins
order.

Property test (see §7): generate a synthetic policy of 10K rules
with deterministic seed, choose a packet that matches multiple
rules, assert DAG returns the same `policy_id` as the linear scan.
Run 1K iterations with different packets + assert no divergence.

## 3. Construction algorithm — two-pass exact allocator (Codex F5)

```rust
fn build_policy_dag(state: &PolicyState) -> PolicyDag {
    // Phase A: build per-book citation arrays (sorted).
    let mut src_citations: Vec<Vec<u32>> = vec![Vec::new(); state.books.len()];
    let mut dst_citations: Vec<Vec<u32>> = vec![Vec::new(); state.books.len()];
    for (rule_idx, rule) in state.rules.iter().enumerate() {
        for &book_idx in &rule.source_book_idxs {
            src_citations[book_idx as usize].push(rule_idx as u32);
        }
        for &book_idx in &rule.destination_book_idxs {
            dst_citations[book_idx as usize].push(rule_idx as u32);
        }
    }
    // Phase A is already sorted since rule_idx is processed
    // ascending; no sort needed. Freeze to Arc<[u32]>.
    let book_src: Vec<Arc<[u32]>> = src_citations.into_iter()
        .map(|v| Arc::from(v.into_boxed_slice()))
        .collect();
    let book_dst: Vec<Arc<[u32]>> = dst_citations.into_iter()
        .map(|v| Arc::from(v.into_boxed_slice()))
        .collect();
    // Phase B: build Multi-Book LPM v4 (DIR-24-8).
    // First pass: count book indices per /24 entry.
    // Second pass: allocate exact Arc<[u16]> sorted slices.
    let lpm_v4 = MultiBookLpmV4::build_two_pass(&state.books);
    let lpm_v6 = MultiBookLpmV6::build_two_pass(&state.books);
    // Phase C: per zone-pair Stage 2 index.
    // First pass: count per (proto, exact_dport) and (proto, any_port).
    // Second pass: allocate exact Arc<[u32]> sorted slices.
    let stage2_by_zone_pair = build_stage2_index_two_pass(state);
    PolicyDag {
        stage2_by_zone_pair,
        global_stage2: build_stage2_index_for_global(state),
        multi_book_lpm_v4: Arc::new(lpm_v4),
        multi_book_lpm_v6: Arc::new(lpm_v6),
        book_src: book_src.into(),
        book_dst: book_dst.into(),
    }
}
```

No bitsets. No roaring. Every output slice is sorted ascending at
construction; no per-packet sort.

## 4. Round-1 kill axis resolution (Codex F1-F10 + AGY findings)

| Round-1 finding | v2 resolution |
|---|---|
| Codex F1 (sandbox infra-blocked source-availability) | v2 plan is self-contained: every claim has a line-level reference to current master code; no requirement to grep into worktree. |
| Codex F2 (DIR-24-8 vs Poptrie stride math) | v4: DIR-24-8 over /24 (16 MB level-0 table acceptable). v6: per-/48 FxHashMap + sub-LPM (no 2^48 table feasible). Rationale: v4 lookup hit latency dominated by L2 cache hit on level-0 entry (~5-10 ns); v6 sparsity makes Poptrie's compressed-trie overhead not worth its size win at our rule counts. Reviewer may push back — v6 stride is a tunable, not a structural commitment. |
| Codex F3 (Stage 2 src-port/ICMP semantics) | §2.2 spells out the ICMP carve-out explicitly. `any_port_rules` fall-through is in the data structure (per-proto bucket field). Stage 4's `try_match_rule` re-runs `compiled_apps.matches(protocol, src_port, dst_port)` so ICMP id matching, src_port range matching, etc. all close the over-approximation gap. |
| Codex F4 (first-match-wins across stages) | §2.6 proof sketch + galloping merge over sorted-ascending Arc<[u32]> slices. Property test in §7. |
| Codex F5 (construction cost) | §3 two-pass exact-allocator builder. Phase A is already sorted; no per-book sort. Phase B/C count then allocate. ~1-1.5 sec at 1M rules. |
| Codex F6 (K_bucket soft cap not structural) | §2.4 drops the "≤ 32 structural" claim. Honest framing: well-behaved configs accelerate ≥10× (claim pending #1612 ratification); pathological configs are no-worse-than-master linear scan inside the surviving slice. Soft Prometheus diagnostic at >64 surfaces pathology. |
| Codex F7 (feature-flag ship per user override) | This v2 ships feature-flagged. **Step 1** (this PR): Multi-Book LPM v4 primitive + feature flag wired + property tests; production code path untouched, flag default OFF. **Step 2** (separate issue): full multi-stage DAG hot path. **Step 3** (separate issue): Junos `cos.policy.lookup` knob + flip default to ON gated on #1612. |
| Codex F8 (allocation-free hot path) | §2.5 explicit code sketch + per-worker scratch + Arc-borrow discipline. No per-packet alloc. |
| Codex F9 (cache-key strict 5-tuple) | Stage 2 prunes only on (proto, src_port, dst_port). Stage 3 prunes only on (src_ip, dst_ip). All non-5-tuple selectors (DSCP, TCP flags, IHL, fragment, app-identification, flex-match) land in Stage 4 via `try_match_rule`. Forward-looking carve-out documented in §6. |
| Codex F10 (no `roaring` crate) | Confirmed. v2 uses `Arc<[u32]>` sorted slices + galloping merge over borrowed slices. No new crate dependencies. |
| AGY F1 (Multi-Book LPM restructure) | This v2's core architectural pivot. §2.3. |
| AGY F2 (sorted postings + galloping merge) | §2.6 + §3 + §2.5. |
| AGY F3 (construction cost two-pass) | §3 Phase B/C explicit. |
| AGY F4 (Stage 2 any_port + ICMP) | §2.2 ICMP carve-out + any_port_rules per-proto-bucket field. |
| AGY F5 (K_bucket soft cap is acceptable) | §2.4 soft diagnostic at >64; structural worst-case = master linear scan. |
| AGY F6 (ship now, defer empirical) | This v2 + staged delivery + feature flag. |
| SMR F-r1-1 (RuleBitSet memory blow-up) | Eliminated by Multi-Book LPM restructure. No bitsets in v2. |

## 5. Feature flag rollout

**Wire shape change** (this PR):

```rust
// userspace-dp/src/protocol/snapshot.rs ConfigSnapshot struct:
#[serde(rename = "policy_dag_enable", default)]
pub policy_dag_enable: bool,
```

Default `false` for backwards compatibility (old Go binaries don't
emit this field; serde default = false; linear-scan path active).
This is a v3-additive field — no wire version bump.

**Go side** (this PR adds a one-line wire emit; the Junos CLI knob
is deferred to Step 3):

```go
// pkg/dataplane/userspace/snapshot.go (or equivalent emission site)
PolicyDagEnable: false,  // hard-wired off until Step 3 lands the knob
```

**Hot path dispatch** (this PR):

```rust
// userspace-dp/src/policy.rs evaluate_policy_result_with_len:
if snapshot.policy_dag_enable && state.dag.is_some() {
    return evaluate_via_dag(state, ...);
}
// existing linear scan path (unchanged):
let key = zone_pair_key(from_id, to_id);
...
```

The feature-flag check is a single load + branch — predictable and
out of the inner loop. The DAG construction itself runs at
config-apply time only if the flag is set; this PR's Step 1 builds
only the Multi-Book LPM primitive (no Stage 2/4 yet) so the
"evaluate_via_dag" call still ultimately falls back to the linear
scan inside its body until Step 2 wires Stage 2/4.

**Step 3** (separate issue) adds the Junos knob:

```
set system services userspace dataplane policy-lookup multi-stage-dag
```

with Go-side typed config in `pkg/config/typed.go`, wire emit in
`pkg/dataplane/userspace/snapshot.go`, and Rust-side default flip
once #1612 ratifies the ≥10× claim.

## 6. Empirical-grounding deferral (explicit)

The architectural claim "the DAG accelerates cold-path policy
evaluation by ≥10× at 1M rules" is the v2 goal. It is **NOT**
empirically verified by this PR.

What this PR (Step 1) DOES verify:
- Multi-Book LPM v4 correctness: 10/100/1K/10K rule property tests
  using `test/incus/synthetic-policy-gen.sh`.
- LPM v4 lookup is ≤ 50 ns per call at 10K rules in a Criterion
  microbench (`userspace-dp/src/policy/multi_book_lpm_bench.rs`).
- LPM construction is ≤ 100 ms at 10K rules.
- Feature flag default-OFF preserves master semantics 1:1 (existing
  policy_tests.rs continues to pass unchanged).

What this PR (Step 1) explicitly does NOT verify:
- 1M-rule cold-path budget (blocked on #1612 / #1615).
- End-to-end multi-stage DAG hot path (blocked on Step 2 follow-up).
- Junos CLI knob behavior (blocked on Step 3 follow-up).

The PR body MUST state these gaps explicitly under "Empirical
gaps deferred to follow-ups". Production enablement gated on #1612.

## 7. Test plan

**Step 1 (this PR) — Multi-Book LPM v4 primitive + feature flag**:

- **Unit tests** (in `userspace-dp/src/policy/multi_book_lpm_tests.rs`):
  - Empty LPM returns empty slice for any v4 lookup.
  - Single /24 prefix in one book returns sorted [book_idx] for
    addresses in the /24 and empty slice for addresses outside.
  - Two overlapping books (/16 in book A, /24 in book B inside the
    /16) — addresses in the /24 return sorted [A, B]; addresses in
    the /16 outside the /24 return [A].
  - /32 leaf override: address in /32 returns [book_with_/32]; one
    bit off returns [book_with_covering_/24] if present, else empty.
  - 10K-book synthetic config built via `synthetic-policy-gen.sh`;
    lookup returns correct sorted slice for 1K random addresses.
- **Property tests** (using `proptest`):
  - Lookup result is monotonically non-decreasing as books are added.
  - Lookup result is a subset of books whose v4 PrefixSet contains
    the address (sanity vs ground truth from existing PrefixSet).
- **Existing policy_tests.rs**: continues to pass unchanged with
  flag default-OFF.
- **Feature flag toggled ON test** (in policy_tests.rs): flag-ON
  with Step 1's stub evaluate_via_dag (which immediately falls back
  to linear scan inside) returns identical results to flag-OFF for
  100 random packets against a 1K-rule synthetic config.
- **5/5 flake check** on the new tests (per
  `feedback_no_test_dismissal`).
- **Criterion microbench**: LPM lookup at 10K books, p50 + p99
  latency; LPM construction at 10K rules wall-clock.
- **Smoke matrix** on `loss:xpf-userspace-fw0/fw1`:
  v4 + v6 × push + `-R` × CoS-off + CoS-on. NO regression vs master
  (flag default-OFF means the linear scan path is untouched).
- **`make test-failover`**: HA failover ≤ 60 ms unchanged.

**Step 2 follow-up** will add:
- Stage 2/3/4 unit + property tests.
- Galloping-merge correctness (sorted ascending, dedup correct).
- First-match-wins property test (10K rules; compare DAG vs linear).
- Adversarial K_bucket overflow test (1K rules in one bucket).

**Step 3 follow-up** will add:
- Junos knob parser test.
- Go-side wire emit test.
- Flag-default-flip behavior test under HA failover.

## 8. Acceptance criteria — Step 1 (this PR)

- [ ] Plan v2 → vN PLAN-READY through 4-way quad-review.
- [ ] Multi-Book LPM v4 primitive in `userspace-dp/src/policy/multi_book_lpm.rs`.
- [ ] Per-book citation arrays in `userspace-dp/src/policy/book_citations.rs`.
- [ ] Feature flag `policy_dag_enable` wired through `ConfigSnapshot`,
      default OFF.
- [ ] Stub `evaluate_via_dag` that falls back to linear scan inside
      (so the flag-ON code path is exercised but semantically
      identical to flag-OFF).
- [ ] All existing policy_tests.rs pass unchanged with flag default-OFF.
- [ ] Property tests at 10/100/1K/10K rules pass 5/5 flake check.
- [ ] Criterion microbench shows LPM lookup ≤ 50 ns p50 at 10K
      books AND construction ≤ 100 ms at 10K rules.
- [ ] Smoke matrix passes on loss userspace cluster (flag default-OFF —
      master path).
- [ ] `make test-failover` passes; HA failover ≤ 60 ms.
- [ ] `docs/userspace-jit-design.md` Phase 4 row replaced with the
      Multi-Book LPM architecture pointer (per doc-coherency contract
      from #1605).
- [ ] PR body explicitly states the "≥10× cold-path speedup at 1M
      rules" claim is the goal but is NOT empirically verified by
      this PR; deferred to #1612.
- [ ] Cold-path policy evaluation at 1M rules ≤ 500 ns/packet on
      loss userspace cluster — **DEFERRED to #1612 measurement +
      Step 2 + Step 3 follow-up; this PR ships the primitive +
      feature-flag scaffold, not the full hot path.**

## 9. Files touched — Step 1 (this PR)

In scope:

- `userspace-dp/src/policy/multi_book_lpm.rs` — new module: DIR-24-8
  Multi-Book LPM v4 + per-/48 hash + sub-LPM v6.
- `userspace-dp/src/policy/book_citations.rs` — new module: per-book
  sorted citation arrays + construction helpers.
- `userspace-dp/src/policy/multi_book_lpm_tests.rs` — unit + property
  tests.
- `userspace-dp/src/policy.rs` — add `mod policy;` directory structure
  (move existing policy.rs into `policy/mod.rs` per
  `feedback_refactor_module_dir_layout`). Add `evaluate_via_dag` stub
  that falls back to linear scan. Wire the flag check.
- `userspace-dp/src/protocol/snapshot.rs` — add
  `policy_dag_enable: bool` field on `ConfigSnapshot` (serde default).
- `userspace-dp/src/policy_tests.rs` — add feature-flag-ON regression
  test (Step 1 expected output: identical to flag-OFF since stub
  falls back).
- `pkg/dataplane/userspace/snapshot.go` (or equivalent emission
  site) — emit `PolicyDagEnable: false` on the wire so the Rust
  side gets a deterministic value.
- `docs/userspace-jit-design.md` — Phase 4 row update per
  doc-coherency contract from #1605.

NOT touched in Step 1 (deferred to Step 2 follow-up):

- `userspace-dp/src/policy/decision_dag.rs` — full Stage 2/3/4 hot
  path.
- `userspace-dp/src/policy/galloping_merge.rs` — 3-way merge utility.
- Junos CLI knob in `pkg/config/typed.go` — Step 3 follow-up.

NOT touched (coordinator-enforced scope discipline):

- `test/incus/cold-path-flooder/` — owned by #1611/#1615.
- `userspace-dp/src/afxdp/cos/` — owned by parallel #1614 sub-agent.
- `pkg/cluster/` HA paths — out of scope.

## 10. Implementation order — Step 1 (this PR)

Each step builds clean + tests pass before the next.

1. **Refactor policy.rs into directory layout**: move
   `userspace-dp/src/policy.rs` → `userspace-dp/src/policy/mod.rs`.
   Move `userspace-dp/src/policy_tests.rs` →
   `userspace-dp/src/policy/tests.rs`. Re-declare module path in
   `userspace-dp/src/main.rs`. No semantic change. (Per
   `feedback_refactor_module_dir_layout`.)
2. **Add wire flag**: `policy_dag_enable: bool` on `ConfigSnapshot`
   (serde default = false). Tests verify roundtrip.
3. **Add multi_book_lpm.rs**: data structure + construction
   (two-pass) + lookup. Unit tests.
4. **Add book_citations.rs**: per-book sorted citation arrays.
   Unit tests.
5. **Add stub `evaluate_via_dag` in policy/mod.rs**: when flag is
   on, log via Prometheus counter, and fall back to the existing
   linear scan internally. Sole purpose: exercise the flag plumbing
   end-to-end.
6. **Add Criterion microbench** at
   `userspace-dp/benches/multi_book_lpm.rs` (new bench file).
7. **Property tests** at 10/100/1K/10K rules using
   `test/incus/synthetic-policy-gen.sh`-generated configs (or
   in-process equivalent).
8. **Go-side wire emit**: `PolicyDagEnable: false` so the field is
   always present on the wire.
9. **Doc update**: `docs/userspace-jit-design.md` Phase 4 row.
10. **Smoke matrix on loss userspace cluster** (flag default-OFF,
    so master path validation).
11. **`make test-failover`** (mandatory because the wire shape
    changed).

## 11. Alternatives rejected

- **Cranelift JIT** — killed at #1605.
- **Per-rule LPM** (v1) — KILLED at SMR-r1 + Codex-r1 + AGY-r1: 320 GB
  worst-case memory at 1M rules.
- **Hash-table on dominant selector + linear scan of bucket** —
  doesn't compose with CIDR membership.
- **Single-stage decision tree (CART / RDC)** — build cost at 1M
  rules is minutes.
- **Per-flow JIT** — every cold-path packet is a flow miss by
  definition.
- **`roaring` crate for intersection** — Codex F10 rejected: adds
  dependency + per-packet alloc. Galloping merge over `Arc<[u32]>`
  slices does the same job allocation-free.

## 12. Risks

- **R1**: Step 1 alone delivers only the primitive; the
  end-to-end ≥10× claim is the goal of Step 1 + Step 2 + Step 3.
  Step 2 + Step 3 are tracked as separate follow-up issues.
- **R2**: Multi-Book LPM v4 level-0 table is 16 MB — larger than L2
  on most CPUs. Lookup is one cache miss + one L1/L2 hit on the
  Arc<[u16]> leaf. Per #1612 measurement, if level-0 cold-cache hits
  exceed budget, v6's per-/48-hash + sub-LPM approach can be
  back-ported to v4 (the LPM trait abstracts both).
- **R3**: Construction cost at 1M rules is ~1-1.5 sec. Junos target
  is single-digit sec for total commit, so DAG construction at 1M
  rules eats most of the budget. Acceptable for the cold-path use
  case but reviewers may push back on commit-time impact.
- **R4**: Empirical 1M-rule numbers don't exist on master.
  Acknowledged in §0 + §6; production enablement gated on #1612 +
  Step 3 follow-up.
- **R5**: ICMPv6 NDP packets traverse the policy DAG; carve-out in
  §2.2 covers PROTO_ICMPV6 (58). v6 LPM tests must cover NDP-shaped
  packets (multicast dst, link-local src).

## 13. Out of scope

- **Junos CLI knob** — deferred to Step 3 follow-up issue.
- **Full multi-stage DAG hot path (Stage 2/3/4 + galloping merge)** —
  deferred to Step 2 follow-up issue.
- **Production enablement / default-flip** — gated on #1612 + Step 3.
- **Rate-limit + verdict cache** — #1608.
- **Per-flow JIT specialization** — killed (#1605).
- **Cold-path flooder + Scale Target measurement** — #1611 / #1612 /
  #1615.
- **Application-identification L7 DPI** — out of policy DAG.

## 14. Open architectural questions for v2 reviewers

**v2-Q1**: v6 stride choice — per-/48 FxHashMap → sub-LPM is the v2
default. Reviewers may push back on Poptrie if our v6 prefix
distribution has heavy /64 host concentration. The LPM trait
abstracts both; this is a tunable, not a structural commitment.

**v2-Q2**: Multi-Book LPM v4 level-0 is 16 MB — larger than L2 cache
on most CPUs (typically 1 MB / core). Reviewers should challenge
whether the cold-cache hit on level-0 is within the project's per-
packet budget. Per #1612 measurement may force back-pressure to a
smaller stride.

**v2-Q3**: Step 1 stub `evaluate_via_dag` that immediately falls
back to linear scan — is this "feature flag wired but useless"
acceptable as Step 1 scope, or should Step 1 instead omit the
flag entirely and add it in Step 2 alongside the real DAG hot path?
Reviewer-preference question.

**v2-Q4**: Module layout — `userspace-dp/src/policy.rs` (881 LOC) +
`policy_tests.rs` (1013 LOC) into `policy/` directory with
`mod.rs`, `multi_book_lpm.rs`, `book_citations.rs`, `tests.rs`?
This follows `feedback_refactor_module_dir_layout` and the project's
file-size convention (mod.rs would be ~880 LOC, below the 2000 LOC
trigger; the new files are ≤ 500 LOC each).

**v2-Q5**: Go-side wire emit always `false` until Step 3 — is it
worth emitting the field at all in Step 1 if it's hard-wired off?
Alternative: serde default-false on the Rust side suffices without
any Go-side emission, and Step 3 adds the emission alongside the
knob. The current §5 plan errs on the safe side (always emit) to
avoid serde-default-divergence between old/new Go binaries.

---

## v1 historical record (PLAN-NEEDS-MAJOR + BLOCKED)

The v1 plan proposed per-book multi-rule LPMs (per-/24 RuleBitSet)
and was KILLED at SMR-r1 + Codex-r1 + AGY-r1 for the 320 GB
worst-case memory blowup at 1M rules. The full v1 → r1+r2 review
record is preserved at:

- `docs/pr/1609-multistage-policy-dag/claude-smr-plan-r1.md`
- `docs/pr/1609-multistage-policy-dag/claude-smr-plan-r2.md`
- `docs/pr/1609-multistage-policy-dag/reviewer-ids.md`
- Issue #1609 comment for the v1 BLOCKED determination.

v2 starts from the Multi-Book LPM architectural pivot AGY r1
delivered and is a wholesale restructure of v1. Do NOT merge v2
against v1 — v2 supersedes.
