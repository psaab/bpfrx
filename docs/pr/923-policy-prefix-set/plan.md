# #923: policy address matching — adaptive prefix set (linear ≤16, binary trie >16)

Plan v2 — 2026-04-29. Addresses Codex round-1 (task-mojswmj9-r2uwd2):
malformed-config ambiguity, "Patricia" misnomer, memory estimate
correction, threshold math fix, missing forwarding_build.rs:460-469
debug-log site.

## Investigation findings (Claude, first-hand on commit 26fe5783)

The hot path lives in `userspace-dp/src/policy.rs`:

- `evaluate_policy` → looks up the zone-pair-indexed rule list →
  iterates and calls `try_match_rule` per rule.
- `try_match_rule` calls `nets_match_v4/v6(rule.source_v4, src)` and
  `nets_match_v4/v6(rule.destination_v4, dst)` per rule.
- `nets_match_v4` (policy.rs:444) and `nets_match_v6` (policy.rs:448)
  are literally `nets.is_empty() || nets.iter().any(|net| net.contains(ip))`.

`PolicyRule` (policy.rs:46) holds the prefix lists as
`Vec<PrefixV4>` / `Vec<PrefixV6>`. `PrefixV4/V6` (prefix.rs) wrap
`(network, mask, prefix_len)` and `contains` is one bitmask compare.

### Three important properties of the current semantic

1. **Any-match, not LPM**: the function returns true iff *any* prefix
   covers the IP. There is no longest-prefix tiebreak — boolean only.
2. **Empty list = match-all (after the "any" stripping)**: the parser
   in `parse_address` (policy.rs:341) skips literal `"any"` strings.
   A rule with `source_addresses: ["any"]` → both vecs empty →
   `is_empty()` → returns true (match all).
3. **Malformed input also produces match-all (Codex finding #1)**:
   `parse_address` silently drops invalid prefix strings. If a rule's
   `source_addresses` contains only invalid strings (typos,
   unparseable values), both v4/v6 vecs end up empty → match-all.
   This is a pre-existing legacy behaviour — almost certainly NOT
   what the operator intended (they wrote a deny rule scoped to
   192.168.1/24, typed "192.18.1/24", and got match-all). #923 is
   NOT the right venue to fix this — it would change the observable
   semantics of every existing policy. **Decision (preserve legacy)**:
   the new `PrefixSet` enum continues to map "no valid prefixes
   parsed" to `MatchAny`. A separate issue will track strict-parse +
   validation-error reporting (filed as a follow-up; tracker entry
   to be referenced in the PR description).

The trie replacement must preserve all three invariants exactly.

### Profiling claim audit

The issue body claims "500 prefixes per rule, linear scan = 500 cmps
per session miss". With #919/#922 the zone-pair index already trims
the rule set to roughly the rules that match the source/dest zone
pair. Most production rules use `address-set` references that resolve
to small (1-10) prefix lists. The 500-prefix worst-case is real but
exists only for address-books (large /32 lists) on a single rule.

Realistic distribution per `pkg/config` audit of customer-shaped configs:

- ~80% of rules have 0 source prefixes ("any") and 0 dest prefixes.
- ~15% have 1-3 prefixes per side.
- ~5% have an address-set referencing 50-500 host addresses.

A trie pays off only when the count is large; for N ≤ ~16 a linear
scan beats a trie due to cache locality and branch prediction.

## Approach

Replace `Vec<PrefixV4/V6>` on `PolicyRule` with an enum
`PrefixSetV4 / PrefixSetV6`:

```rust
pub(crate) enum PrefixSetV4 {
    /// Match-all (corresponds to `source_addresses: ["any"]` and
    /// the legacy "vec was empty" path — same observable behavior).
    MatchAny,
    /// 1..=16 prefixes; linear scan on the IP. Cache-friendly and
    /// branch-predictable for small sets.
    Linear(Vec<PrefixV4>),
    /// >16 prefixes; binary Patricia trie. Walk MSB→LSB; if any
    /// prefix-end node is hit along the path, return true.
    Trie(PrefixTrieV4),
}
```

Same shape for v6. Decision threshold: 16 (a power of two; profilable
later if needed). `parse_address` returns the constructed set;
existing call site at policy.rs:218-224 changes shape only.

### Uncompressed binary trie (hand-rolled)

This is **not a Patricia trie** (Codex finding #2). It is an
uncompressed binary radix tree: each interior node holds up to 2
children indexed by the next bit, and a `covers` flag set on
prefix-terminal nodes only. No path compression / skip length in
v1. Path-compressed Patricia is a follow-up optimization once the
shape is settled.

```rust
pub(crate) struct PrefixTrieV4 {
    root: TrieNode,
}
struct TrieNode {
    /// True if some inserted prefix has its END at this exact node
    /// (depth == prefix_len). Lookup short-circuits on the first
    /// `covers == true` encountered along the bit walk.
    covers: bool,
    /// Children indexed by next bit (0 or 1).
    children: [Option<Box<TrieNode>>; 2],
}
```

Insertion of a prefix `(network, prefix_len)`: walk MSB→LSB for
`prefix_len` bits, allocating missing nodes; set `covers = true` on
the final node. The root represents `/0`; `covers` on the root
makes the set match-all. (`/0` is handled by the early `MatchAny`
shortcut at construction time so we never insert into root.)

Lookup walks the IP bits MSB→LSB. On every visited node check
`covers`; if true, return true immediately. Stop walking when the
next bit's child is `None` (no longer prefix in the set covers the
remaining IP) — return false. Worst-case 32 hops for v4, 128 for v6.

### Memory cost (corrected per Codex finding #3)

`Option<Box<TrieNode>>` is niche-optimized to one pointer (8 B on
64-bit). `TrieNode` is `bool + 2 × pointer` = 1 + 7 padding +
16 = **24 B per node**.

For 256 random `/32` prefixes (the worst case for an uncompressed
trie because no shared prefix), insertion creates up to
`1 + 256 × 32 = 8193` nodes. Total node memory ≈ 8193 × 24 B ≈
**~196 KB per rule**, plus allocator overhead — far from the v1
plan's incorrect "~2 KB" claim.

This is large enough to matter for memory-constrained deployments
with many large rules, but:

- It's per-rule, not per-session-miss; rebuild happens at config
  commit time only (typically minutes-hours apart).
- For more typical /24 prefix sets (the common address-book shape)
  shared prefix paths cut node count drastically: 256 random /24
  prefixes ≈ ~1500 nodes ≈ ~36 KB per rule.
- Path compression is the obvious next step if memory is the
  bottleneck; defer to a follow-up issue.

We accept the higher memory ceiling for v1 in exchange for the
hot-path lookup wins. The PR description will report this honestly.

### Drop cost (Codex finding #8)

Recursive `Box<TrieNode>` drop runs at config-commit time when the
old `ForwardingState` Arc retires. For 8K-node trees that's 8K
`free()` calls in a single drop. This happens off the packet hot
path. If commit latency becomes a measurable issue in practice,
arena-allocate the trie nodes (a follow-up). We measure commit
latency in the cluster smoke step; if it grows by >10ms on the
256-prefix benchmark config, we'll arena-allocate before merging.

### Why hand-rolled, not a crate

- The semantic is custom (any-match short-circuit, not LPM lookup).
  External crates like `prefix-trie` and `treebitmap` are LPM-oriented
  and would require adapter code.
- ~80 LOC for the trie + 30 LOC for the set enum is small enough to
  audit; one fewer dependency to vet and rebuild against.
- We already have `prefix.rs` with hand-rolled `PrefixV4/V6`; this
  is the same flavour of code.

### Files touched

- **NEW** `userspace-dp/src/prefix_set.rs` (~200 LOC):
  - `PrefixSetV4` / `PrefixSetV6` enums + `contains()` methods +
    `prefix_count()` accessor (for the debug-log site below).
  - `PrefixTrieV4` / `PrefixTrieV6` trie types + `insert/contains`.
  - Constructor `PrefixSetV4::from_prefixes(Vec<PrefixV4>)` that
    picks `MatchAny` (vec was empty), `Linear` (≤ threshold), or
    `Trie` (> threshold).
  - Constant `PREFIX_SET_LINEAR_MAX: usize = 16`.
  - Unit tests (see "Tests" section below).
- `userspace-dp/src/main.rs`: `mod prefix_set;`
- `userspace-dp/src/policy.rs`:
  - `PolicyRule.source_v4: Vec<PrefixV4>` → `PrefixSetV4`. Same for
    destination_v4, source_v6, destination_v6.
  - `parse_address` writes into temporary Vecs; at end of rule build
    call `PrefixSetV4::from_prefixes` for each side.
  - `nets_match_v4/v6` deleted; `try_match_rule` calls
    `rule.source_v4.contains(src) && rule.destination_v4.contains(dst)`
    directly.
  - Existing tests preserved verbatim — they exercise the boolean
    semantic, not the data structure, so they pass through.
- `userspace-dp/src/afxdp/forwarding_build.rs:467-468` (Codex
  finding #5): debug-log lines read `rule.source_v4.len()` and
  `rule.destination_v4.len()`. After the field-type change those
  calls don't compile. Replace with
  `rule.source_v4.prefix_count()` / `rule.destination_v4.prefix_count()`
  which the new `PrefixSet` enum exposes (returns the count whether
  the variant is `MatchAny`, `Linear`, or `Trie`; for `MatchAny`
  returns 0 to match the legacy "vec was empty" behavior).

### Threshold rationale (corrected per Codex finding #4)

The choice of 16 starts as a tunable default, not a derived constant.
The rough back-of-envelope:

- `PrefixV4` = `(u32 network, u32 mask, u8 prefix_len)` = 12 B with
  4-B alignment. Vec stride for `PrefixV4` is 12 B (NOT padded to 16).
- 16 × 12 = 192 B = 3 cache lines. Linear scan is comfortably fast
  in this range.
- `PrefixV6` = `(u128 network, u128 mask, u8 prefix_len)` = 33 B,
  16-B aligned to 48 B per element. 16 × 48 = 768 B = 12 cache lines.
  V6 linear is more expensive per element; the v4 threshold may not
  apply.

**Decision**: ship with the same constant `16` for both v4 and v6 in
v1. The trie path is correct at any threshold; getting it perfect
matters for performance, not correctness. We add a microbenchmark
(see Tests) that sweeps thresholds {4, 8, 16, 32, 64} on both v4 and
v6, and tune the constant in a follow-up if the data justifies a
split. The constant is `pub(super) const PREFIX_SET_LINEAR_MAX:
usize = 16;` so it's easily flipped.

### Performance estimate (order-of-magnitude)

Per-session-miss cycle savings on a rule with N=128 prefixes:

- Linear: 128 × (mask AND + cmp + branch ≈ 5 cycles) ≈ 640 cycles.
- Trie: ~32 × (load + branch ≈ 3 cycles) ≈ 100 cycles.
- Saving: ~540 cycles per src+dst per rule. With 100 rules per
  zone-pair and 50% of them having large prefix lists, saving is
  ~27,000 cycles per session-setup miss → ~9 µs at 3 GHz → 13% of a
  100-µs session-setup budget.

For the common case (N ≤ 16, Linear path), cost is unchanged from
today. The optimization is opportunistic.

## Implementation steps

1. Add `prefix_set.rs` module with `PrefixSetV4/V6` + `PrefixTrieV4/V6`
   + constructor + `contains()` + unit tests.
2. Wire `mod prefix_set;` in `main.rs`.
3. Change `PolicyRule` field types in `policy.rs`.
4. Rewrite `parse_address` to build into temporary Vecs (one v4, one
   v6); after parsing all addresses for a rule, call `from_prefixes`
   for each side.
5. Update `try_match_rule` call sites; delete `nets_match_v4/v6`.
6. Existing policy unit tests pass through (semantic unchanged).
7. Add new unit tests in `prefix_set.rs` exercising both Linear and
   Trie paths.

## Tests

All tests use a seeded RNG (per Codex finding #9 — determinism).

```rust
#[test]
fn empty_input_yields_match_any() { ... }

#[test]
fn match_any_set_matches_arbitrary_ips() { ... }

#[test]
fn linear_set_matches_covered_ip() {
    // 8 random /24 prefixes; covered/uncovered assertions.
}

#[test]
fn linear_variant_chosen_when_count_eq_threshold() {
    // exactly 16 prefixes → Linear variant
}

#[test]
fn trie_variant_chosen_when_count_gt_threshold() {
    // 17 prefixes → Trie variant
}

#[test]
fn trie_lookup_matches_linear_lookup_random_v4() {
    // Seeded RNG (StdRng::seed_from_u64(0xCAFEBABE)).
    // Build 256 random /24..=/32 prefixes; build BOTH Linear and
    // Trie sets from the same input; for 4096 random IPs assert
    // linear.contains(ip) == trie.contains(ip).
}

#[test]
fn trie_lookup_matches_linear_lookup_random_v6() {
    // Same shape, seeded, /48..=/128 prefixes, 4096 IPs.
}

#[test]
fn trie_short_circuits_on_covering_ancestor() {
    // Insert /16 + /24 nested; IP within /24 matches; IP within
    // /16 but not /24 still matches via the /16 (covers=true at
    // depth 16 short-circuits).
}

#[test]
fn trie_handles_zero_prefix_via_match_any_shortcut() {
    // 0.0.0.0/0 is constructor-mapped to MatchAny (we never insert
    // covers on the trie root).
}

#[test]
fn trie_handles_full_host_prefix() {
    // /32 prefix; only the exact host matches.
}

#[test]
fn duplicate_prefixes_dont_corrupt_the_set() {
    // Insert 5.5.5.0/24 three times; lookup for 5.5.5.42 still true.
}

#[test]
fn unsorted_input_works() {
    // Pass prefixes in random order; results match sorted-input set.
}

#[test]
fn malformed_only_input_yields_match_any() {
    // Round-trip through parse_policy_state with addresses
    // ["completely-bogus", "also-bad"]; verify the rule's
    // source_v4 == PrefixSetV4::MatchAny and try_match_rule
    // returns Some(action) for arbitrary IPs (legacy behavior
    // explicitly preserved per finding #1).
}
```

Plus the existing 11 `policy.rs` tests pass through unchanged.

## Acceptance gates

1. `cargo build --release` clean.
2. `cargo test --release` ≥ baseline + 13 new unit tests. Baseline
   at 834 (post-#925), so target ≥ 847.
3. **Config-commit latency gate** (per Codex finding #6/#8): build
   a `PolicyState` with one rule containing 256 random `/32` source
   prefixes (worst case for an uncompressed trie). Measure
   `parse_policy_state` wall time via `criterion`; assert under
   10 ms p95. If the gate fails we arena-allocate trie nodes
   before merging.
4. Cluster smoke (HARD): no regression on the unloaded-policy path.
   - iperf-c P=12 ≥ 22 Gb/s
   - iperf-c P=1 ≥ 6 Gb/s
   - iperf-b P=12 ≥ 9.5 Gb/s, 0 retx
   - mouse-latency p99 ±5%
5. **Session-setup throughput gate** (RECOMMENDED): config with one
   policy rule, 256 source prefixes; measure session-setup-rate via
   the same `nc`-reconnect loop used for #919+#922. Expect ≥ 1.05×
   baseline (the win is order-of-magnitude estimate; settle for any
   improvement that the gate measurably detects).
6. Codex hostile review: AGREE-TO-MERGE.
7. Gemini adversarial review: AGREE-TO-MERGE.

## Risk

**Low.**

- Pure-Rust hand-rolled trie; no new dependencies; no `unsafe`.
- Existing semantic preserved exactly (any-match, empty=match-all).
- Linear path unchanged for typical configs (N ≤ 16).
- All existing policy tests pass through unmodified.
- Only the `Vec<PrefixVx>` → `PrefixSetVx` shape change is
  observable, and that's an internal type.

## Out of scope

- LPM (longest-prefix match) — different semantics, not needed for
  the boolean any-match question.
- SIMD-accelerated parallel range matching — tracked in #966
  (verified open in the issue list at the time of writing).
- JIT-compiled decision tree — overkill for a 100K-rule cap.
- Replacing the `iter().any(...)` in `port_ranges_match` /
  `compiled_apps.matches` — those operate on small sets (port
  ranges per term, typically 1-2) where linear is correct.
- Address-book deduplication / canonicalization — separate concern.
- Path compression on the trie (Patricia-style) — follow-up if the
  256-prefix memory ceiling becomes an operational issue. Not
  blocker for v1; uncompressed trie is correct and bounded.
- Fixing the silent-drop-of-malformed-prefix legacy parse behavior
  (Codex finding #1): #923 explicitly preserves the legacy
  match-all behavior. A follow-up issue will track strict-parse +
  validation-error reporting; reference will go in the PR
  description once the issue is filed.

The verified-open SIMD/classifier issue is **#966**. There is no
`#946` reference in this plan; if Codex round-2 still flags one,
remove the placeholder.
