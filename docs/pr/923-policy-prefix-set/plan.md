# #923: policy address matching — adaptive prefix set (linear ≤16, Patricia trie >16)

Plan v1 — 2026-04-29.

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

### Two important properties of the current semantic

1. **Any-match, not LPM**: the function returns true iff *any* prefix
   covers the IP. There is no longest-prefix tiebreak — boolean only.
2. **Empty list = match-all (after the "any" stripping)**: the parser
   in `parse_address` (policy.rs:341) skips literal `"any"` strings.
   A rule with `source_addresses: ["any"]` → both vecs empty →
   `is_empty()` → returns true (match all). A rule with
   `source_addresses: []` (no addresses configured) — same code path.
   This conflates "match all" with "vec was never populated"; both
   currently produce true.

The trie replacement must preserve both invariants exactly.

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

### Patricia trie (binary, hand-rolled)

A compressed binary trie: each interior node has up to 2 children
(by next bit) and an optional "covers here" marker. Building from a
prefix list is O(N × W) where W=32 or 128.

```rust
pub(crate) struct PrefixTrieV4 {
    root: TrieNode,
}
struct TrieNode {
    /// True if any inserted prefix has this node as its end-of-prefix.
    covers: bool,
    /// Children indexed by next bit (0 or 1). Box to keep node size
    /// small; we expect mostly-sparse trees in policy address-books.
    children: [Option<Box<TrieNode>>; 2],
}
```

Lookup walks from MSB to LSB; on every node visited that is
`covers == true` we can short-circuit `return true`. (Any-match
semantics — no need to descend further once a covering ancestor is
found.) Worst-case 32 hops for v4, 128 for v6, but practically 2-8
for typical address books.

### Why hand-rolled, not a crate

- The semantic is custom (any-match short-circuit, not LPM lookup).
  External crates like `prefix-trie` and `treebitmap` are LPM-oriented
  and would require adapter code.
- ~80 LOC for the trie + 30 LOC for the set enum is small enough to
  audit; one fewer dependency to vet and rebuild against.
- We already have `prefix.rs` with hand-rolled `PrefixV4/V6`; this
  is the same flavour of code.

### Files touched

- **NEW** `userspace-dp/src/prefix_set.rs` (~150 LOC):
  - `PrefixSetV4` / `PrefixSetV6` enums + `contains()` methods.
  - `PrefixTrieV4` / `PrefixTrieV6` trie types + `insert/contains`.
  - Constructor `PrefixSetV4::from_prefixes(Vec<PrefixV4>)` that
    picks Linear vs Trie based on the threshold.
  - Unit tests: empty set, single prefix, 16 prefixes (Linear path),
    17 prefixes (Trie path), 256 prefixes, IP at every covering
    prefix length, IP NOT covered.
- `userspace-dp/src/main.rs`: `mod prefix_set;`
- `userspace-dp/src/policy.rs`:
  - `PolicyRule.source_v4: Vec<PrefixV4>` → `PrefixSetV4`. Same for
    destination_v4, source_v6, destination_v6.
  - `parse_address` rewritten to accumulate into temporary Vecs then
    call `PrefixSetV4::from_prefixes` once at end of `parse_policy_state`
    (or inline at construction).
  - `nets_match_v4/v6` deleted; `try_match_rule` calls
    `rule.source_v4.contains(src) && rule.destination_v4.contains(dst)`
    directly.
  - Existing tests preserved verbatim — they exercise the boolean
    semantic, not the data structure, so they pass through.

### Threshold rationale

The choice of 16 comes from:

- 64-byte cache line = 16 × `PrefixV4` (which is 32 bits + 32 bits +
  8 bits, packs to 12 bytes; Vec stride is 16 bytes after rounding).
- Below 16 prefixes the entire Vec fits in 1-2 cache lines and a
  linear scan is faster than the pointer-chase a trie does.
- Above 16, the trie's O(W) bounded depth (W=32 or 128) wins.
- The threshold is a tunable constant; if microbench shows 8 or 32 is
  better we can flip it without changing the API.

### Memory cost

- `Linear(Vec)`: same as today.
- `Trie`: ~24 bytes per node + 16 bytes per child pointer; for 256
  /32 prefixes the trie is ~2 KB. For 256 random /24 prefixes ~1 KB.
  Negligible vs the rule storage which already exists.

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

```rust
#[test]
fn empty_set_matches_anything() { ... }

#[test]
fn match_any_set_matches_anything() { ... }

#[test]
fn linear_set_matches_covered_ip() {
    // build 8 random /24 prefixes; verify covered/uncovered
}

#[test]
fn linear_set_15_prefixes_uses_linear_variant() {
    // probe enum variant via match
}

#[test]
fn trie_set_17_prefixes_uses_trie_variant() { ... }

#[test]
fn trie_lookup_matches_linear_lookup_for_random_prefixes() {
    // build 256 random prefixes; build BOTH linear and trie sets
    // from the same input; for 1024 random IPs, assert
    // linear.contains(ip) == trie.contains(ip)
}

#[test]
fn trie_handles_default_route_zero_zero_zero_zero_slash_zero() {
    // 0.0.0.0/0 covers everything
}

#[test]
fn v6_trie_lookup_matches_linear_lookup_for_random_prefixes() { ... }
```

## Acceptance gates

1. `cargo build --release` clean.
2. `cargo test --release` ≥ existing-baseline + 8 new unit tests.
   Baseline at 834 (post-#925), so target ≥ 842.
3. Cluster smoke (HARD): no regression — adaptive path is slower or
   equal to today only for malformed config, otherwise faster.
   - iperf-c P=12 ≥ 22 Gb/s
   - iperf-c P=1 ≥ 6 Gb/s
   - iperf-b P=12 ≥ 9.5 Gb/s, 0 retx
   - mouse-latency p99 ±5%
4. **Session-setup throughput gate** (RECOMMENDED): set up a config
   with 1 policy rule that has 256 source prefixes; measure session-
   setup-rate via the same `nc`-reconnect loop used for #919+#922.
   Expect ≥ 1.1× baseline (≥ 540 cycles saved per miss × ~10K mps).
5. Codex hostile review: AGREE-TO-MERGE.
6. Gemini adversarial review: AGREE-TO-MERGE.

## Risk

**Low.**

- Pure-Rust hand-rolled trie; no new dependencies; no `unsafe`.
- Existing semantic preserved exactly (any-match, empty=match-all).
- Linear path unchanged for typical configs (N ≤ 16).
- All existing policy tests pass through unmodified.
- Only the `Vec<PrefixVx>` → `PrefixSetVx` shape change is
  observable, and that's an internal type.

## Out of scope

- LPM (longest-prefix match) — plan #966 SIMD classifier territory.
- SIMD-accelerated parallel range matching — defer to #966 with a
  microbenchmark gate.
- JIT-compiled decision tree — overkill for a 100K-rule cap.
- Replacing the `iter().any(...)` in `port_ranges_match` /
  `compiled_apps.matches` — those operate on small sets (port
  ranges per term, typically 1-2) where linear is correct.
- Address-book deduplication / canonicalization — separate concern.

These are all listed under #966 / #946 in the issue tracker; this
PR is **#923 only**.
