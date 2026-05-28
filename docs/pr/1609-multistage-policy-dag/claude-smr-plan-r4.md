# Claude SMR plan-review r4 — #1609 v2 round 1 convergence

**Role**: domain SMR (same scope as r1-r3).

**Verdict (round 4): PLAN-NEEDS-MAJOR (3-of-3 convergence with
Codex + AGY).** Revises my own r3 PLAN-READY-WITH-NITS verdict
after seeing Codex's 10 findings + AGY's Class-A findings. r3 was
too soft; the issues Codex and AGY surface are structural, not
nits.

## Convergent fatals (3-of-3)

### Fatal #1 — Level-0 memory math is materially wrong (Codex F1 + AGY F1.1)

Plan v2 §2.3 claims:
> "Level-0: 16 MB pointer table (Box<[LpmLeafV4; 1<<24]> at 8 B/entry
> with niche optimization — Arc<[u16]> and u32 both fit in 8 B via
> tagged enum). Same as DIR-24-8 baseline."

Two errors converged on by both reviewers:
1. Arithmetic: 2^24 × 8 B = **128 MiB**, not 16 MB. (I missed the
   "multiply by entry size" step — embarrassing.)
2. Type-size: `Arc<[u16]>` is a fat pointer (ptr + len), so the enum
   `LpmLeafV4 { Books(Arc<[u16]>), DescendInto(u32) }` is 16 B, not
   8 B. Level-0 = 2^24 × 16 B = **256 MiB**.

With 6 in-flight snapshots, level-0 alone = 1.5 GiB. Bursts the
≤1 GB-per-snapshot acceptance criterion before any leaves are
allocated.

v3 must restructure: either thin handles (packed u32 leaf/subtable
IDs into a deduped leaf arena) or a smaller stride (DIR-16-8 over
2^16 entries = 1 MB level-0; reviewers will need to push back on the
extra level-2 latency).

### Fatal #2 — Literal-only and `any` rules are dropped (Codex F3)

The Multi-Book LPM indexes rules via `source_book_idxs` /
`destination_book_idxs`. Rules with `source any` (no books, no
literals) have empty book idx lists. They never appear in any LPM
leaf. Stage 4 only re-verifies rules that Stage 3 emitted, so a
rule with `source any` is **completely dropped** by the DAG path.

This is a correctness fatal — not "no faster" but "wrong answer".

v3 must add explicit literal/any per-side candidate channels in
Stage 3 output: e.g. a `match_any_src_rules: Arc<[u32]>` and
`match_any_dst_rules: Arc<[u32]>` that every rule with
`*_match_any == true` lands in, merged into the Stage 4 input
alongside the LPM-derived slices.

### Fatal #3 — IPv6 per-/48 FxHashMap is a DoS vector (AGY F1.2)

`FxHashMap` uses a non-cryptographic hash (fxhash). It's hot-path
fine for trusted keys but the v6 LPM hashes attacker-controlled
src/dst IP /48 prefixes. An attacker can construct packets whose
/48s collide in fxhash, forcing the bucket walk to do work
proportional to N at every cold-path packet.

v3 must use either:
- `HashMap` with `RandomState` (SipHash, cryptographically randomized
  per-process), accepting the ~10 ns hash-extra cost; OR
- A different structure (e.g. DIR-24-(24+8) over the first /48
  paired with sub-LPMs over the remaining 80 bits, using DIR-style
  table lookups not hash lookups).

The plan needs to pick one and prove no DoS amplification under
adversarial v6 traffic.

### Fatal #4 — Global rules vs zone rules ordering (Codex F8 + AGY)

Plan v2 §2.6 claims: "rule_idx is dense parse-order so ascending =
first-match". But current `evaluate_policy_result_with_len`
(policy.rs:648-694) does **two-phase**: scan the zone-pair bucket
first, then `global_indices`. A global rule may have a LOWER
rule_idx than a zone-pair rule yet evaluate AFTER it in the current
semantics. The dense-ascending invariant breaks.

The Go builder (policies.go:27) happens to push globals last today,
making rule_idx ordering accidentally consistent — but the plan
doesn't enforce this, and there's no test that asserts it. v3 must
either explicitly assert the invariant at build time and document
it, OR (better) keep the two-phase scan: evaluate zone-pair DAG
first, then global DAG.

### Fatal #5 — Broad prefix (/0, /8, …) construction blow-up (Codex F5 + AGY F2.1)

Plan v2 §3 claims construction touches ≤256 level-0 entries per
prefix. False — a /0 prefix in an address book touches all 2^24
level-0 entries. Go's `policies.go:279` normalizes `any` to
`0.0.0.0/0` and `::/0`, so this is a realistic config.

v3 must add a separate broad-prefix list (Stage 3 fallback for any
src/dst IP), OR a memory-share scheme where /0-/15 prefixes only
touch one shared "universal coverage" entry that every level-0
lookup merges in.

### Fatal #6 — LPM cannot be built from current BookEntry (Codex F4)

§3 builder reads `state.books`, but `BookEntry` stores `PrefixSetV4/V6`
(which is trie-compressed and doesn't expose original prefixes). v3
must either:
- Build the LPM from `AddressBookSnapshot` BEFORE `parse_policy_state`
  collapses prefixes into PrefixSets.
- Add a `prefixes()` iterator on `PrefixSetV4/V6`.
- Store canonical prefix arrays alongside the PrefixSet on
  `BookEntry`.

This is also a build-time, not hot-path, concern, but the plan
sketch at §3 doesn't compile against current `BookEntry`.

## Additional MAJOR (not fatal) findings

### MAJOR #7 — Stage 2 holes (Codex F7)

Plan §2.5 sketch returns default when `proto_bucket.is_none()` before
considering `any_proto_rules`. Plan §2.2 talks about `exact_dport=0`
for ICMP but `parse_port_spec` rejects port 0 at policy.rs:863
(`if port == 0 { return None }`). The ICMP carve-out is conceptually
correct (id goes into src_port; rules use `any_port_rules` of the
ICMP proto bucket) but the example in §2.2 about exact_dport_to_rules
[0] doesn't exist.

### MAJOR #8 — u16 book idx cap is unapproved (Codex F2)

`AddressBookSnapshot::id` is `u32` on the wire (security.rs:190).
The plan switches LPM leaves to `Arc<[u16]>`, capping the system
at 65,535 unique books per snapshot with no admission rule. At 1M
rules with realistic book density, >65K books is plausible. v3
must either use u32 in LPM leaves (doubles the leaf-arena cost) or
add an explicit config-apply admission gate with documented
fallback.

### MAJOR #9 — Stage 4 buffer panic vs silent-drop (AGY F1.4)

Plan §2.4 says scratch buffer = 64 entries. Plan also says
"continue processing without truncation". These contradict — at
K_bucket=1000, the 64-entry buffer either:
- Panics (unwanted in hot path);
- Silently truncates (drops rules — security violation per AGY F5);
- Overflows to heap-Vec (allocation in hot path, violates Codex F8).

v3 must spec the fallback: e.g. when galloping merge fills the
scratch buffer, drop to the master linear-scan fallback path for
that packet. This preserves "no-worse-than-master" framing
without rule drops.

### MAJOR #10 — Feature flag wiring placement (Codex F9)

`evaluate_policy_result_with_len` receives only `&PolicyState`, not
`ConfigSnapshot`. Plan v2 §5 sketch checks
`if snapshot.policy_dag_enable && state.dag.is_some()` — but the
function doesn't have access to `snapshot`. v3 must move the flag
+ optional DAG onto `PolicyState` (or `ForwardingState`) and
update the parser to materialize them from `ConfigSnapshot`.

### MAJOR #11 — synthetic-policy-gen.sh doesn't exist (Codex F10)

Plan v2 §7 references `test/incus/synthetic-policy-gen.sh` from
#1607 step-1. That step shipped the cold-path flooder + plan, but
not a policy generator. v3 must either bundle a small in-Rust
generator or file a follow-up for the harness piece.

### MAJOR #12 — Module refactor + new LPM in one PR (Codex F8 advisory)

Combining `policy.rs` → `policy/` directory move with the new
`multi_book_lpm.rs` + `book_citations.rs` modules in one PR risks
reviewer confusion ("where did this go, was it a semantic change?").
v3 should either split into a pre-cursor refactor PR or use two
explicit commits with clean diff boundaries.

## Verdict and recommendation

**PLAN-NEEDS-MAJOR (3-of-3 convergent).**

Fatals #1-6 are structural. v2 as written cannot be implemented as
Step 1 — it has correctness bugs (literal/any drop, global ordering),
DoS vectors (v6 hashmap), memory math errors (level-0 16×), and
buildability gaps (PrefixSet doesn't expose prefixes). These are
not patches; v3 is a substantive rewrite.

**Recommendation**: do NOT spawn a v3 in this session. Per
`feedback_difficult_path_pragmatism` and `feedback_no_test_dismissal`,
the right move is:
1. Post issue comment with 3-of-3 PLAN-NEEDS-MAJOR convergence +
   captured findings.
2. Keep #1609 OPEN — the architectural axis (Multi-Book LPM +
   sorted postings + galloping merge) is still sound; the v2
   concrete design has fatal patchable issues.
3. Add a `plan-needs-major` label-equivalent marker on the issue
   (no such label exists yet; comment + reference per project
   convention).
4. Defer v3 to a future planning session that can incorporate
   AGY F1.1-F1.4 + Codex F1-F10 + this r4's findings, ideally
   with #1612 numbers also landed to anchor stride and broad-prefix
   handling.

This is a STAGED outcome NOT a PLAN-KILL (the architectural
direction is sound). It's also NOT MERGED. It's BLOCKED-on-v3-redesign.

## Why I'm reversing r3

r3 saw the v2 plan and called PLAN-READY-WITH-NITS because the
architectural pivot resolved v1's headline fatal (320 GB
RuleBitSet). I missed:
- The memory arithmetic error (math I should have caught — 2^24
  × 8 B is 128 MiB not 16 MB, embarrassing).
- The fat-pointer DST size on `Arc<[u16]>`.
- The literal/any-rule drop in Stage 3.
- The global-rule ordering invariant.
- The DoS vector on FxHashMap with attacker-controlled v6 /48s.
- The PrefixSet-doesn't-expose-prefixes buildability gap.

Codex caught 8 of these; AGY caught the DoS vector. I'm aligning to
their findings.

The honest framing is: my r3 was a soft-pass and the hostile
quad-review caught it. This is the system working — three reviewers
agreed v2 needs material rework before Step 1 can ship.
