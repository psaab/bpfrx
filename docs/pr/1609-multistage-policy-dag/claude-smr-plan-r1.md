# Claude SMR plan-review r1 — #1609 multi-stage policy DAG

**Role**: domain SMR (network firewall semantics + Junos policy
order + data-structure algorithms + CPU microarchitecture + AF_XDP
ZC cold-path budgets).

**Verdict (round 1): PLAN-NEEDS-MAJOR**

The plan is structurally on the right axis (data-structure
refactor, not JIT). But it has at least four convergent issues that
must be resolved before PLAN-READY.

## Findings

### F-r1-1 — Stage 3 RuleBitSet memory math is wrong (FATAL)

Plan §2.3 and §4-Q5 contradict each other. §2.3 claims:

> "1M rules × 125 KB/bitset × 256 /24 entries per book × 10K books =
> 320 GB. THIS IS A KILL SHOT IF NOT MITIGATED."

But the §4-Q5 mitigation is hand-waved as "roaring bitmaps, ~64
rules per /24". There is NO supporting argument for "64 rules per
/24". At 1M rules with /24-heavy address books, the worst case is
that ALL 1M rules cite the same /24 — and the bit-set is back to
125 KB.

Mitigation must be **structural**, not statistical. Three options:

1. **Stage 3 is over-approximation only** — the LPM returns "set
   of book-citing-rules that have at least one CIDR covering /24",
   not "rule-by-rule precise match". This already changes the
   per-/24 cost from O(rules-citing-/24) to O(books-covering-/24).
   But the candidate set still has to be enumerated for Stage 4,
   so the bit-set is still needed.

2. **Per-book candidate compaction** — store per-book "rules
   citing this book", a single bit-set per book (NOT per /24).
   Then per-CIDR lookup is: "does this /24 hit this book's LPM?
   if yes, all rules-citing-book are candidates; if no, none".
   This reduces /24-multiplication to book-multiplication, but
   loses precision within a book.

3. **Sparse representation per /24 entry** — `Box<[RuleIdx]>` not
   bit-set, only allocated for /24s with non-empty rule set. At
   1M /24s × 16 bytes average payload = 16 MB. Acceptable.

Plan v2 must pick one. **The reviewer's bet is option 3** —
sparse `Box<[u32]>` per /24, only the populated /24s are
allocated, sorted for binary-search verification in Stage 4.

### F-r1-2 — Stage 2 dst-port-only-prune misses src-port + ICMP semantics (MAJOR)

Plan §2.2 indexes by `proto + exact_dst_port + dst_port_range`.
But Junos `application` matching is **(src-port OR src-port-range)
AND (dst-port OR dst-port-range)** per the existing
`CompiledApplications::matches`:

```rust
terms.range_terms.iter().any(|(src_ranges, dst_ranges)| {
    port_ranges_match(src_ranges, src_port) &&
    port_ranges_match(dst_ranges, dst_port)
})
```

Pruning only on dst port discards rules that match dst-any but
src-specific. For example, a rule `match application source-port
[10000-65535]` is pruned by Stage 2 because it has no dst-port
constraint — but should match every packet whose src-port is in
that range. Plan v1 puts it in `any_port_rules`, which is
correct — but reviewer must double-check that `any_port_rules`
fall through to Stage 3 unconditionally, NOT just for the proto
that owns the bucket.

Also: **ICMP**. `CompiledApplications` indexes by `protocol`
including PROTO_ICMP. ICMP packets have `dst_port = 0` (per
`parse_flow_ports` at `frame/inspect.rs:212-232`). Stage 2's
`exact_dst_port_to_rules.get(&0)` returns the rules with dst port
== 0, which is fine. But Stage 2 must ensure that ICMP rules with
src_port matching the ICMP identifier word are not incorrectly
pruned. Plan v2 should call out the ICMP carve-out explicitly.

### F-r1-3 — Construction cost at 1M rules is under-estimated (MEDIUM)

Plan §3 claims:

> "1M rules × 8 books each × 4 prefixes each × 1 LPM insert =
> 32M LPM inserts. At 100 ns each = 3.2 seconds."

But DIR-24-8 insert at /24-heavy distribution is NOT 100 ns. The
worst case is: insert /32 prefix, which touches the /24 entry +
allocates a second-level table of 256 leaves + writes 256
bit-set updates if the /32 distributes uniformly across the /24.
At ~5 cache misses per insert × 100 ns/miss = 500 ns. So 32M
× 500 ns = 16 sec. Plus Phase B/C/etc.

At ~30 sec total config-apply time, this is borderline. Junos
target is single-digit seconds. **Reviewer requires a
benchmarked construction-cost number at 100K rules before
shipping, OR a contract that defers 1M-rule construction-cost
to a follow-up issue.**

### F-r1-4 — "First-match-wins-by-rule-order" preservation argument is unverified (MAJOR)

Plan §2.1 claims: "iterate candidates in original rule order;
first match wins". But the Stage 2/3 candidate sets are
materialized as bit-sets / Vec<RuleIdx>; iterating them in
original-rule-order requires either:

- sorting at construction time (Plan §2.4 mentions this but doesn't
  spec it), OR
- using a sorted intersection algorithm (galloping merge) across
  Stage 2 + Stage 3 outputs.

The galloping-merge path is well-trodden in IR systems but adds
~50-100 ns per stage. The sort-at-construction path costs
construction-time memory (each candidate-vec is per-/24-per-book,
and sorting them at construction inflates apply latency).

Plan v2 must pick one and prove the first-match-wins invariant
holds in tests. **Reviewer recommends sort-at-construction +
galloping merge across stages** — apply latency is paid once, hot
path is fast.

### F-r1-5 — #1431 cache-key invariant interaction underspecified (MEDIUM)

Plan §4-Q4 classifies DSCP / TCP-flags / IHL / flex-match as
"Stage 4 ONLY (cache-sensitive per #1431)". This is structurally
correct — but the plan doesn't say what `try_match_rule` does
about them today. Today `try_match_rule` does NOT check any of
those fields — they're not on `PolicyRule`. They live on
`FilterTerm` (firewall filters), NOT on `PolicyRule` (security
policies).

So #1431 is a **forward-looking** carve-out for the DAG: if a
future PR adds `tcp_flags_match` to `PolicyRule`, Stage 4 is the
only allowed home. Plan v2 should say this explicitly so future
contributors don't promote a cache-sensitive field to Stage 2/3
by accident.

### F-r1-6 — No empirical justification at any rule count (BLOCKING)

Plan §0 acknowledges this honestly: "If the reviewers converge on
'the empirical justification cannot be hand-waved; this plan must
wait on #1612 numbers', that is a valid BLOCKED outcome."

Reviewer takes the keep-going position: the structural argument
**is** strong enough to ship the implementation now, AS LONG AS
the PR ships with the 1K-rule synthetic microbench showing ≥ 10×
speedup vs linear scan. The 10K/100K/1M numbers are #1612's job
and can land later.

But the PR description must be explicit: "this PR is the
structural skeleton; the 1M-rule cold-path budget verification
ships in #1612 once empirical numbers exist." Otherwise the
acceptance criteria's "≤ 500 ns at 1M rules" is unverifiable.

## Required for v2

1. **Resolve F-r1-1** structurally — Stage 3 per-/24 representation
   must NOT scale with rule count. Pick option 3 (sparse
   `Box<[u32]>` per /24) or argue why option 1/2 is better.
2. **Resolve F-r1-2** — add explicit ICMP carve-out + verify
   `any_port_rules` fall-through. Add a regression test.
3. **Resolve F-r1-3** — benchmark construction at 10K rules in the
   PR, demonstrate < 1 sec apply latency at that scale, defer
   1M-rule construction-cost to a follow-up issue.
4. **Resolve F-r1-4** — pick sort-at-construction OR galloping
   merge; spell out the first-match-wins preservation invariant
   as a property test.
5. **Acknowledge F-r1-5** in §4-Q4 — DAG carve-out is forward-
   looking; today's `PolicyRule` doesn't carry DSCP/TCP-flags/IHL.
6. **Acknowledge F-r1-6** in PR description — defer 1M-rule
   empirical numbers to #1612.

## Process notes

Round 1 verdict: **PLAN-NEEDS-MAJOR** on F-r1-1 + F-r1-2 + F-r1-4.
Other findings are MEDIUM and can be addressed in v2 narrative
without restructuring.

If Codex + AGY converge on F-r1-1 being a hard kill (not just a
fix in v2), and we cannot find a sparse representation that
bounds memory at 1M rules, **PLAN-KILL is the right outcome and
we report BLOCKED-pending-redesign back to the coordinator**.
