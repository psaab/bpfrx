# Claude SMR plan review — round 1

**Issue**: #1606 wire-protocol restructure for address-book deduplication
**Plan**: `docs/pr/1606-wire-protocol-address-book/plan.md`
**Reviewer**: Claude SMR (domain: cross-language wire protocols, Rust
Arc/ArcSwap memory ownership, HA snapshot sync, LPM data structures)

## Verdict: PLAN-NEEDS-MAJOR

The plan is structurally sound on the wire-protocol axis but has three
NEEDS-MAJOR issues that must be addressed before PLAN-READY. I'm not
killing it — the architecture is right and the rescoping of §7 is
honest. But the determinism story, the double-counting risk, and the
acceptance-gate rewording all need tightening.

## Findings

### F1 [MAJOR] §6 collision recovery is non-deterministic across HA peers

The plan acknowledges this risk obliquely but does not close it. Linear
probe ID assignment requires a **stable iteration order** over the set
of books being assigned. The plan says "ID assignment is content-hashed"
in `buildAddressBookTable(cfg) []AddressBookSnapshot` (§3.2) but in Go
`map[string]*Address` iteration is randomized per-process by design.

> "if the low-32 collides with an already-assigned ID for a DIFFERENT
> (name, CIDR-set) tuple, fold in the upper 32 bits of the hash by
> XORing in `(hash >> 32) * (probe + 1)`, retry."

This recovery depends on which book got assigned FIRST. If peer A
processes book "alpha" before "beta" and peer B processes "beta" first,
and both hash to the same low-32, they end up with DIFFERENT IDs for
the same content.

**Required fix**: walk
`cfg.Security.AddressBook.Addresses` + `AddressSets` in a deterministic
order — e.g. sort book names lexicographically before iteration. Add
this requirement to §6 explicitly and add a unit test
`TestAddressBookIDDeterministicAcrossMapOrder` that constructs the
same config with the map keys inserted in different orders and asserts
identical wire IDs. Without this, HA peers can disagree on book IDs
under collision, and the divergence is silent (matching falls back to
literal CIDRs which DO match identically, so the bug is "Arc sharing
gets defeated under collision" not "forwarding diverges" — still
worth fixing because it undermines the memory dedup story).

### F2 [MAJOR] §3.4 double-counting risk in shim phase is hand-waved

The plan §3.4 claims:

> "Always populate `source_literal_v4/v6` / `destination_literal_v4/v6`
> from `source_addresses` / `destination_addresses` regardless. ... A
> v2 snapshot from a new Go binary with books AND literal CIDRs gets
> both checked (union); since the new Go binary emits literals ONLY
> for rule entries that were not address-book names (free-form CIDR
> strings in the rule), this is also a union-equivalent — not
> double-counting."

This is true in matching semantics (union is union; matching the same
prefix twice still says "match"). It is **NOT** true in memory: every
named book referenced by a rule materializes BOTH as a shared
`Arc<BookEntry>` AND as a per-rule literal prefix set built from the
same CIDRs. The memory dedup goal of #1606 is silently defeated until
the shim is removed in the follow-up PR.

The plan must do ONE of:

- **Option A**: change the new-Go emission so that `source_addresses`
  carries ONLY free-form CIDR literals (i.e., addresses that were
  inlined in the rule's `match { source-address X.X.X.X/Y }` rather
  than referenced as a named book). Then the shim path still works
  (old-Rust matches via literal CIDRs OR named-book-name-expanded
  literals it does already), and new-Rust gets the dedup win.

- **Option B**: explicitly document that the FIRST release with this
  PR keeps full per-rule duplication for backward compatibility,
  and the memory win lands only when the follow-up shim-removal PR
  ships. The acceptance gate in this PR is then "the wire surface is
  correct" rather than "the memory is reduced".

Either is acceptable but the plan must pick one. As written §3.4
implies Option A but §4 row 4 "literal CIDRs still emitted by new Go"
implies Option B. The contradiction is the bug — resolve it.

**My recommendation**: Option A. Make new-Go's expansion path
distinguish "I am the result of expanding a named address book" from
"I am a free-form CIDR literal", emit only the latter into
`source_addresses`. The book IDs carry the former. Old-Rust reading
a v2 snapshot then matches via literal-CIDRs (correct, equivalent
semantics because old-Rust didn't know about books anyway, but
matching against the union of (literal-CIDRs + named-book-expansions)
was what old-Rust used to do — and old-Go used to put the named-book
expansions into `source_addresses` for old-Rust to see). Wait — that
means **old-Rust receiving a v2 snapshot loses the named-book matches**
if Option A is taken.

The cleanest resolution: Option B for this PR (full belt-and-braces
emission, no immediate memory win), bake the wire format for one
release, then ship the shim-removal PR that switches to Option A.
The plan should be explicit that #1606 is **wire-protocol-only**;
memory deduplication lands in the follow-up. This matches the plan's
§2 "shim removal is out of scope" but contradicts §1's "memory
acceptance: ≤ 200 MB" framing.

### F3 [MAJOR] §7 acceptance gate rewording — be more direct

The plan §7 walks the math and concludes the issue's stated 200 MB
gate is structurally unachievable with the existing
`PrefixSetV4::Trie`. I agree with the math. But the plan says
"Pre-flight this rescoping with the reviewers in plan v1" — which is
fine, but the new gate should be **stated definitively** in §7, not
left as "tentative". Specifically:

The plan must commit to:

- **Wire-correctness gate**: new-Go emits books, new-Rust deserializes
  them, every existing policy test passes.
- **Arc-sharing gate**: a test asserts that two rules citing the same
  book ID share the same `Arc<BookEntry>` (via `Arc::ptr_eq` or
  `Arc::strong_count`).
- **Memory gate (post-shim-removal)**: NOT in this PR. Move it to the
  follow-up shim-removal issue.

Failure to commit to a concrete gate makes this PR untestable. The
issue's 200 MB is wrong; the plan correctly identifies this; but the
plan must REPLACE it with something achievable in #1606 instead of
saying "let's discuss with reviewers".

### F4 [MINOR] PolicyRule field rename blast radius

The plan §3.3 proposes renaming `source_v4` → `source_literal_v4`. I
grep'd the project: this field is used in `policy.rs`,
`policy_tests.rs`, and the `forwarding_build.rs:467` debug-log
readout for `prefix_count()`. That's a small blast radius. The
rename is fine. Recommend the plan note the exact call sites for
reviewer convenience.

### F5 [MINOR] Hot-path cost for Vec<Arc<BookEntry>> walk

`try_match_rule` will iterate `rule.source_books.iter()` then deref
`Arc::deref()` to read `book.v4.contains(ip)`. For a rule with 5
books, that's 5 dependent loads on heap-allocated Arc bodies. With
the precomputed `source_v4_match_any: bool` flag, the common-case
"any" rule short-circuits cleanly. For rules with actual book
content, the walk is 5 × (load Arc pointer, load PrefixSetV4 enum
discriminant, dispatch). On modern x86 that's ~10-20ns/rule for the
walk plus the trie lookup itself. Acceptable but worth a microbench
in the implementation PR.

Note that this is NOT worse than today's path — today's
`source_v4.contains(ip)` already does enum dispatch + trie walk.
The Arc indirection adds ~1 cache miss per book. At 2-3 books per
rule (typical), this is ≤ 5ns overhead. Acceptable.

### F6 [MINOR] Per-rule Vec<Arc<BookEntry>> allocation churn

At 100K rules × avg 3 books per rule, snapshot apply allocates ~300K
`Arc::clone()` calls. That's pure refcount increments (~30ns each on
contended cache lines, but the Arcs are fresh per snapshot so no
contention) → ~9ms one-shot. Acceptable for snapshot apply (one-shot,
amortized over the rule build).

### F7 [MINOR] Snapshot-apply work spike

The plan defers per-book Arc reuse across snapshots to #1607. Without
it, every snapshot apply rebuilds every book's `PrefixSetV4::Trie`.
At 10K books × 100 CIDRs each, that's ~1M insertions, ~30ns each =
~30ms. Acceptable as a one-shot, but at 10K × 1K (worst case) it's
300ms per snapshot. Note this in the plan as a known limit lifted by
#1607.

### F8 [MINOR] Version field bump

The plan §3.1 says "JSON `version` is bumped from 1 to 2". I verified
`ConfigSnapshot::version: i32` exists in `protocol/snapshot.rs:163`.
But what's the current value? `grep -n "version: 1\|Version: 1" pkg/`
should be sanity-checked in the implementation. The plan should
verify the current value and document the bump explicitly. Minor —
just a docs cleanup.

## Specific corrections to the plan text

1. §6 "ID derivation": add "After hashing, books are processed in
   lexicographic order of `name` (with v4-CIDRs sorted, v6-CIDRs
   sorted, then name itself) to ensure deterministic ID assignment
   across peers under collision."

2. §3.4: pick Option A or Option B explicitly. My recommendation:
   Option B with an explicit note that memory dedup is a follow-up.

3. §7: replace "tentative" with a definitive gate that's measurable
   in THIS PR (wire correctness + Arc-sharing test). Move memory
   gate to the shim-removal follow-up.

4. §11: add an entry for "stable book-table iteration in Go" with
   a sort-by-name invariant.

## What I'd accept

If the plan v2 incorporates F1, F2, F3 cleanly:
- F1: deterministic iteration via sorted book names.
- F2: pick Option B (shim phase keeps duplication; memory win in
  followup). State it explicitly.
- F3: drop the 200 MB gate from this PR; replace with
  wire-correctness + Arc-sharing.

…then I'll vote PLAN-READY in round 2. Codex and AGY may find
additional items.

## What would force me to KILL

- Insisting on the issue's 200 MB gate without restructuring the LPM
  (would require DIR-24-8 work that's out of scope here).
- Hand-waving the HA determinism story.
- Keeping the wire schema unchanged but pretending the dedup
  happened.

None of those are currently in the plan — F1/F2/F3 are
"add precision" items, not "wrong direction" items. The plan's
architecture is correct.
