# Claude SMR plan review — round 6 (plan v6 → v7)

## Plan v6 verdict: PLAN-NEEDS-MINOR (convergent with Codex r6)

V6 cleanly closed F-r5-1 (v3 "any" → MatchAny path via the new
`parse_v3_literal_set` helper with explicit `any_v4` / `any_v6`
flags) and F-r5-2 (fallibility propagation through the full call
graph with preflight builds).

Codex r6 raised two MINOR refinements that I agree with:

### Codex r6 refinement 1: bucket by canonical bytes, not by hash

V6's wording said "bucket unique CONTENT by 64-bit hash" — this is
ambiguous if two distinct canonical byte streams happen to FNV-1a-64
to the same value. The probability is ~2^-32 at 1M books
(birthday) ≈ 1e-7 — astronomically unlikely. But the plan should be
correct by construction.

V7 buckets by canonical bytes; the 64-bit hash is metadata used as
the primary sort key, with canonical bytes as the deterministic
tie-break. This makes the ID assignment correct EVEN under a
64-bit collision.

### Codex r6 refinement 2: "any" in address-book values

`pkg/dataplane/userspace/manager.go:1327` treats "any" as a
supported literal. If an operator declares
`set security address-book global address foo any` (Junos
syntactically supports declaring an address as a value "any" via
some forms), the resolved address-book value is the string "any".

If this propagates into `AddressBookSnapshot.prefixes_v4`, the
Rust side would see `"any"` in the prefix list. The existing
`parse_address("any", ...)` returns early without pushing —
treating "any" as empty. Combined with `from_v3_literals(empty) =
MatchNone`, a book containing only "any" would silently match
nothing. **Fail closed** (not as severe as fail-open, but still a
semantic regression).

V7 normalizes "any" at the Go `buildAddressBookTable` stage:
replace with the explicit pair `{ "0.0.0.0/0", "::/0" }` before
canonicalization. This way the wire never carries an "any" string
inside a book; the Rust side only ever sees concrete CIDRs.

## V7 verdict: PLAN-READY (pending Codex r7 confirmation)

The plan now:

1. Closes all known fail-open paths (book-only, family-incomplete,
   any-in-literal).
2. Closes the v3 "any" → MatchNone regression.
3. Has deterministic ID assignment under all collision regimes.
4. Has correct "any" handling at every layer (rule literal, book
   content).
5. Propagates fallibility through the full call graph with
   preflight builds before any side-effect.
6. All five prior-round critical findings resolved (HA
   determinism, version baseline, content-vs-name dedup, u32
   widening, family/count hash framing).

The plan also:
- Specifies new constructor `from_v3_literals` distinct from
  `from_prefixes`.
- Uses `SmallVec<[u32; 8]>` for inline-cap-of-8 rule references.
- Defines deterministic content-bucket sort by `(hash64,
  canonical_bytes)`.
- Has comprehensive test plan covering the fail-open scenarios,
  the "any" regression, the preflight integrity errors, and the
  HA determinism across map orders.

Pending Codex r7 confirmation, I vote PLAN-READY on v7.

## What would force a kill on r7

- Any new fail-open discovery I missed.
- Any escape hatch in the v3-shaped predicate.
- Any place where `from_prefixes(empty)=MatchAny` leaks into a v3
  path.
- Any deserialization quirk that mixes legacy and v3 paths.

I don't expect any of these. The plan has been hardened by six
rounds of hostile review.
