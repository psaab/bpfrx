# Claude SMR plan review — round 2

**Verdict: PLAN-NEEDS-MAJOR**

V2 addressed five of six v1 findings but introduced new structural
issues, primarily because the plan author (me) failed to read
`pkg/dataplane/userspace/protocol.go:11` before writing v1 or v2.

## Confirmed against repo state

```
$ grep -n "ProtocolVersion" pkg/dataplane/userspace/protocol.go
11:	ProtocolVersion                  = 3
```

```
$ grep -n "CONFIG_SNAPSHOT_PROTOCOL_VERSION" userspace-dp/src/server/handlers/snapshot.rs
25:    if snapshot.version != CONFIG_SNAPSHOT_PROTOCOL_VERSION {
```

The Rust side **strictly rejects** any mismatched version. The "old Go
v1 → new Rust v2 falls through to literal path" claim in v2's §3.4
table is **false**: the request fails closed at line 25 of
`snapshot.rs` before the field-by-field deserialization that would
let serde defaults kick in.

This invalidates v2's rolling-upgrade compatibility story.

## New findings

### N1 [MAJOR] Wrong protocol version baseline

V2 says "bump JSON version from 1 to 2" everywhere. The repo is at
**version 3**. The change is "additive fields on version 3" — no
version bump at all.

**Fix**: keep `ProtocolVersion = 3`. The new fields land as additive
JSON members (already covered by serde `default` / `omitempty`).
Update v3 of the plan to drop every "bump 1→2" reference.

### N2 [MAJOR] Inverted parse-condition in §7

V2 §3.3 / §3.4 says "new Rust prefers the book path when
`address_books` is non-empty". But §7 plan §3.3 pseudo-code says:

> "if v2 path (any of `source_book_ids` / `source_literals` present
> OR `address_books.is_empty()`)"

This is inverted. With `address_books.is_empty()`, there are NO
books to dereference, so the rule's `source_book_idxs` must also be
empty, which means the dense-index path silently produces zero
match candidates. Combined with `source_literal_v4` defaulting to
`MatchAny` (per `prefix_set.rs:58`), an old-Go v1 snapshot fed to
new-Rust would match-any everything — **fail open**.

**Fix**: define the parse-condition cleanly:

- Construct `source_literal_v4` from `source_literals` if the new
  field is present, ELSE from `source_addresses` (legacy field).
- Construct `source_book_idxs` from `source_book_ids` (always; empty
  if absent).
- The "v1 vs v2" distinction is purely about WHICH field feeds the
  literal-CIDR side. Books are always optional on the wire.

This is cleaner than the version-or-emptiness guard.

### N3 [MAJOR] Content-dedup vs name-dedup invariant clash

V2 §5 says "two address books with the same set ... hash to the
same value" — implying content-dedup (same content → same ID).

V2 §6 collision recovery talks about `(name, canonical-content)`
tuples — implying name is part of identity.

Pick one. Recommended: **content-only ID** (the hash is purely a
function of the canonicalized CIDR set). Two books "alpha" and
"beta" with identical CIDRs share the same ID. The
`AddressBookSnapshot.name` becomes diagnostic-only (already stated in
§3.1). The collision-recovery clause then talks about distinct
canonical-content tuples (not name+content tuples).

If we pick content-only, the `address_books` array must dedup
entries by content — emit ONE row per unique content hash, regardless
of how many name aliases reference it. The `book_id_to_idx` map then
gives every alias the same dense index.

### N4 [MAJOR] u16 cap with literal-fallback re-introduces the bug

V2 §3.3 says "Cap at 65,535 books per snapshot. ... overflow falls
through to the literal path (with a warning)."

At the 1M-target scale (Codex's hostile reading) this brings BACK
the per-rule duplication this PR exists to remove. Even at
intermediate scales (50K-200K books), the fallback would be silent
memory blow-up.

**Fix**: either (a) widen the index type to `u32` now (modest cost;
`SmallVec<[u32; 4]>` is 16 bytes inline same as `u16; 4`), or (b)
hard-fail the snapshot apply if the book count exceeds the
implementation cap.

Recommended: **(a) widen to u32 now**. Future-proof for 1M books +
no fail-open risk.

### N5 [MAJOR] Collision math: high-bit reservation costs a bit

V2 §6 sets `id = low_32(hash) | 0x8000_0000`. That reduces the ID
space to 31 bits (low half reserved). At 1M books, P(collision)
goes from 11.3% (32-bit) to ~22.6% (31-bit). Plan's "0.00001% at
10K books" cite was computed against 32 bits.

**Fix**: drop the high-bit reservation. ID = 0 is the only
reservation needed (and even that is just a Rust-side "unused"
sentinel; the Go side can guarantee 0 is never minted by post-
hashing).

### N6 [MINOR] SmallVec inline cap of 4 unproven

Codex correctly notes "rule cites 2-5 books on average" implies the
p95 likely exceeds 4. Without real-world data I'd bump the inline
cap to 8 (still on-stack; 16 bytes inline at u16, 32 inline at
u32). Not a kill blocker but worth doing.

### N7 [MINOR] Per-rule book ID handling needs to be explicit

V2 doesn't say what happens if:
- A rule's `source_book_ids` contains a duplicate ID.
- A rule's `source_book_ids` references an unknown ID (not in the
  `address_books` array).
- `address_books` contains duplicate IDs.

Default policies:
- Per-rule duplicate IDs: sort + dedup at parse time. Idempotent.
- Unknown IDs: log + skip + continue. Don't fail-closed (could
  blackhole traffic). Don't fail-open (could permit unintended).
  Treat as "this book contributed no addresses" — equivalent to
  the book being empty.
- Duplicate `address_books.id`: hard-fail the snapshot. Indicates
  a Go-side bug, not a degraded config.

V3 should specify these.

## What v3 needs

1. Drop all "version 1 → 2" wording. Replace with "additive fields
   on version 3, serde-default handles missing fields".
2. Rewrite §3.4 (and the v1/v2 compat table) to be honest about the
   actual Rust-side gate: it's field presence, not version.
3. Pick content-only ID semantics. Make the dedup test consistent.
4. Widen book index to u32.
5. Drop the 0x8000_0000 reservation.
6. Specify duplicate / unknown ID handling.
7. Bump SmallVec inline cap to 8.

If v3 cleanly addresses N1-N5 (the MAJOR items), and Codex round 3
agrees, I'll vote PLAN-READY.

## What I'd kill on

- Insisting on the version bump.
- Hand-waving the parse-condition.
- Keeping the u16 cap with literal fallback.

None of these are currently in v2 by intent — they're either
unintentional (N1, N2) or under-specified (N3, N4). Plan v3 should
resolve all five MAJOR items in one pass.
