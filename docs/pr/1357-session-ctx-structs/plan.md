# #1357 — collapse 9-10-param session/flowexport pub fns into context structs

**Status:** DRAFT v2 — addressing Codex round-1 PLAN-KILL findings + Gemini round-1 minor

## v1→v2 changelog

Codex round-1 verdict was PLAN-KILL; Gemini round-1 verdict was
PLAN-READY-with-minor (`#[inline]` + drop `FlowFinalize`).

Changes in v2:

1. **`SessionUpsert` no longer embeds `SessionInstall`.** Codex flagged
   the contradiction (v1 said `upsert_synced` takes `SessionUpsert`
   while pre-filling `origin: SyncImport` inside the body — both
   cannot be true). v2 drops `upsert_synced` from the refactor
   entirely: it stays a positional wrapper at 8 params and below
   threshold today (it does NOT take `&self` plus 7 — counting
   carefully: `key, decision, metadata, now_ns, protocol, tcp_flags,
   allow_replace_local` = 7 plus `&mut self` = 8). Since the issue
   text counts it at 9 with `&mut self`, but engineering-style
   says "9 params" includes `&self`, this is borderline. v2 keeps it
   as a positional 8-param wrapper; reviewer may demand inclusion in
   v3.
2. **`promote_synced_with_origin` consumes `SessionUpdate`, not
   `SessionInstall`.** Codex correctly noted that promotion takes
   `&SessionKey` (borrowed) and delegates to `update_session`. v1
   would have forced an owned `SessionKey` clone at the production
   call site `session_glue/mod.rs:1071`. v2 uses the borrowed
   `SessionUpdate<'a>` for `promote_synced_with_origin` (with
   `ha_activation: false` baked in by the wrapper body).
3. **`FlowFinalize` dropped.** Both reviewers say over-factored.
   `finalize_flow` stays positional. Issue #1357 ramps will need a
   separate PR if a production caller appears.
4. **Distinct context structs for install vs update.** v2 defines
   two structs (`SessionInstall`, `SessionUpdate<'a>`) — no embedding,
   no shared "context" trap. Each is the input contract for exactly
   one operation. `upsert_synced_with_origin` reuses `SessionInstall`
   plus its existing `allow_replace_local` bool — *not* via embedding,
   just a separate parameter that stays positional. Final API:

   ```rust
   pub(crate) fn install_with_protocol_with_origin(&mut self, req: SessionInstall) -> bool;
   pub(crate) fn upsert_synced_with_origin(&mut self, req: SessionInstall, allow_replace_local: bool) -> bool;
   pub(crate) fn update_session(&mut self, req: SessionUpdate<'_>) -> bool;
   pub(crate) fn promote_synced_with_origin(&mut self, req: SessionUpdate<'_>) -> bool;
   ```

   That is 4 fns refactored (not 5). `upsert_synced` (wrapper) stays
   positional. `finalize_flow` stays positional. Down from 6 fns in
   v1 to 4 fns in v2.
5. **`#[inline]` added.** Per Gemini's codegen note,
   `SessionInstall` is >64 bytes (SessionKey ~37B + SessionMetadata
   ~24B + scalars) and would otherwise be passed by hidden caller-
   stack-slot pointer. Add `#[inline]` to all 4 refactored fns to
   let LLVM SROA flatten the struct materialization at each call
   site. v2 plan-review must confirm `#[inline]` is sufficient (or
   upgrade to `#[inline(always)]` for the hot install path).
6. **Churn count corrected.** v1 said ~42 production + ~25 test.
   v2 verified: 12 production + 40 test call sites total across all
   four target fns. Mostly test-call-site churn. PLAN-KILL is still
   defensible on this basis alone; reviewers should weigh.
7. **Hot install path scope.** Codex specifically called out
   `install_with_protocol_with_origin` is per-packet on session open
   (`afxdp/forwarding/mod.rs:1087`). v2 commits to a release-build
   `cargo asm` / `objdump -d` check on that fn before/after as
   part of the implementation gate. If lowering regresses, the
   implementation rolls back the install fn refactor and keeps only
   `update_session` + `promote_synced_with_origin` (slow-path) in
   scope.

## Issue framing

`docs/engineering-style.md` flags `>8 params` as a refactor cue, and
`userspace-dp/src/session/mod.rs` has **five sibling pub(crate) fns**
that share an almost-identical 7-9 scalar cluster
(`SessionKey + SessionDecision + SessionMetadata + [SessionOrigin] +
now_ns + protocol + tcp_flags + [allow_replace_local]`).
`userspace-dp/src/flowexport.rs::finalize_flow` is a separate but
isomorphic cluster (5-tuple + 3 counter fields).

The smell isn't just length — the cluster IS the operation's input
contract. Five fns redeclaring the same 7-field tuple positionally is
how field drift happens (issue #1357 cites engineering-style #3:
"two code paths computing the same denominator WILL drift").

This refactor (v2 scope, per Codex round-1):

1. introduces `session/ctx.rs` housing **two** context structs:
   `SessionInstall` (owned key) and `SessionUpdate<'a>` (borrowed
   key) — distinct, non-embedding.
2. rewrites **four** session pub(crate) fns to take those structs:
   `install_with_protocol_with_origin` (SessionInstall),
   `upsert_synced_with_origin` (SessionInstall + allow_replace_local),
   `update_session` (SessionUpdate), and
   `promote_synced_with_origin` (SessionUpdate). `upsert_synced`
   (wrapper) and `finalize_flow` stay positional.
3. mechanically migrates 12 production + 40 test call sites
   (verified by full-repo grep across all four target fns).

Behaviour is unchanged. No new allocations on the hot path — the
context structs are plain field aggregates of the same owned values
the callers already build.

If reviewers conclude the readability/anti-drift gain is too small to
justify the churn at every call site, **PLAN-KILL is an acceptable
verdict**.

## Honest scope/value framing

- **What's the absolute win?** Zero runtime cycles. This is purely
  structural — the function bodies and call sequences inside them are
  byte-identical to today. The only assembly delta is that an
  argument that today comes in via an extra register may instead come
  from a stack slot of the by-move struct (or vice versa); Rust
  optimises monomorphised pass-by-value of small structs into the
  same register usage in release builds for moves at the call
  boundary, so the codegen should be neutral. Plan-review must
  validate this.
- **What's the readability win?** Five sibling fns with 7-9
  positional args where the args are heterogeneous (a `SessionKey`,
  an `SessionDecision`, a `bool` allow_replace_local, three `u8`/`u64`
  scalars) — the call sites today read like
  `f(k, d, m, o, n, p, t, false)` with no in-source hint which `bool`
  flips behaviour. With named fields the call site becomes:

  ```rust
  sessions.upsert_synced_with_origin(SessionUpsert {
      install: SessionInstall { key, decision, metadata, origin,
                                now_ns, protocol, tcp_flags },
      allow_replace_local: false,
  })
  ```

- **Anti-drift gain.** When the next field (e.g. `cos_queue_id`,
  `fabric_redirect_hint`) needs to flow into install/upsert/update,
  it becomes a struct-field addition and the compiler errors at every
  construction site instead of allowing a `0` to be passed positionally.

## What's already shipped / partially batched

- `SessionDecision`, `SessionMetadata`, `SessionOrigin` are already
  aggregate types (see `session/entry.rs`). Only the *outer*
  parameter list is positional today.
- `session/tests.rs` already lives as a sibling (#959-era split). No
  test moves; only construction calls change.
- `pub(crate)` (not `pub`) — `SessionTable` is crate-internal. There
  are **zero Go callers**, **zero external Rust callers** (verified
  by full-repo grep across `*.go` and `*.rs`). API change blast
  radius is fully contained in `userspace-dp/`.

## Concrete design

### New module `userspace-dp/src/session/ctx.rs`

```rust
//! Context structs used by SessionTable::install/upsert/update
//! family of fns. Encapsulates the previously-positional 7-arg
//! cluster so callers don't drift fields. See #1357.

use super::entry::{SessionDecision, SessionMetadata, SessionOrigin};
use super::key::SessionKey;

/// Owned identity + payload + timing for a fresh session insert or
/// a peer-synced upsert (where the caller has just constructed the
/// key). Used by install_with_protocol_with_origin and
/// upsert_synced_with_origin (alongside a positional
/// `allow_replace_local: bool`).
#[derive(Debug, Clone)]
pub(crate) struct SessionInstall {
    pub(crate) key: SessionKey,
    pub(crate) decision: SessionDecision,
    pub(crate) metadata: SessionMetadata,
    pub(crate) origin: SessionOrigin,
    pub(crate) now_ns: u64,
    pub(crate) protocol: u8,
    pub(crate) tcp_flags: u8,
}

/// In-place update or promotion of an existing session. Carries a
/// borrowed `&'a SessionKey` because the caller already owns the
/// key on the surrounding update/promote path; cloning it into a
/// `SessionInstall` would force an unnecessary owned copy at
/// production call sites (session_glue/mod.rs:1071).
#[derive(Debug, Clone)]
pub(crate) struct SessionUpdate<'a> {
    pub(crate) key: &'a SessionKey,
    pub(crate) decision: SessionDecision,
    pub(crate) metadata: SessionMetadata,
    pub(crate) origin: SessionOrigin,
    pub(crate) now_ns: u64,
    pub(crate) protocol: u8,
    pub(crate) tcp_flags: u8,
    pub(crate) ha_activation: bool,
}
```

### Signatures BEFORE → AFTER

| Fn | BEFORE (params incl `&mut self`) | AFTER |
|---|---|---|
| `install_with_protocol_with_origin` | 8 (`self, key, decision, metadata, origin, now_ns, protocol, tcp_flags`) | 2 (`self, req: SessionInstall`) — `#[inline]` |
| `upsert_synced_with_origin` | 9 (`self, key, decision, metadata, origin, now_ns, protocol, tcp_flags, allow_replace_local`) | 3 (`self, req: SessionInstall, allow_replace_local: bool`) — `#[inline]` |
| `update_session` | 9 (`self, key, decision, metadata, origin, now_ns, protocol, tcp_flags, ha_activation`) | 2 (`self, req: SessionUpdate<'_>`) — `#[inline]` |
| `promote_synced_with_origin` | 8 (`self, key, decision, metadata, origin, now_ns, protocol, tcp_flags`) — `key: &SessionKey` | 2 (`self, req: SessionUpdate<'_>`) — `#[inline]`; body forces `ha_activation: false` and calls `update_session` |
| `upsert_synced` (wrapper) | 8 (`self, key, decision, metadata, now_ns, protocol, tcp_flags, allow_replace_local`) | **NOT TOUCHED** — wraps `upsert_synced_with_origin` by constructing the `SessionInstall` itself with `origin: SyncImport`. Stays a positional 8-param thin wrapper. |

**`flowexport.rs::finalize_flow` is dropped from this refactor.**
Both reviewers (Codex round-1 + Gemini round-1) flagged it as
over-factored — the fn has 1 test-only caller and zero production
callers. A separate PR can context-struct it when a production
caller appears.

### `install_with_protocol` (6-param non-origin wrapper at line 627)

It already delegates to `install_with_protocol_with_origin`. After
the refactor it stays a 6-param wrapper (still < 8 threshold) and
constructs the `SessionInstall` itself with
`origin: SessionOrigin::ForwardFlow`. No signature change for it.

### `refresh_local` and `refresh_for_ha_activation` (5-param wrappers)

Both already delegate to `update_session` (lines 857 and 883). They
stay 6-param external wrappers and construct `SessionUpdate { ... }`
internally. No signature change for either.

### `refresh_for_ha_transition` (5-param)

Already < 8 params and does NOT route through `update_session` — it
inlines its own logic. **Not touched.**

### Call-site migration

42 production + ~25 test call sites. Every call site that today reads:

```rust
sessions.upsert_synced_with_origin(
    entry.key, entry.decision, entry.metadata, entry.origin,
    now_ns, entry.protocol, entry.tcp_flags, allow_replace_local,
)
```

becomes:

```rust
sessions.upsert_synced_with_origin(SessionUpsert {
    install: SessionInstall {
        key: entry.key,
        decision: entry.decision,
        metadata: entry.metadata,
        origin: entry.origin,
        now_ns,
        protocol: entry.protocol,
        tcp_flags: entry.tcp_flags,
    },
    allow_replace_local,
})
```

Mechanical 1:1 substitution. Rustc errors guide migration.

## Public API preservation

| API guarantee | Status |
|---|---|
| `pub(crate)` not `pub` | confirmed — `SessionTable` is crate-internal; verified by grep across `*.rs` and `*.go`. No Go FFI binding. |
| Method names unchanged | yes — `install_with_protocol_with_origin`, `upsert_synced`, `upsert_synced_with_origin`, `update_session`, `promote_synced_with_origin`, `finalize_flow` all keep their names. |
| Return types unchanged | yes — `bool` (5 session fns) / `()` (finalize_flow). |
| Behaviour unchanged | yes — bodies move parameters into local bindings from the struct, then continue with the same code. |
| Bench compatibility | `userspace-dp/benches/session_table.rs` has 2 references — both in comments. No bench call sites need rewrite. |

## Hidden invariants the change must preserve

1. **Side-effect ordering inside each fn body.** The body sequences
   (`remove_entry → next_epoch → entries.insert → key_to_handle.insert
   → index_forward_nat_key → push_to_wheel → push_delta`) are unchanged.
   The refactor only changes the prelude that destructures the struct
   into local bindings.
2. **Allocation profile.** `SessionInstall` / `SessionUpsert` /
   `SessionUpdate` are stack-only field aggregates over already-owned
   values. **No `Box`, no `Arc`, no `Vec`, no allocator hit.** The
   move semantics are identical to passing each field individually.
3. **HA sync portability.** The wire protocol consumers of these fns
   (the session-glue worker command path at
   `afxdp/session_glue/mod.rs:698`) build a `SessionUpsert` from
   `SyncedSessionEntry` fields the same way they build the positional
   call today. No wire-format change.
4. **Borrow checker.** `SessionUpdate` carries `&'a SessionKey` — same
   lifetime shape as today's `&SessionKey` parameter. `SessionInstall`
   / `SessionUpsert` take `SessionKey` by move — same as today's
   value-parameter `key: SessionKey`. No new lifetime annotations
   propagate beyond the struct's `'a`.
5. **`SessionMetadata::clone()` count.** The struct stores `metadata`
   by value; each fn body still `.clone()`s exactly where it does
   today (e.g. line 679 `metadata: metadata.clone()` becomes
   `metadata: req.install.metadata.clone()` then later the move into
   the delta).
6. **Wheel push idempotence (#965).** All `push_to_wheel(&key, now_ns)`
   calls preserve their argument site (the local `key` binding after
   destructure).

## Risk assessment

| Class | Level | Notes |
|---|---|---|
| **Behavioral regression risk** | LOW | Bodies are unchanged; parameter binding only. |
| **Lifetime / borrow-checker risk** | LOW | `SessionUpdate<'a>` mirrors today's `&SessionKey`; no new lifetimes propagate to callers because rustc infers them from the struct literal. |
| **Performance regression risk** | LOW-NEUTRAL | Pass-by-move struct ≈ pass-by-value tuple. Release-build codegen for the 7-field struct moves should monomorphise to the same register usage as the positional args. **Plan-review action:** verify this with `cargo build --release` and a casual `objdump` sanity check on `install_with_protocol_with_origin` before/after. |
| **Architectural mismatch (#961 / #946 Ph2)** | LOW | Not a pipeline change. Not a data-structure replacement. Pure call-site shape change with the body untouched. Closest historical analogue is #1166 (TSO extract) and #1187 (BatchCounters disposition extension) — both shipped clean. |
| **Wire-protocol drift (HA sync)** | NONE | Wire format is `SyncedSessionEntry`, unchanged. Only the consumer-side call shape changes. |

## Test plan

1. `TMPDIR=/dev/shm CARGO_TARGET_DIR=/dev/shm/cargo cargo build` clean.
2. `cargo test --release` — full userspace-dp suite passes.
3. `cargo test --release session::tests` — 5/5 named flake check on
   the most affected session-table test module.
4. `GOCACHE=/dev/shm/cache GOTMPDIR=/dev/shm go test ./...` — Go
   suite green.
5. **No smoke this PR** per Wave-2 rules (4-of-4 attestation only;
   batched smoke at end of refactor chain).

## Out of scope (explicitly)

- The semantics of any session fn (collision rules, origin handling,
  GC integration) — all preserved.
- `SessionMetadata` / `SessionDecision` / `SessionOrigin` internals —
  already aggregates.
- `refresh_local`, `refresh_for_ha_activation`,
  `refresh_for_ha_transition` — already ≤ 6 params; only their
  internal `update_session` call mutates to a `SessionUpdate { .. }`
  literal.
- Bench file (`session_table.rs`) — only contains comment references.
- Splitting `session/mod.rs` further — that's #1327 / #946 Phase
  1.5's territory.

## Open questions for adversarial review

1. **Is the readability/anti-drift gain worth the churn at ~67 call
   sites?** PLAN-KILL is appropriate if reviewers conclude this is a
   net loss (e.g. inlining 5 fns is harder to scan than positional
   args).
2. **Should `SessionInstall` embed `SessionUpdate` instead of
   `SessionUpsert` embedding `SessionInstall`?** Asymmetric:
   `update_session` takes `&SessionKey` (borrow), install/upsert take
   `SessionKey` (move). Plan v1 keeps them as siblings (`'a` only
   on update); reviewer may prefer a different shape (e.g. always-by-
   value `SessionKey` with caller doing the `.clone()`).
3. **Does the move-by-value of `SessionInstall` (which contains a
   non-`Copy` `SessionKey` + non-`Copy` `SessionMetadata`) get
   monomorphised to the same register-pressure shape as the
   positional args?** This is the LOW-NEUTRAL perf risk above; plan
   review should confirm release-build codegen does not regress
   `install_with_protocol_with_origin` on the hot install path
   (called from `afxdp/forwarding/mod.rs:1087` per-packet on session
   open).
4. **Is `FlowFinalize` worth defining in `flowexport.rs`?** It's used
   from one call site (`flowexport_tests.rs:72`). Reviewer may
   prefer to keep `finalize_flow` positional since the 5-tuple is
   already a partial flow-key and might want its own
   `FlowKey + FlowCounters` split instead. The plan keeps it simple
   (one flat struct) on the principle that the issue text proposes
   exactly this shape.
5. **Is there a `SessionInstall` field-ordering convention that
   matches the in-source declaration order of `SessionEntry` (or
   `SessionDelta`)?** Plan v1 uses `key, decision, metadata, origin,
   now_ns, protocol, tcp_flags` — same order as today's positional
   args. Reviewer may prefer alignment with `SessionEntry` (which has
   `decision, metadata, origin, install_epoch, last_seen_ns, …`).
6. **`promote_synced_with_origin` and `install_with_protocol_with_origin`
   both take `SessionInstall`.** Risk: a caller swaps the two function
   names and the compiler can't catch it (same input type). Reviewer
   should weigh whether they should take *distinct* structs even
   though their fields are identical. Plan v1 reuses `SessionInstall`
   for both; reviewer may demand newtype wrappers.
