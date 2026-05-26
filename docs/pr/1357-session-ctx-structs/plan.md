# #1357 — collapse 9-param session pub fns into context structs

**Status:** DRAFT v3 — addressing Codex round-2 PLAN-NEEDS-MAJOR + Gemini round-2 PLAN-NEEDS-MINOR

## Review history

| Round | Codex | Gemini |
|---|---|---|
| 1 | PLAN-KILL (5 findings: codegen, SessionInstall reuse, upsert_synced contradiction, #961-style, churn count) | PLAN-READY-with-minor (#[inline] + drop FlowFinalize) |
| 2 | PLAN-NEEDS-MAJOR (1. ha_activation field-in-struct contradiction, 2. v1 doc-rot in v2 plan, 3. churn count still off) | PLAN-NEEDS-MINOR (single finding: ha_activation field-in-struct contradiction — independently identified by both reviewers) |

## v2→v3 changelog

Both reviewers independently converged on the same blocker:

**`ha_activation` cannot live inside `SessionUpdate<'a>` if
`promote_synced_with_origin` then forces it to `false` inside its
body.** Either the caller is forced to populate a meaningless field
that the callee will overwrite, or the wrapper is structurally
useless. Same shape Codex round-1 flagged for `upsert_synced` and
`origin`: a flag on a context struct cannot also be "pre-filled by
the body" — exactly one of those is true.

Changes in v3:

1. **Evict `ha_activation` from `SessionUpdate<'a>`.** Mirroring v2's
   `allow_replace_local` treatment, `ha_activation` becomes a
   positional bool on `update_session`. `SessionUpdate<'a>` carries
   only the 7-field cluster shared by update and promote.
2. **Final API (v3):**

   ```rust
   pub(crate) fn install_with_protocol_with_origin(&mut self, req: SessionInstall) -> bool;
   pub(crate) fn upsert_synced_with_origin(&mut self, req: SessionInstall, allow_replace_local: bool) -> bool;
   pub(crate) fn update_session(&mut self, req: SessionUpdate<'_>, ha_activation: bool) -> bool;
   pub(crate) fn promote_synced_with_origin(&mut self, req: SessionUpdate<'_>) -> bool;
       // body: self.update_session(req, false)
   ```

   `promote_synced_with_origin` regains its semantic purpose: hiding
   the `ha_activation` flag from its caller.

3. **Doc-rot cleanup.** Codex round-2 finding #2 — the v2 plan
   still showed stale `SessionUpsert { install: ... }` migration
   examples, stale `SessionUpsert` invariants, stale `FlowFinalize`
   open questions, and stale churn count claims. v3 rewrites the
   Concrete-design / Migration / Invariants / Open-questions
   sections from scratch against the final v3 API. The lingering
   v1 references are removed entirely.
4. **Churn count cross-checked.** Codex round-2 said the v2 number
   (12 prod + 40 test) was off because the 40 included
   `upsert_synced` (out of scope) test calls. v3 recounts by fn:

   | Fn | Production callers | Test callers |
   |---|---|---|
   | `install_with_protocol_with_origin` | 7 (`shared_ops.rs`, `poll_descriptor/mod.rs ×4`, `session_glue/mod.rs ×2`, `forwarding/mod.rs`) | ~30 (`session/tests.rs`, `session_glue/tests.rs`, `afxdp/tests.rs`) |
   | `upsert_synced_with_origin` | 2 (`session_glue/mod.rs ×2` at lines 698, 1022) | 0 direct (only via `upsert_synced` wrapper which is NOT touched) |
   | `update_session` | 0 direct (only via wrappers `refresh_local`, `refresh_for_ha_activation`, `promote_synced_with_origin`) | 0 direct |
   | `promote_synced_with_origin` | 1 (`session_glue/mod.rs:1071`) | 4 (`session/tests.rs`) |
   | **TOTAL (refactored fns only)** | **10** | **~34** |

   `upsert_synced` (positional wrapper, NOT touched) and its 4 test
   callers + 0 prod callers stay positional. `refresh_local` /
   `refresh_for_ha_activation` change their *internal*
   `update_session(...)` call site to `SessionUpdate { .. }` — that
   is 2 more in-source edits but they are inside `session/mod.rs`
   itself so they don't show in the call-site churn.

   **Effective churn: 10 prod + ~34 test = ~44 call sites
   rewritten.** v2's "12 + 40" was indeed slightly off; the
   accurate split is 10 + 34. Either way the win is anti-drift,
   not call-site simplification — every call site grows roughly
   from 1 line to 8-10 lines of struct-literal.

5. **`#[inline]` discussion sharpened.** Gemini round-2 correctly
   noted that the baseline is *already* passing `key`,
   `decision`, `metadata` by hidden pointer (System V AMD64 ABI
   rules for >16B structs). Grouping them into one `SessionInstall`
   coalesces three caller-side stack materializations into one.
   `#[inline]` is sufficient; `#[inline(always)]` is overkill and
   risks icache bloat for ~110-line fns. v3 commits to plain
   `#[inline]` on all four refactored fns. Implementation gate
   still includes a `cargo asm` check on the hot install path.

6. **`upsert_synced_with_origin` positional-bool acceptance.**
   Codex round-2 flagged that the v2 plan was still selling
   "named-boolean readability" while keeping `allow_replace_local`
   positional. v3 explicitly accepts the positional bool as a
   deliberate pragmatic compromise: separating operational control
   flags (`bool`) from the core data payload (`SessionInstall`) is
   standard practice. We do NOT claim readability gain for that bool;
   the readability/anti-drift gain applies only to the 7-field core
   cluster.

## Issue framing

`docs/engineering-style.md` flags `>8 params` as a refactor cue.
`userspace-dp/src/session/mod.rs` has four sibling pub(crate) fns
that share an almost-identical 7-field scalar cluster
(`SessionKey + SessionDecision + SessionMetadata + SessionOrigin +
now_ns + protocol + tcp_flags`), each plus 0-1 control flags. Issue
#1357 cites engineering-style #3: "two code paths computing the
same denominator WILL drift."

This refactor (v3 scope):

1. introduces `session/ctx.rs` housing **two** context structs
   (`SessionInstall` owned-key, `SessionUpdate<'a>` borrowed-key),
2. rewrites four pub(crate) fns to take those structs (plus their
   existing positional control flag where applicable),
3. mechanically migrates 10 production + ~34 test call sites.

Behaviour is unchanged. No new allocations on the hot path — the
context structs are plain field aggregates over the same owned values
the callers already build.

If reviewers conclude the readability/anti-drift gain is too small to
justify the churn at every call site, **PLAN-KILL is an acceptable
verdict**.

## Honest scope/value framing

- **Runtime cycles delta:** ~0. Bodies are byte-identical to today
  modulo the prelude that destructures the struct. Caller-side
  codegen is at parity (Gemini round-2: baseline already passes
  `key`/`decision`/`metadata` by hidden pointer, so coalescing them
  into one `SessionInstall` is a wash or marginal improvement).
- **Readability win:** confined to the 7-field core cluster. The
  positional `allow_replace_local: bool` and `ha_activation: bool`
  control flags stay positional — that part is *not* a readability
  win, but a deliberate scope choice to avoid the `SessionUpsert`-
  embedding contradictions of v1/v2.
- **Anti-drift win:** when the next field (e.g. `cos_queue_id`,
  `fabric_redirect_hint`) needs to flow into install/upsert/update,
  it becomes a struct-field addition. The compiler errors at every
  construction site instead of allowing a `0` to be passed positionally.

## What's already shipped / partially batched

- `SessionDecision`, `SessionMetadata`, `SessionOrigin` are already
  aggregate types (`session/entry.rs`).
- `session/tests.rs` already lives as a sibling (#959-era split). No
  test moves — only construction calls change.
- `pub(crate)` (not `pub`) — `SessionTable` is crate-internal.
  Verified: zero Go callers, zero external Rust callers. Blast
  radius is contained in `userspace-dp/`.

## Concrete design

### New module `userspace-dp/src/session/ctx.rs`

```rust
//! Context structs used by SessionTable::install/upsert/update fns.
//! Encapsulates the previously-positional 7-field cluster so call
//! sites do not drift fields. See #1357.

use super::entry::{SessionDecision, SessionMetadata, SessionOrigin};
use super::key::SessionKey;

/// Owned identity + payload + timing for a fresh session insert or
/// a peer-synced upsert (where the caller has just constructed the
/// key). Used by `install_with_protocol_with_origin` and
/// `upsert_synced_with_origin` (alongside a positional
/// `allow_replace_local: bool` for the upsert variant).
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
/// production call sites (e.g. `session_glue/mod.rs:1071`).
///
/// Does NOT carry the `ha_activation` flag — that is a control
/// argument to `update_session`, not part of the data payload.
/// `promote_synced_with_origin` hides the flag by calling
/// `update_session(req, false)`.
#[derive(Debug, Clone)]
pub(crate) struct SessionUpdate<'a> {
    pub(crate) key: &'a SessionKey,
    pub(crate) decision: SessionDecision,
    pub(crate) metadata: SessionMetadata,
    pub(crate) origin: SessionOrigin,
    pub(crate) now_ns: u64,
    pub(crate) protocol: u8,
    pub(crate) tcp_flags: u8,
}
```

### Signatures BEFORE → AFTER

| Fn | BEFORE (params incl `&mut self`) | AFTER |
|---|---|---|
| `install_with_protocol_with_origin` | 8 (`self, key, decision, metadata, origin, now_ns, protocol, tcp_flags`) | 2 (`self, req: SessionInstall`) — `#[inline]` |
| `upsert_synced_with_origin` | 9 (`self, key, decision, metadata, origin, now_ns, protocol, tcp_flags, allow_replace_local`) | 3 (`self, req: SessionInstall, allow_replace_local: bool`) — `#[inline]` |
| `update_session` | 9 (`self, key, decision, metadata, origin, now_ns, protocol, tcp_flags, ha_activation`) | 3 (`self, req: SessionUpdate<'_>, ha_activation: bool`) — `#[inline]` |
| `promote_synced_with_origin` | 8 (`self, key, decision, metadata, origin, now_ns, protocol, tcp_flags`) — `key: &SessionKey` | 2 (`self, req: SessionUpdate<'_>`) — `#[inline]`; body is `self.update_session(req, false)` |

Out of scope (positional, NOT touched):

- `upsert_synced` wrapper (8 params) — stays positional; body
  constructs `SessionInstall` with `origin: SessionOrigin::SyncImport`
  and calls `upsert_synced_with_origin(install, allow_replace_local)`.
- `install_with_protocol` (6-param wrapper at line 627) — already
  ≤8 params; body constructs `SessionInstall` with `origin:
  SessionOrigin::ForwardFlow` and calls
  `install_with_protocol_with_origin(install)`.
- `refresh_local` (5-param wrapper at line 845) — already ≤8 params;
  body constructs `SessionUpdate { .. }` and calls
  `update_session(req, false)`.
- `refresh_for_ha_activation` (5-param wrapper at line 871) —
  already ≤8 params; body constructs `SessionUpdate { .. }` and calls
  `update_session(req, true)`.
- `refresh_for_ha_transition` (5-param) — already ≤8 params and
  doesn't route through `update_session` (it inlines its own logic).
  Not touched.
- `flowexport.rs::finalize_flow` — out of scope per round-1 review
  (1 test-only caller, zero production callers, over-factored).

### Call-site migration recipe

Every production call site that today reads:

```rust
sessions.upsert_synced_with_origin(
    entry.key, entry.decision, entry.metadata, entry.origin,
    now_ns, entry.protocol, entry.tcp_flags, allow_replace_local,
)
```

becomes:

```rust
sessions.upsert_synced_with_origin(
    SessionInstall {
        key: entry.key,
        decision: entry.decision,
        metadata: entry.metadata,
        origin: entry.origin,
        now_ns,
        protocol: entry.protocol,
        tcp_flags: entry.tcp_flags,
    },
    allow_replace_local,
)
```

`update_session` call sites (currently only inside
`session/mod.rs` itself):

```rust
self.update_session(key, decision, metadata, origin, now_ns,
                    protocol, tcp_flags, ha_activation)
```

becomes:

```rust
self.update_session(
    SessionUpdate { key, decision, metadata, origin, now_ns,
                    protocol, tcp_flags },
    ha_activation,
)
```

Mechanical 1:1 substitution. Rustc errors guide the migration —
if you mistype a field or transpose two args, the compiler catches
it.

## Public API preservation

| API guarantee | Status |
|---|---|
| `pub(crate)` not `pub` | confirmed — `SessionTable` is crate-internal; verified by full-repo grep across `*.rs` and `*.go`. No Go FFI binding. |
| Method names unchanged | yes — all four touched fns keep their names. |
| Return types unchanged | yes — `bool` for all four. |
| Behaviour unchanged | yes — bodies destructure the struct into local bindings, then continue with byte-identical code. |
| Bench compatibility | `userspace-dp/benches/session_table.rs` has 2 references — both in comments. No bench call sites need rewrite. |

## Hidden invariants the change must preserve

1. **Side-effect ordering inside each fn body.** The body sequences
   (`remove_entry → next_epoch → entries.insert → key_to_handle.insert
   → index_forward_nat_key → push_to_wheel → push_delta`) are
   unchanged. The refactor only changes the prelude that destructures
   the struct.
2. **Allocation profile.** `SessionInstall` and `SessionUpdate<'a>`
   are stack-only field aggregates. **No `Box`, `Arc`, `Vec`, no
   allocator hit.** Move semantics are identical to passing each
   field individually.
3. **HA sync portability.** The wire-protocol consumers
   (`afxdp/session_glue/mod.rs:698, 1022`) build a `SessionInstall`
   from `SyncedSessionEntry` fields the same way they build positional
   args today. No wire-format change.
4. **Borrow checker.** `SessionUpdate<'a>` mirrors today's
   `key: &SessionKey` parameter shape. `SessionInstall` mirrors
   today's `key: SessionKey` by-value shape. No new lifetime
   annotations propagate to caller signatures — rustc infers `'a`
   from the struct literal at each call site (Gemini round-2 #2).
5. **`SessionMetadata::clone()` count.** Bodies still `.clone()`
   metadata exactly where they do today (e.g. line 679 becomes
   `metadata: req.metadata.clone()` after destructuring).
6. **Wheel push idempotence (#965).** `push_to_wheel(&key, now_ns)`
   calls preserve their argument site — the local `key` binding
   from struct destructure.
7. **`promote_synced_with_origin` hides `ha_activation`.** v3's
   wrapper body is `self.update_session(req, false)`. Caller cannot
   accidentally set `ha_activation = true` because the flag is not
   in `SessionUpdate`.

## Risk assessment

| Class | Level | Notes |
|---|---|---|
| **Behavioral regression risk** | LOW | Bodies unchanged; only parameter-binding prelude. |
| **Lifetime / borrow-checker risk** | LOW | `SessionUpdate<'a>` mirrors today's `&SessionKey`. No new lifetimes propagate (Gemini round-2 confirmed). |
| **Performance regression risk** | LOW-NEUTRAL | Baseline already passes `key`/`decision`/`metadata` by hidden pointer (System V ABI, Gemini round-2). Coalescing into one `SessionInstall` materialization is a wash. `#[inline]` lets LLVM SROA flatten across the call boundary. Implementation gate verifies via `cargo asm` on `install_with_protocol_with_origin`. |
| **Architectural mismatch (#961 / #946 Ph2)** | LOW | Not a pipeline change, not a shared-context across stages. Two structs, each is the input for exactly one operation kind. |
| **Wire-protocol drift (HA sync)** | NONE | Wire format `SyncedSessionEntry` unchanged. Only consumer-side call shape changes. |

## Test plan

1. `TMPDIR=/dev/shm CARGO_TARGET_DIR=/dev/shm/cargo cargo build` clean.
2. `cargo test --release` — full userspace-dp suite passes.
3. `cargo test --release session::tests` — 5/5 named flake check on
   the most affected session-table test module.
4. `GOCACHE=/dev/shm/cache GOTMPDIR=/dev/shm go test ./...` — Go
   suite green.
5. **Implementation gate:** spot-check `cargo asm
   userspace_dp::session::SessionTable::install_with_protocol_with_origin`
   before/after to confirm pass-by-move struct does not regress
   the hot install path versus the positional baseline. If the
   instruction count grows materially (>10% on that fn), roll
   back to keep `install_with_protocol_with_origin` positional
   and ship only `update_session` + `upsert_synced_with_origin` +
   `promote_synced_with_origin`.
6. **No smoke this PR** per Wave-2 rules (4-of-4 attestation only;
   batched smoke at end of refactor chain).

## Out of scope (explicitly)

- The semantics of any session fn (collision rules, origin handling,
  GC integration) — all preserved.
- `SessionMetadata` / `SessionDecision` / `SessionOrigin` internals —
  already aggregates.
- `upsert_synced`, `install_with_protocol`, `refresh_local`,
  `refresh_for_ha_activation`, `refresh_for_ha_transition` —
  positional wrappers, already ≤8 params.
- `flowexport.rs::finalize_flow` — over-factored per round-1.
- Bench file (`session_table.rs`) — comment references only.
- Splitting `session/mod.rs` further — that's #1327 / #946 Phase
  1.5's territory.

## Open questions for adversarial review (v3)

1. **Is the readability/anti-drift gain worth the churn at ~44 call
   sites when the call-site grows from 1 line to 8-10 lines?**
   PLAN-KILL is appropriate if reviewers conclude this is a net loss.
   Counter-argument: the new line-count is mostly named fields, not
   logic — a 1-line positional call's information density is high
   precisely because it hides what each token means.
2. **Should `SessionInstall::key` be a `Cow<'a, SessionKey>` to
   eliminate the install-vs-update struct asymmetry?** v3 keeps them
   as two distinct structs because cow-ing the key only saves one
   type at the cost of an enum-tag bit at every access. Reviewer may
   prefer the symmetry.
3. **`#[inline]` vs `#[inline(always)]`** — v3 picks `#[inline]` per
   Gemini round-2. Codex round-2 recommended `#[inline(always)]` for
   the hot install/upsert path. Reviewer is asked to land the call;
   v3's position is that `#[inline]` is sufficient because the call
   site is monomorphic and LLVM SROA aggressively elides struct
   materialization for non-generic callees at LTO.
4. **`promote_synced_with_origin` and `install_with_protocol_with_origin`
   compile-time distinctness.** v3 makes them take DIFFERENT structs
   (`SessionUpdate<'a>` vs `SessionInstall`), so a caller cannot
   accidentally swap them — the compiler catches mismatched argument
   types. Confirmed safe.
5. **`upsert_synced_with_origin` taking `(SessionInstall, bool)`** —
   reviewer should confirm acceptance of the positional bool as a
   deliberate scope choice. Adding a `SessionUpsertOpts { install,
   allow_replace_local }` wrapper would reintroduce the v1
   embedding pattern Codex round-1 PLAN-KILLed.
