# #1678 — fix `--features debug-log` build (ICMPV6_EMBED_LOGGED private)

Status: PLAN-READY v2 — Codex PLAN-NEEDS-MINOR (Makefile framing, addressed below), AGY PLAN-READY (empirically verified), Claude SMR PLAN-READY

## Issue framing

The `debug-log` feature build of `userspace-dp` does not compile on
master. `cargo build --release --features debug-log` fails with:

```
error[E0425]: cannot find value `ICMPV6_EMBED_LOGGED` in this scope
    --> src/afxdp/poll_descriptor/mod.rs:1220:40
note: static `crate::afxdp::bpf_map::ICMPV6_EMBED_LOGGED` exists but is inaccessible
    --> src/afxdp/bpf_map/mod.rs:871:1
```

The default (`default = []`) release build is unaffected. This is a
pure build-config / symbol-visibility defect — no runtime or dataplane
behaviour change.

## Root cause (verified)

`ICMPV6_EMBED_LOGGED` is defined private in `bpf_map`:

```rust
// userspace-dp/src/afxdp/bpf_map/mod.rs
pub(super) static SESSION_CREATIONS_LOGGED: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "debug-log")]
static ICMPV6_EMBED_LOGGED: AtomicU32 = AtomicU32::new(0);   // line 871 — no `pub`
```

The consumer references it unqualified:

```rust
// userspace-dp/src/afxdp/poll_descriptor/mod.rs:1220 (inside #[cfg(feature="debug-log")])
let icmpv6_trace = meta.protocol == PROTO_ICMPV6
    && ICMPV6_EMBED_LOGGED.fetch_add(1, Ordering::Relaxed) < 32;
```

Resolution chain (confirmed by reading the source):

1. `afxdp/mod.rs:144` has `use self::bpf_map::*;` — this glob pulls in
   every `bpf_map` item *visible to `afxdp`* into the `afxdp` namespace.
2. `poll_descriptor/mod.rs:31` has `use super::*;` — re-globs everything
   in `afxdp` (including what step 1 imported).
3. The sibling `SESSION_CREATIONS_LOGGED` is `pub(super)` (visible to
   `crate::afxdp`), so it reaches `afxdp` via the glob and resolves in
   `poll_descriptor` (used unqualified at line 1810).
4. `ICMPV6_EMBED_LOGGED` is *private to `bpf_map`*, so the glob at
   `afxdp/mod.rs:144` cannot see it → it never reaches `afxdp` → the
   `use super::*` in `poll_descriptor` cannot resolve it. E0425.

## Scope of the break (verified — exactly one symbol)

`grep -rn ICMPV6_EMBED_LOGGED` returns exactly two hits: the definition
(`bpf_map/mod.rs:871`) and the single consumer (`poll_descriptor/mod.rs:1220`).
A full `cargo build --release --features debug-log` reports exactly **1**
error (`E0425`) plus 36 pre-existing warnings (unused assignments etc.,
not errors). The issue body's mention of a second reference in
`tx/dispatch/mod.rs` is stale — no such reference exists on current
master. So the fix is a single symbol re-scope; there are no other
debug-log-only build breaks.

## Fix

Match the sibling exactly: change

```rust
static ICMPV6_EMBED_LOGGED: AtomicU32 = AtomicU32::new(0);
```

to

```rust
pub(super) static ICMPV6_EMBED_LOGGED: AtomicU32 = AtomicU32::new(0);
```

`pub(super)` = visible to the parent module `crate::afxdp`, which is the
exact scope the consumer resolves through (steps 1–3 above). This is the
minimal correct visibility: it is identical to `SESSION_CREATIONS_LOGGED`
and `SESSION_PUBLISH_VERIFY_OK/FAIL` immediately above it, and it does
NOT widen to `pub(crate)` or `pub`. `pub(in crate::afxdp)` (the issue's
suggestion) is semantically identical here because `bpf_map`'s `super`
*is* `crate::afxdp`; `pub(super)` is preferred only because it matches
the established sibling spelling on adjacent lines.

The consumer needs no import change: once the static is `pub(super)` it
flows through the same two-hop glob as `SESSION_CREATIONS_LOGGED`.

## Hidden invariants preserved

- **No runtime change in the default build.** The static is
  `#[cfg(feature = "debug-log")]`-gated; under `default = []` it does not
  exist, so the visibility change is a no-op for the production binary.
  Visibility annotations have no codegen effect regardless.
- **No new symbol exposure beyond the crate.** `pub(super)` keeps it
  internal to `crate::afxdp`; nothing outside that module can name it.
- **Side-effect ordering / atomics unchanged.** Only the visibility
  keyword changes; the `AtomicU32` and its single `fetch_add(_, Relaxed)`
  use are untouched.

## CI guard

There is no `.github/workflows` (the repo has no GitHub Actions CI) and
no Makefile target that builds with `--features debug-log`. The only
cargo targets are `build-userspace-dp` (default features) and `make test`
(Go only). Options considered:

- (A) Add a `build-userspace-dp-debug-log` Makefile target that runs
  `cargo build --release --features debug-log` so the feature build can
  be checked locally and can't silently rebreak.
- (B) Note the gap and do nothing structural.

This plan adds a minimal, **manual** guard: a phony Makefile target
`build-userspace-dp-debug-log` (standalone, NOT wired into
`all`/`build`/`test`, mirroring the `audit-check` precedent of an
opt-in drift guard) that compiles the debug-log feature. To be precise
about what this is and is not (Codex round-1 finding): there is no CI in
this repo, so this target is a **manual convenience for local
pre-commit validation**, not an automated gate — nothing runs it unless
a developer invokes it. It does not slow the default build and does not
invent CI that doesn't exist. AGY round-1 endorsed it as warranted
(feature builds rot when nothing compiles them); Codex round-1 flagged
only that the plan must not over-claim it as a "guard that prevents
rebreak" — corrected here to "manual one-command rebreak check".

## Risk assessment

| Class | Level | Notes |
|---|---|---|
| Behavioral regression | NONE | Visibility keyword only; default build has no such symbol. |
| Lifetime / borrow-checker | NONE | No borrows touched. |
| Performance regression | NONE | No codegen change in any build. |
| Architectural mismatch | NONE | Matches the adjacent sibling convention exactly. |

## Test plan

- `cargo build --release --features debug-log` compiles clean (was: E0425).
- Default `cargo build --release` still compiles (no-feature path unchanged).
- `cargo test --release` stays green (no test regressions).
- Go suite unaffected (no Go change) — spot-check `make test` not required
  since no Go files change, but will note it.

## Out of scope

- The 36 pre-existing `unused_assignments` warnings in the debug-log
  build (`tx/dispatch/mod.rs` `build_failed` / `fallback_to_slow_path`).
  Those are warnings, not errors, and predate this fix. File separately
  if cleanup is wanted.

## Open questions for adversarial review

1. Is `pub(super)` the minimal-correct visibility, or is there any
   consumer outside `crate::afxdp` (now or imminently) that would force
   `pub(crate)`? (Grep says no — only `poll_descriptor`, a child of
   `afxdp`.)
2. Does relying on the two-hop glob (`bpf_map::*` → `afxdp` → `super::*`
   → `poll_descriptor`) introduce any ambiguity / shadowing risk vs. an
   explicit `use crate::afxdp::bpf_map::ICMPV6_EMBED_LOGGED;` at the
   consumer? (The sibling already relies on the glob, so this matches
   precedent — but is explicit-import the better fix?)
3. Is adding the `build-userspace-dp-debug-log` Makefile guard worth it,
   or scope creep on a one-symbol fix?
4. Are there OTHER feature flags (besides `debug-log`) whose builds are
   also broken on master that this PR should sweep, or strictly out of
   scope? (Plan asserts `debug-log` is the only feature; reviewers
   should verify against `Cargo.toml [features]`.)
5. Any reason `pub(in crate::afxdp)` should be preferred over
   `pub(super)` here despite being semantically identical?
