# #1543 — Decompose userspace screen + SYN-cookie runtime (Wave-5)

**Status:** DRAFT v1 — pending adversarial plan review (Codex + AGY).

## Issue framing

`userspace-dp/src/screen.rs` is 1420 LOC and braids together unrelated
concerns: SYN-cookie crypto (codec + SipHash24 + validated cache),
per-zone rate counters, TCP/IP stateless screen checks (LAND,
ping-of-death, teardrop, source-route, ICMP-fragment, WinNuke,
SYN+FIN, no-flag, FIN-no-ACK, SYN-frag), port-scan + IP-sweep
trackers, per-IP session limits, and the per-packet field-extraction
helper. Issue #1543 (refs #1374) wants this split into focused
sibling submodules so SYN-cookie crypto can be reviewed independently
from the screen policy and so future screen checks don't perturb
cookie validation.

## Honest scope / value framing

This is **pure code motion** with NO behavioral change. The win is
auditability of security-path code, not performance. Concretely:

- 1420 LOC → ~150 LOC `mod.rs` coordinator + 9-10 focused submodules.
- SYN-cookie crypto isolated from packet policy (the largest
  audit-readability win — the cookie path is the only crypto in the
  runtime and currently spans ~600 LOC braided through ScreenState).
- Zero runtime allocation changes; zero `pub` surface changes (no new
  callers of internal items, no new types exposed).

Expected per-packet behavior: **identical**. The `ScreenState::check_packet_with_zone_id`
control flow is preserved exactly; submodule helpers are pure code
relocation of existing inherent-impl methods and free-standing types.

> If reviewers conclude the perf gain is too small to justify the churn,
> PLAN-KILL is an acceptable verdict. The churn budget here is justified
> by the audit-readability argument, not by perf — and the issue itself
> frames the win as "easier to audit", not "faster".

## What's already shipped / partially batched

- `screen_tests.rs` already lives as a sibling file (loaded via
  `#[path = "screen_tests.rs"]` from screen.rs). After this refactor it
  becomes `screen/tests.rs` loaded by `screen/mod.rs` with the same
  `#[path = "tests.rs"] mod tests;` shape. Test bodies do NOT move —
  they continue to `use super::*;` from the screen module root, which
  now re-exports the same set of items via `mod.rs`.
- #1374 closed the SYN-cookie feature gap (issue refs); the SYN-cookie
  runtime in screen.rs is the artifact this refactor splits.
- Wave-3/4 refactors (#1540 rest-api, #1541 cluster-mgr, #1542 nat-runtime)
  established the `module/foo.rs` sibling layout convention and the
  `pub(crate) use` re-export pattern in `mod.rs`.

## Concrete design

### Target file layout (per #1543 issue body, with `module/foo.rs` layout — no `screen_` prefix)

```
userspace-dp/src/screen/
  mod.rs          — ScreenState struct, new(), update_profiles(),
                    update_syn_cookie_master_key(), check_packet(),
                    check_packet_with_zone_id(),
                    validate_syn_cookie_ack_on_session_miss(),
                    session_created(), session_expired(),
                    has_profiles(), has_advanced_features(),
                    plus pub(crate) re-exports.
  syncookie.rs    — SynCookieTuple, SynCookieValidation,
                    SynCookieChallenge, SynCookieAckVerdict,
                    SynCookieCodec (mint/validate/MAC/secret/cache
                    keys), SYN_COOKIE_* constants,
                    SYN_COOKIE_MSS_VALUES,
                    SipHash24, SynCookieValidatedKey,
                    SynCookieValidatedEntry, SynCookieValidatedSet,
                    SynCookieValidatedCache.
  rate.rs         — RateCounter (per-zone 1-second window counter).
  stateless.rs    — Pure helpers for LAND, SYN+FIN, no-flag,
                    FIN-no-ACK, WinNuke, ping-of-death, teardrop,
                    icmp-fragment, source-route, syn-frag.
                    Pure-fn signatures: take (&ScreenProfile, &ScreenPacketInfo)
                    and return Option<&'static str> reason on drop.
  scan.rs         — PortScanTracker, IpSweepTracker (per-src
                    windowed unique-port / unique-dst-IP set).
  session_limit.rs — SessionLimitTracker (per-IP session counts).
  packet.rs       — ScreenPacketInfo (parsed packet fields),
                    ScreenProfile (per-zone config), ScreenVerdict
                    (Pass / Drop / SynCookieBypass /
                    SynCookieChallenge), PROTO_* and TCP_*
                    constants used by stateless.rs and mod.rs.
  extract.rs      — extract_screen_info() — the no-alloc IPv4/IPv6
                    + TCP header parser.
  tests.rs        — Existing screen_tests.rs file relocated here.
                    `use super::*;` continues to work because
                    screen/mod.rs re-exports the same items the test
                    file currently uses.
```

This matches the issue's preferred shape; the only deviations are:

- The issue suggested a `syncookie.rs` singular module; I keep all
  cookie state (codec + cache + SipHash) in one file to preserve the
  "easier to audit as one unit" win. SipHash24 is a private impl
  detail of SynCookieCodec and SynCookieValidatedCache — splitting it
  out into a sibling adds a hop without an audit win.
- `packet.rs` is added (not in the issue) to host shared types
  (`ScreenPacketInfo`, `ScreenProfile`, `ScreenVerdict`, protocol/flag
  constants) that both `stateless.rs` and `mod.rs` need. The
  alternative — re-defining or pub(super)-ing them across siblings —
  adds cross-module coupling that defeats the audit-readability win.
  This adds one sibling beyond the issue's named set; PLAN-KILL is the
  right call if reviewers think this fragments the API.

### Module visibility shape

All currently-`pub(crate)` items stay `pub(crate)` at their
definition site in their new submodule. `screen/mod.rs` re-exports
them with `pub(crate) use` so `crate::screen::<Item>` keeps working
for every external caller:

```rust
// screen/mod.rs
mod extract;
mod packet;
mod rate;
mod scan;
mod session_limit;
mod stateless;
mod syncookie;

pub(crate) use extract::extract_screen_info;
pub(crate) use packet::{ScreenPacketInfo, ScreenProfile, ScreenVerdict};
pub(crate) use syncookie::{
    SynCookieAckVerdict, SynCookieChallenge, SynCookieCodec,
    SynCookieTuple, SynCookieValidation, SYN_COOKIE_MSS_VALUES,
};

#[cfg(test)]
#[path = "tests.rs"]
mod tests;

pub(crate) struct ScreenState { /* fields */ }
impl ScreenState { /* preserved method set */ }
```

Submodules use `pub(super)` for items that must be reachable across
siblings (e.g. `RateCounter::increment`, `SipHash24` if
`syncookie.rs` needs to expose it for tests, the `PROTO_*` /
`TCP_*` constants in `packet.rs`).

The four external callers in `userspace-dp/src/afxdp/` keep their
imports unchanged:

```
afxdp/mod.rs:           use crate::screen::{ScreenProfile, ScreenState, ScreenVerdict, extract_screen_info};
afxdp/poll_stages.rs:   use crate::screen::{SynCookieAckVerdict, SynCookieChallenge};
afxdp/event_emit.rs:    use crate::screen::ScreenPacketInfo;
afxdp/poll_descriptor:  use crate::screen::SynCookieChallenge;
```

### Item mapping (every line of the old screen.rs accounted for)

| Old screen.rs lines | New location |
|--------------------:|--------------|
| 1-17 (doc comment, use, PROTO_*, TCP_*) | `packet.rs` (constants) + `mod.rs` (doc) |
| 35-64 (SYN_COOKIE_* consts, SYN_COOKIE_MSS_VALUES) | `syncookie.rs` |
| 66-86 (SynCookieTuple + impl) | `syncookie.rs` |
| 87-108 (SynCookieValidation, SynCookieChallenge, SynCookieAckVerdict) | `syncookie.rs` |
| 110-266 (SynCookieCodec) | `syncookie.rs` |
| 268-383 (SipHash24) | `syncookie.rs` (private to module) |
| 385-409 (ScreenPacketInfo) | `packet.rs` |
| 411-438 (ScreenProfile) | `packet.rs` |
| 440-447 (ScreenVerdict) | `packet.rs` |
| 449-474 (RateCounter) | `rate.rs` |
| 476-525 (SessionLimitTracker) | `session_limit.rs` |
| 527-568 (PortScanTracker) | `scan.rs` |
| 570-611 (IpSweepTracker) | `scan.rs` |
| 613-790 (SynCookieValidated* types + Cache) | `syncookie.rs` |
| 792-832 (ScreenState struct + new()) | `mod.rs` |
| 834-902 (update_profiles, update_syn_cookie_master_key, current_syn_cookie_full_epoch, standby_syn_cookie_ack_validation_limited) | `mod.rs` |
| 904-1154 (check_packet, check_packet_with_zone_id) | `mod.rs` (calls stateless.rs helpers) |
| 1156-1218 (validate_syn_cookie_ack_on_session_miss) | `mod.rs` |
| 1220-1236 (#[cfg(test)] accessors) | `mod.rs` |
| 1238-1261 (session_created, session_expired, has_advanced_features) | `mod.rs` |
| 1264-1416 (extract_screen_info) | `extract.rs` |
| 1418-1420 (`#[cfg(test)] mod tests` w/ #[path]) | `mod.rs` (path becomes `"tests.rs"`) |

The stateless helpers in `stateless.rs` are *new function shells*
that capture the existing inline branches in `check_packet_with_zone_id`.
Each helper is signed `#[inline] fn check_<name>(profile: &ScreenProfile,
pkt: &ScreenPacketInfo) -> Option<&'static str>`; the caller in
`mod.rs` uses `if let Some(reason) = stateless::check_land(&profile,
pkt) { return ScreenVerdict::Drop(reason); }` patterns. **Hot-path
discipline**: every helper is `#[inline]` so codegen is identical;
verified with `cargo build --release` + `objdump -d` spot check on
the SYN-cookie MAC path post-implementation.

### Why this is pure code motion

- Side effects (rate counter increments, syn_cookie cache mutations,
  port-scan / ip-sweep set inserts, session-limit map mutations,
  `last_cleanup_secs` update) all stay in `mod.rs`'s
  `check_packet_with_zone_id` orchestrator. Stateless helpers are
  side-effect-free — they only read `profile` and `pkt`.
- The order of checks in `check_packet_with_zone_id` is preserved
  byte-for-byte (LAND → TCP stateless guard → TCP flag screens →
  ping-of-death → teardrop → icmp-fragment → source-route → flood
  rate checks → SYN flood + cookie path → port-scan → ip-sweep →
  session-limits → cleanup → return). The plan does NOT reorder
  checks; reordering would change drop precedence (e.g. LAND drops
  before flood counters increment), which is observable.
- Drop reason strings (`"land-attack"`, `"tcp-syn-fin"`,
  `"syn-cookie-unavailable"`, etc.) are preserved exactly — these are
  consumed by the event-emit path and by tests.

## Public API preservation

External callers (`afxdp/`) use only these items from `crate::screen`:

- `ScreenProfile` (struct)
- `ScreenState` (struct + 9 methods: `new`, `update_profiles`,
  `update_syn_cookie_master_key`, `has_profiles`, `check_packet`,
  `check_packet_with_zone_id`, `validate_syn_cookie_ack_on_session_miss`,
  `session_created`, `session_expired`, `has_advanced_features`)
- `ScreenVerdict` (enum, all variants)
- `ScreenPacketInfo` (struct, all fields)
- `SynCookieAckVerdict` (enum, all variants)
- `SynCookieChallenge` (struct + fields)
- `extract_screen_info` (free fn)

All of these are preserved at the same `crate::screen::<Item>` path
via `pub(crate) use` re-exports in `mod.rs`. No caller in
`afxdp/` needs to change.

## Hidden invariants the change must preserve

1. **Drop precedence order**: `check_packet_with_zone_id` must visit
   checks in the existing order. Tests assert this implicitly by
   asserting specific drop reasons under specific packets.
2. **Side-effect ordering**: rate counters increment BEFORE the
   threshold check returns Drop; SYN-cookie cache `take_valid` runs
   BEFORE `syn_counters.increment` so a validated cookie bypasses
   the rate counter. This is preserved by keeping the orchestrator
   in `mod.rs` and only delegating side-effect-free checks to
   `stateless.rs`.
3. **`#[cfg(test)]` shims**: `set_syn_cookie_full_epoch_for_test`,
   `syn_cookie_validated_len`, `syn_cookie_active_zone_count`,
   `syn_cookie_standby_ack_count`, and the `SYN_COOKIE_STANDBY_ACK_VALIDATION_RATE_LIMIT_PER_SEC`
   `#[cfg(test)]` override stay reachable from `tests.rs`. They're
   defined on `impl ScreenState` in `mod.rs` and `tests.rs`
   continues to `use super::*;`.
4. **`#[cfg_attr(not(test), allow(dead_code))]`** annotations on
   items only used by tests stay applied — moving these items to
   submodules must preserve the attribute so production builds don't
   warn.
5. **Allocation rules (hot path)**: zero new allocations per packet.
   Helper functions in `stateless.rs` take `&ScreenProfile` /
   `&ScreenPacketInfo` by reference and return `Option<&'static str>`
   — no `String`, no `Vec`, no `Box`. The existing `profile.clone()`
   in `check_packet_with_zone_id` (line 932 — clones a small
   `ScreenProfile` to release the `&mut self` borrow on `self.profiles`)
   stays exactly where it is; we don't refactor it away in this PR.
6. **SipHash24 codegen**: `cookie_mac` and `epoch_secret` are
   security-critical and on the SYN-flood hot path. Both stay
   `#[inline]`-able (no public surface; same crate). `SipHash24`
   stays a private item inside `syncookie.rs`.
7. **`SYN_COOKIE_VALIDATED_CACHE_TTL_SECS` const expression**: the
   `const _: [(); SYN_COOKIE_ISN_BITS as usize] = [(); SYN_COOKIE_LAYOUT_BITS as usize];`
   compile-time bit-layout assertion at line 58 moves to
   `syncookie.rs` and stays a compile-time check.

## Risk assessment

| Class | Level | Rationale |
|-------|-------|-----------|
| Behavioral regression | LOW | Pure code motion; order of checks preserved; drop reasons preserved; tests cover all check paths and run from the same module root. |
| Lifetime / borrow-checker | LOW | The only borrow shape that bit screen.rs is `profile.clone()` at line 932; that line is kept verbatim. Stateless helpers take `&` borrows. |
| Performance regression | LOW | `#[inline]` on every per-check helper; private cross-module use means LLVM still sees the bodies. Spot-check with `objdump` on release build before merging. SipHash24 stays inside one file as a private type. |
| Architectural mismatch | LOW | The plan matches the issue's preferred shape (with one justified deviation: `packet.rs` shared-types module + keeping SipHash inside syncookie.rs). |

## Test plan

- `cargo build --release` clean (no warnings, no errors).
- `cargo test --release` — full userspace-dp suite passes.
- `cargo test --release screen` — every test in the relocated
  `tests.rs` passes, 5×loop for flake.
- `cargo test --release syn_cookie` — every cookie-specific test
  passes, 5×loop for flake.
- Go suite `go test ./...` passes (30 packages — no Rust dep on Go,
  but smoke discipline says run it anyway).
- **No per-PR smoke** for this PR per Wave-5 rules: marker
  `<!-- AWAITING-BATCH-MERGE -->` only.

## Out of scope (explicitly)

1. **Behavior changes.** No new screen checks, no new flag bits, no
   altered drop reasons, no reordered checks, no perf tweaks.
2. **`profile.clone()` elimination.** Acknowledged as not-ideal but
   preserving it keeps this PR pure code motion. A follow-up could
   restructure `ScreenState` so the orchestrator borrows `profile`
   immutably while mutating disjoint sub-state.
3. **SipHash24 extraction to a crate-level utility.** It's only used
   by SynCookieCodec and SynCookieValidatedCache; keeping it private
   in `syncookie.rs` is the audit-readability win the issue cites.
4. **Trait-ifying stateless checks** (e.g. a `ScreenCheck` trait
   with `fn check(&self, pkt) -> Option<&str>`). Free-fn helpers
   keep codegen flat and avoid dyn-dispatch entirely.
5. **Pulling `extract_screen_info` into the afxdp module that
   owns the packet parser.** It currently lives in screen.rs and stays
   there (in `extract.rs`) — moving it across crate-internal module
   boundaries to afxdp is a different design question.

## Open questions for adversarial review

1. Is the addition of `packet.rs` (not in the issue's named module
   list) justified by the audit-readability argument, or does it
   fragment the API enough to PLAN-KILL? An alternative is to keep
   `ScreenPacketInfo`, `ScreenProfile`, `ScreenVerdict`, and
   `PROTO_*` / `TCP_*` constants in `mod.rs` — at the cost of `mod.rs`
   growing to ~450 LOC with three large type definitions plus the
   orchestrator. Reviewers' call.
2. Should `SipHash24` be its own sibling module
   (`screen/siphash.rs`) for testability, or kept private inside
   `syncookie.rs`? The plan keeps it private — splitting it adds a
   `pub(super)` hop without an audit win because no test inspects
   SipHash directly.
3. Are there any hidden callers I missed? The grep found only 4
   external uses of `crate::screen` (all in `afxdp/`). If any
   benchmarks, integration tests, or `cmd/` binaries import from
   `crate::screen`, the plan's re-export list needs updating.
4. Is the `profile.clone()` at line 932 a real hot-path cost?
   `ScreenProfile` is ~80 bytes. The clone happens once per packet
   on screen-configured zones. Reviewers may want this called out as
   a follow-up issue even though it's out of scope here.
5. Should the `stateless::check_*` helpers take `&ScreenProfile`
   AND `&ScreenPacketInfo` (two refs, current plan) or a packed
   `&CheckCtx<'a>` struct (one ref)? Two refs is simpler. PLAN-KILL
   if reviewers think the param count grows past 2 in any helper.
6. Drop precedence: the plan preserves the existing order exactly.
   If a reviewer argues a different order is correct (e.g. flood
   counters should always increment even when LAND fires), that's a
   behavior change and must be a separate issue/PR.
7. Architectural mismatch vs #946 Phase 2 / #961: this is not a
   pipeline-batching refactor, not a data-structure refactor — it
   is module-boundary code motion. The #946 Phase 2 trap was
   batching across order-coupled state. The trap doesn't apply here
   because the orchestrator stays serial. Reviewers should confirm.
