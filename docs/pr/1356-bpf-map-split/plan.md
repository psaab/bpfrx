# #1356 — Split `bpf_map.rs` 204-LOC `publish_bpf_conntrack_entry` into per-address-family helpers

**Status:** v2 — addresses Codex r1 PLAN-NEEDS-MAJOR + AGY r1 PLAN-NEEDS-MINOR.
Codex r2 returned PLAN-READY (provisional); AGY r2 retry returned PLAN-READY.
Implementation shipped as commit c542c77b; Codex code-review MERGE-NEEDS-MINOR
on plan/comment staleness against the implemented shape — addressed in commit
4b23cdf4 and Copilot inline-comment delta (this commit).

## Round-1 disposition

### Codex r1 (task-mpmypz53-viyk24) — PLAN-NEEDS-MAJOR

1. **"`pub(super) use` of `pub(super) fn` is compile-invalid."**
   **ACCEPTED.** A child `pub(super)` item is only visible to `bpf_map`,
   so re-exporting it wider to `afxdp` is rejected by Rust privacy.
   **Fix:** keep the orchestrator (`pub(super) fn publish_bpf_conntrack_entry`)
   in `bpf_map/mod.rs`. Only the two per-family **helpers** move into the
   child `publish_conntrack.rs`. The orchestrator becomes a thin
   dispatcher that calls into the child's helpers via `use
   publish_conntrack::{publish_v4_session, publish_v6_session};`.
   This sidesteps the privacy issue entirely — the orchestrator's
   visibility doesn't change, and the helpers stay file-private to
   the child module.

2. **"Visibility bumps are unnecessary and widen encapsulation."**
   **ACCEPTED.** Child submodules already have access to private parent
   items. With the orchestrator staying in `mod.rs`, the helpers in
   `publish_conntrack.rs` reach `BpfSessionKey/Value V4/V6` and `SESS_*`
   via `use super::{BpfSessionKeyV4, BpfSessionValueV4, …};` — no
   visibility bump needed. **Drop all `pub(super)` additions on those
   items.** Keep them private at module scope.

3. **"`#[path = \"bpf_map.rs\"]` in afxdp/mod.rs must change to
   `bpf_map/mod.rs`."**
   **ACCEPTED.** v2 updates `userspace-dp/src/afxdp/mod.rs:59-60` to
   `#[path = "bpf_map/mod.rs"] mod bpf_map;` per the project's
   explicit-path convention.

4. **"`#[path = \"bpf_map_tests.rs\"]` in bpf_map.rs resolves to
   `afxdp/bpf_map/bpf_map_tests.rs` after the move."**
   **ACCEPTED.** v2 updates the test include at the new
   `bpf_map/mod.rs` tail to `#[path = "../bpf_map_tests.rs"] mod tests;`
   so the existing sibling file is found.

5. **"5 call sites, not 4."**
   **ACCEPTED.** v2 §Public API preservation lists all 5: 2 in
   `bpf_map.rs` (839, 853) → become `bpf_map/mod.rs`; 3 in
   `poll_descriptor.rs` (915, 1482, 2782).

6. **"Don't claim sub-nanosecond / oversold `bpf_map_tests.rs:197`."**
   **ACCEPTED.** v2 reframes the cost note as "extra call dwarfed by
   `bpf_map_update_elem`" and the test as "byte-order verification
   that manually constructs the key — adjacent coverage, not direct".

### AGY r1 (review-mpmytock-qbgl6a) — PLAN-NEEDS-MINOR

All three AGY findings overlap with Codex's:

1. **Revert visibility bumps.** Same as Codex finding #2. Accepted.
2. **Use `#[path = "bpf_map/mod.rs"] mod bpf_map;` styling.** Same as
   Codex finding #3. Accepted.
3. **Document early-return equivalence.** v2 §Hidden invariants #4
   spells out: helper `return` exits the helper, control returns to
   the orchestrator's `match` arm which is the final statement; the
   observable effect (skip BPF write, no fallthrough) is byte-identical
   to the original.

## Issue framing

`userspace-dp/src/afxdp/bpf_map.rs` is 1,191 LOC. The largest function
in the file is `publish_bpf_conntrack_entry()` at lines 449-652 — a
204-LOC body that branches on `key.addr_family` and inlines the v4
and v6 BPF key/value construction in two parallel arms. Per
`docs/engineering-style.md`, the soft cap is 100 LOC per function
and the hard Tier-1 cap is 200 LOC. This body crosses the hard cap.

The function bridges the userspace-dp `SessionDecision` /
`SessionMetadata` model into the kernel BPF conntrack HASH maps
(`sessions` for v4, `sessions_v6` for v6) so that `show security
flow session` and HA session-sync see consistent zone / NAT / timer
state for helper-managed sessions.

## Honest scope/value framing

This is **pure code motion**. The function is invoked on conntrack
publish — not per-packet — so there is no measurable performance
win. The motivation is solely Tier-1 hard-cap compliance and
isolation of the two address-family code paths so future v4 / v6
divergences (e.g., NAT64 mirror entries) land in one place rather
than the middle of a 200-LOC match arm.

**If reviewers conclude the perf gain is too small to justify the
churn, PLAN-KILL is an acceptable verdict.** The honest answer is
that the perf gain is zero. The win is structural — file/function
hygiene and readability for the next person who has to extend NAT
or zone handling on the bridge.

This refactor follows the same wave-2 per-feature-split pattern
already shipped in #1325 (protocol split), #1326 (worker loop),
#1327 (poll descriptor stages), #1342 (forwarding build),
#1345 (server handlers), #1351 (umem snapshot), and #1352 (frame
build). It is the next-smallest item in that audit.

## What's already shipped / partially batched

- The BPF map structs (`BpfSessionKeyV4`, `BpfSessionValueV4`,
  `BpfSessionKeyV6`, `BpfSessionValueV6`) are already defined at
  module scope (lines 342-436) and are `struct`-private to
  `bpf_map.rs`. After the split they **stay private** at
  `bpf_map/mod.rs` scope; the child `publish_conntrack` submodule
  reaches them via Rust's parent-private-item access rule
  (`use super::{…}` for ergonomic unqualified names). **No
  `pub(super)` bump is needed and v2 dropped that idea per Codex r1
  + AGY r1 findings.**
- `delete_bpf_conntrack_entry` (655-695) and
  `refresh_bpf_conntrack_last_seen` (709-787) also branch on
  `addr_family` with identical BPF-key construction. **They are
  out of scope for this PR** — see §Out of scope. Splitting them
  is structurally identical work and can land in a follow-up if
  the project decides the pattern is worth chasing.
- `ConntrackCtx<'a>` (lines 336-340) is already in place to bundle
  the two map FDs and the zone-name table.
- `session_flag` computation (`SESS_FLAG_SNAT` / `SESS_FLAG_DNAT`)
  is one-line per flag and stays inline in the orchestrator.
- `reverse_session_key()` already exists at module scope and is
  used by both arms.

## Concrete design

### Layout

```
userspace-dp/src/afxdp/
├── bpf_map/
│   ├── mod.rs              ← was bpf_map.rs (orchestrator stays here)
│   ├── publish_conntrack.rs ← per-AF helpers only (publish_v4_session, publish_v6_session)
└── bpf_map_tests.rs        (unchanged, still at afxdp/ scope; bpf_map/mod.rs
                             includes it via #[path = "../bpf_map_tests.rs"])
```

The directory promotion mirrors the layout used in #1326, #1345,
and #1352. Tests stay at the original `afxdp/` scope (parent of
the new `bpf_map/` directory) — moving them is unnecessary churn;
the test file's existing `use super::*;` keeps working because the
`#[path = "../bpf_map_tests.rs"] mod tests;` include in `bpf_map/mod.rs`
brings the test module back inside the `bpf_map` namespace.

The wave-2 prompt suggested `bpf_map/{mod,publish_ipv4,publish_ipv6}.rs`.
v2 instead consolidates the per-family helpers under a single
`publish_conntrack.rs` because (a) the dispatch lives in `mod.rs`
alongside any shared zone/flag computation and (b) splitting
**further** into per-family files gives two ~80-LOC files that are
mirror images of each other — that's the kind of cohesion-violating
fragmentation AGY r1 flagged on #1345. The cohesion line for this
fan-out is "BPF conntrack publish" not "address family"; the
per-family functions live together because they share the
orchestrator and the flag/zone computation.

If reviewers prefer the stricter per-AF layout the prompt sketched,
that's a minor variant — argue in the code review.

### Function shape

The **orchestrator stays in `bpf_map/mod.rs`**. Only the per-family
helpers move into the child `publish_conntrack.rs`. This sidesteps the
`pub(super) use` privacy hazard Codex r1 flagged: the orchestrator's
visibility never changes, and the helpers don't need to be re-exported.

```rust
// bpf_map/mod.rs — orchestrator (~25 LOC, unchanged signature)

use publish_conntrack::{publish_v4_session, publish_v6_session};

pub(super) fn publish_bpf_conntrack_entry(
    conntrack_v4_fd: c_int,
    conntrack_v6_fd: c_int,
    key: &SessionKey,
    decision: SessionDecision,
    metadata: &SessionMetadata,
    _zone_name_to_id: &FastMap<String, u16>,
) {
    let ingress_zone_id = metadata.ingress_zone;
    let egress_zone_id = metadata.egress_zone;
    let now_secs = monotonic_nanos() / 1_000_000_000;

    let mut flags: u8 = 0;
    if decision.nat.rewrite_src.is_some() { flags |= SESS_FLAG_SNAT; }
    if decision.nat.rewrite_dst.is_some() { flags |= SESS_FLAG_DNAT; }

    match (key.addr_family as i32, &key.src_ip, &key.dst_ip) {
        (libc::AF_INET, IpAddr::V4(src), IpAddr::V4(dst)) if conntrack_v4_fd >= 0 => {
            publish_v4_session(
                conntrack_v4_fd, key, *src, *dst,
                decision, metadata, flags,
                ingress_zone_id, egress_zone_id, now_secs,
            );
        }
        (libc::AF_INET6, IpAddr::V6(src), IpAddr::V6(dst)) if conntrack_v6_fd >= 0 => {
            publish_v6_session(
                conntrack_v6_fd, key, *src, *dst,
                decision, metadata, flags,
                ingress_zone_id, egress_zone_id, now_secs,
            );
        }
        _ => {}
    }
}

mod publish_conntrack;
```

```rust
// bpf_map/publish_conntrack.rs

use super::{
    BpfSessionKeyV4, BpfSessionValueV4, BpfSessionKeyV6, BpfSessionValueV6,
    SESS_FLAG_SNAT, SESS_FLAG_DNAT, SESS_STATE_ESTABLISHED,
    reverse_session_key,
};
use crate::session::{SessionDecision, SessionKey, SessionMetadata};
use std::ffi::{c_int, c_void};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub(super) fn publish_v4_session(
    conntrack_v4_fd: c_int,
    key: &SessionKey,
    src: Ipv4Addr,
    dst: Ipv4Addr,
    decision: SessionDecision,
    metadata: &SessionMetadata,
    flags: u8,
    ingress_zone_id: u16,
    egress_zone_id: u16,
    now_secs: u64,
) {
    // exact body of the AF_INET arm from lines 474-562
}

pub(super) fn publish_v6_session( /* same shape with v6 structs */ ) { ... }
```

The helpers are `pub(super)` so the parent `mod.rs` orchestrator can
call them. They are NOT re-exported further — only the orchestrator's
`pub(super) fn publish_bpf_conntrack_entry` reaches `afxdp` callers.
The submodule's items remain scoped to `bpf_map`.

Why `pub(super)` on helpers is safe here: the orchestrator lives in
the **parent** of `publish_conntrack`, so the helpers must be visible
to `bpf_map/mod.rs`. `pub(super)` is exactly the visibility that says
"reachable from the parent module, no farther." This is structurally
different from Codex's flagged hazard, which was about re-exporting
a `pub(super)` item across module boundaries via `pub(super) use`.
Here there is no re-export — the parent simply calls the child.

### Orchestrator size

~25 LOC after extraction (signature + zone-id derivation + flag
compute + dispatch). The two per-family helpers are roughly 80 LOC
each — well under the 100-LOC soft cap and the 200-LOC hard cap.

### Imports

`publish_conntrack.rs` reaches the BPF struct types, `SESS_*`
constants, and `reverse_session_key` via `use super::{…}`. Because
`publish_conntrack` is a child module of `bpf_map`, it has implicit
access to all private items in `bpf_map/mod.rs` — **no visibility
bumps required**. The `use super::{…}` is just for ergonomic
unqualified names.

Other needs:
- `std::net::{IpAddr, Ipv4Addr, Ipv6Addr}` explicitly.
- `std::ffi::{c_int, c_void}`, `std::io` for the `libbpf_sys` call sites.
- `libbpf_sys` (workspace dep, already used by parent).
- `libc` (workspace dep).
- `crate::session::{SessionDecision, SessionKey, SessionMetadata}`.

### `mod.rs` + parent-module updates

Three mechanical changes outside the new submodule:

1. **`userspace-dp/src/afxdp/mod.rs:59-60`**: change
   `#[path = "bpf_map.rs"] mod bpf_map;` →
   `#[path = "bpf_map/mod.rs"] mod bpf_map;`. Matches the existing
   `forwarding/mod.rs` and `frame/mod.rs` registrations at
   lines 65-66 and 69-70.

2. **`bpf_map.rs` → `bpf_map/mod.rs`** via `git mv` (verbatim move,
   then the 204-LOC `publish_bpf_conntrack_entry` body shrinks to
   the ~25-LOC orchestrator + `mod publish_conntrack;` declaration).

3. **The `#[cfg(test)] #[path = "bpf_map_tests.rs"] mod tests;`
   block at the new `bpf_map/mod.rs` tail** (was line 1189-1191)
   becomes `#[path = "../bpf_map_tests.rs"] mod tests;`. After the
   directory promotion, the relative path resolves up one level to
   the sibling `afxdp/bpf_map_tests.rs`, which stays in place.

**No visibility bumps.** `BpfSessionKey/Value V4/V6`, `SESS_FLAG_SNAT`,
`SESS_FLAG_DNAT`, `SESS_STATE_ESTABLISHED` all stay private at
`bpf_map/mod.rs` scope. The child `publish_conntrack` module reaches
them via Rust's parent-private-item access rule.

## Public API preservation

`publish_bpf_conntrack_entry` keeps its existing signature (file
descriptors, `SessionKey`, `SessionDecision`, `SessionMetadata`,
`FastMap<String, u16>`). No call site changes — the re-export
keeps the symbol path identical (`super::publish_bpf_conntrack_entry`
from the caller's perspective).

Confirmed call sites (**5 actual calls + 1 doc/comment reference**):
- `bpf_map.rs:839` (becomes `bpf_map/mod.rs`)
- `bpf_map.rs:853` (becomes `bpf_map/mod.rs`)
- `poll_descriptor.rs:915`
- `poll_descriptor.rs:1482`
- `poll_descriptor.rs:2782`
- `bpf_map_tests.rs:197` — **doc comment only, no code call**.

All 5 actual callers reach `publish_bpf_conntrack_entry` via
`use super::*;` (poll_descriptor.rs:1 reads `use super::*;` which
re-exports from `afxdp/mod.rs`). The orchestrator keeps its
`pub(super)` visibility on the parent `bpf_map/mod.rs` — symbol
resolution is identical pre/post split.

## Hidden invariants the change must preserve

1. **`now_secs` is computed once.** Each family arm reads it. The
   orchestrator computes it once and passes it down, which is
   what the original does. Don't recompute inside each helper —
   they'd diverge by nanoseconds.

2. **Flag computation order matters for diffability.** SNAT bit
   (1<<0) before DNAT bit (1<<1) — match the original.

3. **Zone IDs come from `metadata`, NOT from `_zone_name_to_id`.**
   The `_zone_name_to_id` parameter is already unused (#919 made
   zones `u16` directly in `SessionMetadata`). It stays in the
   signature for caller compat. Don't rename / remove in this PR.

4. **Early-return path on cross-family reverse key (equivalence
   spelled out per AGY r1).** Both arms have `_ => return,` paths
   inside `match rev.src_ip { … }` and `match rev.dst_ip { … }`
   (v4: lines 489, 500; v6: lines 578, 589). After extraction
   those `return` statements exit the per-family helper instead
   of the orchestrator.

   This is byte-identical in observable effect to the original.
   Original semantics: skip the BPF map write entirely, fall
   through to the closing `}` of the `match`, exit the function.
   Post-split semantics: skip the BPF map write inside the helper,
   `return` to the orchestrator's `match` arm, which is the final
   statement in the orchestrator, so the orchestrator immediately
   exits as well. **No fallthrough to the other family arm** —
   the helpers are only entered when the address-family pattern
   matched, and the original code didn't try the other family
   either (the `match` arms are mutually exclusive). The
   `_ => {}` catch-all in the orchestrator continues to handle
   mixed-family edge cases (e.g., `addr_family=AF_INET` but
   `IpAddr::V6` for source) by doing nothing, same as today.

5. **`eprintln!("xpf-ha: …")` text is preserved verbatim.** The
   project memory `Rust helper: eprintln!("xpf-ha: ...") goes to
   journald via stderr. Use sparingly` already constrains these.
   Two messages exist (`conntrack v4 map update failed`,
   `conntrack v6 map update failed`). Don't merge or unify.

6. **`#[repr(C, packed)]` on the BPF key structs.** Visibility
   bumps don't touch repr. Verify after the bump.

7. **`pub(super)` bump on private constants doesn't change the
   constant's value.** Trivially true but worth restating.

8. **HA session-sync portability.** The BPF map write is what HA
   peer reads via `iter_with_idle` / kernel-local mirror. Byte
   layout of `BpfSessionValueV4` / `…V6` is unchanged; only the
   Rust function that builds it moved. Wire-compatible.

9. **No new allocations.** Both helpers stack-allocate the
   `BpfSessionKey*` / `BpfSessionValueV*` structs (already true)
   and pass raw pointers to `libbpf_sys`. No `Box`, no `Vec`.

10. **Helper visibility scoped to bpf_map.** `publish_v4_session`
    and `publish_v6_session` are declared `pub(super)` in
    `publish_conntrack.rs` so the parent `bpf_map/mod.rs`
    orchestrator can call them. They are NOT re-exported further
    and do NOT leak past the `bpf_map` module boundary. (v1
    proposed file-private `fn`; v2 changed to `pub(super)` once
    the orchestrator moved up to `mod.rs` and needed to call the
    helpers from the parent.)

## Risk assessment

| Class | Level | Rationale |
|---|---|---|
| Behavioral regression | **LOW** | Pure code motion. Each helper's body is byte-identical to the corresponding match arm. Field order, byte order, flag bits, struct init all preserved. Compiler will catch any field-name mismatch. |
| Lifetime / borrow-checker | **LOW** | Helpers take `&SessionKey`, copy `Ipv4Addr`/`Ipv6Addr`, take `SessionDecision` by value (already `Copy` per its definition), `&SessionMetadata`. No new lifetimes. |
| Performance regression | **NONE** | Function fires on conntrack publish (session install path), not per-packet. Even if the compiler doesn't inline, any per-publish overhead of one extra call frame is dwarfed by the `libbpf_sys::bpf_map_update_elem` syscall the helper already performs. No new allocations. |
| Architectural mismatch (#961 / #946-Phase-2 pattern) | **LOW** | The issue is a Tier-1 hard-cap violation. The fix is a per-family fan-out — same cohesion principle as the wave-2 batch already merged. No premise to fail. The only architectural option-call is "single file with extracted helpers" vs "directory with submodule" — the directory route is what the wave-2 prompt asked for and matches recent merged PRs. |

## Test plan

- [ ] `cargo build --release` clean (no warnings, no errors)
- [ ] `cargo test --release` — full suite passes (current count
      should match pre-refactor)
- [ ] Named test 5/5 flake check: `bpf_map_tests.rs:197` is
      **adjacent coverage**, not direct — it manually constructs the
      `BpfSessionKeyV4` and verifies byte-order (`to_be()`). It does
      not call `publish_bpf_conntrack_entry`. Still useful as a
      regression net for the visibility and struct-import paths the
      split touches. Run the containing test 5×.
- [ ] Go suite — `make test` 30 packages pass (the Go conntrack
      bridge sits behind userspace-dp control socket, no direct
      coupling).
- [ ] **No per-PR smoke** per wave-2 rule. Marker after 4-of-4
      attestation; cluster smoke is batched at #1477 end-of-chain.

## Out of scope (explicitly)

- **Splitting `delete_bpf_conntrack_entry`.** Same v4/v6 pattern,
  ~40 LOC body, under the soft cap. Not a Tier-1 violator.
- **Splitting `refresh_bpf_conntrack_last_seen`.** ~78 LOC body,
  under the soft cap. Not a Tier-1 violator. Has the same v4/v6
  arm pattern but extracting it would be churn-for-churn's-sake.
- **Removing the unused `_zone_name_to_id` parameter.** That is
  a public API change at the callee, requires touching all
  callers, and belongs in its own dead-parameter PR.
- **Unifying v4 / v6 via a generic `BpfSessionEntryBuilder<T>`.**
  Issue body explicitly calls this out: "Don't pitch this here —
  it crosses into 'Refactor: <Pattern>' territory which has 100%
  PLAN-KILL rate on this codebase."
- **Moving `bpf_map_tests.rs` under `bpf_map/`.** Tests stay at
  `afxdp/` scope — moving them is parallel work that touches more
  files for zero structural win.

## Open questions for adversarial review

1. **Is the directory split (`bpf_map/{mod,publish_conntrack}.rs`)
   the right shape, or should the per-family helpers live in two
   separate files (`publish_v4.rs` / `publish_v6.rs`) as the
   wave-2 prompt sketched?** The plan argues a single
   `publish_conntrack.rs` for cohesion; the prompt's two-file
   variant is also defensible. PLAN-KILL on this point if either
   reviewer thinks the consolidation undermines the issue's
   address-family fan-out intent.

2. **Is bumping `BpfSessionKeyV4` / `BpfSessionValueV4` / `…V6` /
   `SESS_FLAG_*` / `SESS_STATE_ESTABLISHED` from private to
   `pub(super)` a meaningful encapsulation loss?** They were
   private to `bpf_map.rs`; they become `pub(super)`-scoped to
   `bpf_map/` module, which is still the same logical unit.
   Argue that this is an acceptable price for the split.

3. **Does the issue body's claim that this is "the smallest
   Tier-1 fn in the audit, defer if higher-impact land first"
   mean the PR should be deferred entirely?** The wave-2 batch
   has shipped #1325/#1326/#1327/#1342/#1345/#1351/#1352 already —
   this is part of the same hygiene pass. Argue defer if you
   think the audit's higher-impact items haven't all landed.

4. **Is the orchestrator-then-helper shape (one function dispatches
   to two by address family) the right pattern, or should there be
   a single shared inner helper parametrized by a type-state /
   trait that handles both address families generically?** The
   issue body and the plan both say no — but if either reviewer
   thinks the parallel-structure duplication is itself the bug,
   propose it explicitly. PLAN-KILL is acceptable here.

5. **Are there hidden v4/v6 differences in the original 204-LOC
   body that the plan glosses over?** Walk both arms (449-562 v4,
   563-651 v6) and confirm they differ only in struct type,
   `nat_src_ip` / `nat_dst_ip` shape (`u32` vs `[u8;16]`), and the
   `eprintln!` text — i.e., no behavior difference the split
   would accidentally erase or unify.

6. **Should `now_secs` be computed inside each helper instead of
   the orchestrator?** Plan says no (timing invariance). But it
   adds the orchestrator-helper coupling. PLAN-KILL on this point
   would push for either inlining the timestamp or making it
   a parameter on a shared `PublishCtx` struct. Argue either way.

7. **Does the project memory `feedback_refactor_module_dir_layout`
   apply here?** Plan assumes yes (uses `bpf_map/mod.rs`). Confirm
   that the project standard is directory-with-`mod.rs`, not
   `bpf_map.rs` + sibling `bpf_map/` (the latter is the new-style
   Rust idiom but apparently not the convention here).

8. **Is "no per-PR smoke, marker after 4-of-4 attestation" the
   right call for this PR?** The wave-2 batch carries that policy
   from project memory (`feedback_retirement_batch_smoke_at_end`,
   except this isn't retirement — it's the wave-2 hygiene pass).
   Argue if you think this specific PR needs its own smoke before
   merge because it touches conntrack publish (an HA session-sync
   path).
