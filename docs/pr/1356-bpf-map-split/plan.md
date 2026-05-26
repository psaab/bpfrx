# #1356 — Split `bpf_map.rs` 204-LOC `publish_bpf_conntrack_entry` into per-address-family helpers

**Status:** DRAFT v1 — pending adversarial plan review.

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
  `bpf_map.rs`. After the split, they need to be visible to the
  per-family submodules — `pub(super)` on the structs and constants
  is sufficient.
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
│   ├── mod.rs              ← was bpf_map.rs (everything except publish_conntrack)
│   ├── publish_conntrack.rs ← orchestrator + per-AF helpers
└── bpf_map_tests.rs        (unchanged, still at afxdp/ scope)
```

The directory promotion mirrors the layout used in #1326, #1345,
and #1352. Tests stay at the original `afxdp/` scope (parent of
the new `bpf_map/` directory) — moving them is unnecessary churn
and they already use `super::super::` paths via the existing
`#[path = ...]` include.

The wave-2 prompt suggested `bpf_map/{mod,publish_ipv4,publish_ipv6}.rs`.
The plan instead consolidates the per-family helpers under a single
`publish_conntrack.rs` because (a) the dispatch lives there alongside
the helpers and (b) splitting **further** into per-family files
gives two ~75-LOC files that are mirror images of each other —
that's the kind of cohesion-violating fragmentation AGY r1 flagged
on #1345. The cohesion line for this fan-out is "BPF conntrack
publish" not "address family"; the per-family functions live
together because they share the orchestrator and the flag/zone
computation.

If reviewers prefer the stricter per-AF layout the prompt sketched,
that's a minor variant the implementer can ship — argue this point
in your verdict.

### Function shape

```rust
// publish_conntrack.rs

use super::*;
use crate::session::{SessionDecision, SessionKey, SessionMetadata};
use std::net::IpAddr;

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

fn publish_v4_session(
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
    // exact body of the AF_INET arm, from line 474 onward
}

fn publish_v6_session( /* same shape with v6 structs */ ) { ... }
```

Per-family helpers are `fn` (module-private), not `pub(super)` —
they have only one caller each (the orchestrator) and don't need
to leak past the `publish_conntrack` module.

### Orchestrator size

~25 LOC after extraction (signature + zone-id derivation + flag
compute + dispatch). The two per-family helpers are roughly 80 LOC
each — well under the 100-LOC soft cap and the 200-LOC hard cap.

### Imports

`publish_conntrack.rs` needs:
- `super::*` to pick up `BpfSessionKeyV4` / `BpfSessionValueV4` /
  `BpfSessionKeyV6` / `BpfSessionValueV6` / `SESS_FLAG_*` /
  `SESS_STATE_ESTABLISHED` / `monotonic_nanos` / `reverse_session_key` /
  `FastMap`. These are all crate-internal already; only the
  `BpfSession*` structs and `SESS_*` constants need a visibility
  bump (currently private at module scope, will become `pub(super)`
  for the new module to reach them).
- `std::net::{IpAddr, Ipv4Addr, Ipv6Addr}` explicitly (currently
  `IpAddr` comes via `super::*`, `Ipv4Addr`/`Ipv6Addr` were not
  imported because the previous code only matched on the variant
  pattern).
- `libc` / `libbpf_sys` / `c_int` / `c_void` — re-exported via
  `super::*`.

### `mod.rs` update

`bpf_map.rs` becomes `bpf_map/mod.rs` (verbatim move except the
204-LOC function body removed and `pub mod publish_conntrack;` +
`pub(super) use publish_conntrack::publish_bpf_conntrack_entry;`
added at the top). All other call sites of
`publish_bpf_conntrack_entry` (poll_descriptor.rs, bpf_map.rs's
own callers inside `publish_session_map_entry_for_session_with_conntrack`)
keep their existing import paths because `publish_bpf_conntrack_entry`
is re-exported.

The struct/constant visibility bumps:
- `BpfSessionKeyV4` / `BpfSessionValueV4` — private → `pub(super)`
- `BpfSessionKeyV6` / `BpfSessionValueV6` — private → `pub(super)`
- `SESS_FLAG_SNAT` / `SESS_FLAG_DNAT` — `const … = …;` → `pub(super) const`
- `SESS_STATE_ESTABLISHED` — `const … = …;` → `pub(super) const`

None of these escape the `afxdp` parent module.

## Public API preservation

`publish_bpf_conntrack_entry` keeps its existing signature (file
descriptors, `SessionKey`, `SessionDecision`, `SessionMetadata`,
`FastMap<String, u16>`). No call site changes — the re-export
keeps the symbol path identical (`super::publish_bpf_conntrack_entry`
from the caller's perspective).

Confirmed call sites (8):
- `bpf_map.rs:839, 853` (will become `bpf_map/mod.rs`)
- `poll_descriptor.rs:915, 1482, 2782`
- `bpf_map_tests.rs:197` (comment reference only, no code)

The 4 actual callers (2 in mod.rs, 3 in poll_descriptor.rs) all
use the same path `publish_bpf_conntrack_entry(...)` via
`use super::*` or equivalent — none break.

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

4. **Early-return path on cross-family reverse key.** Both arms
   have `_ => return,` arms inside `match rev.src_ip { … }` and
   `match rev.dst_ip { … }`. After extraction those returns now
   exit the per-family helper instead of the orchestrator, which
   is the same observable effect (skip the BPF write entirely).
   No fallthrough to the other family — neither path tried that.

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

10. **Helper visibility scoped to module.** `publish_v4_session`
    and `publish_v6_session` are file-private (`fn`, not
    `pub(super)`). Don't widen.

## Risk assessment

| Class | Level | Rationale |
|---|---|---|
| Behavioral regression | **LOW** | Pure code motion. Each helper's body is byte-identical to the corresponding match arm. Field order, byte order, flag bits, struct init all preserved. Compiler will catch any field-name mismatch. |
| Lifetime / borrow-checker | **LOW** | Helpers take `&SessionKey`, copy `Ipv4Addr`/`Ipv6Addr`, take `SessionDecision` by value (already `Copy` per its definition), `&SessionMetadata`. No new lifetimes. |
| Performance regression | **NONE** | Function fires on conntrack publish (session install path), not per-packet. Even if the compiler doesn't inline, the per-publish overhead of one extra call frame is sub-nanosecond. No new allocations. |
| Architectural mismatch (#961 / #946-Phase-2 pattern) | **LOW** | The issue is a Tier-1 hard-cap violation. The fix is a per-family fan-out — same cohesion principle as the wave-2 batch already merged. No premise to fail. The only architectural option-call is "single file with extracted helpers" vs "directory with submodule" — the directory route is what the wave-2 prompt asked for and matches recent merged PRs. |

## Test plan

- [ ] `cargo build --release` clean (no warnings, no errors)
- [ ] `cargo test --release` — full suite passes (current count
      should match pre-refactor)
- [ ] Named test 5/5 flake check: `publish_bpf_conntrack_entry`
      has direct test coverage at `bpf_map_tests.rs:197` (byte-order
      / port `to_be()` verification). Run that specific test 5×.
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
