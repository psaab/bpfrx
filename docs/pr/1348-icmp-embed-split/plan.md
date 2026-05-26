# #1348 — icmp_embed.rs split + 10-param collapse (Wave-5)

**Status:** v2 — addresses Codex r1 PLAN-NEEDS-MAJOR (E0364
visibility trap, module declaration change, single-ctx design,
NPTv6 parse-API safety). Gemini r1 verdict was PLAN-READY.

## Codex r1 findings + dispositions

1. **E0364 visibility trap (BLOCKING)** — Rust forbids
   `pub(super) use` of a `pub(super)` child item; this is documented
   in `userspace-dp/src/afxdp/tx/mod.rs:38-42`. The v1 plan re-exported
   children with `pub(super) use builders::{...}`, which would not
   compile.
   **Disposition:** APPLIED. The new design defines the 8
   public-surface items as **wrapper functions / structs in
   `icmp_embed/mod.rs` itself**, with `pub(super)` visibility, and
   each wrapper delegates to a child item that is declared
   `pub(in crate::afxdp)` (or kept private and called via
   `use super::child::item` inside the wrapper body). No
   `pub(super) use child::item` of `pub(super)` child items.
2. **Module declaration change at afxdp/mod.rs:78 (BLOCKING)** —
   v1 said "import block untouched" but missed that
   `#[path = "icmp_embed.rs"] mod icmp_embed;` itself must change
   to `mod icmp_embed;` (with the new `icmp_embed/mod.rs`).
   **Disposition:** APPLIED. The path attribute is removed; the new
   declaration is `mod icmp_embed;` per afxdp's convention
   (`bpf_map`, `forwarding`, `frame`, `coordinator`,
   `poll_descriptor`, `cos` all use this exact form). The
   `use self::icmp_embed::{...}` imports at lines 148-154 keep the
   same item paths, so they ARE untouched, but the bare `mod`
   declaration replaces the `#[path]` form.
3. **Two ctx structs is muddy (BLOCKING)** — v1 sketched both an
   `EmbeddedReturnCtx<'a>` AND a `nat_match_v4::Ctx`, both holding
   `&mut SessionTable`. This is unsafe: two structs cannot
   simultaneously hold `&mut` to the same table.
   **Disposition:** APPLIED. There is now ONE struct,
   `NatMatchCtx<'a>`, defined in `icmp_embed/mod.rs`. It contains
   all 5 borrow refs the return-resolution path needs PLUS the
   `shared_nat_sessions` ref the v4/v6 NAT-match path needs.
   `embedded_icmp_return_resolution` is called as
   `embedded_icmp_return_resolution(ctx, ...)` and reborrows
   internally. The v4 and v6 match functions take
   `ctx: &mut NatMatchCtx<'_>` and pass it through to
   `embedded_icmp_return_resolution`. No second `Ctx` struct.
4. **NPTv6 parse safety (BLOCKING)** — v1 sketched
   `parse_embedded_v6_header` returning a generic `(proto, src,
   dst, l4_off)`. That risks callers mistakenly using a single
   "normalized" src and losing the wire-vs-translated distinction.
   **Disposition:** APPLIED. The v6 parse helper returns an
   `EmbeddedV6Header { proto, src_wire: Ipv6Addr, dst: IpAddr,
   l4_off: usize, src_port: u16, dst_port: u16 }`. The NPTv6
   translation is applied AT THE CALL SITE in `nat_match_v6.rs`
   (matching the current pattern at icmp_embed.rs:358-360), so the
   parse helper is incapable of accidentally normalising the
   source. The v4 parse helper returns `EmbeddedV4Header { proto,
   src: Ipv4Addr, dst: Ipv4Addr, l4_off, src_port, dst_port }`
   directly.

Non-blocking Codex findings:
- Perf framing sound.
- Granularity acceptable.
- Keep `use super::*;` globs in submodules for this pure-motion PR.

## Issue framing

`userspace-dp/src/afxdp/icmp_embed.rs` is 761 production LOC. Two
specific items cross the engineering-style thresholds:

- `try_embedded_icmp_nat_match_from_frame` (icmp_embed.rs:190) is a
  269-LOC body — Tier-1 (>200 LOC), 2.7x the 100-LOC cap.
- `embedded_icmp_return_resolution` (icmp_embed.rs:460) is a 10-param
  free function — over the 8-param cap.

Issue #1348 asks for two things:

1. Split `try_embedded_icmp_nat_match_from_frame` along its natural
   structural seams (v4 outer / v6 outer × parse / lookup / build
   match) into a module-with-foo layout
   (`icmp_embed/{mod,…}.rs`).
2. Collapse the 10-param `embedded_icmp_return_resolution` into a
   typed context struct.

## Honest scope/value framing

This is a pure code-motion + parameter-bundling refactor on the
embedded-ICMP NAT-reversal path. The hot-path call is from
`poll_descriptor/mod.rs:1221` — invoked only when the packet is an
ICMP error (ICMP type 3/11/12/etc. or ICMPv6 type 1/2/3/4) AND we are
on the NAT reversal path. That is a tiny minority of packets in
steady-state iperf3 traffic. The perf win at absolute scale is
essentially zero — the goal is **modularity and maintainability**, not
throughput.

The value is:

- Each of the four cases (v4 outer / v6 outer × forward-NAT-by-reverse
  / session-lookup-fallback) becomes individually readable.
- The 10-param fn collapses to a single `&EmbeddedReturnCtx` borrow,
  which is the same pattern already used in `forwarding/` and
  `bpf_map/` submodules.
- Future ICMP/ICMPv6 work (e.g. NPTv6 cross-family path, new ICMP
  error subtypes for NAT64) gets a cleaner seam to land on.

*If reviewers conclude the perf gain is too small to justify the
churn, PLAN-KILL is an acceptable verdict.* The counter-argument is
that the engineering-style doc explicitly lists the 100-LOC / 8-param
gates as triggers, and #1348 is one of several Wave-5 split PRs being
driven serially under that policy.

## What's already shipped / partially batched

- `icmp_embed.rs` itself is the post-#1476 retired-BPF-replacement
  Rust path for embedded-ICMP NAT reversal. Build-side
  `build_nat_reversed_icmp_error_v4/v6` and post-resolution
  `finalize_embedded_icmp_resolution` already sit alongside it.
- Sibling Wave-5 PRs are splitting other hot-path files
  (`snapshot.go` #1592, etc.) using the same "module/foo" convention.
- The afxdp module already uses the directory-with-`mod.rs` pattern
  for `bpf_map/`, `coordinator/`, `forwarding/`, `frame/`,
  `poll_descriptor/`, `cos/`. We follow that pattern.

The `EmbeddedIcmpMatch` struct (icmp_embed.rs:7) and the four sibling
`pub(super)` helpers (`try_embedded_icmp_session_match*`,
`try_embedded_icmp_nat_match*`, `build_nat_reversed_icmp_error_v4/v6`,
`finalize_embedded_icmp_resolution`) are imported by
`afxdp/mod.rs:148-154` and called from `poll_descriptor/mod.rs:1221+`.
Their `pub(super)` visibility plus exact signatures must be preserved
under the new module layout.

## Concrete design

### Module layout (v2)

```
userspace-dp/src/afxdp/icmp_embed/
├── mod.rs              // ALL pub(super) wrappers + EmbeddedIcmpMatch +
│                       //   NatMatchCtx<'a> definition. No `pub(super) use`
│                       //   of child items (avoid E0364).
├── parse.rs            // EmbeddedV4Header / EmbeddedV6Header parse helpers,
│                       //   embedded_reply_key, embedded_reply_ports.
│                       //   v6 parse returns src_wire (NOT translated).
├── session_match.rs    // lookup_embedded_session +
│                       //   try_embedded_icmp_session_match_from_frame impl
│                       //   (the v4 + v6 session-only path).
├── nat_match_v4.rs     // pub(in crate::afxdp::icmp_embed) match_outer_v4 +
│                       //   v4-outer body (~125 LOC).
├── nat_match_v6.rs     // pub(in crate::afxdp::icmp_embed) match_outer_v6 +
│                       //   v6-outer body (~130 LOC, applies NPTv6 inbound).
├── return_resolution.rs // pub(in crate::afxdp::icmp_embed)
│                       //   embedded_icmp_return_resolution (takes &mut NatMatchCtx).
└── builders.rs         // pub(in crate::afxdp::icmp_embed)
                        //   build_nat_reversed_icmp_error_v4/v6 +
                        //   finalize_embedded_icmp_resolution impls.
```

**Note on `afxdp/mod.rs` declaration change:** the current line
`#[path = "icmp_embed.rs"] mod icmp_embed;` (mod.rs:78-79) becomes
`mod icmp_embed;` (no `#[path]`). The `use self::icmp_embed::{...}`
imports at lines 148-154 reference exactly the same item names with
exactly the same `pub(super)` visibility, so they ARE textually
untouched.

### `icmp_embed/mod.rs` shape (~120 LOC)

This file owns the entire `pub(super)` surface. Wrappers (not `pub
use`) delegate to children to avoid E0364:

```rust
use super::*;

mod parse;
mod session_match;
mod nat_match_v4;
mod nat_match_v6;
mod return_resolution;
mod builders;

#[derive(Clone, Debug)]
pub(super) struct EmbeddedIcmpMatch {
    pub(super) nat: NatDecision,
    pub(super) original_src: IpAddr,
    pub(super) original_src_port: u16,
    pub(super) embedded_proto: u8,
    pub(super) resolution: ForwardingResolution,
    pub(super) metadata: SessionMetadata,
}

/// Borrow bundle threaded through both v4/v6 NAT-match paths and the
/// embedded-ICMP return-resolution helper. One struct only — both
/// the NAT lookup path (which needs `shared_nat_sessions`) and the
/// return-resolution path (which doesn't) share the same `&mut`
/// borrow on `SessionTable`, so co-existing two structs would be a
/// borrow-checker error.
pub(in crate::afxdp::icmp_embed) struct NatMatchCtx<'a> {
    pub sessions: &'a mut SessionTable,
    pub forwarding: &'a ForwardingState,
    pub dynamic_neighbors: &'a Arc<ShardedNeighborMap>,
    pub shared_sessions:
        &'a Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    pub shared_nat_sessions:
        &'a Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    pub shared_forward_wire_sessions:
        &'a Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
}

#[allow(dead_code)]
pub(super) fn try_embedded_icmp_session_match(
    area: &MmapArea,
    desc: XdpDesc,
    meta: UserspaceDpMeta,
    sessions: &mut SessionTable,
    now_ns: u64,
) -> Option<SessionLookup> {
    let frame = area.slice(desc.addr as usize, desc.len as usize)?;
    session_match::try_embedded_icmp_session_match_from_frame(
        frame, meta, sessions, now_ns,
    )
}

pub(super) fn try_embedded_icmp_session_match_from_frame(
    frame: &[u8],
    meta: UserspaceDpMeta,
    sessions: &mut SessionTable,
    now_ns: u64,
) -> Option<SessionLookup> {
    session_match::try_embedded_icmp_session_match_from_frame(
        frame, meta, sessions, now_ns,
    )
}

pub(super) fn try_embedded_icmp_nat_match(
    area: &MmapArea,
    desc: XdpDesc,
    meta: UserspaceDpMeta,
    sessions: &mut SessionTable,
    forwarding: &ForwardingState,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    shared_sessions:              &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions:          &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    now_ns: u64,
) -> Option<EmbeddedIcmpMatch> {
    let frame = area.slice(desc.addr as usize, desc.len as usize)?;
    try_embedded_icmp_nat_match_from_frame(
        frame, meta, sessions, forwarding, dynamic_neighbors,
        shared_sessions, shared_nat_sessions, shared_forward_wire_sessions, now_ns,
    )
}

#[inline]
pub(super) fn try_embedded_icmp_nat_match_from_frame(
    frame: &[u8],
    meta: UserspaceDpMeta,
    sessions: &mut SessionTable,
    forwarding: &ForwardingState,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    shared_sessions:              &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions:          &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    now_ns: u64,
) -> Option<EmbeddedIcmpMatch> {
    let l4 = meta.l4_offset as usize;
    let icmp_type = *frame.get(l4)?;
    if !is_icmp_error(meta.protocol, icmp_type) {
        return None;
    }
    let mut ctx = NatMatchCtx {
        sessions, forwarding, dynamic_neighbors,
        shared_sessions, shared_nat_sessions, shared_forward_wire_sessions,
    };
    match meta.protocol {
        PROTO_ICMP   => nat_match_v4::match_outer_v4(frame, meta, &mut ctx, now_ns),
        PROTO_ICMPV6 => nat_match_v6::match_outer_v6(frame, meta, &mut ctx, now_ns),
        _ => None,
    }
}

pub(super) fn build_nat_reversed_icmp_error_v4(
    frame: &[u8], meta: UserspaceDpMeta, icmp_match: &EmbeddedIcmpMatch,
) -> Option<Vec<u8>> {
    builders::build_nat_reversed_icmp_error_v4(frame, meta, icmp_match)
}

pub(super) fn build_nat_reversed_icmp_error_v6(
    frame: &[u8], meta: UserspaceDpMeta, icmp_match: &EmbeddedIcmpMatch,
) -> Option<Vec<u8>> {
    builders::build_nat_reversed_icmp_error_v6(frame, meta, icmp_match)
}

pub(super) fn finalize_embedded_icmp_resolution(
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    now_secs: u64,
    ingress_ifindex: i32,
    icmp_match: &EmbeddedIcmpMatch,
) -> ForwardingResolution {
    builders::finalize_embedded_icmp_resolution(
        forwarding, ha_state, now_secs, ingress_ifindex, icmp_match,
    )
}
```

The wrapper-function pattern is mandatory here: a `pub(super) use
child::item;` where `child` is declared `mod child;` (private) and
`item` is `pub(in icmp_embed)` would trigger E0364. By placing the
`pub(super)` items directly in `mod.rs` and delegating to private
children via direct function calls, we sidestep that trap entirely.
The forwarding state struct types (e.g. `SessionLookup`,
`NatDecision`, `ForwardingResolution`, etc.) come in via `use
super::*;` from `afxdp/mod.rs`.

### `return_resolution.rs` (~25 LOC)

```rust
use super::*;

#[inline]
pub(in crate::afxdp::icmp_embed) fn embedded_icmp_return_resolution(
    ctx: &mut NatMatchCtx<'_>,
    forward_key: &SessionKey,
    forward_decision: SessionDecision,
    original_src: IpAddr,
    now_ns: u64,
) -> ForwardingResolution {
    let reverse_key = reverse_session_key(forward_key, forward_decision.nat);
    if let Some(reverse) = lookup_session_across_scopes(
        ctx.sessions,
        ctx.shared_sessions,
        ctx.shared_forward_wire_sessions,
        &reverse_key,
        now_ns,
        0,
    ) {
        return reverse.lookup.decision.resolution;
    }
    lookup_forwarding_resolution_with_dynamic(
        ctx.forwarding, ctx.dynamic_neighbors, original_src,
    )
}
```

5 params total (was 9 + self / 10 free fn): `ctx`, `forward_key`,
`forward_decision`, `original_src`, `now_ns`.

### `parse.rs` (~80 LOC) — wire-safe v6 parse

```rust
use super::*;

pub(in crate::afxdp::icmp_embed) struct EmbeddedV4Header {
    pub proto: u8,
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub l4_off: usize,
    pub src_port: u16,
    pub dst_port: u16,
}

pub(in crate::afxdp::icmp_embed) struct EmbeddedV6Header {
    pub proto: u8,
    /// Wire-form embedded source. NPTv6 inbound translation, if any,
    /// MUST be applied at the call site (see nat_match_v6.rs). The
    /// parser does not translate.
    pub src_wire: Ipv6Addr,
    pub dst: IpAddr,            // already wrapped IpAddr::V6
    pub l4_off: usize,
    pub src_port: u16,
    pub dst_port: u16,
}

pub(in crate::afxdp::icmp_embed) fn parse_embedded_v4(
    frame: &[u8], embedded_ip_start: usize,
) -> Option<EmbeddedV4Header> { /* mirror icmp_embed.rs:210-245 */ }

pub(in crate::afxdp::icmp_embed) fn parse_embedded_v6(
    frame: &[u8], embedded_ip_start: usize,
) -> Option<EmbeddedV6Header> { /* mirror icmp_embed.rs:333-357 */ }

pub(in crate::afxdp::icmp_embed) fn embedded_reply_key(
    addr_family: u8, protocol: u8,
    src_ip: IpAddr, dst_ip: IpAddr,
    src_port: u16, dst_port: u16,
) -> SessionKey { /* unchanged from icmp_embed.rs:504-521 */ }

pub(in crate::afxdp::icmp_embed) fn embedded_reply_ports(
    protocol: u8, src_port: u16, dst_port: u16,
) -> (u16, u16) { /* unchanged from icmp_embed.rs:523-529 */ }
```

The `EmbeddedV6Header.src_wire` field name encodes the invariant in
the type system: anyone wanting a "translated" source must apply
`forwarding.nptv6.translate_inbound(&mut hdr.src_wire)` themselves
into a freshly-named local, then build keys appropriately.

### `nat_match_v4.rs` / `nat_match_v6.rs` shape

```rust
// nat_match_v4.rs
use super::*;
use super::parse::{parse_embedded_v4, embedded_reply_key};
use super::return_resolution::embedded_icmp_return_resolution;

pub(in crate::afxdp::icmp_embed) fn match_outer_v4(
    frame: &[u8],
    meta: UserspaceDpMeta,
    ctx: &mut NatMatchCtx<'_>,
    now_ns: u64,
) -> Option<EmbeddedIcmpMatch> {
    let l4 = meta.l4_offset as usize;
    let embedded_ip_start = l4 + 8;
    if frame.len() < embedded_ip_start + 28 { return None; }
    let hdr = parse_embedded_v4(frame, embedded_ip_start)?;
    let emb_src = IpAddr::V4(hdr.src);
    let emb_dst = IpAddr::V4(hdr.dst);
    let embedded_key = SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: hdr.proto,
        src_ip: emb_src, dst_ip: emb_dst,
        src_port: hdr.src_port, dst_port: hdr.dst_port,
    };
    let reverse_key = embedded_reply_key(
        libc::AF_INET as u8, hdr.proto,
        emb_src, emb_dst, hdr.src_port, hdr.dst_port,
    );
    // ----- forward-NAT-by-reverse path -----
    if let Some(fwd) = lookup_forward_nat_across_scopes(
        ctx.sessions, ctx.shared_nat_sessions, &reverse_key,
    ) {
        let nat = fwd.decision.nat;
        let original_src = fwd.key.src_ip;
        let original_src_port = fwd.key.src_port;
        let resolution = embedded_icmp_return_resolution(
            ctx, &fwd.key, fwd.decision, original_src, now_ns,
        );
        return Some(EmbeddedIcmpMatch {
            nat, original_src, original_src_port,
            embedded_proto: hdr.proto,
            resolution, metadata: fwd.metadata,
        });
    }
    // ----- session-fallback path -----
    lookup_session_across_scopes(
        ctx.sessions, ctx.shared_sessions, ctx.shared_forward_wire_sessions,
        &embedded_key, now_ns, 0,
    )
    .or_else(|| lookup_session_across_scopes(
        ctx.sessions, ctx.shared_sessions, ctx.shared_forward_wire_sessions,
        &reverse_key, now_ns, 0,
    ))
    .map(|resolved| {
        let sl = resolved.lookup;
        let resolution = if sl.metadata.is_reverse {
            sl.decision.resolution
        } else {
            embedded_icmp_return_resolution(
                ctx, &embedded_key, sl.decision, emb_src, now_ns,
            )
        };
        EmbeddedIcmpMatch {
            nat: sl.decision.nat,
            original_src: emb_src,
            original_src_port: hdr.src_port,
            embedded_proto: hdr.proto,
            resolution, metadata: sl.metadata,
        }
    })
}
```

Reborrow note: `ctx: &mut NatMatchCtx<'_>` is reborrowed implicitly
each time it crosses a function-call boundary. The forward-NAT
branch returns via `return Some(...)` BEFORE entering the fallback
branch, so the two `embedded_icmp_return_resolution(ctx, ...)` calls
in the same fn are mutually-exclusive control-flow paths. Inside the
fallback's `.or_else(|| ...)` / `.map(|resolved| ...)`, the
sequential evaluation contract Gemini already confirmed holds: the
`or_else` closure is consumed before the `map` closure runs. The
`map` closure captures `ctx` again by `&mut`, after the chained
lookups are done.

The v6 version is structurally identical, but applies
`forwarding.nptv6.translate_inbound(&mut emb_src_lookup_v6)` AT THE
CALL SITE on a local copy of `hdr.src_wire`, then uses
`hdr.src_wire` for the `reverse_key` (forward-NAT branch) and the
translated `emb_src_lookup` for `embedded_key` AND for
`shared_reverse_key` (fallback branch), exactly mirroring
icmp_embed.rs:358-419.

### Behavioral invariants (literal, NOT to be changed)

- v6 outer path applies `forwarding.nptv6.translate_inbound(&mut
  emb_src_lookup_v6)` on the embedded source BEFORE building the
  embedded `SessionKey` (icmp_embed.rs:358-360). The `reverse_key`
  uses the **wire** address (`emb_src_wire.into()`,
  icmp_embed.rs:372), not the translated address. The
  `shared_reverse_key` inside the fallback branch uses the
  **translated** `emb_src_lookup` (icmp_embed.rs:415). Splitting must
  preserve this asymmetry.
- `embedded_reply_ports` swaps src/dst ports for TCP/UDP but NOT for
  ICMP/ICMPv6 (where "ports" are echo id).
- `lookup_forward_nat_across_scopes` is consulted FIRST, before the
  `lookup_session_across_scopes` fallback. If both find a hit, the
  first wins. Don't reorder.
- `EmbeddedIcmpMatch.original_src_port` is set from the embedded src
  port on the session-fallback path, but from `fwd.key.src_port` on
  the forward-NAT path.
- When `sl.metadata.is_reverse` is true, we use
  `sl.decision.resolution` directly and DO NOT call
  `embedded_icmp_return_resolution`. The call only happens on
  forward-direction matches.

### Public API preservation

These 5 items keep their exact signatures and `pub(super)` visibility,
imported the same way from `afxdp/mod.rs`:

- `EmbeddedIcmpMatch` (struct, with all 6 fields)
- `try_embedded_icmp_nat_match_from_frame(frame, meta, sessions,
  forwarding, dynamic_neighbors, shared_sessions, shared_nat_sessions,
  shared_forward_wire_sessions, now_ns)`
- `try_embedded_icmp_nat_match(area, desc, meta, sessions, forwarding,
  dynamic_neighbors, shared_sessions, shared_nat_sessions,
  shared_forward_wire_sessions, now_ns)`
- `try_embedded_icmp_session_match_from_frame(frame, meta, sessions,
  now_ns)`
- `try_embedded_icmp_session_match(area, desc, meta, sessions, now_ns)`
- `build_nat_reversed_icmp_error_v4(frame, meta, icmp_match)`
- `build_nat_reversed_icmp_error_v6(frame, meta, icmp_match)`
- `finalize_embedded_icmp_resolution(forwarding, ha_state, now_secs,
  ingress_ifindex, icmp_match)`

`embedded_icmp_return_resolution`, `lookup_embedded_session`,
`embedded_reply_key`, `embedded_reply_ports` are private; their
signatures may change. Only `embedded_icmp_return_resolution` changes
shape (typed ctx); the other three are pure code-motion.

`afxdp/mod.rs:148-154` import block is untouched.

## Hidden invariants the change must preserve

- **Side-effect ordering**: `lookup_forward_nat_across_scopes`
  consulted before `lookup_session_across_scopes` (both can mutate
  `sessions` via internal `lookup`). The two ICMP types (v4-outer vs
  v6-outer) MUST NOT cross-pollute lookups.
- **NPTv6 translation gate**: applied ONLY on v6 outer, BEFORE
  building `embedded_key`, NOT on the `reverse_key` for
  `lookup_forward_nat_across_scopes`, and applied AGAIN on
  `shared_reverse_key`. The original code is intentionally split
  across two `embedded_reply_key` calls (wire vs lookup); the refactor
  must keep both.
- **Allocation rules**: ZERO new per-packet heap allocations. The
  `EmbeddedReturnCtx` struct is a borrow bundle (no `Box`, no `Arc`
  clones). `nat_match_v4::Ctx` similarly is a stack-local borrow
  bundle. `#[inline]` on the dispatch fn ensures the compiler can
  flatten the indirection.
- **HA sync portability**: none of the maps' wire shapes change.
  `EmbeddedIcmpMatch` is internal to userspace-dp; not serialized to
  HA peer.
- **Stale-handle hazards**: `&mut SessionTable` mutable borrow flows
  through the context struct; cannot be split into two simultaneous
  `&mut` paths. The plan keeps a single mut borrow on the context,
  consistent with current behavior.
- **Lifetime/borrow-checker shape**: `EmbeddedReturnCtx<'a>` holds
  `&'a mut SessionTable` + 4× `&'a Arc<…>` / `&'a …`. Callers must
  reborrow when calling within a branch. This pattern is used
  elsewhere in afxdp (e.g. `forwarding_build`, `forwarding/`); no new
  lifetime gymnastics.
- **`#[inline]` hint preservation**: hot dispatch fn
  (`try_embedded_icmp_nat_match_from_frame`) gets `#[inline]` so the
  compiler can fold the family-dispatch back into the caller. Inner
  `match_outer_v4` / `match_outer_v6` are NOT `#[inline]` — they're
  cold-ish (only embedded-ICMP errors hit them) and inlining them
  would bloat I-cache for code that runs on a rare path.

## Risk assessment

| Class | Severity | Notes |
|---|---|---|
| Behavioral regression | LOW | Pure code-motion + struct bundling; no logic change |
| Lifetime/borrow-checker | LOW-MED | `EmbeddedReturnCtx<'a>` holds 5 borrow refs incl. `&mut SessionTable`. Must reborrow carefully across the two paths in each v4/v6 branch |
| Performance regression | LOW | Hot path is ICMP-error only (rare); `#[inline]` on dispatch keeps it folded; ctx struct is stack |
| Architectural mismatch (#961 / #946-P2) | LOW | Issue body already sketches the split; afxdp/ already uses dir-with-mod.rs pattern; this is not a re-architecture, just a sibling split |

## Test plan

- `cargo build` clean
- `TMPDIR=/dev/shm CARGO_TARGET_DIR=/dev/shm/cargo cargo test --release`
  — full 952+ test suite
- Existing icmp_embed tests at `userspace-dp/src/afxdp/tests.rs:2279`,
  `:2427`, `:2569`, `:2617` (4 known call sites of
  `try_embedded_icmp_nat_match_from_frame`) MUST pass unchanged
- 5/5 named-test flake check on the affected tests
- Go suite: 30 packages pass
- **No per-PR smoke** — per Wave-5 batch-merge rule. Post
  `<!-- AWAITING-BATCH-MERGE -->` after 4-of-4 attestation.

## Out of scope (explicitly)

- Tightening the embedded-ICMP NAT reversal logic itself (deferred
  to #867 follow-up).
- Adding new tests for icmp_embed beyond what exists today.
- Touching `lookup_forward_nat_across_scopes`,
  `lookup_session_across_scopes`,
  `lookup_forwarding_resolution_with_dynamic`,
  `reverse_session_key`, or any shared session helper.
- Merging the v4 + v6 branches into a generic family-parameterised
  function (the asymmetry around NPTv6 and IPv6 reverse-key wire
  semantics makes a generic merge unsafe in this PR).
- Inline-test colocation under `icmp_embed/tests.rs`. The issue body
  *mentions* this as a follow-up opportunity; we don't include it in
  this PR to keep the diff pure code-motion.

## Open questions for adversarial review

1. **Is `#[inline]` on `try_embedded_icmp_nat_match_from_frame`
   correct?** The function dispatches on `meta.protocol` (PROTO_ICMP
   vs PROTO_ICMPV6) — inlining lets the compiler fold the match into
   the caller, but inflates I-cache if the caller is itself cold.
   PLAN-KILL-worthy if the call frequency at
   `poll_descriptor/mod.rs:1221` is hot enough that I-cache pressure
   matters. (Argument for: it's already on a rare path — only entered
   when `parsed_icmp_error` is true.)

2. **Does collapsing 10 params to a struct cause a measurable extra
   indirection on a hot path?** The current 10-arg fn fits in
   registers/spills cleanly; a `&EmbeddedReturnCtx` may force a
   pointer dereference for each of the 5 refs. If the inliner doesn't
   flatten this, we add ~5 loads per call. Argument for: the call
   site is `is_icmp_error == true` only — cold path.

3. **Is the v6 `embedded_reply_key` asymmetry (wire vs translated)
   correctly preserved if v6 path is moved to `nat_match_v6.rs`?**
   The current code calls `embedded_reply_key(…, emb_src_wire.into(),
   …)` for the forward-NAT branch (icmp_embed.rs:369-376) but later
   builds `shared_reverse_key` with `emb_src_lookup` (the
   NPTv6-translated form, icmp_embed.rs:412-419). Splitting risks
   accidentally unifying these.

4. **Should `lookup_embedded_session` move to `parse.rs` or to
   `session_match.rs`?** It's called only from
   `try_embedded_icmp_session_match_from_frame`, so
   `session_match.rs` is the natural home. But it's also one of the
   few helpers that touches the slow-path forward-NAT match
   (`sessions.find_forward_nat_match`) — does that argue for keeping
   it next to `embedded_icmp_return_resolution`?

5. **Module split granularity** — is 6 sibling files
   (parse / session_match / nat_match_v4 / nat_match_v6 /
   return_resolution / builders) too fine-grained for a 761-LOC
   parent? Argument for fewer files: collapse `nat_match_v4` +
   `nat_match_v6` + `return_resolution` into a single `nat_match.rs`
   (~270 LOC) and drop `parse.rs`. Argument against: the explicit
   "split by phase / address family" wording in #1348 prefers
   separation.

6. **Is the implicit `use super::*;` glob from `super::*` (inherited
   in current `icmp_embed.rs`) safe to keep in each submodule?**
   It pulls in everything from `afxdp::*` (which is itself
   re-exporting half the userspace-dp surface). Tighter imports would
   be more hygienic but would balloon the diff. Issue #1200's
   "use super::*; glob anti-pattern" memo (recorded in MEMORY.md
   under project_1189_done) was deferred. Reviewer: do we relitigate
   here or defer again?

7. **Wave-5 acceptance test** — does this PR materially reduce the
   maintenance burden on the next person who has to touch
   embedded-ICMP? Or does the 6-file split just spread the same
   complexity across 6 files without making any single one
   reviewable? Honest answer is needed.
