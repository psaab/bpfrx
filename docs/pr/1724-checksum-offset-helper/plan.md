# #1724 — dedup the 5 offset-lookup `match protocol` checksum sites via a statically-dispatched helper

**Status:** DRAFT v3 — Codex PLAN-NEEDS-MINOR + AGY PLAN-KILL(LOC-bloat) both addressed; pending re-review convergence

## v3 changelog (addressing AGY round-1 PLAN-KILL: LOC-negative payoff)

AGY's PLAN-KILL rested on the v1/v2 call-site shape being **LOC-negative**:
the `match l4_checksum_field_delta(protocol) { Some(d)=>d, None=>return
Some(()) }` form is 4 lines + `checked_add` = 5 lines/site vs the 5-6 line
match it replaces — net ~+5 LOC, no dedup win. **AGY is correct about that
shape.** v3 fixes it with two changes that make the refactor genuinely
LOC-negative AND centralize the correctness-critical pieces:

1. **`let-else` single-line call sites.** Edition 2024 + rustc 1.95 support
   `let-else`. The offset helper takes the BASE (`ihl` for v4, `40` for v6)
   and returns the ABSOLUTE offset, so each call site collapses to ONE
   line: `let Some(off) = l4_checksum_offset(protocol, base) else { return
   Some(()) };`. 5 sites: 5 lines (was 28) + helper ~9 lines = 14 vs 28 →
   **−14 LOC on the offset path.** This is the dedup win AGY said was
   missing.
2. **AGY's split-predicate naming adopted.** AGY Finding 1 (site-3 naming
   inversion) and Codex Finding #1 converge: the site-3 pre-adjust skip is
   "IPv4 UDP checksum 0 = sender disabled it, RFC 768" — a DIFFERENT concept
   from "computed 0 must canonicalize to 0xFFFF". v3 uses AGY's two clearly
   named predicates: `l4_udp_checksum_optional(protocol)` for the site-3
   skip and `adjust_zero_checksum_illegal(protocol, family)` for the
   canonicalization. No `zeroed_checksum_is_illegal` overload.

AGY's remaining objections (codegen reliance on inliner; "worth it") are
addressed: `#[inline(always)]` + a build-time codegen confirmation, and the
now-negative LOC delta answers "worth it". If reviewers still judge the
abstraction not worth the churn, PLAN-KILL remains acceptable.

## v2 changelog (addressing Codex round-1 PLAN-NEEDS-MINOR)

- **Title fixed** (Codex #4): the dedup target is **5** Class-A
  offset-lookup sites, not 7. The 2 Class-B recompute sites are out of
  scope. Title no longer says "7×".
- **Wording fixed** (Codex #2): dropped the inaccurate "monomorphized"
  term (a non-generic fn with a runtime enum arg is not monomorphized).
  The helpers are `#[inline(always)]` **statically-dispatched free
  functions** — no `dyn`, no trait, no generics. The task's
  "monomorphized" constraint is satisfied in spirit: zero dynamic
  dispatch on the hot path.
- **Design simplified** (Codex #6 + SMR): the offset delta is
  **family-independent** (TCP=16, UDP=6, ICMPv6=2 universally — ICMPv6
  simply never reaches the v4 callers because v4 packets aren't ICMPv6).
  So there is exactly ONE offset fn (no enum needed for offsets), plus
  ONE family-aware zero-canonicalization predicate. No `ChecksumFamily`
  enum on the offset path.
- **Site-3 guard kept literal** (Codex #1 + SMR): the pre-adjust
  `if matches!(protocol, PROTO_UDP) && current == 0 { return Some(()) }`
  at checksum.rs:376 stays a literal `protocol == PROTO_UDP`. It encodes
  RFC 768 "received IPv4/UDP datagram with checksum 0 = no checksum
  computed, don't fabricate one" — a DISTINCT concept from the
  computed-zero canonicalization. Not routed through the predicate helper.
- **Predicate scoped + renamed** (Codex #3 + SMR): renamed to
  `adjust_zero_checksum_is_illegal` with a doc comment scoping it to the
  **incremental-adjust** sites only. Verified pre-existing asymmetry:
  `recompute_l4_checksum_ipv6` ICMPv6 arm (checksum.rs:533) writes raw
  `sum` and does NOT canonicalize 0→0xFFFF, whereas the incremental v6
  ICMPv6 adjust sites DO (checksum.rs:319/428/455). This refactor
  PRESERVES that pre-existing inconsistency verbatim and does not extend
  the predicate to Class B.

## Issue framing

`userspace-dp/src/afxdp/frame/checksum.rs` (631 LOC) contains 7
`match protocol { ... }` sites. #1724 (promoted from #1669 §3) asks for a
small **monomorphized** (NON-`dyn`, hot-path-safe) helper —
`l4_checksum_offset(protocol) -> Option<usize>` or similar — to dedup the
uniform `match protocol => offset` arms, while explicitly **preserving the
v4/v6 zero-checksum distinction**: IPv4 sites zero-guard on `PROTO_UDP`
only; IPv6 sites zero-guard on `PROTO_UDP | PROTO_ICMPV6`. A blind unify
would break ICMPv6 zero-checksum handling.

## Honest scope/value framing

This is a **readability / DRY** refactor, not a perf change. The win is:
eliminate 5 near-identical `match protocol` offset-lookup blocks (and the
risk that a future edit fixes the offset in 4 places and forgets the 5th),
and centralize the correctness-critical v4/v6 zero-checksum guard
asymmetry in one named, doc-commented, unit-tested predicate. There is
**no measurable runtime win** — the `#[inline(always)]` fns fold to the
same code. With the v3 `let-else` shape the offset path is **−14 LOC**
(28 → 14); the predicate path is roughly LOC-neutral but turns 5 inline
`matches!` expressions into 5 named-predicate calls.

*If reviewers conclude the dedup doesn't cleanly share enough to justify
the helper (over-abstraction worse than a little duplication), PLAN-KILL
is an acceptable verdict.*

## Site-by-site audit (all 7, read end-to-end)

The 7 `match protocol` sites split into TWO structurally distinct classes.

### Class A — offset-lookup matches (the dedup target): 5 sites

These compute an L4 checksum-field offset, read the current u16, adjust it,
optionally apply the zero-checksum fixup, and write it back. The `match`
arm is *purely* `protocol -> base + delta`.

| # | Fn | Line | Base | TCP | UDP | ICMPV6 | `_` arm | Zero-guard |
|---|----|------|------|-----|-----|--------|---------|------------|
| 1 | `adjust_l4_checksum_ipv4` | 278 | `ihl` | `+16` | `+6` | — | `return Some(())` | `UDP` only |
| 2 | `adjust_l4_checksum_ipv6` | 307 | `40` | `+16` | `+6` | `+2` | `return Some(())` | `UDP\|ICMPV6` |
| 3 | `adjust_l4_checksum_ipv4_words` | 367 | `ihl` | `+16` | `+6` | — | `return Some(())` | `UDP` only (+ `current==0` UDP skip) |
| 4 | `adjust_l4_checksum_ipv6_words` | 417 | `40` | `+16` | `+6` | `+2` | `return Some(())` | `UDP\|ICMPV6` |
| 5 | `adjust_l4_checksum_ipv6_addr_bytes` | 444 | `40` (const-folded) | `56` | `46` | `42` | `return Some(())` | `UDP\|ICMPV6` |

Observations:
- All five use the SAME deltas: TCP `+16`, UDP `+6`, ICMPV6 `+2`.
- IPv4 sites (1, 3) have base `ihl` (runtime) and NO ICMPV6 arm.
- IPv6 sites (2, 4, 5) have base `40` (fixed). Site 5 writes the constants
  pre-added (`56`/`46`/`42` = `40+16`/`40+6`/`40+2`) — semantically
  identical to `40 + delta`.
- The `_ => return Some(())` arm is uniform: unknown protocol → no-op
  success.
- **Zero-guard asymmetry (the #1669 trap):** sites 1, 3 guard
  `matches!(protocol, PROTO_UDP)`; sites 2, 4, 5 guard
  `matches!(protocol, PROTO_UDP | PROTO_ICMPV6)`. This MUST be preserved.

### Class B — full-recompute matches (NOT a clean dedup target): 2 sites

| # | Fn | Line | Shape |
|---|----|------|-------|
| 6 | `recompute_l4_checksum_ipv4` | 471 | per-proto min-len check + zero the field + pseudo-header `checksum16_ipv4` recompute + UDP `zero_offset` fixup |
| 7 | `recompute_l4_checksum_ipv6` | 506 | per-proto min-len check + zero the field + pseudo-header `checksum16_ipv6` recompute |

Class B does NOT compute-then-reuse an offset the same way: each arm does a
min-length guard (`segment.len() < 20/8/4`), zeroes the field, calls the
pseudo-header checksum, and (for v4 UDP) applies a `zero_offset`-gated
fixup. The offset *literals* (`ihl+16`, `40+6`, ...) match Class A's
deltas, but the surrounding per-arm logic (different min-len per proto,
zeroing-before-recompute, distinct fixup conditions) is not uniform. The
ICMPV6 arm in site 7 has min-len 4 (vs TCP 20 / UDP 8), and the v4 UDP arm
threads the `zero_offset` parameter. **Class B is OUT OF SCOPE for the
offset helper.** The arms could *consume* the same delta constants for the
field offset, but doing so does not reduce the match (each arm still needs
its own body), so it is churn without dedup. Plan keeps Class B untouched.

## Concrete design (v3)

Three small `#[inline(always)]` statically-dispatched free functions (no
`dyn`, no trait, no generics — zero dynamic dispatch). The offset helper
takes the L4 BASE so the call site is a single `let-else`.

```rust
/// Absolute offset of the L4 checksum field within `packet`, given the L4
/// header `base` (the IPv4 IHL, or 40 for the fixed IPv6 header). The
/// field deltas are family-independent: TCP=+16, UDP=+6 in both families,
/// and ICMPv6=+2 only ever applies on v6 (v4 callers never pass
/// PROTO_ICMPV6 — IPv4 ICMP has no entry and falls to `None`). `None` =>
/// no L4 checksum field this module adjusts (IPv4 ICMP, unknown) → caller
/// no-ops with `Some(())`, never propagates as a failure.
#[inline(always)]
fn l4_checksum_offset(protocol: u8, base: usize) -> Option<usize> {
    let delta = match protocol {
        PROTO_TCP => 16,
        PROTO_UDP => 6,
        PROTO_ICMPV6 => 2,
        _ => return None,
    };
    base.checked_add(delta)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ChecksumFamily { V4, V6 }

/// IPv4-UDP-only: a received IPv4 UDP datagram with checksum 0x0000 carried
/// NO checksum (RFC 768 — the checksum is optional for IPv4 UDP). The
/// incremental-adjust path must NOT fabricate one, so it skips. This is a
/// DISTINCT concept from `adjust_zero_checksum_illegal` (computed-to-zero
/// canonicalization) and must not be conflated with it (AGY/Codex r1).
#[inline(always)]
fn l4_udp_checksum_optional(protocol: u8) -> bool {
    protocol == PROTO_UDP
}

/// Whether a freshly-computed checksum of 0x0000 must be canonicalized to
/// 0xFFFF on the INCREMENTAL-ADJUST sites. IPv4: UDP only. IPv6: UDP and
/// ICMPv6 (RFC 2460 §8.1 / RFC 8200 forbid a transmitted 0x0000 for both).
/// SCOPE: incremental adjust_l4_checksum_* sites ONLY — deliberately does
/// NOT describe recompute_l4_checksum_ipv6, whose ICMPv6 arm
/// (checksum.rs:533) writes the raw sum without canonicalization, a
/// pre-existing asymmetry this refactor preserves and does not unify.
#[inline(always)]
fn adjust_zero_checksum_illegal(protocol: u8, family: ChecksumFamily) -> bool {
    match family {
        ChecksumFamily::V4 => protocol == PROTO_UDP,
        ChecksumFamily::V6 => matches!(protocol, PROTO_UDP | PROTO_ICMPV6),
    }
}
```

Rationale: the offset is genuinely single-source across all 5 sites and the
helper absorbs both the delta table AND the `base + delta` arithmetic, so
the call site is one `let-else` line — that is what makes the refactor
LOC-negative. The zero-canonicalization guard legitimately differs by
family (the #1724 correctness point), so it carries a `ChecksumFamily` arg
with both arms written out. `l4_udp_checksum_optional` is kept separate per
both reviewers so the RFC-768 skip is not confused with canonicalization.
Every caller passes a literal `V4`/`V6`; under `#[inline(always)]` the
match folds to a constant → identical codegen to today, zero dynamic
dispatch.

### Call-site transformation (Class A site 1 shown)

Before (5 lines for the match + 1 for the guard):
```rust
let checksum_offset = match protocol {
    PROTO_TCP => ihl.checked_add(16)?,
    PROTO_UDP => ihl.checked_add(6)?,
    _ => return Some(()),
};
...
if matches!(protocol, PROTO_UDP) && updated == 0 { updated = 0xffff; }
```
After (1 line for the offset + 1 for the guard):
```rust
let Some(checksum_offset) = l4_checksum_offset(protocol, ihl) else {
    return Some(());   // unknown proto → no-op success (NOT a failure)
};
...
if adjust_zero_checksum_illegal(protocol, ChecksumFamily::V4) && updated == 0 {
    updated = 0xffff;
}
```

- Site 2/4 (v6): `l4_checksum_offset(protocol, 40)`.
- Site 5 (`adjust_l4_checksum_ipv6_addr_bytes`): `l4_checksum_offset(protocol, 40)`
  yields `56`/`46`/`42` exactly (`40+16`/`40+6`/`40+2`), replacing the
  hard-coded constants. Build-time codegen check confirms the
  `#[inline(always)]` fn still folds to constant offsets.
- Site 3 (`adjust_l4_checksum_ipv4_words`) pre-adjust skip (checksum.rs:376)
  becomes `if l4_udp_checksum_optional(protocol) && current == 0 { return
  Some(()); }` — RFC-768 concept kept textually separate.

`let-else` is mandatory over `?`: `?` on the `Option<usize>` would `return
None` (a failure) but the original `_` arm is `return Some(())` (no-op
success).

## Public API preservation

NO public signatures change. The 7 `pub(in crate::afxdp)` / `pub(super)`
functions keep identical signatures and visibility. The two new helpers are
private (`fn`, file-local). No callers in `frame/mod.rs`, `nat64.rs`,
`poll_stages.rs`, `tx/tcp_segmentation.rs`, `frame/build/*` are touched.

## Hidden invariants the change must preserve

1. **v4 zero-guard = UDP only; v6 zero-guard = UDP|ICMPV6.** Encoded in
   `adjust_zero_checksum_illegal` and asserted by new unit tests.
2. **`_` arm = `return Some(())` (no-op success), NOT `None`.** Helper
   returns `None` for unknown proto; caller maps via `let-else { return
   Some(()) }`, never `?`. Must not propagate `None` (a parse failure).
3. **Site-3 `current == 0` UDP early-skip** stays before the adjust as
   `l4_udp_checksum_optional(protocol)` (== `protocol == PROTO_UDP`) — a
   separate predicate from the canonicalization guard.
4. **Offset deltas unchanged:** TCP 16, UDP 6, ICMPV6 2.
5. **Site-5 absolute constants 56/46/42** remain numerically identical via
   `40 + delta`.
6. **One's-complement arithmetic untouched** — only offset/guard derivation
   is refactored; `checksum16_adjust*` calls are byte-identical.
7. **Class B (recompute_*) untouched** — no behavior change there at all.

## Risk assessment

| Class | Level | Note |
|-------|-------|------|
| Behavioral regression | LOW | Pure offset/guard derivation move; deltas + guards preserved verbatim; new tests pin both family cases. |
| Lifetime / borrow-checker | NONE | Helpers take `u8` + `Copy` enum, return `Option<usize>`; no refs. |
| Performance regression | NONE | `#[inline]` fns with const `family` arg fold to identical codegen; checksum16 path untouched. |
| Architectural mismatch (#961/#1207) | NONE | Free fns + `Copy` enum; NO `dyn`, NO trait object, NO new trait. afxdp's single trait is untouched. |

## Test plan

- `cargo build --release` clean.
- `cargo test --release` full userspace-dp suite (incl. existing
  `simd_checksum_tests` parity / one's-complement-wrap + `frame/tests.rs`
  checksum tests) green.
- **New unit tests** in `checksum.rs` test module:
  - `l4_checksum_offset(proto, base)`: returns `base+16`/`base+6`/`None` for
    TCP/UDP/IPv4-ICMP, and `base+2` for ICMPV6; `None` for unknown. Asserted
    for `base=20` (v4 IHL) and `base=40` (v6), and that `base=40` reproduces
    `56/46/42`.
  - `adjust_zero_checksum_illegal`: true for (V4, UDP) only — false for
    (V4, TCP/ICMP/ICMPV6); true for (V6, UDP) and (V6, ICMPV6) — false for
    (V6, TCP).
  - `l4_udp_checksum_optional`: true for UDP, false otherwise.
  - End-to-end: an `adjust_l4_checksum_ipv6` call on an ICMPv6 packet whose
    adjusted checksum computes to 0 yields `0xFFFF` (the #1669-trap
    regression); a v4 ICMP/TCP packet computing to 0 is left unchanged
    (no canonicalization).
- 5× flake loop on the checksum test module.
- Go suite (`go test ./...`) — known pre-existing
  `pkg/dataplane/userspace` sandbox unix-socket failures proven
  pre-existing on master before claiming green.
- **No cluster smoke required:** this is a pure offset-computation /
  guard-derivation refactor with no datapath behavior change; the existing
  checksum parity tests + new per-protocol/zero-checksum unit tests cover
  the change. Confirm coverage in the PR body.

## Out of scope (explicitly)

- Class B `recompute_l4_checksum_ipv4` / `_ipv6` (sites 6, 7) — full
  recompute, not offset-lookup; touching them is churn without dedup.
- Any change to `checksum16*` arithmetic, SIMD path, or pseudo-header fns.
- Any public API / visibility change.

## Open questions for adversarial review (v2)

Codex round-1 resolved its own OQs 1/3/4/5/6 (see v2 changelog). Remaining
for AGY + SMR:

1. **Is the dedup worth it at all?** 5 sites, ~20-30 LOC saved, zero perf.
   Over-abstraction (PLAN-KILL) or genuine maintainability win (offset
   table single-source)? Codex round-1 said "worth doing after the edits".
2. **Predicate name + scope.** Is `adjust_zero_checksum_is_illegal` with
   the "incremental-adjust ONLY" doc comment a sufficiently clear guard
   against a future dev extending it to `recompute_l4_checksum_ipv6` (which
   would change behavior on the v6-ICMPv6 arm)? Or should the predicate
   live as a private fn physically adjacent to the 3 adjust sites?
3. **`#[inline(always)]` codegen.** Does forcing inline on these two tiny
   fns risk any regression vs the current open-coded `match`/`matches!`?
   (Expectation: identical; flagged for build-time confirmation.)
