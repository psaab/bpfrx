# #1724 — dedup 7× `match protocol` checksum-offset logic via a monomorphized helper

**Status:** DRAFT v1 — pending adversarial plan review (Codex + AGY + Claude SMR)

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
risk that a future edit fixes the offset in 4 places and forgets the
5th). There is **no measurable runtime win** — the helper is `#[inline]`
and monomorphizes to the same code. LOC drops modestly (~25-35 lines).

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

## Concrete design

Introduce two small free functions (monomorphized, no `dyn`, no trait):

```rust
/// L4 checksum-field offset within the L4 segment, relative to the start
/// of the L4 header (i.e. add the IPv4 IHL or the fixed IPv6 40-byte
/// header to get the packet offset). `None` => protocol carries no L4
/// checksum field we adjust (IPv4 ICMP, unknown) → caller no-ops.
#[inline]
fn l4_checksum_field_delta(protocol: u8, family: ChecksumFamily) -> Option<usize> {
    match (protocol, family) {
        (PROTO_TCP, _) => Some(16),
        (PROTO_UDP, _) => Some(6),
        (PROTO_ICMPV6, ChecksumFamily::V6) => Some(2),
        _ => None,
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ChecksumFamily { V4, V6 }

/// Apply the family-correct zero-checksum fixup. IPv4: UDP only.
/// IPv6: UDP and ICMPv6 (both forbid a transmitted 0x0000 checksum;
/// 0x0000 means "no checksum" for v4 UDP and is illegal for v6 UDP /
/// ICMPv6, so a computed 0 is rewritten to the equivalent 0xFFFF).
#[inline]
fn zeroed_checksum_is_illegal(protocol: u8, family: ChecksumFamily) -> bool {
    match family {
        ChecksumFamily::V4 => protocol == PROTO_UDP,
        ChecksumFamily::V6 => matches!(protocol, PROTO_UDP | PROTO_ICMPV6),
    }
}
```

Why `family` param rather than two helpers: it keeps the offset deltas in
ONE place (the real dedup value) while making the v4/v6 asymmetry explicit
and type-checked. `ChecksumFamily` is a 1-byte `Copy` enum; the `#[inline]`
fns monomorphize at each call with `family` a compile-time constant at
every call site (every caller passes a literal `V4`/`V6`), so the match
folds to a constant — identical codegen to today.

Alternative considered: separate `l4_checksum_field_delta_v4` /
`_v6` free fns + `zeroed_v4`/`zeroed_v6`. This avoids the enum entirely.
The enum keeps the delta table truly single-source (v4 and v6 share TCP/UDP
deltas); two fns would duplicate the TCP/UDP arms again. The plan leans
toward the `family`-param form; reviewers may prefer the split-fn form —
flagged as Open Question 1.

### Call-site transformation (Class A site 1 shown)

Before:
```rust
let checksum_offset = match protocol {
    PROTO_TCP => ihl.checked_add(16)?,
    PROTO_UDP => ihl.checked_add(6)?,
    _ => return Some(()),
};
...
if matches!(protocol, PROTO_UDP) && updated == 0 { updated = 0xffff; }
```
After:
```rust
let delta = match l4_checksum_field_delta(protocol, ChecksumFamily::V4) {
    Some(d) => d,
    None => return Some(()),
};
let checksum_offset = ihl.checked_add(delta)?;
...
if zeroed_checksum_is_illegal(protocol, ChecksumFamily::V4) && updated == 0 {
    updated = 0xffff;
}
```

Site 5 (`adjust_l4_checksum_ipv6_addr_bytes`) becomes
`40usize.checked_add(delta)?` (was const `56`/`46`/`42`) — preserves the
exact same values; `40+16=56`, `40+6=46`, `40+2=42`. The `checked_add` on a
const can't actually overflow but keeps the shape uniform with the others;
the optimizer folds it.

Site 3 (`adjust_l4_checksum_ipv4_words`) additionally has the
`if matches!(protocol, PROTO_UDP) && current == 0 { return Some(()); }`
early-return BEFORE the adjust. That guard is **v4-UDP-specific** and is
NOT the zero-checksum-illegal fixup — it's "incoming UDP packet had no
checksum, don't start computing one". Keep it as
`if zeroed_checksum_is_illegal(protocol, ChecksumFamily::V4) && current == 0`
— for v4 this is `protocol == PROTO_UDP`, identical. (Confirmed: there is
no ICMP arm on v4, so `zeroed_checksum_is_illegal(_, V4)` is true ONLY for
UDP, exactly matching the original `matches!(protocol, PROTO_UDP)`.)

## Public API preservation

NO public signatures change. The 7 `pub(in crate::afxdp)` / `pub(super)`
functions keep identical signatures and visibility. The two new helpers are
private (`fn`, file-local). No callers in `frame/mod.rs`, `nat64.rs`,
`poll_stages.rs`, `tx/tcp_segmentation.rs`, `frame/build/*` are touched.

## Hidden invariants the change must preserve

1. **v4 zero-guard = UDP only; v6 zero-guard = UDP|ICMPV6.** Encoded in
   `zeroed_checksum_is_illegal` and asserted by new unit tests.
2. **`_` arm = `return Some(())` (no-op success), NOT `None`.** Helper
   returns `None` for unknown proto; caller maps `None -> return Some(())`.
   This must stay `Some(())`, not propagate `None` (which would signal a
   parse failure to the caller).
3. **Site-3 `current == 0` UDP early-skip** stays before the adjust.
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
  - `l4_checksum_field_delta` returns 16/6/None for v4 TCP/UDP/ICMP and
    16/6/2/None for v6 TCP/UDP/ICMPV6.
  - `zeroed_checksum_is_illegal` is true for v4 UDP only (false for v4 TCP /
    v4 ICMP / v4 ICMPV6); true for v6 UDP and v6 ICMPV6 (false for v6 TCP).
  - End-to-end: an `adjust_l4_checksum_ipv6` call on an ICMPv6 packet whose
    adjusted checksum computes to 0 yields `0xFFFF` (the regression the
    #1669 trap warns about); the matching v4-UDP-only behavior verified by
    showing a v4 ICMP/TCP packet computing to 0 is left as 0.
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

## Open questions for adversarial review

1. **`family` enum vs split free fns.** Is the `ChecksumFamily` enum the
   right call, or do two pairs of family-specific free fns
   (`l4_checksum_field_delta_v4/_v6`) read cleaner and remove the enum?
   The enum keeps the TCP/UDP deltas single-source; split fns re-duplicate
   them. Which wins?
2. **Is the dedup worth it at all?** 5 sites, ~25-35 LOC saved, zero perf.
   Is this over-abstraction (PLAN-KILL) or a genuine maintainability win
   (the offset table now lives in one place)?
3. **Site-3 `current == 0` early-skip rewrite.** Is reusing
   `zeroed_checksum_is_illegal(_, V4)` for the pre-adjust skip correct, or
   does conflating the "incoming had no checksum" skip with the
   "computed-to-zero illegal" fixup obscure two distinct concerns? Keep a
   literal `protocol == PROTO_UDP` there instead?
4. **Site-5 `40 + delta` vs literal constants.** Does replacing `56/46/42`
   with `40usize.checked_add(delta)?` improve or harm clarity, given the
   `#[inline(always)]` hot-path-adjacent annotation on that fn? Any codegen
   concern from the extra `checked_add` on a const base?
5. **Class B exclusion.** Is leaving `recompute_*` untouched correct, or
   should the offset literals there also consume the delta helper for
   consistency even though it doesn't reduce the match?
6. **`None` → `Some(())` mapping.** Is mapping the helper's `None` to
   `return Some(())` at each call site clear enough, or does it risk a
   future caller treating `None` as a hard error? Should the helper's
   contract be documented to forbid that?
