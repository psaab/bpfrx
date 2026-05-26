# #1352 Step 1 — Split `frame/mod.rs` 236-LOC `build_forwarded_frame_into_from_frame` + 223-LOC `apply_rewrite_descriptor` into `frame/{build,rewrite}/` by address family

**Status:** v2 — addresses Codex r1 PLAN-NEEDS-MAJOR (codegen parity not
established + deferred batch smoke insufficient) and AGY r1
PLAN-NEEDS-MINOR (mandate `#[inline(always)]` + add codegen
verification step + plan wording on `rewrite_apply_v4/v6` caller
separation). Pending r2.

## Round-1 review disposition

Codex r1 ([task-mpmyvdz3-7x6rhd](docs/pr/1352-frame-build-rewrite-split/reviewer-ids.md)) returned PLAN-NEEDS-MAJOR with 2 major + 1 minor finding. AGY r1
([adversarial-review-mpmz4yjh-gerhrw](docs/pr/1352-frame-build-rewrite-split/reviewer-ids.md)) returned PLAN-NEEDS-MINOR with the
same two architectural axes flagged but ranked minor.

1. **Codex Major #1 / AGY #1 — codegen parity not established by
   `#[inline]`.** Both reviewers walked the System V AMD64 ABI for
   the proposed 8-param signature and confirmed:
   - `ForwardPacketMeta` is a 28-byte aggregate (AGY counted bytes
     against `userspace-dp/src/afxdp/types/mod.rs:143-159`); passed
     by value it consumes ~4 register slots OR spills to stack.
   - At 8 flat params + the meta aggregate, two scalars
     (`tunnel_tcp_mss`, `force_tunnel_l4_recompute`) AND the meta
     spill to the stack when the helper is NOT inlined.
   - `#[inline]` is a hint not a contract; LLVM may decline to
     inline a ~85-LOC body that's called from a single dispatcher
     site.
   - **Resolution:** v2 mandates `#[inline(always)]` on the
     per-family helpers. AGY's argument is decisive: each
     per-family helper has exactly one call site (inside its
     orchestrator), so `#[inline(always)]` carries zero i-cache
     bloat from duplication. SROA + SSA at the inlined site
     turns the flat-param list into independent register-class
     scalars, bypassing the ABI register classification entirely.
   - Plan keeps the flat-param signature (Option A, AGY §1) NOT
     a `&FrameBuildCtx` (Option B). Reason: a by-reference ctx
     forces LLVM to keep ctx-field loads behind a pointer
     unless it can prove no-alias with the `&mut [u8] out`
     buffer — which requires walking unsafe blocks in sibling
     modules. Flat params + `#[inline(always)]` is the codegen
     contract.

2. **Codex Major #2 — deferred batch smoke insufficient for
   hot-path codegen claim.** Both reviewers flagged that
   wave-end batch smoke cannot isolate a 1-2% line-rate regression
   to this PR. **Resolution:** v2 adds a per-PR codegen
   verification step BEFORE merge:
   - `cargo rustc --release -p userspace-dp -- --emit=asm`
   - Verify the generated asm at the two call sites
     (`tx/dispatch.rs:651`, `poll_descriptor.rs:746`) contains
     NO `call` instruction to per-family helper symbols
     (`build_forwarded_frame_into_ipv4/6`,
     `apply_rewrite_descriptor_ipv4/6`).
   - If a `call` IS present, the `#[inline(always)]` failed and
     the PR MUST NOT MERGE until codegen is restored.
   - The codegen-verification artifact is attached as a PR
     comment with the relevant asm slice + the post-grep result.
   - Wave-end batch smoke remains the final perf gate, but the
     codegen verification step is the per-PR isolation
     mechanism. **AWAITING-BATCH-MERGE marker stays** — the
     wave-2 rule about deferred smoke is preserved; we add a
     deterministic codegen check INSTEAD OF an iperf smoke,
     not in addition to one.

3. **Codex Minor #3 / AGY §6 — wording on `rewrite_apply_v4/v6`
   caller separation.** v1 said "different TX caller"; Codex
   noted `poll_descriptor.rs:746` actually tries
   `apply_rewrite_descriptor` AND falls back to
   `rewrite_forwarded_frame_in_place` (mod.rs:770) in the SAME
   TX flow at `poll_descriptor.rs:754`. They are separate
   implementation paths (descriptor-driven vs.
   decision-driven), not separate caller sites. **Resolution:**
   v2 fixes the wording in §Out of scope.

4. **AGY §9 — test colocation TODO for follow-up.**
   **Resolution:** v2 adds an explicit follow-up TODO
   to schedule test colocation as a subsequent refactoring step
   (likely a separate small PR).

## Issue framing

`userspace-dp/src/afxdp/frame/mod.rs` is 1783 prod LOC (Tier-2 size
band) and contains two Tier-1 fn-size hits both >2× the 100-LOC soft
cap from `docs/engineering-style.md`:

- `build_forwarded_frame_into_from_frame()` — 236 LOC body
  (mod.rs:218..453). Builds an outbound forwarded frame into a
  scratch buffer from an ingress frame: ethertype detection → L2
  rewrite → L3 (v4/v6) rewrite → L4 (TCP/UDP/ICMP) checksum delta →
  optional GRE encap → in-place writeback. The fan-out is `addr_family ×
  protocol × tunnel/encap` and is currently inlined.

- `apply_rewrite_descriptor()` — 223 LOC body (mod.rs:906..1128).
  Applies a precomputed `RewriteDescriptor` (NAT, ports, MAC) to a
  packet in place inside a UMEM-resident frame. Branches on
  `ether_type` (0x0800 / 0x86dd) then on `protocol` (TCP/UDP/ICMPv6).

Both are on the per-packet TX dispatch hot path:

- `build_forwarded_frame_into_from_frame` is called from
  `tx/dispatch.rs:651` (per-packet build for the slow / scratch
  path) and `frame/mod.rs:480` (one of the public adapters).
- `apply_rewrite_descriptor` is called from `poll_descriptor.rs:746`
  (per-packet fast-path in-UMEM rewrite).

Wave-2 of the refactor program asks for an address-family split
under `frame/{build,rewrite}/` mirroring the directory-with-mod.rs
pattern already in use for `frame/` (alongside `checksum.rs`,
`inspect.rs`, `tcp.rs`, `tcp_segmentation.rs`, `byte_writes.rs`).

## Honest scope/value framing

**Pure code motion.** No new allocations, no new branches, no new
atomics, no semantic change. The hot path receives the same
instructions in the same order; reviewers should verify codegen
parity by spot-check rather than chasing perf.

Win is **readability + review tractability**:

- Two of the four LOC-cap hits in `frame/mod.rs` go away.
- Address-family fan-out becomes the file boundary, matching the
  existing `frame/` split-by-sub-concern pattern (`checksum.rs`,
  `inspect.rs`, `tcp.rs`).
- `frame/mod.rs` drops from 1783 prod LOC to ~1300 LOC (still in
  the Tier-2 band but well under the soft 2000-LOC ceiling).

Loss / hazard surface:

- IPv4 + IPv6 arms in each function share **non-trivial preludes**
  (ethertype dispatch + `prep` from `rewrite_prepare_eth_from_parts`
  for `apply_rewrite_descriptor`; eth header write + `payload`
  memcpy + `ip_start` + `tunnel_tcp_mss` for
  `build_forwarded_frame_into_from_frame`). The split has to keep
  those preludes in the orchestrator (`build/mod.rs`,
  `rewrite/mod.rs`) and pass the resolved primitives into the
  per-family helpers. Getting the boundary wrong would either
  duplicate the prelude (regression hazard, breaks code-motion
  property) or push too much into the per-family helpers
  (re-introduces the same fanout).

- Both functions terminate with debug-only blocks
  (`cfg!(feature = "debug-log")`) that run AFTER the per-family
  arm. These stay in the orchestrator, not in the per-family
  helpers, so debug instrumentation remains in one place.

**If reviewers conclude the readability gain is too small to
justify the churn, PLAN-KILL is an acceptable verdict.** The
hot-path codegen-parity hazard is the dominant risk — pure code
motion that breaks `#[inline]` boundaries can show up as 1-2%
throughput regression at line rate. Plan addresses this with
explicit `#[inline]` attribute mandates on the per-family helpers
and a smoke-matrix line-rate-with-zero-retrans gate.

## What's already shipped / partially batched

The `frame/` directory split-by-sub-concern is already established:

```
userspace-dp/src/afxdp/frame/
├── mod.rs                    1783 LOC (this PR's target)
├── byte_writes.rs              81 LOC  — write_ipv4_src/dst, write_l4_src/dst_port
├── byte_writes_tests.rs        97 LOC
├── checksum.rs                616 LOC  — adjust_l4_checksum_*, recompute_l4_checksum_*
├── inspect.rs                 744 LOC  — parse helpers, frame_l3_offset, etc.
├── tcp.rs                     542 LOC  — clamp_tcp_mss_frame, build_syn_cookie_*
├── tcp_segmentation.rs        338 LOC  — segment_forwarded_tcp_frames* (#1166 PR #1199)
├── tcp_tests.rs               575 LOC
└── tests.rs                  5275 LOC  — colocation; out of scope for this PR
```

Cross-PR dependency note for **#1347** (`tcp_segmentation.rs`):
`#1347` proposes sharing the segmentation algorithm between
`afxdp/frame/tcp_segmentation.rs` (legacy emission) and
`afxdp/tx/tcp_segmentation.rs` (TSO emission). That refactor is
**out of scope for this PR** — #1347 touches the segmentation
helpers (which are already extracted and called from outside
`build_forwarded_frame_into_from_frame`), while this PR touches
the build/rewrite orchestrators. No file overlap. If #1347
lands first, this PR's `build_forwarded_frame_into_from_frame` is
unchanged (still calls `segment_forwarded_tcp_frames_from_frame`
the same way). If this PR lands first, #1347 still operates on
`frame/tcp_segmentation.rs`, untouched here.

#1166 extraction (TSO builders → `tcp_segmentation.rs`) is the
mechanical precedent — `pub(in crate::afxdp)` re-export from
`mod.rs` so external `use self::frame::*;` import sites continue
to surface the symbol at the same path. This PR follows the
same visibility shape.

## Concrete design

### Target layout

```
userspace-dp/src/afxdp/frame/
├── mod.rs                    # existing helpers + thin wrappers; ~1300 LOC after split
├── build/
│   ├── mod.rs                # build_forwarded_frame_into_from_frame orchestrator (~60 LOC)
│   ├── ipv4.rs               # build_forwarded_frame_into_ipv4 (~85 LOC)
│   └── ipv6.rs               # build_forwarded_frame_into_ipv6 (~60 LOC)
└── rewrite/
    ├── mod.rs                # apply_rewrite_descriptor orchestrator (~50 LOC)
    ├── ipv4.rs               # apply_rewrite_descriptor_ipv4 (~95 LOC)
    └── ipv6.rs               # apply_rewrite_descriptor_ipv6 (~80 LOC)
```

No nested L2 / L3 / L4 split inside the per-family files — the
issue body sketches `build/l2.rs`, `build/l3_v4.rs`, etc., but the
L2 write is already factored as `write_eth_header_slice` (one call,
one site) and the L4 checksum delta is already factored as
`adjust_l4_checksum_*` / `recompute_l4_checksum_*` in
`checksum.rs`. Splitting `ipv4.rs` further into per-protocol files
would re-introduce the same fanout we're trying to remove. The
per-family file is the unit of cohesion.

### `build/mod.rs` orchestrator shape

```rust
// frame/build/mod.rs
use super::*;
mod ipv4;
mod ipv6;
pub(in crate::afxdp::frame) use ipv4::build_forwarded_frame_into_ipv4;
pub(in crate::afxdp::frame) use ipv6::build_forwarded_frame_into_ipv6;

#[inline]
pub(in crate::afxdp) fn build_forwarded_frame_into_from_frame(
    out: &mut [u8],
    frame: &[u8],
    meta: impl Into<ForwardPacketMeta>,
    decision: &SessionDecision,
    forwarding: &ForwardingState,
    apply_nat_on_fabric: bool,
    expected_ports: Option<(u16, u16)>,
) -> Option<usize> {
    let meta = meta.into();
    let dst_mac = decision.resolution.neighbor_mac?;

    // (L3 offset derivation, payload trim, src_mac/vlan_id resolution,
    // eth_len / ether_type derivation, eth header write + payload memcpy —
    // byte-identical to today's lines 227..280)

    let force_tunnel_l4_recompute = decision.resolution.tunnel_endpoint_id != 0;
    let tunnel_tcp_mss = native_gre_tcp_mss(forwarding, decision, meta.addr_family);
    let ip_start = eth_len;

    match meta.addr_family as i32 {
        libc::AF_INET => build_forwarded_frame_into_ipv4(
            &mut out[..frame_len],
            ip_start,
            meta,
            decision,
            apply_nat,
            expected_ports,
            tunnel_tcp_mss,
            force_tunnel_l4_recompute,
        )?,
        libc::AF_INET6 => build_forwarded_frame_into_ipv6(
            &mut out[..frame_len],
            ip_start,
            meta,
            decision,
            apply_nat,
            expected_ports,
            tunnel_tcp_mss,
            force_tunnel_l4_recompute,
        )?,
        _ => return None,
    }

    // Debug-log + checksum-verify + RST-corrupt blocks stay here,
    // byte-identical to today's lines 384..451.

    Some(frame_len)
}
```

### `build/ipv4.rs` shape

```rust
// frame/build/ipv4.rs
use super::super::*;

#[inline]
pub(in crate::afxdp::frame) fn build_forwarded_frame_into_ipv4(
    out: &mut [u8],
    ip_start: usize,
    meta: ForwardPacketMeta,
    decision: &SessionDecision,
    apply_nat: bool,
    expected_ports: Option<(u16, u16)>,
    tunnel_tcp_mss: u16,
    force_tunnel_l4_recompute: bool,
) -> Option<()> {
    // Body byte-identical to today's mod.rs:285..341 (the AF_INET arm
    // of the existing function), with `out` instead of `&mut out[..]`
    // and `ip_start` already resolved by the orchestrator.
    if out.len() < ip_start + 20 {
        return None;
    }
    let ihl = ((out[ip_start] & 0x0f) as usize) * 4;
    // ... rest of body byte-identical ...
    Some(())
}
```

(IPv6 mirrors the same shape — body byte-identical to today's
mod.rs:342..380.)

### `rewrite/mod.rs` orchestrator shape

```rust
// frame/rewrite/mod.rs
use super::*;
mod ipv4;
mod ipv6;
pub(in crate::afxdp::frame) use ipv4::apply_rewrite_descriptor_ipv4;
pub(in crate::afxdp::frame) use ipv6::apply_rewrite_descriptor_ipv6;

#[inline]
pub(in crate::afxdp) fn apply_rewrite_descriptor(
    area: &MmapArea,
    desc: XdpDesc,
    meta: UserspaceDpMeta,
    rd: &super::RewriteDescriptor,
    expected_ports: Option<(u16, u16)>,
) -> Option<InPlaceRewriteResult> {
    // NAT64 and NPTv6 use the generic path.
    if rd.nat64 || rd.nptv6 {
        return None;
    }

    let prep = rewrite_prepare_eth_from_parts(
        area, desc, meta.into(),
        RewriteEthParams {
            dst_mac: rd.dst_mac,
            src_mac: rd.src_mac,
            vlan_id: rd.tx_vlan_id,
            ether_type: rd.ether_type,
            apply_nat: !rd.fabric_redirect || rd.apply_nat_on_fabric,
        },
    )?;
    let packet = unsafe { area.slice_mut_unchecked(prep.tx_offset as usize, prep.frame_len)? };
    let frame_len = prep.frame_len;
    let ip = prep.ip_start;
    let skip_ttl = prep.skip_ttl;
    let apply_nat = prep.apply_nat;

    match rd.ether_type {
        0x0800 => apply_rewrite_descriptor_ipv4(
            packet, ip, skip_ttl, apply_nat, meta, rd, expected_ports,
        )?,
        0x86dd => apply_rewrite_descriptor_ipv6(
            packet, ip, skip_ttl, apply_nat, meta, rd, expected_ports,
        )?,
        _ => return None,
    }

    if cfg!(feature = "debug-log") {
        verify_built_frame_checksums(&packet[..frame_len]);
    }
    Some(InPlaceRewriteResult {
        offset: prep.tx_offset,
        len: frame_len as u32,
        l2_rewrite: prep.l2_rewrite,
    })
}
```

### Hot-path discipline (per-packet)

**v2 codegen contract:** Per-family helpers
(`build_forwarded_frame_into_ipv4/6`,
`apply_rewrite_descriptor_ipv4/6`) get `#[inline(always)]`. Each
helper has EXACTLY ONE call site (its orchestrator's match arm),
so `#[inline(always)]` carries zero i-cache bloat from
duplication while guaranteeing that the System V AMD64 ABI
register-spill described in §Round-1 disposition is bypassed via
SROA + SSA scalarization at the inlined site.

Orchestrators
(`build_forwarded_frame_into_from_frame`,
`apply_rewrite_descriptor`) get `#[inline]` (the standard hint,
not `(always)`) so LLVM keeps discretion at the
two-call-site `tx/dispatch.rs:651` / `poll_descriptor.rs:746`
boundary. The orchestrator bodies are 50-60 LOC after the split,
small enough for the standard inlining heuristic to fold through.

**Verification step (per-PR codegen gate):**

```bash
# In the worktree, after implementation:
TMPDIR=/dev/shm CARGO_TARGET_DIR=/dev/shm/cargo \
  cargo rustc --release -p userspace-dp -- --emit=asm
ASM=/dev/shm/cargo/release/deps/userspace_dp-*.s
# Verify no per-family helper symbols are emitted as separate functions:
grep -E "build_forwarded_frame_into_ipv4|build_forwarded_frame_into_ipv6|apply_rewrite_descriptor_ipv4|apply_rewrite_descriptor_ipv6" $ASM \
  | grep -v "^;" | head
# Expected: zero matches (helpers fully inlined into their orchestrators).
# If matches present, the PR MUST NOT MERGE until codegen is restored
# (likely a missing #[inline(always)] or LLVM-side bailout).
```

The codegen verification artifact is posted as a PR comment with
the grep result + a brief asm slice of the two call sites
(`tx/dispatch.rs:651` and `poll_descriptor.rs:746`).

Code sketch of the orchestrator/helper layering (v2 attributes):

```rust
// frame/build/mod.rs
#[inline]                       // standard hint at the 2-call-site boundary
pub(in crate::afxdp) fn build_forwarded_frame_into_from_frame(...) -> Option<usize> { ... }

// frame/build/ipv4.rs
#[inline(always)]               // mandate: single call site, bypass ABI spill
pub(in crate::afxdp::frame) fn build_forwarded_frame_into_ipv4(...) -> Option<()> { ... }

// frame/rewrite/mod.rs
#[inline]
pub(in crate::afxdp) fn apply_rewrite_descriptor(...) -> Option<InPlaceRewriteResult> { ... }

// frame/rewrite/ipv4.rs
#[inline(always)]
pub(in crate::afxdp::frame) fn apply_rewrite_descriptor_ipv4(...) -> Option<()> { ... }
```

The debug-only `#[cold]` candidate is the inner `BUILD_RST_CORRUPT_COUNT`
block (mod.rs:417..451) — it runs only under `cfg!(feature =
"debug-log")` and only when a forwarded frame contains a TCP RST.
This block is already gated by the debug-log feature flag; we do
NOT add `#[cold]` to its enclosing branch in v1 because it's
inside the orchestrator (single site, already cold via the feature
gate). The ICMP-error embed branch mentioned in the wave-2 rules
does NOT exist in either of these two functions — it's handled
upstream by the screen / conntrack path, not by frame
building/rewriting. No `#[cold]` annotations are added by this PR.

### Per-packet allocation audit

Walked both functions for `Vec::new() / String::new() / Box::new() /
.to_vec() / .to_string() / .collect::<Vec<_>>()` and friends. The
**only** allocations on either path are inside the
`cfg!(feature = "debug-log")` blocks (the hex-dump `String::collect`).
None on the production hot path. The split does not add any new
allocation site — the orchestrator passes already-trimmed slice
references and `Option<(u16, u16)>` `Copy` values through to the
per-family helpers.

### Public API preservation

Both functions stay at `pub(in crate::afxdp)` visibility (matching
today's `pub(super)` from inside `frame/mod.rs`, which expands to
the same path because `frame/mod.rs` lives at `crate::afxdp::frame`).
Re-exported through `frame/mod.rs` so external import sites
(`tx/dispatch.rs:651`, `poll_descriptor.rs:746`, `frame/mod.rs:480`'s
internal call) continue to surface the symbols at
`crate::afxdp::frame::build_forwarded_frame_into_from_frame` and
`crate::afxdp::frame::apply_rewrite_descriptor`.

External signature byte-identical:

```rust
pub(in crate::afxdp) fn build_forwarded_frame_into_from_frame(
    out: &mut [u8],
    frame: &[u8],
    meta: impl Into<ForwardPacketMeta>,
    decision: &SessionDecision,
    forwarding: &ForwardingState,
    apply_nat_on_fabric: bool,
    expected_ports: Option<(u16, u16)>,
) -> Option<usize>;

pub(in crate::afxdp) fn apply_rewrite_descriptor(
    area: &MmapArea,
    desc: XdpDesc,
    meta: UserspaceDpMeta,
    rd: &super::RewriteDescriptor,
    expected_ports: Option<(u16, u16)>,
) -> Option<InPlaceRewriteResult>;
```

## Hidden invariants the refactor must preserve

1. **Side-effect ordering inside the per-family arm.** For IPv4
   `build`: (a) restore_l4_tuple_from_meta → (b) apply_nat_ipv4 →
   (c) TTL decrement → (d) enforce_expected_ports_at → (e)
   adjust_ipv4_header_checksum → (f) clamp_tcp_mss_frame → (g)
   recompute_l4_checksum_ipv4. The IPv4 helper preserves this
   order byte-identical. IPv6 mirrors with no IP header checksum
   step. The split does NOT reorder any step.

2. **Order matters for `repaired_ports && !enforced`.** Today's
   condition is "if we repaired ports from meta AND
   enforce_expected_ports did NOT take its repair path, force a
   full L4 checksum recompute." This semantically couples
   `restore_l4_tuple_from_meta`'s return value to
   `enforce_expected_ports_at`'s return value. Both vars must be
   captured in the per-family helper local scope and combined
   inside it — the orchestrator cannot see them.

3. **`force_tunnel_l4_recompute` is resolved BEFORE the per-family
   arm.** Today it's computed at mod.rs:281 from
   `decision.resolution.tunnel_endpoint_id != 0`. The orchestrator
   computes it once and passes it into both per-family helpers.
   The `tunnel_tcp_mss` value is computed similarly. Per-family
   helpers receive both by value (Copy).

4. **`meta` is `Copy`.** `ForwardPacketMeta` is `Copy`-marked (see
   `afxdp.rs`); passing by value to the per-family helper costs
   the same as passing by reference but avoids a borrow. Walked
   the type for any heap-owning fields — none.
   `UserspaceDpMeta` is also `Copy`.

5. **`out: &mut [u8]` length must shrink to `frame_len` BEFORE
   the per-family arm.** Today's code does `let out = &mut
   out[..frame_len];` at mod.rs:280 before the match arm. The
   orchestrator does the same shrink and passes the shrunken slice
   to the per-family helper.

6. **`decision: &SessionDecision` borrow shape.** Today's code
   holds an immutable borrow across the match arm. Per-family
   helpers receive `&SessionDecision` (immutable borrow); no
   change to the borrow shape.

7. **`expected_ports: Option<(u16, u16)>` is `Copy`.** Passed by
   value to per-family helpers.

8. **`apply_nat: bool` resolution.** Today's `apply_nat` is
   computed in the prelude from `decision.resolution.disposition
   == ForwardingDisposition::FabricRedirect ? apply_nat_on_fabric
   : true`. The orchestrator computes this once and passes the
   bool into the per-family helper. No re-derivation inside the
   per-family arm.

9. **`apply_rewrite_descriptor`'s NAT64/NPTv6 early-return.**
   Today returns `None` at mod.rs:914 when `rd.nat64 || rd.nptv6`.
   The orchestrator preserves this gate BEFORE invoking
   `rewrite_prepare_eth_from_parts`. Per-family helpers never see
   nat64/nptv6 frames.

10. **`InPlaceRewriteResult` construction.** Today the result
    bundles `prep.tx_offset` + `frame_len as u32` + `prep.l2_rewrite`.
    The orchestrator constructs this AFTER the per-family arm
    succeeds. Per-family helpers return `Option<()>` (success/fail
    only); the orchestrator owns the result-construction step.

11. **`#[inline]` codegen parity.** Today both functions are
    monomorphic and inlinable at their two call sites
    (`tx/dispatch.rs:651` and `poll_descriptor.rs:746`). With
    `#[inline]` on both the orchestrator and per-family helpers,
    LLVM should produce equivalent codegen. **Smoke must verify
    line rate.**

## Risk assessment

| Risk class | Level | Notes |
|---|---|---|
| Behavioral regression | LOW | Pure code motion. Per-family bodies byte-identical to the existing AF_INET / AF_INET6 / 0x0800 / 0x86dd arms modulo the parameter list. Side-effect ordering preserved by keeping all steps inside the per-family helper. |
| Lifetime / borrow-checker | LOW-MED | Per-family helpers take `&mut [u8]` + several `Copy` scalars + `&SessionDecision` (immutable). No new lifetime parameter; the helper signature uses one lifetime implicitly (the `&mut [u8]`). `apply_rewrite_descriptor_ipv4/6` takes `&mut [u8]` (the unsafe-borrowed UMEM slice) and `meta: UserspaceDpMeta` (Copy) and `rd: &RewriteDescriptor` — same shape as today's match arm. |
| Performance regression | LOW-MED (verified by smoke) | The codegen-parity hazard is real. Mitigation: `#[inline]` on both layers + line-rate + 0-retrans smoke gate. If the smoke matrix shows <line rate or any retrans, the split is reverted to a single-file orchestrator + helper module shape OR the `#[inline]` attributes are reconsidered. |
| Architectural mismatch (#961 / #946 Phase 2) | LOW | Canonical address-family split mirroring the existing `frame/` sub-concern split. The wave-2 issue body specifies this exact layout. The alternative (per-protocol split inside each family) is explicitly out of scope; per-family cohesion is the chosen boundary. |
| Cross-PR collision with #1347 | LOW | #1347 touches `frame/tcp_segmentation.rs` (segmentation helper consolidation); this PR touches `build_forwarded_frame_into_from_frame` and `apply_rewrite_descriptor` only. No file overlap. Either PR can land first. |
| Test colocation drift | MEDIUM (documented) | `frame/tests.rs` is currently 5275 LOC and houses tests for both functions. The issue body suggests colocating per-file tests after the split. This PR does NOT move any test — the tests reach symbols via `frame::*` re-export and stay where they are. Test colocation is a deliberate out-of-scope follow-up. Reviewers may push back. |

## Test plan

1. `cargo build --release` clean inside the worktree.
2. `cargo test --release` — full Rust suite (target: same pass
   count as origin/master). Particular focus:
   - Existing `frame/tests.rs` covers
     `build_forwarded_frame_into_from_frame` and
     `apply_rewrite_descriptor` (search keywords:
     `build_forwarded_frame`, `apply_rewrite`, `rewrite_descriptor`).
   - `flow_cache_tests.rs:550` references
     `apply_rewrite_descriptor` semantics; ensure those tests
     still pass.
3. 5x flake check on the most affected named test (TBD —
   pick after Step 5 implementation reveals which test bundle is
   slowest / most senstitive).
4. `go test ./...` — all 30 Go packages.
5. **Codegen verification step (per-PR, v2 mandate).** After
   `cargo build --release` in the worktree, run
   `cargo rustc --release -p userspace-dp -- --emit=asm`, grep
   the generated `.s` file for the per-family helper symbols
   (`build_forwarded_frame_into_ipv4`,
   `build_forwarded_frame_into_ipv6`,
   `apply_rewrite_descriptor_ipv4`,
   `apply_rewrite_descriptor_ipv6`), confirm ZERO matches
   (helpers fully inlined into their orchestrators), and
   attach the grep result + a brief asm slice of the two
   call sites to the PR as a comment. **If any per-family
   helper symbol is still emitted as a separate function, the
   PR MUST NOT MERGE until codegen is restored.**
6. **Smoke matrix is wave-2 deferred.** Per the wave-2 rule
   (`<!-- AWAITING-BATCH-MERGE -->`), no per-PR iperf smoke runs.
   The batch smoke at the end of the wave runs the full v4+v6 ×
   push+rev × CoS-off+on matrix, including line-rate `-P 12 -R`
   reproducers. **This PR's hot-path codegen-parity claim is
   verified per-PR by the asm grep (step 5), not by an iperf
   smoke. The wave-end batch smoke is the final aggregate-perf
   gate.**

## Out of scope (explicitly)

- Moving tests out of `frame/tests.rs` into per-file colocated
  test modules. Test colocation for the new build/ and rewrite/
  files is a deliberate follow-up; tests continue to reach the
  symbols via the `pub(in crate::afxdp::frame)` re-export.
  **TODO follow-up:** schedule a separate small PR after the
  build/rewrite split lands to colocate the build + rewrite tests
  into `frame/build/{ipv4_tests.rs,ipv6_tests.rs}` and
  `frame/rewrite/{ipv4_tests.rs,ipv6_tests.rs}`, leaving
  `frame/tests.rs` as the home for tests that exercise other
  parts of `frame/`.
- Touching `rewrite_apply_v4` / `rewrite_apply_v6` / the larger
  `rewrite_forwarded_frame_in_place` (mod.rs:770). These are a
  **separate implementation path** (decision-driven via
  `&SessionDecision`, no precomputed `RewriteDescriptor` deltas).
  They are NOT a "different caller" — `poll_descriptor.rs` calls
  `apply_rewrite_descriptor` at line 746 AND falls back to
  `rewrite_forwarded_frame_in_place` at line 754 in the same TX
  flow when the descriptor path declines (e.g. NAT64). The split
  is a separate-implementation-path split, not a separate-caller
  split. Either path being unmoved by this PR is coherent because
  the v4/v6 fan-out in `rewrite_apply_*` shares NO state with
  `apply_rewrite_descriptor` (different input type, different
  prepare step). Moving them is wave-2 follow-up work, not #1352
  scope.
- Per-protocol (TCP / UDP / ICMP) further split inside the
  per-family files. Cohesion is per-family at this step.
- The `RewriteDescriptor` struct shape, `RewriteEthParams`, or
  any upstream changes to how the descriptor is computed.
- GRE encap / native_gre_tcp_mss / TSO segmentation paths.
- The non-debug-log call to `verify_built_frame_checksums` —
  it stays in the orchestrator.

## Open questions for adversarial review

1. **Is the per-family helper signature too wide?**
   `build_forwarded_frame_into_ipv4/6` takes 8 parameters
   (`out`, `ip_start`, `meta`, `decision`, `apply_nat`,
   `expected_ports`, `tunnel_tcp_mss`,
   `force_tunnel_l4_recompute`). The engineering style doc's
   guideline is "fns with >8 params trigger refactor on the way
   in." This is AT the 8-param boundary. Should a typed
   `FrameBuildCtx { meta, decision, apply_nat, expected_ports,
   tunnel_tcp_mss, force_tunnel_l4_recompute }` struct bundle
   the dispatch state? Pro: signature shrinks to 3 params
   (out, ip_start, ctx). Con: introduces a new type that exists
   only to bundle parameters, and the `#[inline]` boundary may
   prefer flat scalars for register passing (System V AMD64
   passes the first 6 ints in registers; an 8-param signature
   spills two to the stack, but a 1-param struct-by-value would
   spill differently depending on `repr`). Plan v1 keeps the
   flat signature for clarity and codegen predictability.
   **Reviewers may push back either way.**

2. **`apply_rewrite_descriptor_ipv4/6` parameter list.**
   `(packet, ip, skip_ttl, apply_nat, meta, rd, expected_ports)`
   — 7 params, under the cap. No `FrameBuildCtx`-style bundle
   proposed.

3. **`#[inline]` attribute granularity.** Plan specifies
   `#[inline]` on both the orchestrator and the per-family
   helpers. Alternative: `#[inline(always)]` on the per-family
   helpers only, to force inlining regardless of size. Risk
   of `#[inline(always)]`: blows up the call-site code size at
   `tx/dispatch.rs:651` and `poll_descriptor.rs:746`; may worsen
   i-cache footprint at the call site. The plan's `#[inline]`
   leaves the decision to LLVM. **If smoke shows perf regression,
   bump to `#[inline(always)]`.**

4. **Cohesion boundary: per-family vs. per-protocol.** Issue
   body sketches `build/l2.rs`, `build/l3_v4.rs`, `build/l3_v6.rs`,
   `build/encap_gre.rs`. Plan rejects L2/L3/L4 nesting because
   `write_eth_header_slice` is already factored into `mod.rs` and
   the L3 work is intrinsic to the per-family logic.
   `encap_gre.rs` correspondingly doesn't get carved out because
   `clamp_tcp_mss_frame` (the only GRE-coupled call) is already
   in `frame/tcp.rs`. **Reviewers may disagree.**

5. **`rewrite_apply_v4` / `rewrite_apply_v6` left in `mod.rs`.**
   These are 56 / 37 LOC respectively and serve a different code
   path (`rewrite_forwarded_frame_in_place` at mod.rs:770, the
   in-place rewrite called from a DIFFERENT TX path). They share
   the address-family fan-out shape with the two split fns but
   are not the wave-2 #1352 target. **Should they also move?**
   Plan v1 says NO — they're a separate code path, not on the
   #1352 scope. **Reviewers may push for a more thorough split.**

6. **Test colocation deferral.** `frame/tests.rs` keeps testing
   both functions through the re-export. Issue body suggests
   colocation. Plan defers. Reviewers may push back.

7. **`pub(in crate::afxdp::frame)` for the per-family helpers.**
   Helpers are only called from their sibling orchestrator
   (`build/mod.rs` or `rewrite/mod.rs`), so a tighter
   `pub(super)` would work. Plan uses the wider visibility for
   uniformity with the existing `frame/` re-export shape;
   reviewers may push for the tighter `pub(super)`.

8. **Codegen parity verification.** Plan asserts codegen parity
   by smoke matrix only. Should the PR include a `cargo asm` or
   `cargo show-asm` comparison between origin/master and the
   refactor branch? Plan v1 says no — that's a manual auditor
   step, not a CI gate. **Reviewers may push for an explicit
   diff.**
