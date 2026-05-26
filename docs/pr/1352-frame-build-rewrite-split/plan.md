# #1352 Step 1 — Split `frame/mod.rs` 236-LOC `build_forwarded_frame_into_from_frame` + 223-LOC `apply_rewrite_descriptor` into `frame/{build,rewrite}/` by address family

**Status:** v4 — addresses Codex r3 PLAN-NEEDS-MAJOR (cargo
`--bin xpf-userspace-dp` + objdump on canonical binary +
**generic monomorphization axis: `impl Into<ForwardPacketMeta>`
breaks the ONE-binary-definition invariant**) and AGY r3
PLAN-NEEDS-MINOR (**`apply_rewrite_descriptor` `#[inline(never)]`
hurts fast-path** because only one caller; `mod tcp;` is private
and blocks `super::super::tcp::clamp_tcp_mss_frame`; missing
imports in build/ipv6.rs and both rewrite per-family files;
`trim_l3_payload` / `rewrite_prepare_eth_from_parts` private
visibility blockers).

## Round-3 review disposition

Codex r3 ([task-mpmzkrop-r368rl](reviewer-ids.md)) PLAN-NEEDS-MAJOR;
AGY r3 ([adversarial-review-mpmzl98h-i50fex](reviewer-ids.md))
PLAN-NEEDS-MINOR. Combined findings:

1. **Codex r3 Major #1 — cargo command needs `--bin
   xpf-userspace-dp`.** This package has two bin targets
   (`main.rs:52` → `xpf-userspace-dp`, `bin/fairness-eval.rs:15` →
   `fairness-eval`). Cargo refuses `cargo rustc ... -- --emit=asm`
   without an explicit `--bin`. **Resolution:** v4 adds
   `--bin xpf-userspace-dp` to the rustc invocation.

2. **Codex r3 Major #2 — asm-diff via `--emit=asm` doesn't
   reflect canonical shipped binary.** Even with
   `codegen-units=1`, `--emit=asm` runs without final ThinLTO
   link-time inlining; register allocation, block layout,
   wrapper call shape can differ from the linked binary.
   **Resolution:** v4 adds `objdump -drwC
   target/release/xpf-userspace-dp` slices at each caller
   region as the canonical asm-diff artifact (baseline vs PR).
   The `--emit=asm` step stays for the supplementary
   helper-symbol grep but is no longer the primary asm diff.

3. **Codex r3 Major #3 — generic monomorphization breaks
   ONE-definition invariant.** The orchestrator signature
   uses `meta: impl Into<ForwardPacketMeta>` (preserved from
   today's `mod.rs:221`). `#[inline(never)]` prevents normal
   inlining BUT does NOT prevent rustc from emitting one
   non-inlined body per concrete monomorphization. In current
   master, all callers pass `ForwardPacketMeta` itself
   (`request.meta` is `ForwardPacketMeta`), so only one
   monomorphization exists empirically. **But the invariant
   "ONE binary definition" is not statically guaranteed by the
   generic signature.**
   **Resolution:** v4 changes the orchestrator signature from
   `meta: impl Into<ForwardPacketMeta>` to `meta:
   ForwardPacketMeta` (concrete). Callers either already pass
   `ForwardPacketMeta` (dispatch.rs:654 passes `request.meta`
   which IS `ForwardPacketMeta` per `types/tx.rs:68`) or
   convert at the call site with `.into()`. The internal
   `build_forwarded_frame_into` adapter at `mod.rs:470` and
   `build_forwarded_frame_from_frame` at `mod.rs:191` keep
   their generic `impl Into` for ergonomic test wrappers, but
   they call `.into()` BEFORE invoking the concrete-typed
   orchestrator. ONE binary definition of
   `build_forwarded_frame_into_from_frame` is now structurally
   guaranteed. Same for `apply_rewrite_descriptor` — already
   takes concrete `UserspaceDpMeta` (mod.rs:909), no change
   needed.

4. **AGY r3 §3-A — `apply_rewrite_descriptor` `#[inline(never)]`
   hurts fast-path.** AGY argued: `apply_rewrite_descriptor`
   has exactly ONE caller (`poll_descriptor.rs:746`),
   inside a per-packet SIMD descriptor loop. Forcing
   `#[inline(never)]` causes a real call/ret + parameter spill
   for every packet, blocking inter-procedural register
   allocation across the loop. With one caller, transitive
   i-cache duplication is impossible — there's nowhere to
   duplicate INTO. The `#[inline(never)]` is over-conservative.
   **Resolution:** v4 changes
   `apply_rewrite_descriptor`'s attribute from `#[inline(never)]`
   back to `#[inline]` (LLVM heuristic), while `apply_rewrite_descriptor_ipv4/6`
   stays `#[inline(always)]`. This restores fast-path
   inter-procedural register allocation while preserving the
   per-family helper inlining.

   For `build_forwarded_frame_into_from_frame` the
   `#[inline(never)]` stays because it has 5 caller sites
   (transitive duplication IS a real risk) AND because it's
   on the slower scratch TX dispatch path (the per-packet
   register-allocation latency cost is less critical there
   than for the SIMD descriptor loop).

5. **AGY r3 §3-B + §4-A — `mod tcp;` is private** in
   `frame/mod.rs:6`. v3's sketch `use super::super::tcp::clamp_tcp_mss_frame;`
   cannot traverse the private parent sibling module.
   **Resolution:** v4 promotes `mod tcp;` to `pub(super) mod
   tcp;` in `frame/mod.rs:6`. The sub-module visibility
   widens by ONE step (from "frame-private" to "afxdp-private")
   which is the minimum needed to let descendants of
   `frame::build` and `frame::rewrite` traverse into `tcp`.
   Alternative considered: re-export `clamp_tcp_mss_frame` at
   `pub(super)` from `frame/mod.rs` and import via
   `super::super::clamp_tcp_mss_frame`. Rejected because v4
   would need similar re-exports for other helpers
   (`packet_rel_l4_offset`, etc.); making `tcp` reachable is
   the smaller change.

6. **AGY r3 §3-B — `trim_l3_payload` (`mod.rs:849`) and
   `rewrite_prepare_eth_from_parts` (`mod.rs:565`) are
   private.** v3 keeps these in `frame/mod.rs`, but the
   orchestrators in `frame/build/mod.rs` and
   `frame/rewrite/mod.rs` need to call them.
   **Resolution:** v4 upgrades both to `pub(super)` in
   `frame/mod.rs`. They stay defined where they are; only
   visibility changes so the orchestrator submodules can
   reach them via `use super::super::{trim_l3_payload,
   rewrite_prepare_eth_from_parts};`.

7. **AGY r3 §4-B — `packet_rel_l4_offset` missing from
   `build/ipv6.rs` imports.** The IPv6 build arm at
   `mod.rs:355` calls `packet_rel_l4_offset(&out[ip_start..],
   meta.addr_family)`. **Resolution:** v4 adds
   `use super::super::packet_rel_l4_offset;` to `build/ipv6.rs`.

8. **AGY r3 §4-C — `rewrite/ipv4.rs` + `rewrite/ipv6.rs`
   import blocks missing.** The IPv4 rewrite arm calls
   `write_ipv4_src/dst`, `write_l4_src/dst_port`, `PROTO_TCP/UDP`.
   The IPv6 rewrite arm calls `packet_rel_l4_offset`,
   `write_ipv6_src/dst`, `write_l4_src/dst_port`,
   `PROTO_TCP/UDP/ICMPV6`. **Resolution:** v4 lists the
   import blocks explicitly in the §rewrite/ipv4.rs and
   §rewrite/ipv6.rs sketches (added below).

9. **Codex r3 minor — stale wording at `plan.md:267`
   (smoke-matrix line-rate gate) and at `plan.md:858`.**
   **Resolution:** v4 sweeps remaining stale references.

10. **AGY r3 §1 — confirmed v3 closes all r2 high-confidence
    findings.** Accepted.

11. **AGY r3 §2 — `#[inline(never)]` is structurally honored
    by ThinLTO across CGUs.** Accepted; the attribute does
    survive the ThinLTO boundary. The remaining concern is
    the generic-monomorphization axis (Codex r3 Major #3),
    addressed by §3 above.

## Round-2 review disposition

Codex r2 ([task-mpmzar03-0i9jmr](reviewer-ids.md)) PLAN-NEEDS-MAJOR; AGY r2
([adversarial-review-mpmzb3y8-hxt9tj](reviewer-ids.md))
PLAN-NEEDS-MINOR. Combined findings:

1. **Codex r2 Major #1 / AGY r2 HIGH-1+HIGH-2 — cargo command
   shape is wrong.** Package name is `xpf-userspace-dp` (verified
   `userspace-dp/Cargo.toml:2`). Repo has no root workspace —
   `cargo metadata` from repo root fails. Asm glob mismatch:
   compiler emits `xpf_userspace_dp-*.s`, not `userspace_dp-*.s`.
   **Resolution:** v3 fixes the cargo invocation.

2. **AGY r2 #3 — codegen-units=16 default false positives.**
   `cargo --emit=asm` emits BEFORE ThinLTO; cross-codegen-unit
   calls appear as `call` instructions in the `.s` even when
   ThinLTO inlines them in the final linked binary. **Resolution:**
   v3 forces `RUSTFLAGS="-C codegen-units=1"` for the codegen
   verification step.

3. **AGY r2 #1 — grep target should match `call` instructions,
   not symbol names.** Symbol names appear in `.file` / `.asciz`
   / `.loc` directives even when inlined. **Resolution:** v3
   greps for `callq?\s+.*<helper>` and also adds `nm -C` on the
   final compiled binary as the canonical canary.

4. **Codex r2 Major #2 — asm-grep necessary but not sufficient.**
   The grep can pass while register allocation, branch layout,
   caller inlining, cold block placement regresses. **Resolution:**
   v3 strengthens the gate. Required artifacts on the PR:
   - `nm -C` against the final `target/release/xpf-userspace-dp`
     binary: ZERO definitions of the per-family helper symbols.
   - Asm slice (~80-120 lines) at each caller site from the `.s`
     compiled with `-C codegen-units=1`: must match what's
     present in baseline (origin/master) for THE SAME caller
     site after subtracting the obvious symbol renames. A
     `diff` of the two asm slices is included as a PR
     attachment; reviewer reads it before MERGE-READY.
   - The wave-end batch smoke remains the aggregate-perf gate.
     The codegen artifacts are the per-PR isolation mechanism
     (catch a missed inline) — not a perf proof on their own.

5. **Codex r2 Major #3 — i-cache duplication risk from wrapper
   transitive inlining.** `build_forwarded_frame_into_from_frame`
   is called from 5 places: `frame/mod.rs:201` and `:480`
   (internal wrappers) plus TX caller sites at
   `tx/dispatch.rs:505`, `:651`, `:785`. If LLVM inlines the
   orchestrator through ANY of those wrappers, the always-inlined
   per-family helpers duplicate. **Resolution:** v3 reduces
   `#[inline(always)]` only to the per-family helpers AND adds a
   `#[inline(never)]` veto on `build_forwarded_frame_into_from_frame`
   to prevent the orchestrator from being inlined into its caller
   wrappers (and thus duplicating the helpers transitively).

   Practical effect: ONE definition of the
   `build_forwarded_frame_into_from_frame` body exists in the
   binary. Each TX caller site sees ONE `call` to the orchestrator
   (acceptable — these are NOT the per-packet inner loop, they're
   the per-batch dispatch step). The per-family body is fully
   folded into the orchestrator's body, no register-spill bleed.

   For `apply_rewrite_descriptor` (which has fewer callers — just
   `poll_descriptor.rs:746` and is itself called per-batch not
   per-packet inside the SIMD descriptor loop), the same
   `#[inline(never)]` veto is applied. Same rationale.

   The codegen verification step is now: ZERO `nm -C` definitions
   of `build_forwarded_frame_into_ipv4/6` /
   `apply_rewrite_descriptor_ipv4/6` (per-family helpers fully
   inlined), exactly ONE definition each of
   `build_forwarded_frame_into_from_frame` /
   `apply_rewrite_descriptor` (orchestrators NOT inlined into
   wrappers).

6. **Codex r2 Minor — stale `#[inline]` in code sketch + risk
   table.** Two stale references at lines 283 and 547 of v2.
   **Resolution:** v3 sweeps all `#[inline]` mentions in code
   sketches + risk text to match the v3 attribute matrix.

7. **AGY r2 HIGH-3 — private-import scoping.** `frame/mod.rs:59`
   does `use tcp::clamp_tcp_mss_frame;` (private). Sub-modules
   under `build/` and `rewrite/` cannot inherit private items
   via `use super::super::*;`. Same applies to
   `native_gre_tcp_mss` (a re-export from `crate::afxdp::*` via
   the `super::*` in `frame/mod.rs:1`). **Resolution:** v3 adds
   explicit imports at the top of each per-family file:

   ```rust
   // build/ipv4.rs / build/ipv6.rs
   use super::super::tcp::clamp_tcp_mss_frame;
   use crate::afxdp::native_gre_tcp_mss;  // if used in helper
   use super::super::{
       adjust_ipv4_header_checksum, apply_nat_ipv4, apply_nat_ipv6,
       enforce_expected_ports_at, recompute_l4_checksum_ipv4,
       recompute_l4_checksum_ipv6, restore_l4_tuple_from_meta,
   };
   ```

   `native_gre_tcp_mss` is computed in the orchestrator (the
   `tunnel_tcp_mss` value is passed into the per-family helper by
   value), so per-family helpers do NOT need to import
   `native_gre_tcp_mss` themselves. Only `clamp_tcp_mss_frame`
   needs the explicit import.

8. **AGY r2 HIGH-4 — `expected_ports` / `enforced_ports` naming
   mismatch.** v2 sketch parameter named `expected_ports`; the
   real body at mod.rs:229 stores `let enforced_ports =
   expected_ports;` and then uses `enforced_ports`. **Resolution:**
   v3 renames the sketch parameter to `expected_ports` AND keeps
   the local `let enforced_ports = expected_ports;` rebinding
   inside the per-family helper, byte-identical to today.

9. **AGY r2 MED-1 — `RewriteDescriptor` path from `rewrite/mod.rs`.**
   v2 uses `&super::RewriteDescriptor`; the correct path from
   inside `rewrite/mod.rs` (where `super` is `frame`) is
   `crate::afxdp::RewriteDescriptor`. **Resolution:** v3 uses
   `crate::afxdp::RewriteDescriptor` explicitly.

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
the v4 codegen contract (§Hot-path discipline) — `#[inline(always)]`
on per-family helpers + `#[inline(never)]` on
`build_forwarded_frame_into_from_frame` + `#[inline]` on
`apply_rewrite_descriptor` + concrete `ForwardPacketMeta`
parameter type to prevent monomorphization duplication — plus
the per-PR codegen-verification gate (nm + objdump + asm-grep,
all on the canonical linked binary).

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

#[inline(never)]
pub(in crate::afxdp) fn build_forwarded_frame_into_from_frame(
    out: &mut [u8],
    frame: &[u8],
    meta: ForwardPacketMeta,   // v4: concrete (was `impl Into<...>`)
    decision: &SessionDecision,
    forwarding: &ForwardingState,
    apply_nat_on_fabric: bool,
    expected_ports: Option<(u16, u16)>,
) -> Option<usize> {
    // v4: meta arrives concrete; no .into() call here. The two
    // wrappers at frame/mod.rs:201 and frame/mod.rs:480 still
    // take `impl Into<ForwardPacketMeta>` and call .into() before
    // forwarding the concrete value into this orchestrator.
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

Note v3 import shape: per AGY r2 HIGH-3, private items reached
via `use tcp::clamp_tcp_mss_frame;` in `frame/mod.rs:59` are NOT
inherited by `use super::super::*;` in nested modules, so each
per-family file imports its direct dependencies explicitly.

```rust
// frame/build/ipv4.rs
use super::super::tcp::clamp_tcp_mss_frame;
use super::super::{
    adjust_ipv4_header_checksum, apply_nat_ipv4,
    enforce_expected_ports_at, recompute_l4_checksum_ipv4,
    restore_l4_tuple_from_meta,
};
use crate::afxdp::{ForwardPacketMeta, SessionDecision};
use std::net::Ipv4Addr;

#[inline(always)]
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
    // Note: preserves the existing `let enforced_ports = expected_ports;`
    // rebinding at the top of the function so all interior references
    // continue to use the `enforced_ports` name byte-identical to today.
    let enforced_ports = expected_ports;
    if out.len() < ip_start + 20 {
        return None;
    }
    let ihl = ((out[ip_start] & 0x0f) as usize) * 4;
    // ... rest of body byte-identical to mod.rs:289..341 ...
    Some(())
}
```

(IPv6 mirrors the same shape — body byte-identical to today's
mod.rs:342..380. Per-family v4 import block for `build/ipv6.rs`
(AGY r3 §4-B `packet_rel_l4_offset` missing in v3):

```rust
// frame/build/ipv6.rs
use super::super::tcp::clamp_tcp_mss_frame;
use super::super::{
    apply_nat_ipv6, enforce_expected_ports_at, packet_rel_l4_offset,
    recompute_l4_checksum_ipv6, restore_l4_tuple_from_meta,
};
use crate::afxdp::{ForwardPacketMeta, SessionDecision};
```

### `rewrite/ipv4.rs` sketch (v4 — AGY r3 §4-C)

```rust
// frame/rewrite/ipv4.rs
use super::super::byte_writes::{
    write_ipv4_dst, write_ipv4_src, write_l4_dst_port, write_l4_src_port,
};
use crate::afxdp::{
    RewriteDescriptor, UserspaceDpMeta, PROTO_TCP, PROTO_UDP,
};
use std::net::IpAddr;

#[inline(always)]
pub(in crate::afxdp::frame) fn apply_rewrite_descriptor_ipv4(
    packet: &mut [u8],
    ip: usize,
    skip_ttl: bool,
    apply_nat: bool,
    meta: UserspaceDpMeta,
    rd: &RewriteDescriptor,
    expected_ports: Option<(u16, u16)>,
) -> Option<()> {
    // Body byte-identical to today's mod.rs:937..1037.
    // ...
    Some(())
}
```

### `rewrite/ipv6.rs` sketch (v4 — AGY r3 §4-C)

```rust
// frame/rewrite/ipv6.rs
use super::super::byte_writes::{
    write_ipv6_dst, write_ipv6_src, write_l4_dst_port, write_l4_src_port,
};
use super::super::packet_rel_l4_offset;
use crate::afxdp::{
    RewriteDescriptor, UserspaceDpMeta, PROTO_ICMPV6, PROTO_TCP, PROTO_UDP,
};
use std::net::IpAddr;

#[inline(always)]
pub(in crate::afxdp::frame) fn apply_rewrite_descriptor_ipv6(
    packet: &mut [u8],
    ip: usize,
    skip_ttl: bool,
    apply_nat: bool,
    meta: UserspaceDpMeta,
    rd: &RewriteDescriptor,
    expected_ports: Option<(u16, u16)>,
) -> Option<()> {
    // Body byte-identical to today's mod.rs:1038..1115.
    // ...
    Some(())
}
```

(`byte_writes` is already `mod byte_writes;` at `frame/mod.rs:3`
— v4 needs to promote it to `pub(super) mod byte_writes;` to be
reachable from descendants of `frame/rewrite/`.)

### Visibility upgrades in `frame/mod.rs` (v4)

```rust
// frame/mod.rs (modifications by this PR)
pub(super) mod byte_writes;   // was: mod byte_writes;
pub(super) mod tcp;           // was: mod tcp;

pub(super) fn trim_l3_payload<'a>(...) -> &'a [u8] { ... }  // was: fn ...
pub(super) fn rewrite_prepare_eth_from_parts(...) -> Option<...> { ... }  // was: fn ...
```

These visibility upgrades are the minimum needed for the
descendants of `frame/build/` and `frame/rewrite/` to reach the
helpers they call. Same-scope behavior is unchanged (no new
external symbol surface — `pub(super)` from `frame/mod.rs` is
"frame-private", same as before).)

### `rewrite/mod.rs` orchestrator shape

```rust
// frame/rewrite/mod.rs
use super::*;
mod ipv4;
mod ipv6;
pub(in crate::afxdp::frame) use ipv4::apply_rewrite_descriptor_ipv4;
pub(in crate::afxdp::frame) use ipv6::apply_rewrite_descriptor_ipv6;

#[inline]   // v4: standard hint (was #[inline(never)]); AGY r3 §3-A
pub(in crate::afxdp) fn apply_rewrite_descriptor(
    area: &MmapArea,
    desc: XdpDesc,
    meta: UserspaceDpMeta,
    rd: &crate::afxdp::RewriteDescriptor,
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

**v3 codegen contract** (after Codex r2 Major #3 +
i-cache-duplication finding):

| Symbol | Attribute | Rationale |
|---|---|---|
| `build_forwarded_frame_into_ipv4` | `#[inline(always)]` | One call site (orchestrator's match arm). Bypass SysV ABI register-spill via SROA + SSA at inlined site. |
| `build_forwarded_frame_into_ipv6` | `#[inline(always)]` | Same. |
| `apply_rewrite_descriptor_ipv4` | `#[inline(always)]` | Same. |
| `apply_rewrite_descriptor_ipv6` | `#[inline(always)]` | Same. |
| `build_forwarded_frame_into_from_frame` (orchestrator) | `#[inline(never)]` + concrete `meta: ForwardPacketMeta` | Prevent transitive duplication through 5 caller wrappers: `frame/mod.rs:201`, `:480`, `tx/dispatch.rs:505`, `:651`, `:785`. Concrete `ForwardPacketMeta` parameter (v4 — was generic `impl Into<...>`) closes the monomorphization-duplication axis. ONE definition in the binary; each caller emits one `call` instruction. The orchestrator + folded-in per-family body is the unit of code that lives in i-cache. |
| `apply_rewrite_descriptor` (orchestrator) | `#[inline]` (v4 — was `#[inline(never)]`) | Per-packet SIMD descriptor loop above caller (`poll_descriptor.rs:746`) is the production hot path. Has exactly ONE caller, so transitive i-cache duplication impossible. v4 lets LLVM heuristic inline at this call site to restore inter-procedural register allocation across the loop. AGY r3 §3-A finding. |

v4 attribute logic (asymmetric, derived from caller count):

- Per-family helpers MUST be inlined (register-spill avoidance,
  same for both functions — single call site).
- Orchestrator with >1 caller (build) MUST NOT be inlined
  (transitive duplication avoidance + slow-path tolerable
  per-call latency).
- Orchestrator with =1 caller (rewrite) gets standard `#[inline]`
  hint (no duplication risk; LLVM optimizes for fast-path
  inter-procedural register allocation).
- Concrete (non-generic) `meta: ForwardPacketMeta` parameter on
  the build orchestrator closes the monomorphization-duplication
  axis. ONE definition structurally guaranteed.

**Verification step (per-PR codegen gate, v3):**

The gate is intentionally tighter than v2: package name corrected
(`xpf-userspace-dp`), codegen-units forced to 1 (so the asm
emission reflects the same inlining decisions LLVM will make in
the linked binary), grep targets only `call` instructions (not
symbol references in `.file` / `.loc` directives), and `nm -C`
on the final linked binary is the canonical canary.

```bash
# === In the worktree, after implementation ===

# Step A: Build the release binary normally and run the canonical
# nm -C check. This is the load-bearing gate. The linked binary
# reflects ThinLTO's final inlining decisions.
TMPDIR=/dev/shm CARGO_TARGET_DIR=/dev/shm/cargo \
  cargo build --release --manifest-path userspace-dp/Cargo.toml

BIN=/dev/shm/cargo/release/xpf-userspace-dp
nm -C "$BIN" | \
  grep -E "build_forwarded_frame_into_ipv4|build_forwarded_frame_into_ipv6|apply_rewrite_descriptor_ipv4|apply_rewrite_descriptor_ipv6"
# Expected: ZERO matches (per-family helpers fully inlined).
# If any match, the PR MUST NOT MERGE until codegen is restored.

# Also verify exactly ONE definition each of the orchestrators
# (#[inline(never)] mandate from v3):
nm -C "$BIN" | \
  grep -E "build_forwarded_frame_into_from_frame|apply_rewrite_descriptor"
# Expected: exactly ONE definition per orchestrator (no duplication
# through caller wrappers).

# Step B: objdump disassembly of the canonical linked binary
# at each caller region. This is the load-bearing asm-diff
# artifact (Codex r3 Major #2). objdump operates on the final
# linked binary so ThinLTO's actual inlining decisions are
# baked in.
objdump -drwC "$BIN" \
  | awk '/<[^>]*build_forwarded_frame_into_from_frame[^>]*>:/,/^$/ {print}' \
  > /tmp/1352-orch-build.asm
objdump -drwC "$BIN" \
  | awk '/<[^>]*apply_rewrite_descriptor[^>]*>:/,/^$/ {print}' \
  > /tmp/1352-orch-rewrite.asm
# Baseline pair captured on origin/master:
git worktree add -f /dev/shm/master-baseline origin/master \
  && (cd /dev/shm/master-baseline && cargo build --release \
      --manifest-path userspace-dp/Cargo.toml 2>/dev/null \
      && objdump -drwC /dev/shm/cargo/release/xpf-userspace-dp \
         | awk '/<[^>]*build_forwarded_frame_into_from_frame[^>]*>:/,/^$/ {print}' \
         > /tmp/1352-master-orch-build.asm)
# Reviewer attaches diff /tmp/1352-master-orch-build.asm
# /tmp/1352-orch-build.asm as PR artifact (and same for rewrite).

# Step C: supplementary --emit=asm grep for per-family helper
# call instructions (AGY HIGH-1 + r2 #3). codegen-units=1 +
# explicit --bin xpf-userspace-dp (Codex r3 Major #1).
RUSTFLAGS="-C codegen-units=1" \
  TMPDIR=/dev/shm CARGO_TARGET_DIR=/dev/shm/cargo-asm \
  cargo rustc --release --manifest-path userspace-dp/Cargo.toml \
    --bin xpf-userspace-dp -- --emit=asm
ASM=$(ls /dev/shm/cargo-asm/release/deps/xpf_userspace_dp-*.s | head -1)

# Sanity-check that no `call` instructions to per-family helpers
# leak into the final asm:
grep -E "callq?\s+.*build_forwarded_frame_into_ipv[46]" "$ASM" || true
grep -E "callq?\s+.*apply_rewrite_descriptor_ipv[46]" "$ASM" || true
# Expected: zero output from each grep.
```

**Required PR artifacts** (posted as comments on the PR):

1. `nm -C` output filtered to the 6 symbols above. ZERO
   per-family helper definitions, exactly ONE orchestrator
   definition each.
2. The 80-120-line asm slice around each caller region
   (`tx/dispatch.rs:651`, `poll_descriptor.rs:746`,
   `frame/mod.rs:201`, `:480`, `tx/dispatch.rs:505`, `:785`),
   captured BOTH for `origin/master` and the PR HEAD. A unified
   diff of the two slices is attached. Reviewer reads the diff
   before MERGE-READY.
3. The grep results from Step B (zero output expected).

**If any gate fails (nm finds a per-family helper symbol; nm
finds duplicate orchestrators; asm grep finds a `call` to a
per-family helper), the PR MUST NOT MERGE.** The attributes
need adjustment OR an upstream wrapper at `frame/mod.rs:201` /
`:480` needs its own attribute to keep ThinLTO from
duplicating the orchestrator transitively.

Code sketch of the orchestrator/helper layering (v4 attributes):

```rust
// frame/build/mod.rs
#[inline(never)]                // veto: 5 caller wrappers; ONE binary definition
pub(in crate::afxdp) fn build_forwarded_frame_into_from_frame(
    out: &mut [u8],
    frame: &[u8],
    meta: ForwardPacketMeta,    // v4: concrete (closes generic monomorphization axis)
    ...
) -> Option<usize> { ... }

// frame/build/ipv4.rs
#[inline(always)]               // mandate: single call site, bypass ABI spill
pub(in crate::afxdp::frame) fn build_forwarded_frame_into_ipv4(...) -> Option<()> { ... }

// frame/rewrite/mod.rs
#[inline]                       // v4: standard hint (was inline(never)); single caller fast-path
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

11. **v4 codegen contract.** Per-family helpers inline into
    their orchestrator (SROA/SSA bypass of ABI register-spill).
    `build_forwarded_frame_into_from_frame` is non-inlined +
    concrete-typed `ForwardPacketMeta` parameter (ONE definition
    structurally guaranteed; no transitive duplication through
    5 wrapper paths; no generic-monomorphization fanout).
    `apply_rewrite_descriptor` gets standard `#[inline]` hint
    (single caller, fast-path inter-procedural register
    allocation across the SIMD descriptor loop). **Codegen is
    verified per-PR via the nm + objdump + asm-grep gate
    (§Test plan step 5), NOT by an iperf smoke.** Wave-end
    batch smoke remains the aggregate-perf gate.

## Risk assessment

| Risk class | Level | Notes |
|---|---|---|
| Behavioral regression | LOW | Pure code motion. Per-family bodies byte-identical to the existing AF_INET / AF_INET6 / 0x0800 / 0x86dd arms modulo the parameter list. Side-effect ordering preserved by keeping all steps inside the per-family helper. |
| Lifetime / borrow-checker | LOW-MED | Per-family helpers take `&mut [u8]` + several `Copy` scalars + `&SessionDecision` (immutable). No new lifetime parameter; the helper signature uses one lifetime implicitly (the `&mut [u8]`). `apply_rewrite_descriptor_ipv4/6` takes `&mut [u8]` (the unsafe-borrowed UMEM slice) and `meta: UserspaceDpMeta` (Copy) and `rd: &RewriteDescriptor` — same shape as today's match arm. |
| Performance regression | LOW-MED (verified by asm-diff + wave-batch smoke) | The codegen-parity hazard is real. Mitigation: `#[inline(always)]` on per-family helpers + `#[inline(never)]` on orchestrators + per-PR nm/asm-grep/asm-diff gate (§Test plan step 5) + wave-end batch smoke. If the codegen gate fails (per-family helper symbol present in nm, orchestrator duplicated, or asm `call` to helper present), the PR does NOT merge. If the wave-end batch smoke shows <line rate or any retrans, the split is reverted to a single-file orchestrator + helper module shape OR the inline attributes are reconsidered. |
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
5. **Codegen verification step (per-PR, v4 mandate).** Run the
   commands in §Hot-path discipline (§Verification step). The
   load-bearing artifacts are:
   - `nm -C target/release/xpf-userspace-dp` — ZERO per-family
     helper definitions; exactly ONE definition each of the two
     orchestrators (canonical linked binary).
   - `objdump -drwC target/release/xpf-userspace-dp` slices
     around the orchestrator regions, baseline vs PR HEAD,
     attached as a unified diff (Codex r3 Major #2 canonical
     gate).
   - Supplementary: `RUSTFLAGS="-C codegen-units=1" cargo rustc
     --release --manifest-path userspace-dp/Cargo.toml --bin
     xpf-userspace-dp -- --emit=asm` followed by
     `grep "callq?\s+.*<helper>"` on the emitted
     `xpf_userspace_dp-*.s` — ZERO matches.
   **If any gate fails the PR MUST NOT MERGE until codegen is
   restored.**
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
