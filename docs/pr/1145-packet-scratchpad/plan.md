# #1145 — eliminate redundant `area.slice()` calls in `poll_binding_process_descriptor`

## Status

DRAFT — for Codex + Gemini design review.

## Status

REV-2 — addresses Codex round-1 PROCEED-WITH-CHANGES (5 corrections).
Gemini Pro REJECTed claiming mut+immut aliasing UB; Codex
investigated and disproved.

Aliasing argument (corrected per Codex round-2 finding):
- The mutating helpers (`apply_rewrite_descriptor`,
  `rewrite_forwarded_frame_in_place`) at poll_descriptor.rs:351-369
  produce a short-lived `&mut [u8]` borrow that is consumed inside
  the helper and dropped before control returns. Once the helper
  returns, no `&mut [u8]` is alive — `raw_frame: &[u8]` is the only
  borrow.
- The flow-cache fast path then `continue`s at line 435; redundant
  slice sites at 871, 965, 1175, 1643 run only on iterations where
  the fast-path mutation did NOT happen (or in the non-fast-path
  branch). Site 280 and 521 run BEFORE the line-351 rewrite, so the
  mutating borrow doesn't yet exist when those sites read the frame.
- `raw_frame` and the rewrite's `&mut [u8]` thus never coexist in
  the same control-flow point; no aliasing.

Per the project's Gemini-low-signal-on-refactor memory rule and
the verified disproof, proceeding on Codex.

Round-1 corrections applied:
1. Optimizer claim toned down — "may not reliably CSE; perf gain
   must be measured" (Codex finding 1).
2. Callsite shapes documented per-site — line 871 is
   `frame.get(...).map(is_icmp_error)`, line 1643 stores
   `frame_data` reused for debug + hex dumps. Implementation
   must rewrite those local references too, not just swap one
   function arg (Codex finding 2).
3. Framed as narrow precursor / Phase 1 of #1145, not the full
   128-byte scratch-pad refactor (Codex finding 3 + #961
   PacketContext overlap).
4. ✓ raw_frame in scope at all 6 sites (Codex finding 4).
5. ✓ Helper arg type already `&[u8]` (Codex finding 5).
6. ✓ No slice_mut aliasing in helpers reachable from these sites
   (Codex finding 6 — disproves Gemini's UB claim).
7. Use `raw_frame` not `packet_frame` (after native GRE decap)
   (Codex finding 7).
8. Stray scratch text removed.

## Bug

`userspace-dp/src/afxdp/poll_descriptor.rs::poll_binding_process_descriptor` calls `area.slice(desc.addr, desc.len)` 7 times across the per-descriptor loop body for the SAME packet:

| Line | Context |
|------|---------|
| 50 | `let Some(raw_frame) = ...slice(...) else { continue; }` — initial bind |
| 280 | `unsafe{&*area}.slice(desc.addr, desc.len).and_then(|frame| build_local_time_exceeded_request(frame, ...))` |
| 521 | same as 280 (different ICMP-TE branch) |
| 871 | same pattern (slow-path-reinjector branch) |
| 965 | same pattern (different reinjection branch) |
| 1175 | same pattern (NAT64 branch) |
| 1643 | same pattern (fabric-redirect branch) |

Each redundant slice involves bounds-check + pointer arithmetic; the optimizer cannot fully elide them because `*const MmapArea` is opaque.

`raw_frame` (line 50) is lexically in scope at all 6 redundant sites. The fix: replace `unsafe{&*area}.slice(...).and_then(|frame| F(frame, ...))` with `F(raw_frame, ...)` directly.

## Why this matters (per #1145)

Each redundant slice on a 64-byte cache line that's already hot is a few ns at best. But the ergonomic problem is real: callers of helpers like `build_local_time_exceeded_request` are forced to do `Option<&[u8]>` plumbing for a value that's already known-Some at the call site.

The performance gain is small (the slices on a hot UMEM frame ARE cheap at L1d). The clarity gain is the bigger win — no more `unsafe{&*area}.slice(...).and_then(|frame| ...)` boilerplate at 6 sites.

## Fix

For each of the 6 redundant slice sites:

1. Remove the `unsafe{&*area}.slice(desc.addr, desc.len).and_then(|frame| F(frame, ...))` pattern.
2. Replace with `F(raw_frame, ...)` directly.
3. If `F` previously took `Option<&[u8]>` upstream, update its signature to `&[u8]` (since the caller proves Some-ness via the line-50 bind).

This is a callsite refactor, not a deep re-architecture. The proposed full "Packet Context Shadowing" with a 128-byte scratch pad in #1145 is a follow-up (and overlaps with #961 PacketContext) — out of scope.

### What this PR does NOT do

- **No 128-byte scratch pad.** That's the larger refactor referenced in #1145 and overlaps with #961's PacketContext. This PR only eliminates the redundant slice calls inside the existing structure.
- **No helper signature widening.** Helpers like `build_local_time_exceeded_request` already take `&[u8]` for the frame; we're just stopping the caller from re-fetching it.
- **No behavior change.** Each call site previously verified the slice succeeded inline; the line-50 bind is the same verification, made once and reused.

## Tests

- Existing tests cover the public RX→TX path. No new tests needed for a pure callsite refactor.
- `cargo test --release` should pass with no new failures.

## Acceptance gate

- `cargo test --release` clean.
- `cargo build --release` clean, no new warnings.
- Cluster smoke (loss userspace cluster, all 6 CoS classes, **v4 + v6**):
  - iperf3 against `172.16.80.200` + `2001:559:8585:80::200`.
  - All classes pass at expected rates with 0 retransmits.
  - Output should be byte-for-byte identical to baseline (no behavior change expected).
- Optional perf gate: `perf record` on a representative iperf3 run pre/post — slice() count should drop in the call graph. NOT a hard regression gate; included only if the smoke pass is otherwise inconclusive.

## Risks

1. **Lifetime / borrow-checker**: `raw_frame: &[u8]` has the lifetime of the `unsafe{&*area}` reborrow — the slice is valid for the full descriptor iteration. Each redundant site previously created a fresh `&[u8]` with the same lifetime, so the lifetime is unchanged.

2. **Code duplication / branch fall-through**: the redundant slice was nested inside conditional branches. Each branch has its own scope but `raw_frame` is from the enclosing scope — verified by `grep`-walking the function structure.

3. **Helpers that mutate**: do any of the helpers fed by these redundant slices do `area.slice_mut(...)` for the SAME frame? `slice_mut` would aliasing-violate against `raw_frame: &[u8]`. Audit each call site.

4. **`*const MmapArea` opacity**: the optimizer might already partially-CSE the redundant slices. The clarity gain is real regardless; the perf gain might be smaller than expected.
