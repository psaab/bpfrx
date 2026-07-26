# Plan: split `coordinator/wg_control.rs` into `wg_control/{mtu,sock,attempt,dispatch}.rs` (#6438)

## Goal

`wg_control.rs` (exactly 1,600 LOC) is the WG datapath control thread
with god-functions on the per-packet WG tunnel path:

| Function | Lines | Params | Layer |
|---|---|---|---|
| `run_wg_control_loop` (:334) | 325 | 9 | orchestration |
| `dispatch_inbound` (:1324) | 209 | 11 | dispatch + encap |
| `drive_attempt_machine` (:712) | 130 | 11 | attempt machine |

plus three more fused layers: MTU math (:59-93), the poll(2) wait layer
(:274-328), and the socket+cmsg codec (:912-1275). Split the file into a
`wg_control/` module directory with one responsibility per file, pure
code-motion, no behavior change (docs/engineering-style.md modularity
discipline).

## Layout (mirrors the issue's prescribed split)

| File | Contents (moved verbatim) | ~LOC |
|---|---|---|
| `wg_control/mod.rs` | module docs, thread entry `wg_control_loop`, the orchestrating `run_wg_control_loop`, loop-level consts (`WG_RX_BURST`, `WG_TIMER_TICK_NS`, `WG_TUN_FATAL_READ_LIMIT`), submodule wiring + re-exports, `mod tests` | ~500 |
| `wg_control/mtu.rs` | `WG_DEFAULT_OUTER_MTU`, `wg_encapped_size`, `wg_inner_fits_outer_mtu` (`pad_to_16` now imported from the `wg` framing SSOT) | ~45 |
| `wg_control/sock.rs` | socket+cmsg codec + poll layer: `bind_wg_socket`, `bind_dual_stack_v6`, `set_recv_tos_options`, `canonicalize_endpoint`, `wg_send_to`, `WgRecv`, `CmsgBuf` (+ its `const _` align assert, #2334), `wg_recvmsg`, `parse_outer_ecn_from_cmsg`, `sockaddr_storage_to_socketaddr`, `PollWait`, `wg_poll_wait`, `poll_timeout_ms`, `WG_POLL_CAP_MS` | ~460 |
| `wg_control/attempt.rs` | attempt state machine: `HandshakeAttempt`, `AttemptTrigger`, `start_attempt`, `drive_attempt_machine`, `drive_initiation`, `send_keepalive`, `pace_keepalive_skip` | ~320 |
| `wg_control/dispatch.rs` | `InboundOutcome` + impl, `dispatch_inbound`, `encap_and_send` | ~310 |

The `wg_control_tests.rs` file (822 LOC) moves byte-identical to
`wg_control/wg_control_tests.rs` (git rename) — the
`#[path = "wg_control_tests.rs"] mod tests;` declaration in `mod.rs`
resolves relative to the module directory, and the tests' `use super::*`
then binds the `wg_control` module namespace exactly as before.

## Guardrails honored

- **No per-packet alloc**: the four 64 KiB scratch buffers stay
  once-allocated in `run_wg_control_loop`; buffers keep flowing into the
  moved helpers by `&mut [u8]` exactly as today.
- **`CmsgBuf` const assert travels** to `sock.rs` with the wrapper.
- **ECN-cmsg codec + auth-before-roam ordering**: `wg_recvmsg` /
  `parse_outer_ecn_from_cmsg` land in `sock.rs`; the
  dispatch→authenticate→`outcome.peer()` endpoint-learn ordering and the
  completion-site edge-drain + post-msg2 keepalive stay in
  `run_wg_control_loop` (mod.rs), statement-for-statement.
- **Attributes travel**: `#[inline]` on `pad_to_16` / `wg_encapped_size`
  / `wg_inner_fits_outer_mtu`; `#[allow(clippy::too_many_arguments)]` on
  each god-fn; fn-local `use` statements inside `drive_attempt_machine`
  / `send_keepalive` / `bind_dual_stack_v6` move verbatim with their fns.
- **Visibility preserved**: moved items become `pub(super)` inside their
  submodule = visible across the `wg_control` tree, exactly the reach
  they had as file-private items. `WG_DEFAULT_OUTER_MTU` keeps
  coordinator-tree visibility via `pub(super) use mtu::WG_DEFAULT_OUTER_MTU`
  in mod.rs (tunnel_supervision.rs names
  `wg_control::WG_DEFAULT_OUTER_MTU` at :716/:728/:760).
  `wg_control_loop` stays `pub(super)` in mod.rs (named by
  tunnel_supervision.rs:843). Test-only seams (`wg_send_to`, `CmsgBuf`,
  `parse_outer_ecn_from_cmsg`, `sockaddr_storage_to_socketaddr`,
  `wg_encapped_size`, `wg_inner_fits_outer_mtu`, `WG_POLL_CAP_MS`,
  `pad_to_16`) re-import into mod.rs `#[cfg(test)]`-gated, matching the
  #6436 gating precedent so non-test builds carry no unused-import
  warnings.

## pad_to_16 SSOT fold (in scope — same files)

Three identical private `const fn pad_to_16` bodies exist:
`wg_control.rs:73`, `wg/engine.rs:326`, `frame/wg.rs:29`. Per
engineering-style "one source of truth for every formula", the
definition moves to `wg/mod.rs` next to the other wire-format constants
(`WG_DATA_HEADER_LEN`, `POLY1305_TAG_LEN`) as
`pub(crate) const fn pad_to_16`; the three sites delete their local
copies and import it. All three call-graphs are intra-crate; the
`const _` pad-proof assert in engine.rs (:318-322) keeps working
(const-fn resolution is import-path independent). The
`pad_to_16_rounds_up` unit test in `frame/wg_tests.rs` and the MTU-guard
tests in `wg_control_tests.rs` resolve the helper through their existing
`use super::*` chains — no test edits.

## Files touched

- `userspace-dp/src/afxdp/coordinator/wg_control.rs` → deleted (split)
- `userspace-dp/src/afxdp/coordinator/wg_control/{mod,mtu,sock,attempt,dispatch}.rs` → new
- `userspace-dp/src/afxdp/coordinator/wg_control_tests.rs` → `wg_control/wg_control_tests.rs` (rename, verbatim)
- `userspace-dp/src/afxdp/wg/mod.rs` (+~10: pad_to_16 SSOT)
- `userspace-dp/src/afxdp/wg/engine.rs` (−6/+1: drop local pad_to_16)
- `userspace-dp/src/afxdp/frame/wg.rs` (−6/+1: drop local pad_to_16)
- `userspace-dp/src/afxdp/coordinator/README.md` (file-table row)
- `_Log.md`

## Alternatives rejected

- **Keep `wg_control.rs` as a thin shell + `wg_control/` submodules** —
  Rust 2018 forbids `foo.rs` and `foo/` coexisting; the rename to
  `wg_control/mod.rs` is the idiomatic move and matches `reconcile/`,
  `binding_state/`.
- **Poll layer as its own `poll.rs`** — the issue prescribes four files;
  the poll helpers are 60 LOC of fd-wait logic that belongs with the
  socket layer (`sock.rs`).
- **Leave pad_to_16 triplicated** — the issue offers the fold "if it
  stays in scope for these files"; all three sites are in the touched
  set (`wg_control.rs` itself, plus two one-line import changes), so it
  folds here.

## Test strategy

- `wg_control_tests.rs` (822 LOC, incl. `run_wg_control_loop` poll-loop
  fixtures, `drive_attempt_machine` give-up/T8 pacing, cmsg codec,
  v4-mapped send, MTU guard) passes **unmodified** — the primary
  behavior-preservation gate.
- Full `cargo test` on the crate (make test-rust runs
  `--test-threads=1`) for the engine/frame/WG suites that share the
  moved `pad_to_16`.
- Warning parity on `cargo check` / `cargo check --tests` vs the
  4bc33a3b0 base (the #6436 precedent: no new warnings).
- asm-diff (objdump -Cd, address/symbol normalized) of the release
  binary on the per-packet fns: `run_wg_control_loop`,
  `dispatch_inbound`, `drive_attempt_machine`, `encap_and_send`,
  `wg_recvmsg`, `wg_send_to`, `drive_initiation`, `send_keepalive`,
  `wg_encap_frame` (frame/wg.rs pad_to_16 fold site). Report any delta
  with explanation.
- No cluster smoke: pure code-motion refactor with no dataplane-behavior
  change (per assignment: engineer agents do not run cluster smokes).
