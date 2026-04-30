# #956 Phase 6: extract cos/builders.rs from tx.rs

Plan v1 — 2026-04-30. Continues #956 (cos/ submodule decomposition).
Phases 1-5 merged at PRs #976-#980. Phase 6 = the runtime/batch
builders + send-result helpers that the queue-service path
(deferred to Phase 7) will consume.

## Goal

Move 6 builder/lifecycle helpers out of tx.rs into
`userspace-dp/src/afxdp/cos/builders.rs`. This deliberately
extracts BEFORE Phase 7 (queue_service) so the service-path entry
points have clean dependencies on cos/* rather than on tx.rs.

## Investigation findings (Claude, on commit 78b68219)

**Move list (6 fns)** in tx.rs source order:

| Item | Line | Visibility | Production callers (non-test) | Test-only |
|---|---|---|---|---|
| `prime_cos_root_for_service` | 1505 | private | tx.rs (drain entry — to verify) | tests |
| `build_cos_batch_from_queue` | 3231 | private | tx.rs select_cos_*_batch paths (Phase 7 consumers) | tests |
| `ensure_cos_interface_runtime` | 4299 | private | tx.rs interface lifecycle | tests |
| `build_cos_interface_runtime` | 4339 | private | called by `ensure_cos_interface_runtime` (moving) | tests |
| `apply_cos_send_result` | 4635 | private | tx.rs TX-completion handler | tests |
| `apply_cos_prepared_result` | 4696 | private | tx.rs TX-completion handler | tests |

(Codex round-1 will verify the call-site classification — same
production-vs-test trap Phases 4/5 exposed.)

## Approach

Create `userspace-dp/src/afxdp/cos/builders.rs` with all 6
functions. Visibility: items with cross-module production callers
become `pub(in crate::afxdp)`; helpers with only co-located callers
stay file-private.

Likely classification (subject to Codex verification):
- `pub(in crate::afxdp)`:
  - `prime_cos_root_for_service`
  - `build_cos_batch_from_queue` (Phase 7 will consume)
  - `ensure_cos_interface_runtime`
  - `apply_cos_send_result`
  - `apply_cos_prepared_result`
- File-private:
  - `build_cos_interface_runtime` (only `ensure_cos_interface_runtime`,
    co-located after move)

Test-only re-exports: cfg-gated where any moved fn has direct
`tx::tests` callers but no production caller in tx.rs. Codex
round-1 verifies.

`#[inline]` per the Phase 4/5 lesson: hot-path fns get explicit
attribute. Most builders are one-shot (interface bring-up,
TX-completion); `build_cos_batch_from_queue` is the one that may
fire per dispatch and warrants `#[inline]`.

## Scope notes (Codex/Gemini round-1 will validate)

- `apply_cos_queue_flow_fair_promotion` is already in
  `cos/admission.rs` (Phase 3). `ensure_cos_interface_runtime`
  imports it from cos/.
- `cos_queue_*` ops moved in Phase 5; `build_cos_batch_from_queue`
  reaches them via the cos/ re-exports.
- `build_shared_cos_*` helpers in coordinator.rs and
  `build_worker_cos_*` in worker.rs are deferred to Phase 8
  (cross_binding) where they'll move with the rest of the
  shared-lease wiring.

## Files touched

- **NEW** `cos/builders.rs`: ~250-300 LOC.
- `cos/mod.rs`: register module + re-exports.
- `tx.rs`: remove the 6 fn definitions; extend cos:: import.
- 0 changes in worker.rs / coordinator.rs (deferred builders).

## Acceptance

- `cargo build --bins` clean.
- `cargo test --bins` 865/0/2.
- Cluster smoke per the standard 7-class iperf3 + failover.
- Both reviewers (Codex hostile + Gemini adversarial) sign off.
