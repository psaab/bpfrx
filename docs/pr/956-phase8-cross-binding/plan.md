# #956 Phase 8: extract cos/cross_binding.rs from tx.rs

Plan v1 — 2026-04-30. **Final phase** of #956. Phases 1-7 merged
at PRs #976-#982.

## Goal

Move 5 cross-binding redirect helpers from tx.rs into
`userspace-dp/src/afxdp/cos/cross_binding.rs`. These resolve the
"is this request bound to the owner of the egress, or do we hand
off via MPSC inbox?" question for both Local and Prepared TX
requests.

## Move list (5 fns)

| Item | Line | Visibility | Notes |
|---|---|---|---|
| `redirect_local_cos_request_to_owner` | 1217 | private | step-1 entry |
| `redirect_local_cos_request_to_owner_binding` | 1248 | private | step-2 inbox handoff |
| `prepared_cos_request_stays_on_current_tx_binding` | 1268 | private | gate predicate |
| `redirect_prepared_cos_request_to_owner` | 1276 | private | prepared step-1 |
| `redirect_prepared_cos_request_to_owner_binding` | 1328 | private | prepared step-2 |

(Codex round-1 verifies callers. Plan-stage assumption: each fn
has tx.rs production callers — non-test — so all 5 become
`pub(in crate::afxdp)`.)

## Approach

`cos/cross_binding.rs` (~160 LOC) hosts the 5 fns + module-level
docs explaining the two-step redirect model (resolve owner →
hand off via MPSC inbox if it's a different binding).

Visibility: all 5 → `pub(in crate::afxdp)`. tx.rs's existing cos::
import block extends with the new entries.

`#[inline]` per Phase 4-7 lesson: all 5 are per-enqueue hot path
helpers — add `#[inline]` on the move.

## Files touched

- **NEW** `userspace-dp/src/afxdp/cos/cross_binding.rs`: ~180 LOC.
- `userspace-dp/src/afxdp/cos/mod.rs`: register module + re-exports.
- `userspace-dp/src/afxdp/tx.rs`: -160 LOC; extend cos:: imports.

## After this Phase 8

`tx.rs` left in place is just XSK ring management (descriptor
pop/push, kick threshold, completion reap) + orchestration glue
(drain_pending_tx, bound_pending_tx_*) + the deferred TX-completion
family that was bumped to `pub(in crate::afxdp)` during Phase 7
(apply_cos_*_result, restore_cos_*_inner, transmit_*, etc).

The umbrella plan called for those to also extract eventually
(probably as cos/tx_completion.rs and a coordinator/worker-side
cross-binding extraction). Those are explicitly OUT-OF-SCOPE for
this PR and tracked as future work.

## Tests

No new tests — pure structural refactor. Existing tests in
`tx::tests` exercise the 5 fns indirectly via the `enqueue_*` and
`drain_*` paths.

## Risk

**Low.** Smallest move in the campaign (~160 LOC). Forward
dependencies clean: cross_binding.rs imports types and a few
helpers from existing cos/* modules. No new back-edges expected.

## Acceptance

- `cargo build --bins` clean
- `cargo test --bins` 865/0/2
- Cluster smoke per the standard 7-class iperf3 + failover
- Both reviewers (Codex hostile + Gemini adversarial) sign off
