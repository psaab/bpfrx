# #956 Phase 8: extract cos/cross_binding.rs from tx.rs

Plan v2 — 2026-04-30. **Final phase** of #956. Phases 1-7 merged
at PRs #976-#982.

Round-1 changelog (v1 → v2): Codex round-1 returned
PLAN-NEEDS-MAJOR with 7 findings. v2 expands scope to capture the
true cross-binding cluster:

- v1 listed only the 5 redirect_* fns; v2 adds the helpers they
  depend on (cos_fast_interface, cos_fast_queue,
  resolve_local_routing_decision) and the routing-decision types
  (Step1Action, LocalRoutingDecision).
- Visibility corrected: `redirect_local_cos_request_to_owner_binding`
  has only test callers (tx.rs:3941, 3989) — needs cfg-gated re-
  export, not always-on.
- Back-edge to `recycle_prepared_immediately` (tx.rs:2622, stays
  in tx.rs) acknowledged; visibility already pub(super), bumped
  to pub(in crate::afxdp).
- cos/mod.rs wiring made explicit.

## Move list (v2)

### Types (2)
| Item | Line | Kind |
|---|---|---|
| `Step1Action` | 1131 | enum |
| `LocalRoutingDecision` | 1147 | struct |

### Helpers (3)
| Item | Line | Notes |
|---|---|---|
| `resolve_local_routing_decision` | 1164 | step-1 owner resolution |
| `cos_fast_interface` | 1199 | binding fast-path lookup |
| `cos_fast_queue` | 1207 | binding queue fast-path lookup |

### Redirect fns (5)
| Item | Line | Visibility | Callers |
|---|---|---|---|
| `redirect_local_cos_request_to_owner` | 1217 | pub | production |
| `redirect_local_cos_request_to_owner_binding` | 1248 | cfg-gated | tests only (tx.rs:3941, 3989) |
| `prepared_cos_request_stays_on_current_tx_binding` | 1268 | pub | production |
| `redirect_prepared_cos_request_to_owner` | 1276 | pub | production |
| `redirect_prepared_cos_request_to_owner_binding` | 1328 | pub | production |

**Total: 2 types + 8 fns ≈ 250 LOC**

## Back-edges to tx.rs (deferred TX-completion / worker-binding)

`recycle_prepared_immediately` (tx.rs:2622) — currently
`pub(super)`. Bumped to `pub(in crate::afxdp)` so cos/cross_binding.rs
can call it. Stays in tx.rs because it touches XSK ring frame
recycling — worker-binding territory, not cos.

## Approach

Visibility:
- `pub(in crate::afxdp)`: 4 redirect fns + 3 helpers + 2 types.
- cfg-gated `pub(super) use`: redirect_local_cos_request_to_owner_binding
  (test-only after move).

`#[inline]` per Phase 4-7 lesson:
- Per-byte hot path (called from enqueue): all 4 production
  redirect fns + 3 helpers + resolve_local_routing_decision —
  add `#[inline]`.
- Larger memcpy bodies (redirect_prepared variants ~47-51 lines)
  follow Phase 7 precedent for similar-sized fns: leave un-
  attributed; LLVM heuristic should cover.

## cos/mod.rs additions

```rust
pub(super) mod cross_binding;

pub(super) use cross_binding::{
    cos_fast_interface, cos_fast_queue, prepared_cos_request_stays_on_current_tx_binding,
    redirect_local_cos_request_to_owner, redirect_prepared_cos_request_to_owner,
    redirect_prepared_cos_request_to_owner_binding, resolve_local_routing_decision,
    LocalRoutingDecision, Step1Action,
};

#[cfg(test)]
pub(super) use cross_binding::redirect_local_cos_request_to_owner_binding;
```

## Files touched

- **NEW** `userspace-dp/src/afxdp/cos/cross_binding.rs`: ~280 LOC.
- `userspace-dp/src/afxdp/cos/mod.rs`: register module + re-exports.
- `userspace-dp/src/afxdp/tx.rs`: -250 LOC; bump
  `recycle_prepared_immediately` to `pub(in crate::afxdp)`; extend
  cos:: imports.

## Risk

**Low.** Smallest move of remaining work (~250 LOC). Forward
dependencies clean: cross_binding.rs imports types from afxdp::types,
worker::BindingWorker, and one back-edge to tx::recycle_prepared_immediately.

## Acceptance

- `cargo build --bins` clean
- `cargo test --bins` 865/0/2
- Cluster smoke per the standard 7-class iperf3 + failover
- Both reviewers (Codex hostile + Gemini adversarial) sign off

## After this Phase 8

`tx.rs` left in place is XSK ring management + worker-binding glue
+ deferred TX-completion family (apply_cos_*_result, restore_*_inner,
transmit_*, etc — bumped to `pub(in crate::afxdp)` during Phase 7).

Future work (out of scope for #956):
- TX-completion phase: extract apply_cos_*_result + restore_*_inner
  + advance_cos_timer_wheel + timer-wheel constants.
- Worker-binding extraction: extract transmit_batch, reap_tx_completions,
  cos_queue_dscp_rewrite, etc.
