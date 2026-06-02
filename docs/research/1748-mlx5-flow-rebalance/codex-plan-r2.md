# Codex hostile plan-review — #1748 r2

Session: CODEX_COMPANION_SESSION_ID=research-1748-r2-1780378661
Verdict: **PLAN-NEEDS-WORK (overturn correct, R1-spike gate)**

## Wall B re-attack — cannot restore (quoted evidence)

- Forward broadcast: `poll_descriptor/mod.rs:1267`
  `replicate_session_upsert(worker_ctx.peer_worker_commands, &forward_entry)`.
- Reverse broadcast: `poll_descriptor/mod.rs:1480`
  `replicate_session_upsert(worker_ctx.peer_worker_commands, &reverse_entry)`.
- Sibling worker set: `coordinator/reconcile/bringup.rs:193` builds
  `peer_commands_clone` with `.filter(|(id, _)| **id != worker_id)`.
- Replica origin: `shared_ops.rs:51` `replica.origin =
  entry.origin.worker_replica_origin()`; `session/entry.rs:78` includes
  `WorkerLocalImport` in `is_peer_synced()`.
- Active gate is per-RG, NOT per-worker: `forwarding/mod.rs:541` gates on
  `owner_rg_id` + `group.is_forwarding_active(now_secs)`; `session_glue/mod.rs:137`
  same. No packet-path worker-owner rejection found. `WorkerLocalImport` is
  non-promotable but `promote.rs:86` just returns metadata; does not reject
  forwarding.

## R1 pre-judgment — ugly but NOT floor-bound by theorem

- The multinomial bound holds only under its premises: `docs/per-5-tuple/state.md:166-169`
  "Drop any premise and the bound disappears." Static steering is dead
  (`fairness-regimes.md:204`); reactive exact re-pin is the named premise break
  (line 216, "negative dependence").
- #1203/#789 precedent is the dominant kill RISK, not a theorem proof:
  `refactor/789-phase2-byte-rate:docs/pr/789-phase2-byte-rate/plan.md:9-15`
  closed-loop ntuple controller measured 55% / 49% CoV while flattening
  per-queue flow count; lines 24-25 "correctly drives each queue to 2 flows."
  Severe.
- BUT contradictory manual evidence on the sibling branch:
  `refactor/789-fairness-via-ntuple:docs/pr/789-fairness-via-ntuple/findings-experiment-1.md:7`
  mlx5 ntuple dropped CoV **62.5% -> 3.8%** (manual exact rules); lines 106-108
  conclude within-worker fairness was excellent and CROSS-WORKER variance
  dominated; line 90 shows 12 flows within +/-5% of mean after manual steering.
  This prevents a clean KILL-NOW. The right gate is exactly r2's R1: manually
  prove whether exact established-flow re-pin still materially lowers CoV after
  VERIFIED queue placement and RX-byte movement. If it stays in the 49-55% band
  after verified balanced placement, kill immediately.

## Wall A re-attack — still holds

Current Torvalds master `net/xdp/xsk.c` `xsk_rcv_check()`:
`if (xs->dev != xdp->rxq->dev || xs->queue_id != xdp->rxq->queue_index) return -EINVAL;`
reached via `xsk_rcv()` from `__xsk_map_redirect()`. No current-kernel Path 1
revival.

No code changed.

VERDICT: PLAN-NEEDS-WORK (overturn correct, R1-spike gate)
