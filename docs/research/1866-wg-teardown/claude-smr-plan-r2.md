# #1866 plan review — Claude SMR (hostile), round 2

Reviewer: Claude (domain SMR). Target: plan.md v2 @ 4badf0e87.
Method: re-traced the v2 design end-to-end with worked sequences,
specifically hunting interactions BETWEEN the newly-added changes.

## Round-1 resolution check

- SMR F1 (stop-gate): resolved — sweep call site is `refresh_status`
  under `should_run_afxdp` (§5 Change 2). Verified the disarm sequence
  (`set_forwarding_state` → `reconcile_status_bindings` → `stop()`) runs
  under the same ServerState guard as `refresh_status`, so no interleave
  window exists between stop and the gate check.
- SMR F2 (D1 wording): resolved (§4b — identity change / plan-changing
  commit / restart).
- SMR F3 (transition logging): resolved and extended to the Go publish
  boundary per Codex 3 (§5 Change 3).
- SMR F4 (backoff stamp): resolved — stamped at every attempt, applies
  at apply-time too (§5 Change 1 pass 3).
- SMR F5 (single-mutex invariant): resolved (§7 first bullet).

## New finding (hostile re-trace of v2)

**F7 (MAJOR — Change 2 × Change 2b interaction): the periodic sweep
resurrects the thread Change 2b just pruned.**

Worked sequence:
1. NOT-same-plan apply with `defer_workers == true` removes the WG
   endpoint. Change 2b stops+joins the thread and REMOVES its map entry.
   Per the §5 Change 2b contract, `self.forwarding` is intentionally NOT
   touched — so `forwarding.tunnel_endpoints`/`wg_engines` still contain
   the removed endpoint until the deferred bring-up reconciles.
2. `defer_workers` does not imply disarmed: `should_run_afxdp` can be
   TRUE during the defer window (RETH-MAC reprogramming on an armed
   helper). The next control response triggers `refresh_status` → the
   Change-2 sweep.
3. The sweep computes its desired set from `self.forwarding` (stale —
   still contains the endpoint), finds the map entry MISSING (2b removed
   it), and v2's pass 3 says a missing entry "has no backoff and spawns
   immediately" ⇒ **the sweep respawns the just-pruned thread and
   re-binds the port** — exactly the leak the change set is supposed to
   eliminate, now self-inflicted.

**Required fix (adopted for v3): the periodic sweep must be
tombstone-only.** `reconcile_wg_control_liveness` = finished-sweep
(thread → tombstone) + respawn ONLY for entries that EXIST as tombstones
(backoff-gated). It never creates entries for ids absent from the map.
Entry creation (new endpoints) happens exclusively at apply-time
(`spawn_wg_control_threads` pass 3, where the desired set and
`self.forwarding` are coherent by construction). Consequences:
- The 2b-pruned id stays gone until the deferred bring-up's full
  reconcile re-evaluates it against fresh forwarding — correct.
- The EADDRINUSE self-heal path is unaffected (a failed/finished thread
  leaves a tombstone, which the sweep retries past backoff).
- The sweep's surface narrows further: it can only ever re-create a
  thread that the apply path already legitimated.

## Re-answers to v2 §11 under the F7 fix

1. Tick placement: clean with tombstone-only respawn — the sweep cannot
   originate new lifecycle, only retry apply-legitimated ids.
2. Residual-unknown stance: sufficient (D4 closed; both boundaries
   logged; suspects named).
3. Tombstone lifecycle: with F7's rule, tombstones are created only for
   apply-legitimated ids and removed at apply-time when the id leaves the
   desired set — flapping cannot grow the map beyond the desired-set
   cardinality high-water within one apply cycle. No leak path found.
4. Change 2b gates: prune on the MIRRORED populate gates is right —
   pruning only on absent-id would leave a thread bound for an endpoint
   whose new snapshot row is non-hydratable (port 0 / bad key), which the
   apply path would tear down anyway; matching populate keeps the two
   paths' semantics identical. A transiently-malformed row equals a
   config that could not have produced an engine — stopping its thread is
   the correct fail-closed behavior.
5. Backoff 3s: appropriate; bounded exception cadence, no give-up.
6. #1868: confirmed mandatory; spawn-helper must thread `socket_is_v6`.

## Verdict

**PLAN-NEEDS-CHANGES** — F7 only (tombstone-only periodic respawn).
Everything else in v2 verified sound. F7's fix is a one-rule narrowing
that strictly shrinks the new code's authority; with it folded I expect
PLAN-READY at round 3.
