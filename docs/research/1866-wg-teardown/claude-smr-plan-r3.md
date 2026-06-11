# #1866 plan review — Claude SMR (hostile), round 3

Reviewer: Claude (domain SMR). Target: plan.md v3 @ 597055089.

## Round-2 resolution check

- F7 (sweep resurrection after defer-prune): resolved — §5 Change 2 is
  now tombstone-only with the rationale spelled out; §7 pins it as an
  invariant; §9 test 6b is the regression pin. Re-ran the worked
  sequence against v3: after Change 2b removes the entry, the sweep has
  no tombstone for the id and `self.forwarding`'s stale desired set is
  never consulted by the sweep — the id stays down until the deferred
  bring-up reconciles against fresh forwarding. Closed.
- Codex r2 secondary (engine_ptr in the Option): resolved — §5 Change 1
  keeps `engine_ptr` outside the Option with the reset-backoff-on-
  identity-change semantics made explicit.
- Codex r2 Q4 nuance (no over-prune): resolved — §5 Change 2b keeps rows
  with unparsable `wg_endpoint` (hydrates to None / responder-only) and
  individually-bad allowed-ips, matching `populate_tunnel_endpoints`.

## Round-3 confirmation questions (§11)

1. **Any remaining incoherent-desired-set spawn path?** I enumerated
   every site that can create a `wg_control_threads` entry under v3:
   apply-time `spawn_wg_control_threads` from (a) `refresh_runtime_snapshot`
   — runs strictly AFTER `self.forwarding = new_forwarding`, coherent;
   (b) `reconcile/bringup.rs` — runs after the snapshot phase installs
   the new forwarding, coherent; and nothing else (the sweep is
   tombstone-only; Change 2b never spawns; `stop_inner` only clears).
   Rapid add/remove/add lands as successive coherent applies; each pass-2
   join precedes any same-id pass-3 spawn under the single ServerState
   guard. The stop/rebind handlers call `stop()`/full reconcile + then
   `refresh_status` — the sweep there can only retry tombstones the
   reconcile itself just (re)legitimated. No counter-sequence found.
2. **Identity-flap backoff abuse**: an operator flapping the WG identity
   per-commit gets one immediate spawn attempt per identity change —
   identical to today's behavior (identity change already rebuilds the
   engine and respawns). The backoff exists to bound RETRIES of a
   failing identical config, not to rate-limit distinct configs; commit
   cadence is operator-controlled and already heavyweight. Not a
   meaningful abuse path.
3. **Anything else?** Two record-keeping items, neither blocking:
   the /engineer phase must (a) file the tunnel-ID-instability follow-up
   issue (AGY r1 F3) before or with the PR, and (b) note for the parent
   that the post-merge smoke should include a live add→remove→re-add WG
   cycle (§9). Both are already in the plan text.

## Verdict

**PLAN-READY** — v3's tombstone-only narrowing eliminates the last
incoherent-desired-set path I could construct; the defect inventory
(D1-D4) is closed by Changes 1/2/2b, observability (D3) by Change 3, and
the residual-unknown stance is honest and instrumented. Implementation
must sequence after #1868 and follow §9's gates.
