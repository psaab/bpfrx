# Claude SMR hostile plan-review — #1748 r2

In r1 I ratified the kill. AGY overturned it on Wall B. My job in r2 is to
**verify AGY's overturn against master myself** (AGY has a history of
over-claiming — `feedback_agy_writes_code_during_review`, and several
"falsifications" that didn't survive code-reading) and either restore the kill
or change my verdict honestly.

## Verification of AGY's Wall-B falsification (did the work, against master)

AGY's three claims, checked line-by-line:

1. **"Forward + reverse sessions are pre-replicated to all sibling workers."**
   VERIFIED. `replicate_session_upsert(worker_ctx.peer_worker_commands,
   &forward_entry)` at `poll_descriptor/mod.rs:1267`; reverse companion
   `replicate_session_upsert(peer_worker_commands, &reverse_entry)` at
   `shared_ops.rs:618`. `peer_worker_commands` is the local sibling-worker set.
   TRUE for forwarded sessions, not just HA-cross-node.

2. **"The replica is forwarding-ready (re-resolved with local egress)."**
   VERIFIED. `handle_upsert_synced` (`session_glue/commands/upsert_synced.rs`)
   re-resolves with local forwarding and stores a `ForwardCandidate`; doc
   comment: "immediately forwarding-ready." Replica origin =
   `WorkerLocalImport` (`tests.rs:473`), `is_peer_synced()==true`.

3. **"The active-node packet path has no per-worker ownership gate."** VERIFIED
   — this is the load-bearing one. `enforce_ha_resolution_snapshot`
   (`forwarding/mod.rs:524`) gates ONLY on `owner_rg_for_resolution` +
   `group.is_forwarding_active`. `owner_rg_is_locally_active`
   (`session_glue/mod.rs:137`) checks RG, never worker. There is no
   `if session.owner_worker != self.worker_id { reject }` anywhere on the
   active forwarding path. So worker 5 forwards a re-steered flow correctly.

AGY's overturn is **correct**, not over-claimed. The original Wall-B
("strands/splits/duplicates") is materially wrong for the same-node active-node
case. I withdraw my r1 ratification of the kill on Wall B. Wall A still holds
(I could not falsify it in r1 and don't now).

## Where AGY over-reached (why r2 is NEEDS-WORK, not AGY's "PLAN-READY for prototyping")

AGY concluded "no code changes needed, just turn it on." That's too strong:

- **R1 (does it beat the floor) is unresolved and is the historical kill
  point.** #1203/#789 built a reactive placement controller on THIS cluster and
  got 49–55% CoV at P=12 — below gate. AGY never addressed why Path 2 would
  beat #1203. The substrate being safe (which AGY proved) is necessary but not
  sufficient; the *benefit* is unproven and one realized data point is
  below-gate. This is the dominant remaining risk and AGY ignored it.
- **R2 (reverse direction not moved), R3 (transient reorder window), R4 (HA
  peer-mirroring), R5 (rule cap / 1ms cost / control-socket contention / #840
  thrash lesson), R6 (selection policy)** are all real and unaddressed by AGY.

So the honest verdict is NEEDS-WORK: kill withdrawn, Path 2 substrate viable,
but gate on the R1 spike before funding a controller. The plan now leads with
the cheapest possible falsification (manual-ethtool R1 spike, no production
code) so if placement IS floor-bound we kill for ~one maintenance window's cost
instead of a controller build.

## Verdict

**PLAN-NEEDS-WORK (kill withdrawn; Wall A confirmed dead-path, Wall B
falsification verified correct).** Converge target: Path 1/3 dead; Path 2
substrate viable; fund the R1 manual-ethtool spike as the next gate; KILL at R1
if reactive re-pin can't beat the #1203 49–55% precedent. Not PLAN-READY-to-
ship until R1 passes.
