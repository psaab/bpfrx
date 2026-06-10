# Codex plan-review r3 — task-mq8lc001-kflut9 (on v2.2)

PLAN-READY

Both r2 folds are present and technically coherent:

- Lease lifecycle survey now correctly names `finishClient` as terminal cleanup owner and calls the inline `ctx.Done` deletes redundant/pre-existing.
- The failed-bump hole is closed: `BumpFIBGeneration() (uint32, error)`, `pendingFIBBump` under `applySem`, and `published || pendingFIBBump` retry semantics cover the successful-publish/failed-bump/hash-skip ordering.

No blocking findings. One wording cleanup before implementation would be useful: §4.6 still says “actuator bump-on-published-only”; it should say “bump-on-published-or-pending.” The normative sections §4.3 and §7 are correct.