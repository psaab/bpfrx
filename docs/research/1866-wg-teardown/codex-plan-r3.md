===== RESULT =====
PLAN-NEEDS-CHANGES

Round-2 findings are textually addressed in v3:

1. Periodic resurrection of a Change-2b-pruned removed endpoint: v3 says the sweep is “tombstone-only” and “never creates entries for ids absent from the map” [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1866-research/docs/research/1866-wg-teardown/plan.md:11). It also says liveness retry applies “ONLY entries that already EXIST in the map as tombstones” and “never creates entries for ids absent from the map” [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1866-research/docs/research/1866-wg-teardown/plan.md:237). Test 6b pins the removed-endpoint case: “NO entry recreated, NO bind attempt” [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1866-research/docs/research/1866-wg-teardown/plan.md:399).

2. Tombstone identity storage: resolved. `WgControlEntry` now keeps `engine_ptr` outside `handle: Option<...>` and says this lets stale prune “detect identity changes on tombstones too” [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1866-research/docs/research/1866-wg-teardown/plan.md:193).

3. Change-2b no-over-prune nuance: resolved. v3 says Change 2b mirrors populate gates and “must NOT over-prune” rows with unparsable `wg_endpoint` or individually bad AllowedIPs [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1866-research/docs/research/1866-wg-teardown/plan.md:285).

Blocking finding for round 3:

There is still a stale-defer sequence for a same-id WG identity change with an existing tombstone. Current defer flow stores the new snapshot and skips reconcile when `defer_workers` is true [snapshot.rs](/home/ps/git/bpfrx/.claude/worktrees/1866-research/userspace-dp/src/server/handlers/snapshot.rs:101). Current WG desired/spawn state is derived from `self.forwarding.wg_engines` [mod.rs](/home/ps/git/bpfrx/.claude/worktrees/1866-research/userspace-dp/src/afxdp/coordinator/mod.rs:497), and v3 Change 2b explicitly “does NOT touch `self.forwarding`” [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1866-research/docs/research/1866-wg-teardown/plan.md:292).

Counterexample: S0 is fully reconciled with WG id 1 identity A, then the control thread fails and becomes a tombstone. S1 is NOT-same-plan, `defer_workers=true`, and still has hydratable WG id 1 but identity B. Change 2b keeps the row because it is present/hydratable. `self.forwarding` remains identity A. After backoff, tombstone-only sweep respawns the existing tombstone “against the current `forwarding.wg_engines` Arc” [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1866-research/docs/research/1866-wg-teardown/plan.md:237), creating a thread for A after the latest accepted snapshot says B. Test 6b does not catch this because it only covers a snapshot “WITHOUT the endpoint” [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1866-research/docs/research/1866-wg-teardown/plan.md:395).

Answers to section 11:

1. Yes: the same-id identity-change + existing tombstone + NOT-same-plan defer window above. Rapid remove/add with an absent id is fixed by tombstone-only; stop/rebind looks safe because stop clears the WG map and reconcile uses stored snapshot.

2. Identity-flapping during normal coherent apply does not materially defeat backoff; it is apply-rate-limited and a fresh identity reasonably gets an immediate attempt. The abuse path that matters is the defer-window tombstone case, because the identity changes in the stored snapshot while `self.forwarding` remains old.

3. Nothing else blocks PLAN-READY from my pass. Required fix: make liveness respawn snapshot-aware, or have Change 2b remove/suppress tombstones whose latest snapshot WG identity differs from current forwarding, plus add a regression for same-id changed-identity tombstone under `defer_workers`.

Codex session ID: 019eb656-4bd7-7063-850b-c29b80e8abf3
Resume in Codex: codex resume 019eb656-4bd7-7063-850b-c29b80e8abf3
