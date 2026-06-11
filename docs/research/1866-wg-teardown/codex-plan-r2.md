===== RESULT =====
PLAN-NEEDS-CHANGES

**Finding**
Major: Change 2b is not safe with Change 2 as written. It can prune a removed WG thread and then immediately respawn it from stale coordinator forwarding.

Counterexample:

1. v2 says the defer branch calls `prune_wg_control_threads_for_snapshot(&snapshot)` and “does NOT touch `self.forwarding`, does NOT spawn” ([plan.md](/home/ps/git/bpfrx/.claude/worktrees/1866-research/docs/research/1866-wg-teardown/plan.md:241)).
2. Current defer branch stores the snapshot, skips `reconcile_status_bindings`, then calls `refresh_status(guard)` ([snapshot.rs](/home/ps/git/bpfrx/.claude/worktrees/1866-research/userspace-dp/src/server/handlers/snapshot.rs:100)).
3. v2 puts `reconcile_wg_control_liveness()` inside `refresh_status` when `should_run_afxdp` is true ([plan.md](/home/ps/git/bpfrx/.claude/worktrees/1866-research/docs/research/1866-wg-teardown/plan.md:216)); `should_run_afxdp` is just `forwarding_armed && forwarding_supported` ([helpers.rs](/home/ps/git/bpfrx/.claude/worktrees/1866-research/userspace-dp/src/server/helpers.rs:404)), and `apply_snapshot` does not clear `forwarding_armed`.
4. v2 defines the liveness sweep as passes 1+3, and pass 3 spawns desired endpoints whose entry is “missing or a tombstone”; “a missing entry has no backoff and spawns immediately” ([plan.md](/home/ps/git/bpfrx/.claude/worktrees/1866-research/docs/research/1866-wg-teardown/plan.md:199)).
5. The desired set is still based on `self.forwarding.wg_engines` in the existing coordinator shape ([mod.rs](/home/ps/git/bpfrx/.claude/worktrees/1866-research/userspace-dp/src/afxdp/coordinator/mod.rs:496)), and Change 2b explicitly did not update `self.forwarding`.

So: NOT-same-plan + `defer_workers=true` removes wg0; Change 2b stops and removes the entry; the same handler’s `refresh_status` sees stale forwarding still containing wg0 and respawns the just-pruned thread. Required fix: make periodic liveness tombstone-only. It may retry entries that already exist as tombstones, but it must not create missing entries. Missing-entry creation belongs only to apply-time `spawn_wg_control_threads`, where forwarding and snapshot are coherent.

Secondary spec mismatch: the sketched tombstone entry cannot implement “recorded engine ptr differs” for tombstones because the ptr lives inside `thread: Option<(LocalTunnelSourceHandle, usize)>`; `None` loses it ([plan.md](/home/ps/git/bpfrx/.claude/worktrees/1866-research/docs/research/1866-wg-teardown/plan.md:176)). Either store `engine_ptr` outside the option, or explicitly say tombstones retain only backoff and will spawn against the current engine, accepting up to 3s delay after same-id identity changes.

**Round-1 Verification**
Resolved in v2 text:

1. Durable tombstone backoff: “finished thread leaves a tombstone that preserves the backoff stamp” and stamp is at “EVERY spawn attempt” ([plan.md](/home/ps/git/bpfrx/.claude/worktrees/1866-research/docs/research/1866-wg-teardown/plan.md:171)).
2. `refresh_status` cadence + bind/TUN invariant: “runs on EVERY non-suppressed control response” and bind/open “continue to run INSIDE the spawned aux thread” ([plan.md](/home/ps/git/bpfrx/.claude/worktrees/1866-research/docs/research/1866-wg-teardown/plan.md:225)).
3. Both-boundary logs + stale republisher suspects: Rust apply logging, Go publish logging, and both `*m.lastSnapshot` republishers are named ([plan.md](/home/ps/git/bpfrx/.claude/worktrees/1866-research/docs/research/1866-wg-teardown/plan.md:263), [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1866-research/docs/research/1866-wg-teardown/plan.md:141)).
4. D1 “forever” precision: dead until “identity change, a binding-plan-changing commit … or a daemon restart” ([plan.md](/home/ps/git/bpfrx/.claude/worktrees/1866-research/docs/research/1866-wg-teardown/plan.md:113)).
5. #1868 sequencing: “Sequencing is MANDATORY” and #1866 lands only after #1868, preserving `(UdpSocket, bool)` / `wg_send_to` ([plan.md](/home/ps/git/bpfrx/.claude/worktrees/1866-research/docs/research/1866-wg-teardown/plan.md:57)).

**Section 11**
1. Tick placement: not safe as written because of the defer respawn counterexample. Safe after tombstone-only periodic respawn.
2. Residual unknown: acceptable after that fix. D4 is covered, stale republishers are named, and Go/Rust transition logs should identify the layer in one capture.
3. Tombstone lifecycle: no unbounded growth if pass 2 removes absent/nonhydratable ids. Endpoint flapping releases tombstones on removal; that resets backoff, but does not leak.
4. Change 2b gates: mirror actual populate gates, not absent-id only. Absent-only would leave a port bound for `mode` change, port 0, or bad keys. Do not over-prune on invalid `wg_endpoint` or individual bad AllowedIPs, because current Rust hydration keeps those rows.
5. Backoff: 3s/id is acceptable; bounded and no give-up cap. Keep logs at the same cadence, not more.
6. #1868: preserve `socket_is_v6` through all existing `wg_send_to` paths; the factored spawn helper should move the closure shape unchanged.

Codex session ID: 019eb646-e229-7b81-956e-d10d9436d2e5
Resume in Codex: codex resume 019eb646-e229-7b81-956e-d10d9436d2e5
