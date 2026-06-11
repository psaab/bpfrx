Here is the adversarial review of the v4 plan for **xpf issue #1866** based on the worktree `/home/ps/git/bpfrx/.claude/worktrees/1866-research` (commit 677566943).

---

### Re-derived Stale-Defer Sequence (Codex r3 Residual)

1. **S0 (Active Config)**: ID `1` is configured with **identity A**. The snapshot reconciles successfully, spawning the control thread under identity A. The coordinator's `self.forwarding.wg_engines` maps `1` to the engine representing identity A.
2. **Thread Failure**: The control thread exits/fails and the periodic finished sweep marks it as a tombstone (`handle: None`), preserving the stamp and `engine_ptr` for identity A.
3. **S1 (Deferred Config Change)**: A `NOT-same-plan` commit updates ID `1` to **identity B** with `defer_workers == true`.
   * The snapshot handler in [snapshot.rs:102](file:///home/ps/git/bpfrx/.claude/worktrees/1866-research/userspace-dp/src/server/handlers/snapshot.rs#L102) updates the stored state: `guard.snapshot = Some(snapshot);`
   * However, it skips worker reconciliation due to `defer_workers` ([snapshot.rs:109-115](file:///home/ps/git/bpfrx/.claude/worktrees/1866-research/userspace-dp/src/server/handlers/snapshot.rs#L109-L115)). Thus, the coordinator's active `self.forwarding` state remains stale (identity A).
   * Change 2b runs, but since ID `1` is still present in the snapshot (albeit with identity B), the row is kept and the tombstone is **not** pruned.
4. **Resurrection Race (under v3 Plan)**: A periodic status check runs after the 3-second backoff. Because the v3 sweep was blind to `state.snapshot`'s identity fields, it would check `self.forwarding` (which contains identity A) and respawn a control thread using identity A—incoherently diverging from the latest accepted snapshot (identity B).

---

### Verification of the v4 Fix

The v4 plan introduces the **snapshot-coherent respawn** condition in [plan.md:249-264](file:///home/ps/git/bpfrx/.claude/worktrees/1866-research/docs/research/1866-wg-teardown/plan.md#L249-L264):

> ```text
> 249: `Coordinator::reconcile_wg_control_liveness(&mut self, latest_snapshot:
> 250: Option<&ConfigSnapshot>)` = the finished sweep (pass 1) + a
> 251: **TOMBSTONE-ONLY, SNAPSHOT-COHERENT respawn**: it retries (backoff-gated,
> 252: ≤1 spawn per invocation) ONLY entries that already EXIST in the map as
> 253: tombstones, and only when BOTH hold (Codex r3 blocking finding):
> 254: 
> 255: 1. `forwarding.wg_engines`/`tunnel_endpoints` still carry the id, AND
> 256: 2. the latest STORED snapshot (`state.snapshot`, passed in by the
> 257:    server) contains a hydratable WG row for that id whose identity tuple
> 258:    (listen_port, decoded local privkey, decoded peer pubkey,
> 259:    allowed-ips, endpoint, keepalive) is IDENTICAL to the forwarding
> 260:    endpoint it would spawn against. `None`/missing/identity-mismatched
> 261:    row ⇒ skip silently (the tombstone stays; the deferred/next apply
> 262:    reconciles it coherently).
> ```

In the re-derived sequence, the sweep receives `state.snapshot` containing identity B. Because the forwarding engine has identity A, they do not match. The sweep skips the spawn, keeping the tombstone disarmed until the next full reconcile updates forwarding and handles the transition. This fully closes the race.

---

### Answers to Section 11 Questions

#### 1. Snapshot-Coherence Condition Soundness & Completeness
* **Soundness & Completeness**: Yes. The identity comparison matches the exact fields used in [wg.rs:87-94](file:///home/ps/git/bpfrx/.claude/worktrees/1866-research/userspace-dp/src/afxdp/forwarding_build/wg.rs#L87-L94) (`wg_listen_port`, `wg_local_privkey`, `wg_peer_pubkey`, `wg_allowed_ips`, `wg_endpoint`, `wg_keepalive_secs`). Any change to these properties forces a new engine instantiation, meaning comparison over these specific fields is necessary and sufficient to detect identity changes.
* **Is `state.snapshot` always the latest accepted snapshot?**: Yes. In all snapshot handling branches ([snapshot.rs:92, 96, 102](file:///home/ps/git/bpfrx/.claude/worktrees/1866-research/userspace-dp/src/server/handlers/snapshot.rs#L92-L102)), `guard.snapshot` is updated with the incoming configuration *before* any call to `refresh_status`. Since all status checks and handler paths run sequentially under the state lock `Mutex<ServerState>` ([helpers.rs:16](file:///home/ps/git/bpfrx/.claude/worktrees/1866-research/userspace-dp/src/server/helpers.rs#L16)), there are no concurrent snapshot updates, guaranteeing the sweep always has the latest accepted snapshot.

#### 2. Remaining Incoherent-Spawn Sequences
* **No remaining sequences exist**:
  * **Defer Windows**: Closed by the snapshot-coherent mismatch check and Change 2b.
  * **Rapid Add/Remove/Add**: Change 2b immediately deletes the thread's control entry upon config deletion ([plan.md:309](file:///home/ps/git/bpfrx/.claude/worktrees/1866-research/docs/research/1866-wg-teardown/plan.md#L309)). Since the sweep is tombstone-only, it will not resurrect a missing entry. If re-added, the entry remains absent (not a tombstone) and will not be touched by the liveness sweep until a full reconcile runs.
  * **Helper Restart**: The helper starts from a clean slate (`snapshot: None`, [lifecycle.rs:168](file:///home/ps/git/bpfrx/.claude/worktrees/1866-research/userspace-dp/src/server/lifecycle.rs#L168)). It does not reload the persisted state file. Even if it did, the local private key is marked `skip_serializing` ([snapshot.rs:356](file:///home/ps/git/bpfrx/.claude/worktrees/1866-research/userspace-dp/src/protocol/snapshot.rs#L356)), meaning the key defaults to empty on deserialization and fails hydration validation, preventing any incorrect or accidental spawn.

#### 3. Other Blockers
* **None**. The v4 plan correctly implements the snapshot-coherent-respawn invariant ([plan.md:379-383](file:///home/ps/git/bpfrx/.claude/worktrees/1866-research/docs/research/1866-wg-teardown/plan.md#L379-L383)) and pins it with regression test `6c` ([plan.md:436-441](file:///home/ps/git/bpfrx/.claude/worktrees/1866-research/docs/research/1866-wg-teardown/plan.md#L436-L441)).

---

### Summary of Work
1. Re-derived and verified the same-id identity change under a defer window with an existing tombstone race condition.
2. Verified that the v4 plan's snapshot-coherent tombstone check correctly resolves the issue.
3. Inspected the code structure ([snapshot.rs](file:///home/ps/git/bpfrx/.claude/worktrees/1866-research/userspace-dp/src/server/handlers/snapshot.rs), [helpers.rs](file:///home/ps/git/bpfrx/.claude/worktrees/1866-research/userspace-dp/src/server/helpers.rs), and [wg.rs](file:///home/ps/git/bpfrx/.claude/worktrees/1866-research/userspace-dp/src/afxdp/forwarding_build/wg.rs)) to confirm serialization, locking, and fields.

PLAN-READY
