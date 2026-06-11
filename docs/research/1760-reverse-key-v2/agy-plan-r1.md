I will list the directory contents of `/home/ps/git/bpfrx/.claude/worktrees/1760-research-v2` to verify its existence and locate the plan document.
I will read the plan document at `/home/ps/git/bpfrx/.claude/worktrees/1760-research-v2/docs/research/1760-reverse-key-v2/plan.md`.
I will use `grep_search` to find occurrences of `replicate_session_upsert` to begin verifying the code paths.
I will view the `replicate_session_upsert` function in `userspace-dp/src/afxdp/session_glue/mod.rs`.
I will search for `synced_replica_entry` in the codebase.
I will view the `synced_replica_entry` function in `userspace-dp/src/afxdp/shared_ops.rs`.
I will search for `worker_replica_origin` in the codebase.
I will view the `worker_replica_origin` implementation in `session/entry.rs`.
I will search for `upsert_synced_with_origin` in the codebase.
I will view the `upsert_synced_with_origin` function implementation in `userspace-dp/src/session/mod.rs`.
I will view the `handle_upsert_synced` function in `userspace-dp/src/afxdp/session_glue/commands/upsert_synced.rs`.
I will search for the definition of `synced_entry_allows_local_replace`.
I will view `synced_entry_allows_local_replace` in `userspace-dp/src/afxdp/session_glue/mod.rs`.
I will search for the definition of `is_peer_synced` to see which session origins are peer-synced.
I will view `is_peer_synced` in `userspace-dp/src/session/entry.rs`.
I will view the definition of `SessionOrigin` in `userspace-dp/src/session/entry.rs`.
I will view the `index_forward_nat_key` function in `userspace-dp/src/session/mod.rs`.
I will view `index_forward_nat_key` in `userspace-dp/src/session/mod.rs` from lines 1350 to 1380 to see how it's defined and how it determines `is_reverse`.
I will search for occurrences of `WorkerCommand::UpsertSynced` in the codebase.
I will view `userspace-dp/src/afxdp/session_glue/mod.rs` to see how `WorkerCommand::UpsertSynced` is handled.
I will view `userspace-dp/src/afxdp/ha.rs` to see how HA import commands are queued.
I will view `upsert_synced_session` in `userspace-dp/src/afxdp/ha.rs` from lines 250 to 300.
I will search for occurrences of `nat_reverse_index` to see how keys are removed.
I will view lines 1450 to 1485 in `userspace-dp/src/session/mod.rs`.
I will view the `install_with_protocol_with_origin` implementation in `userspace-dp/src/session/mod.rs`.
I will search for `last_seen_ns` in `session/mod.rs` to confirm how hits are processed.
I will search for occurrences of `SharedPromote` in the codebase to understand its role.
I will view `userspace-dp/src/afxdp/session_glue/promote.rs` around lines 50-80.
I will view lines 81 to 140 of `userspace-dp/src/afxdp/session_glue/promote.rs`.
I will search for `promote_synced_with_origin` in the codebase.
I will view `promote_synced_with_origin` in `userspace-dp/src/session/mod.rs`.
I will view the `update_session` function implementation in `userspace-dp/src/session/mod.rs`.
I will view the rest of `update_session` in `userspace-dp/src/session/mod.rs`.
I will view the `publish_shared_session` function in `userspace-dp/src/afxdp/shared_ops.rs`.
I will search for `lock_recover` to see if worker queue poisoning can lead to command loss.
I will view the `lock_recover` implementation in `userspace-dp/src/afxdp/worker_queue.rs`.
I will search for occurrences of `try_lock_recover` to see where it is used.
I will view `userspace-dp/src/afxdp/session_glue/mod.rs` around line 476 to check if replica commands can be dropped.
I will search for `live_userspace_session_action` in `userspace-xdp/src/lib.rs`.
I will view `userspace-xdp/src/lib.rs` from lines 520 to 600.
I will view the next block of lines (601 to 690) in `userspace-xdp/src/lib.rs`.
I will view the `live_userspace_session_action` function in `userspace-xdp/src/lib.rs` starting at line 1331.
I will search for `USERSPACE_SESSIONS` in `userspace-xdp/src/lib.rs`.
I will search for `publish_worker_session_map_entry` to see how the userspace dataplane writes to `USERSPACE_SESSIONS` map.
I will view the `publish_worker_session_map_entry` function in `userspace-dp/src/afxdp/session_glue/mod.rs`.
I will search for `publish_session_map_entry_for_session_with_origin` to see how it writes to the map.
I will view the `publish_session_map_entry_for_session_with_origin` function in `userspace-dp/src/afxdp/bpf_map/mod.rs`.
I will search for `publish_live_session_key` definition.
I will view the `publish_live_session_key` function definition in `userspace-dp/src/afxdp/bpf_map/mod.rs`.
I will list the directory `userspace-xdp/src` to see what files exist in the XDP shim.
I will search for `xdp_action` in `userspace-xdp/src/lib.rs` to see what XDP actions are returned.
I will view `userspace-xdp/src/lib.rs` around line 935 and line 1050 to see the context of these XDP_PASS returns.
I will view lines 1030 to 1060 of `userspace-xdp/src/lib.rs`.
I will search for the definition of `classify_native_gre_inner` in `userspace-xdp/src/lib.rs`.
I will view `classify_native_gre_inner` in `userspace-xdp/src/lib.rs`.
I will view the next block of lines in `userspace-xdp/src/lib.rs` to see the rest of `classify_native_gre_inner_ipv4`.
I will view `userspace-dp/src/session/mod.rs` around line 610.
I will search for `shared_nat_sessions` to check its type and how it is locked.
I will view `userspace-dp/src/afxdp/poll_descriptor/mod.rs` from lines 1310 to 1355.
I will view lines 1270 to 1310 of `userspace-dp/src/afxdp/poll_descriptor/mod.rs` to see the install call and its context.
I will view lines 1350 to 1420 of `userspace-dp/src/afxdp/poll_descriptor/mod.rs` to verify the failed-install control-flow behavior.
I will view lines 1421 to 1460 of `userspace-dp/src/afxdp/poll_descriptor/mod.rs`.
I will view lines 1235 to 1270 of `userspace-dp/src/afxdp/poll_descriptor/mod.rs` to see how `install_local_reverse` is defined.
I will view lines 1461 to 1500 of `userspace-dp/src/afxdp/poll_descriptor/mod.rs`.
I will view lines 1501 to 1540 of `userspace-dp/src/afxdp/poll_descriptor/mod.rs` to see what happens to the packet when `forward_installed` is `false`.
I will view lines 1541 to 1570 of `userspace-dp/src/afxdp/poll_descriptor/mod.rs` to see what is done with the packet.
VERDICT: PLAN-KILL

---

### Hostile Plan Review & Findings

#### Finding 1: High — Inherent Watch Under-counting ("Forgetfulness" via Value-Guarded Removal)
* **File:Line**: [userspace-dp/src/session/mod.rs:L1459-1467](file:///home/ps/git/bpfrx/.claude/worktrees/1760-research-v2/userspace-dp/src/session/mod.rs#L1459-L1467) and [userspace-dp/src/session/mod.rs:L1399-1405](file:///home/ps/git/bpfrx/.claude/worktrees/1760-research-v2/userspace-dp/src/session/mod.rs#L1399-L1405)
* **Rationale**: The plan relies on `nat_reverse_key_collisions` to watch for NAT collisions. However, `nat_reverse_index` is single-valued. If session `S1` and session `S2` share reverse key `K`, and `S2` (the winner) is installed last, `K` maps to `S2`'s handle. When `S2` is eventually removed or expires, the value-guarded removal logic in [mod.rs:L1459-1467](file:///home/ps/git/bpfrx/.claude/worktrees/1760-research-v2/userspace-dp/src/session/mod.rs#L1459-L1467) matches `*stored == handle` (since `K` maps to `S2`) and removes `K` from `nat_reverse_index` entirely. Although `S1` remains active, `K` is now completely missing from the index. If a new session `S3` is later installed and shares key `K`, the insert at [mod.rs:L1399-1405](file:///home/ps/git/bpfrx/.claude/worktrees/1760-research-v2/userspace-dp/src/session/mod.rs#L1399-L1405) returns `prev = None`, failing to detect the collision. This means the watch counter is fundamentally "forgetful" and will systematically under-count active collisions, invalidating the counter's soundness.

#### Finding 2: Critical — Failed Forward Install Continues to Install Reverse Session and Forward Packets
* **File:Line**: [userspace-dp/src/afxdp/poll_descriptor/mod.rs:L1340-1444](file:///home/ps/git/bpfrx/.claude/worktrees/1760-research-v2/userspace-dp/src/afxdp/poll_descriptor/mod.rs#L1340-L1444)
* **Rationale**: When a session install fails at [poll_descriptor/mod.rs:L1275-1283](file:///home/ps/git/bpfrx/.claude/worktrees/1760-research-v2/userspace-dp/src/afxdp/poll_descriptor/mod.rs#L1275-L1283) (e.g., due to a `max_sessions` limit), the code rolls back the source NAT allocation at [poll_descriptor/mod.rs:L1341-1349](file:///home/ps/git/bpfrx/.claude/worktrees/1760-research-v2/userspace-dp/src/afxdp/poll_descriptor/mod.rs#L1341-L1349) but fails to abort the block. It continues to compute the reverse resolution, installs the reverse session into the session table at [poll_descriptor/mod.rs:L1436-1444](file:///home/ps/git/bpfrx/.claude/worktrees/1760-research-v2/userspace-dp/src/afxdp/poll_descriptor/mod.rs#L1436-L1444), and forwards the packet using the *rolled-back/freed* source NAT allocation. This is a severe correctness/NAT state corruption bug that remains live in the worktree. Leaving this critical bug unfixed while shipping a watch-only PR (Path W) represents a poor priority alignment.

#### Finding 3: High — Global Lock Contention under Path A1 Install-Time Refusal
* **File:Line**: [userspace-dp/src/session/mod.rs:L724](file:///home/ps/git/bpfrx/.claude/worktrees/1760-research-v2/userspace-dp/src/session/mod.rs#L724) and [userspace-dp/src/afxdp/poll_descriptor/mod.rs:L1275-1283](file:///home/ps/git/bpfrx/.claude/worktrees/1760-research-v2/userspace-dp/src/afxdp/poll_descriptor/mod.rs#L1275-L1283)
* **Rationale**: Path A1 proposes install-time refusal by checking `shared_nat_sessions` for the presence of the reverse key before committing the install. Currently, `install_with_protocol_with_origin` is completely worker-local and lock-free. Interjecting a presence check on the global `shared_nat_sessions` mutex prior to installation commits will introduce critical lock contention under high connection setup rates (session misses), serializing worker threads and degrading packet processing throughput.

#### Finding 4: Medium — Log Spam and Pollution Risk in W1 Warn
* **File:Line**: [userspace-dp/src/afxdp/worker/loop_body/mod.rs:L187](file:///home/ps/git/bpfrx/.claude/worktrees/1760-research-v2/userspace-dp/src/afxdp/worker/loop_body/mod.rs#L187)
* **Rationale**: Path W1 proposes a rate-limited (60 seconds) warning to `journald` per-worker. On systems with many workers (e.g., 12 workers), if a burst of NAT collisions occurs (which is highly likely in production per §2.7), each worker will log to `journald` independently. This can result in up to 12 log lines per minute, cluttering system logs. Since the warning contains no specific address details (only ports and protocols), logging it repeatedly from multiple workers adds no diagnostic value and violates log-hygiene. A centralized coordinator-level rate-limiter is required.

#### Finding 5: Medium — Thread Synchronization Overhead in W3 Shared-Map Displacement Counter
* **File:Line**: [userspace-dp/src/afxdp/shared_ops.rs:L670-689](file:///home/ps/git/bpfrx/.claude/worktrees/1760-research-v2/userspace-dp/src/afxdp/shared_ops.rs#L670-L689)
* **Rationale**: W3 proposes counting displacements in `publish_shared_session`. However, the shared maps are accessed concurrently by coordinator and worker threads. Adding a displacement counter here requires either passing an atomic reference or introducing a new global atomic, creating extra thread synchronization/wire overhead for a redundant watch metric that is already covered by the local-replica checks.

---

### Adjudication of Revisit Questions

1. **Section 2.3 watch-coverage audit**: The replica fanout mechanism works, but the single-valued index deletion (Finding 1) introduces a structural under-counting bug. When the winner session is removed, the reverse key mapping is deleted, leaving active loser sessions invisible to subsequent collision checks.
2. **Section 2.4 bypass audit**: The AF_XDP shim ([lib.rs:L530-690](file:///home/ps/git/bpfrx/.claude/worktrees/1760-research-v2/userspace-xdp/src/lib.rs#L530-L690)) redirects all established transit flows to userspace. There is no kernel bypass or fast path offload in XDP. The userspace dataplane sees every single packet of all established transit flows.
3. **Section 2.6 blast-radius walk**: The logic is correct. Wrong-host delivery occurs while both are live due to single-valued reverse lookup mapping ([mod.rs:L609-623](file:///home/ps/git/bpfrx/.claude/worktrees/1760-research-v2/userspace-dp/src/session/mod.rs#L609-L623)), and the loser's path dies after winner expiry due to value-guarded removal.
4. **Section 2.7 birthday math**: The birthday math is correct. Ephemeral port collisions will occur routinely in production when distinct hosts share a destination IP/port behind interface-SNAT.
5. **Path adjudication**: Path W's watch is fundamentally broken (under-counts/forgets active collisions) and has no operational value. Path A1 introduces serious lock-contention risks. The critical failed-install-continues wart should be addressed independently. Therefore, **Path K (PLAN-KILL / Close issue as accepted-risk)** is the only sound path.
