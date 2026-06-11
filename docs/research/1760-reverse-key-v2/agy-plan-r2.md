I will list the contents of the `docs/research` directory to locate the plan documents and reviews for the #1760 issue.
I will run `git worktree list` from the main checkout to see the active worktrees and locate the branch for issue #1760.
I will view the plan document at the specified path within the 1760-research-v2 worktree.
I will search for `nat_reverse_key_collisions` to find where the collision counter is defined and manipulated in the codebase.
I will search for `nat_reverse_key_collisions` in the `1760-research-v2` worktree directory to locate the relevant session table logic.
I will view `userspace-dp/src/session/mod.rs` around the collision detection and index removal paths to verify the exact logic.
I will view lines 1350-1395 of `userspace-dp/src/session/mod.rs` to see the entry point and signature of the index function.
I will search for references to `index_forward_nat_key` and `index_forward_nat_key_parts` in the worktree.
I will view lines 915-945 of `userspace-dp/src/session/mod.rs` to inspect the refresh paths and how they re-assert the index entries.
I will search for `update_session` in the codebase to understand when session updates and re-assertions occur.
I will view `update_session` in `userspace-dp/src/session/mod.rs` to see how session refresh behaves, specifically the conditions under which it re-asserts indices.
I will search for `update_session` or `refresh_local` calls within `poll_descriptor` to see how frequently they are triggered during packet forwarding.
I will view `refresh_local` in `userspace-dp/src/session/mod.rs` to see what wrapper arguments it passes to `update_session`.
I will search for usages of `refresh_local` and `update_session` in the rust source files to find where they are invoked on the packet path.
I will search for `lookup` methods in `userspace-dp/src/session/mod.rs` to see if lookups trigger session refreshes.
I will view the `lookup` and `lookup_with_origin` methods in `userspace-dp/src/session/mod.rs`.
I will view lines 600-650 of `userspace-dp/src/session/mod.rs` to see the rest of `lookup_with_origin`.
I will search for `.lookup` or `update_session` in `userspace-dp/src/afxdp/poll_descriptor/mod.rs` to see what is called on the packet path.
I will search for references to `sessions.lookup` or `sessions.find` in `poll_descriptor/mod.rs`.
I will search for `flow_cache` in `poll_descriptor/mod.rs` to see how it resolves session lookups.
I will view `userspace-dp/src/afxdp/poll_descriptor/flow_cache_hit.rs` to see how flow cache hits and lookups are managed.
I will search for the `touch` method in `userspace-dp/src/session/mod.rs` to see what it modifies.
I will view `userspace-dp/src/session/mod.rs` around line 367 to see what `touch` does.
I will search for `refresh_for_ha_activation` or `update_session` calls in the `userspace-dp/src` directory (excluding tests and test files) to see where updates are triggered.
I will search for `update_session` calls in `userspace-dp/src` to see where it is invoked.
I will view lines 1070-1100 of `userspace-dp/src/session/mod.rs` to see what wrapper methods call `update_session` and who imports them.
I will search for `promote_synced_with_origin` in `userspace-dp/src` to see if it is called during packet processing.
I will view the contents of `userspace-dp/src/afxdp/session_glue/promote.rs` to see under what conditions peer-synced sessions are promoted to local.
I will view the definition of `upsert_synced_with_origin` in `userspace-dp/src/session/mod.rs`.
I will search for `refresh_for_ha_transition` to see where it is invoked.
I will view `expire_stale_entries` in `userspace-dp/src/session/mod.rs` starting around line 391.
I will view lines 450-480 of `userspace-dp/src/session/mod.rs` to see what happens when the entry is still active during a wheel pop.
I will view lines 480-510 of `userspace-dp/src/session/mod.rs` to confirm Case 4 does not perform index re-assertion.
I will search for `remove_entry` in `userspace-dp/src/session/mod.rs` to see if it cleans up secondary indices before inserting.
I will view lines 1260-1310 of `userspace-dp/src/session/mod.rs` to see how `remove_entry` handles secondary indices.
I will view lines 1270-1340 of `userspace-dp/src/afxdp/poll_descriptor/mod.rs` to inspect the rollback and failed install logic.
I will view lines 1340-1420 of `userspace-dp/src/afxdp/poll_descriptor/mod.rs` to see what happens in the `else` block when `forward_installed` is `false`.
I will view lines 1420-1480 of `userspace-dp/src/afxdp/poll_descriptor/mod.rs` to see what is done with the reverse key.
I will search for `install_local_reverse` in `poll_descriptor/mod.rs` to see how it is initialized.
I will search for `install_with_protocol_with_origin` in `userspace-dp/src/session/mod.rs` to see how it handles installation failures.
I will view lines 680-750 of `userspace-dp/src/session/mod.rs` to see the implementation of `install_with_protocol_with_origin`.
I will search for `publish_shared_session` in the codebase to verify the lock behavior and how it is called during session installation.
I will view `userspace-dp/src/afxdp/shared_ops.rs` around line 648 to see the lock implementation of `publish_shared_session`.
I will search for `find_forward_nat_match` in `poll_descriptor/mod.rs` to see how NAT reverse lookups are handled.
I will search for `find_forward_nat_match` in `userspace-dp/src` to see where it is used.
I will view lines 1445-1485 of `userspace-dp/src/afxdp/poll_descriptor/mod.rs` to check if there is rollback logic for the forward session when the reverse session installation fails.
I will view lines 1485-1515 of `userspace-dp/src/afxdp/poll_descriptor/mod.rs` to see the end of the reverse-install conditional block.
I will view lines 1515-1545 of `userspace-dp/src/afxdp/poll_descriptor/mod.rs` to see if there is any cleanup after the block.
VERDICT: PLAN-NEEDS-MAJOR

### Findings

#### 1. The "event detector" refutation of AGY r1 F1 is invalid because normal packet refreshes do not re-assert indices
* **Severity**: HIGH
* **File & Line Evidence**:
  * [session/mod.rs:928-940](file:///home/ps/git/bpfrx/.claude/worktrees/1760-research-v2/userspace-dp/src/session/mod.rs#L928-L940) — re-assert of secondary indices in `update_session`.
  * [session/mod.rs:367](file:///home/ps/git/bpfrx/.claude/worktrees/1760-research-v2/userspace-dp/src/session/mod.rs#L367) — `sessions.touch` (updates `last_seen_ns`/`expires_after_ns` but does not call `index_forward_nat_key_parts`).
  * [session/mod.rs:523](file:///home/ps/git/bpfrx/.claude/worktrees/1760-research-v2/userspace-dp/src/session/mod.rs#L523) ��� `sessions.lookup_with_origin` (updates `last_seen_ns`/`expires_after_ns` but does not call `index_forward_nat_key_parts`).
  * [flow_cache_hit.rs:156](file:///home/ps/git/bpfrx/.claude/worktrees/1760-research-v2/userspace-dp/src/afxdp/poll_descriptor/flow_cache_hit.rs#L156) — `sessions.touch` called on flow cache hit.
  * [session/mod.rs:1459-1461](file:///home/ps/git/bpfrx/.claude/worktrees/1760-research-v2/userspace-dp/src/session/mod.rs#L1459-L1461) — removal of `K` from `nat_reverse_index` when the winner expires.
  * [shared_ops.rs:444](file:///home/ps/git/bpfrx/.claude/worktrees/1760-research-v2/userspace-dp/src/afxdp/shared_ops.rs#L444) ��� `sessions.find_forward_nat_match` lookup for reply packets.
* **Details**:
  * The plan (Sections 1.7, 2.3, 11.1) defends the watch's event-detection capability by arguing that if S1 (loser) and S2 (winner) collide on reverse key `K`, and S2 is eventually removed, the live loser S1 *"re-wins K on its next session refresh because update_session unconditionally re-asserts secondary ADDS"*.
  * This premise is **empirically false** in the codebase. During normal traffic forwarding, packets matching an existing session hit the flow cache or the slow-path lookup. These paths call `sessions.touch` (flow cache hit) or `sessions.lookup_with_origin` (slow path lookup).
  * Neither of these paths calls `update_session` or `index_forward_nat_key_parts`. They only update the `last_seen_ns`/`expires_after_ns` timestamps and push to the timer wheel.
  * Thus, when S2 (winner) expires and deletes `K` from `nat_reverse_index`, the still-active S1 **never re-asserts** `K`.
  * This has two critical consequences:
    1. **Traffic Blackhole**: S1's reverse path remains permanently broken because inbound reply packets looking up `K` will miss (`find_forward_nat_match(K)` returns `None`).
    2. **Missed Collisions**: If a third session S3 installs and collides on `K` with the still-live S1, `nat_reverse_index.insert(K, S3)` will return `prev = None` (since `K` was removed). The collision between S3 and S1 is completely missed by the counter.
  * Therefore, the watch is not a reliable "event detector" for active colliding pairs, and the plan's adjudication of AGY r1 F1 must be rejected.

#### 2. Failed-install control-flow wart leaks reverse sessions and causes half-open / unidirectional flows near `max_sessions` limit
* **Severity**: MEDIUM
* **File & Line Evidence**:
  * [poll_descriptor/mod.rs:1274-1283](file:///home/ps/git/bpfrx/.claude/worktrees/1760-research-v2/userspace-dp/src/afxdp/poll_descriptor/mod.rs#L1274-L1283) — `install_with_protocol_with_origin` for forward session.
  * [poll_descriptor/mod.rs:1340-1350](file:///home/ps/git/bpfrx/.claude/worktrees/1760-research-v2/userspace-dp/src/afxdp/poll_descriptor/mod.rs#L1340-L1350) — `else` rollback block for forward session.
  * [poll_descriptor/mod.rs:1434-1444](file:///home/ps/git/bpfrx/.claude/worktrees/1760-research-v2/userspace-dp/src/afxdp/poll_descriptor/mod.rs#L1434-L1444) — `install_with_protocol_with_origin` for reverse session.
  * [session/mod.rs:690-693](file:///home/ps/git/bpfrx/.claude/worktrees/1760-research-v2/userspace-dp/src/session/mod.rs#L690-L693) — `self.len() >= self.max_sessions` check.
* **Details**:
  * In `poll_descriptor/mod.rs`, when the forward session fails to install (`forward_installed = false` because `sessions.len() >= max_sessions`), the code rolls back SNAT but **still attempts to install the reverse session**. This causes a half-open session leak (a reverse session entry with no matching forward entry).
  * Conversely, if the table is at `max_sessions - 1` when a flow arrives:
    1. The forward session installs successfully (`self.len()` becomes `max_sessions`).
    2. The reverse session then tries to install, but its installation fails because `self.len() >= self.max_sessions` is now true.
    3. The code does not roll back the forward session installation.
  * This leaves the forward session fully active, fanned out, and NAT'd, but the reverse session is completely absent. Inbound reply packets will fail to match the reverse key, resulting in a permanent one-way traffic blackhole for the flow.

---

### Round-2 Questions Adjudication

1. **Does the event-detector adjudication hold?**
   No. As demonstrated in Finding 1, the live loser does not hit `update_session` during normal traffic refreshes, meaning it never re-wins `K` once displaced. The watch permanently under-counts and fails to detect subsequent collisions on `K` for the remaining lifetime of the loser.
2. **W1 process-global CAS throttle + warn text + descriptor-help semantics acceptable?**
   If the operator chooses Path W, they must accept that the watch is structurally highly unreliable and under-counting. The help text and warning log must be updated to explicitly state that the counter is highly forgetful and misses subsequent collisions for long-lived flows after a colliding winner expires.
3. **Is W2 preflight sufficient for attributability?**
   Yes. The preflight assertions verify active SNAT configurations and establish the baseline reverse path functionality before triggering the forced collision.
4. **Final path verdict W vs K vs A1?**
   Path W is not sound because it monitors a broken metric and accepts silent traffic blackholing on the reverse path. If the project cannot accept silent cross-flow wrong-host data leakage and subsequent blackholing, Path A1 (steady-state refusal with commit-order inversion) is the only correct path to preserve index integrity. If the deployment posture is strictly lab-only/accepted-risk, Path K (closing as accepted-risk) is more honest than shipping an unreliable watch.
5. **PLAN-KILL invitation stands:**
   The recommendation conditional must be revised. Recommending W is only valid if we accept monitoring a broken metric. A major revision of the plan is required to address the incorrect assumptions around session refreshes.
