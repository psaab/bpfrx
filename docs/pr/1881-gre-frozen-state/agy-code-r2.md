I will start by listing the contents of the worktree directory `/home/ps/git/bpfrx/.claude/worktrees/1881-engineer-impl` to understand the codebase structure and locate the relevant files, specifically `coordinator/mod.rs` and the tests.
I will run a search to find files containing `prune_local_tunnel_sources_for_snapshot` to locate the exact path of the coordinator code and test cases.
I will view the `prune_local_tunnel_sources_for_snapshot` function definition and its logic in `/home/ps/git/bpfrx/.claude/worktrees/1881-engineer-impl/userspace-dp/src/afxdp/coordinator/mod.rs`.
I will view the next segment of the coordinator code to see the definition of `local_tunnel_tombstone_respawn_coherent`, `stop_remove_local_tunnel_entry`, and related helper methods.
I will search for `tunnel_sources` in `/home/ps/git/bpfrx/.claude/worktrees/1881-engineer-impl/userspace-dp/src/afxdp/coordinator/mod.rs` to locate the normal "pass-2" spawn/prune logic for tunnels.
I will view lines 560 to 650 of `userspace-dp/src/afxdp/coordinator/mod.rs` to examine the normal same-plan `reconcile_local_tunnel_sources()` logic, which implements the "pass-2" stale check.
I will search for `interfaces.rs` or references to `linux_name` to understand the label semantics and ensure equivalence.
I will search for `forwarding_build` or `interfaces.rs` in the entire repository to find where forwarding tables/interfaces are built and verify the `linux_name` fallback behavior.
I will search for `linux_name` in `userspace-dp/src/afxdp/forwarding_build/interfaces.rs` to see how interface names/labels are mapped and fallback logic is structured.
I will view lines 30 to 80 of `userspace-dp/src/afxdp/forwarding_build/interfaces.rs` to inspect the exact label fallback behavior.
I will search for the definition of the snapshot row types (e.g., `tunnel_endpoints` elements) to see the field names and types.
I will search for the definition of `ConfigSnapshot` to locate the configuration schema.
I will view `userspace-dp/src/protocol/snapshot.rs` around line 183 to understand the fields in `ConfigSnapshot` and the related structs.
I will search for the definition of `TunnelEndpointSnapshot` in `userspace-dp/src/protocol/snapshot.rs`.
I will view `userspace-dp/src/protocol/snapshot.rs` from line 309 to 350 to see the fields of `TunnelEndpointSnapshot`.
I will view the `tunnels.rs` file to see how tunnel endpoints from the snapshot are mapped into the `ForwardingState`.
I will search for `spawn_one_local_tunnel_source` to see how `spawned_tunnel_name` is populated when the GRE tunnel reader thread is spawned.
I will view lines 700 to 800 of `userspace-dp/src/afxdp/coordinator/mod.rs` to see how `spawn_one_local_tunnel_source` initializes the spawned tunnel entry.
I will search for `gre1881` in the tests to see the new test cases and how they construct the snapshot fields.
I will view the relevant test cases in `userspace-dp/src/afxdp/coordinator/tests.rs` around lines 2450 to 2770 to see how the GRE tunnel coordinator tests are written and how the hole is pinned.
I will view `userspace-dp/src/server/handlers/snapshot.rs` around line 129 to see how the pruning function is invoked on the snapshot handler path.
I will search for `prune_wg_control_threads_for_snapshot` in `/home/ps/git/bpfrx/.claude/worktrees/1881-engineer-impl/userspace-dp/src/afxdp/coordinator/mod.rs`.
I will view lines 1300 to 1360 of `/home/ps/git/bpfrx/.claude/worktrees/1881-engineer-impl/userspace-dp/src/afxdp/coordinator/mod.rs` to inspect the WG control thread pruning implementation for comparison.
I will run the `gre1881` tests in `userspace-dp` to verify that they compile, run, and pass.
I will run `git show b2f5560fa -- userspace-dp/` to view the full delta of userspace-dp changes in this commit.
I will check the status of the background cargo test task to see if the tests completed.
I will search for `stop_remove_local_tunnel_entry` to check the stopping, joining, and cleanup sequence.
I will view lines 665 to 695 of `/home/ps/git/bpfrx/.claude/worktrees/1881-engineer-impl/userspace-dp/src/afxdp/coordinator/mod.rs` to examine `stop_remove_local_tunnel_entry`.
I will check the status of the tests to verify if they have completed.
I will run `git show --stat b2f5560fa` to verify if any other files in the repository were modified in this commit.
I will view the contents of the documentation files `docs/pr/1881-gre-frozen-state/agy-code-r1.md` and `docs/pr/1881-gre-frozen-state/reviewer-ids.md` to check the context of the previous code review and design decisions.
# Adversarial Review Verdict: MERGE-READY

Following a fresh, hostile pressure-test of the fixes introduced at commit `b2f5560fa`, the implementation of the deferred-prune logic is verified to be correct, robust, and free of over-pruning. 

---

## 1. Verification of the Predicate & Label Semantics
The stale predicate logic in the deferred prune method exactly matches the same-plan `reconcile_local_tunnel_sources` check (which queries the active forwarding tables).

### Equivalence Comparison
* **Armed Pass-2 Stale Predicate** ([userspace-dp/src/afxdp/coordinator/mod.rs:567-590](file:///home/ps/git/bpfrx/.claude/worktrees/1881-engineer-impl/userspace-dp/src/afxdp/coordinator/mod.rs#L567-L590)) checks:
  1. If index is absent from `forwarding.tunnel_endpoints`.
  2. If the mode changes (not `gre` or `ip6gre`).
  3. If the attachment drifted (`logical_ifindex` doesn't match `spawned_ifindex` OR `ifindex_to_name` resolver doesn't match `spawned_tunnel_name`).
* **Deferred Prune Predicate** ([userspace-dp/src/afxdp/coordinator/mod.rs:855-882](file:///home/ps/git/bpfrx/.claude/worktrees/1881-engineer-impl/userspace-dp/src/afxdp/coordinator/mod.rs#L855-L882)) checks against the new snapshot row:
  1. If the row with the endpoint `id` is absent (or `row.ifindex <= 0`).
  2. If `row.mode != "gre" && row.mode != "ip6gre"`.
  3. If the attachment drifted (`row.ifindex != entry.spawned_ifindex` OR `row_label != entry.spawned_tunnel_name`).

### Interface Name Fallback
The `row_label` calculation in the prune:
```rust
let row_label = if row.linux_name.is_empty() {
    row.interface.as_str()
} else {
    row.linux_name.as_str()
};
```
correctly mirrors the fallback logic used in `populate_interfaces` ([userspace-dp/src/afxdp/forwarding_build/interfaces.rs:44-48](file:///home/ps/git/bpfrx/.claude/worktrees/1881-engineer-impl/userspace-dp/src/afxdp/forwarding_build/interfaces.rs#L44-L48)), `populate_tunnel_endpoints` ([userspace-dp/src/afxdp/forwarding_build/tunnels.rs:80-84](file:///home/ps/git/bpfrx/.claude/worktrees/1881-engineer-impl/userspace-dp/src/afxdp/forwarding_build/tunnels.rs#L80-L84)), and the tombstone liveness coherence check ([userspace-dp/src/afxdp/coordinator/mod.rs:975-979](file:///home/ps/git/bpfrx/.claude/worktrees/1881-engineer-impl/userspace-dp/src/afxdp/coordinator/mod.rs#L975-L979)). This avoids O(N*M) lookups on interface tables in the defer path while remaining completely accurate.

---

## 2. No Over-Pruning (Unchanged Entry Survival)
For an unchanged tunnel, the new snapshot row preserves `row.id == id`, `row.ifindex == entry.spawned_ifindex`, `row.mode == entry.mode`, and the fallback `row_label == entry.spawned_tunnel_name`. 

All conditions of the filter evaluate to `false`, returning `None` (no stale state). Because `stale` is empty, the function returns early:
```rust
if stale.is_empty() {
    return;
}
```
This guarantees that an unchanged entry will survive without interruption or thread churn.

---

## 3. Test Coverage Pins the Hole
The extended test `gre1881_defer_prune_removes_only_stale_entries` ([userspace-dp/src/afxdp/coordinator/tests.rs:2674-2699](file:///home/ps/git/bpfrx/.claude/worktrees/1881-engineer-impl/userspace-dp/src/afxdp/coordinator/tests.rs#L2674-L2699)) successfully pins this hole by proving:
1. **Unchanged survival**: The entry is kept when the same snapshot is passed.
2. **Attachment drift (the main bug)**: Moving the endpoint's interface index from `36289` to `46289` triggers immediate pruning.
3. **Full removal**: Emptying the configuration snapshot prunes the entry and cleans up the delivery sender.

The test suite compiled and completed successfully:
```text
running 10 tests
test afxdp::coordinator::tests::gre1881_no_workers_spawn_gate ... ok
test afxdp::coordinator::tests::gre1881_refresh_creates_entry_and_publishes_delivery ... ok
test afxdp::coordinator::tests::gre1881_disarmed_refresh_stops_threads ... ok
test afxdp::coordinator::tests::gre1881_stop_inner_clears_and_sweep_creates_nothing ... ok
test afxdp::coordinator::tests::gre1881_destination_edit_preserves_entry_without_respawn ... ok
test afxdp::coordinator::tests::gre1881_removal_refresh_prunes_entry_and_unpublishes ... ok
test afxdp::coordinator::tests::gre1881_attachment_change_restarts_thread ... ok
test afxdp::coordinator::tests::gre1881_defer_prune_removes_only_stale_entries ... ok
test afxdp::coordinator::tests::gre1881_mode_flip_to_wireguard_prunes_gre_entry ... ok
test afxdp::coordinator::tests::gre1881_exit_tombstones_sweep_unpublishes_and_respawn_is_coherence_gated ... ok

test result: ok. 10 passed; 0 failed; 0 ignored; 0 measured; 1967 filtered out; finished in 0.02s
```

---

## Final Verdict
**MERGE-READY**
