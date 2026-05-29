# Codex plan-review r5 — #1648 (on plan v5, `2f0b60bf39a5`)

Task ID: `task-mpr2hb2t-i7cnmy`
Codex session: `019e7450-f500-7513-a29a-75ad0fdc0cb2`

**Verdict: PLAN-NEEDS-REVISION.**

The core lock/staging pieces mostly converge, but v5 has two verified blockers.

1. **Double-buffered swap is read-atomic, but v5 misses concurrent worker
   writes.** Read side checks out: `with_all_shards` locks all shards before
   running the closure (`sharded_neighbor.rs:135-150`), `get()` locks the target
   shard (`sharded_neighbor.rs:87-90`), and `lookup_neighbor_entry` uses
   `dynamic_neighbors.get()` (`forwarding/mod.rs:1529-1542`). So workers see
   pre-swap or post-swap, not an in-lock clear miss.

   **Blocker:** workers also write directly to `dynamic_neighbors`, outside the
   netlink dump/staging stream. ARP/NA classification inserts directly
   (`poll_stages.rs:80-85, 103-106`), and L3 source learning calls
   `learn_dynamic_neighbor` (`poll_stages.rs:180-190`), which bulk-inserts into
   `dynamic_neighbors` (`neighbor_dispatch.rs:340-343`). A full clear+copy from
   only dump rows + staged netlink deltas can erase a worker-learned entry written
   after the side table was built but before swap. That is worse than the #949
   manager path, which removes only tracked manager keys then inserts manager
   entries (`coordinator/mod.rs:165-178`).

2. **Key-collapsed staging is last-writer-correct.** v5's explicit tombstone
   requirement is correct. Current `parse_neighbor_msg` maps unusable NEW states
   to removal and RTM_DELNEIGH to removal (`neighbor.rs:345-359`). If staging
   overwrites per key on arrival, DEL→NEW ends present and NEW→DEL ends removed.

3. **H-E as written is false against active code.** v5 says `stop_inner` "never
   clears or resets self.neighbors.dynamic" (`plan.md:271-281`). Active code DOES
   clear it: `self.neighbors.dynamic.with_all_shards` then `shard.clear()`
   (`coordinator/mod.rs:261-267`). Full-shard clear+copy would remove entries
   absent from the dump, but the claimed W3 "pre-existing leak on master"
   rationale is contradicted and must be rewritten.

4. **Window-3 narrowing is correctly applied.** Same-plan snapshots branch at
   `same_plan` (`snapshot.rs:72-96`): no reconcile calls
   `refresh_runtime_snapshot`; only `needs_reconcile` calls
   `reconcile_status_bindings`. That reaches `afxdp.reconcile()`
   (`helpers.rs:312-317`), whose teardown/bringup path is at
   `reconcile/mod.rs:98-119`. v5's BINDING-reconcile wording is faithful.

5. **R3 matrix is clean now.** The clean-failover ENOBUFS=0 cell says "do NOT
   ship either fix; escalate" (`plan.md:442-449`). No stale World-1 /
   ship-any-fix wording in the matrix.

6. **Remaining blocker:** the plan must specify how 5.A.2 handles non-netlink
   worker-learned dynamic entries during the dump window, and must remove/reframe
   the false H-E "stop_inner never clears" claim.
