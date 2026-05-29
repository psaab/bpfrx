# Codex plan-review r6 — #1648 (on plan v6, `8ca9a0dc5105`)

Task ID: `task-mpr2vojj-dwcoaf`
Codex session: `019e745b-30e9-7742-80d0-ba7d079b4589`

**Verdict: PLAN-READY. No new blocker.**

1. **v6 does not erase worker-learned entries.** The plan explicitly says replay
   uses "per-key `insert`/`remove`" and "NO clear; NO blanket copy"
   (`plan.md:485`). Code confirms the bringup map starts empty: workers are
   stopped at `coordinator/mod.rs:220`, then all neighbor shards cleared at
   `coordinator/mod.rs:263`. On bringup, workers spawn before the monitor dump:
   `bringup.rs:233` vs `bringup.rs:338`.

2. **Worker-write paths are real and v6 preserves untouched keys.** ARP writes at
   `poll_stages.rs:80`, NDP writes at `poll_stages.rs:103`, L3 source learning at
   `poll_stages.rs:183`, bulk-inserts at `neighbor_dispatch.rs:340`. Per-key map
   ops lock only the target shard: `sharded_neighbor.rs:88`, `:93`.

3. **DEL/NEW key-collapsed staging remains correct.** Current netlink semantics
   treat unusable NEW as removal, usable NEW as upsert, DEL as remove
   (`neighbor.rs:345/351/357/359`). A staged seq=0 DEL can remove a
   worker-just-learned same-key entry, but that is not permanent: the next miss
   uses the existing probe/retry path (`neighbor_dispatch.rs:136/150`).

4. **H-E retraction is accurate.** v6 says H-E is retracted and "There is no
   stale-entry leak on master" (`plan.md:273`). Matches code: `stop_inner` clears
   all shards after workers are stopped (`coordinator/mod.rs:220` + `:263`).
   Remaining stale-leak text is confined to changelog/history and is explicitly
   marked wrong.

5. **§5.E does not reintroduce the blanket-clear hazard.** ENOBUFS-gated;
   specifies "per-key diff" and "NOT a blanket clear" (`plan.md:629`).
   **Minor editorial nit only:** `plan.md:673` still says "5.A.2 swap"; should say
   staged-replay — not a blocker, does not claim full-clear. *(Fixed post-r6.)*
