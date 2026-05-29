# Claude SMR plan-review r6 — #1648 (on plan v6)

**Verdict r6: PLAN-READY for Gate-R.** Hostile pass over the v6 reversion. Codex
r5's two blockers were real and I verified both against code before accepting the
reversion; v6 addresses them and I found no new hole.

## 1. The v5 full-clear swap was genuinely harmful — reversion is correct
I re-verified Codex r5 blocker 1 directly:
- Workers write `dynamic_neighbors` outside the netlink stream: ARP reply insert
  (`poll_stages.rs:80`), NDP NA insert (`poll_stages.rs:103`), and L3 source
  learning → `learn_dynamic_neighbor` bulk insert (`poll_stages.rs:189` →
  `neighbor_dispatch.rs:340`).
- Workers spawn at `bringup.rs:233`; the monitor (and thus `initial_neighbor_dump`)
  spawns at `bringup.rs:338` — AFTER. So during the dump, workers are live and can
  learn a neighbor that is in NEITHER the dump rows NOR the seq=0 multicast stream
  (e.g. an ARP reply to a worker-fired probe whose RTM_NEWNEIGH the kernel also
  multicast — but also the worker's *own* direct insert lands first). A blanket
  clear+copy at dump-end would drop the worker-learned entry.
- v6's per-key insert/remove (no clear) preserves it. Correct.

## 2. H-E retraction is correct — there is no leak on master
Codex r5 blocker 3 verified: `stop_inner` clears the full map at
`coordinator/mod.rs:261-267` (`with_all_shards` → `each_shard_mut().clear()`),
and this runs AFTER `workers.stop_and_clear` (`:221`) so no worker is writing
concurrently with that teardown clear. The bringup map is therefore empty;
nothing to purge. The earlier "parent verified the leak" was a misread of
`stop_inner` (lines 199-208 only). v6 retracts H-E cleanly and removes the
stale-leak justification + the stale-leak unit test. Good.

## 3. Staged-replay last-writer-wins still holds with the live (non-empty) map
The map is empty at bringup, but workers may insert during the dump. Worked the
interactions:
- dump row X then worker-insert X (newer MAC): worker wins (later write). The
  dump row is older; if the dump row arrives after the worker insert it would
  overwrite — but the dump reflects the kernel table at dump-request time, and a
  worker insert during the dump reflects a live ARP reply, so a benign same-MAC or
  a newer-MAC race. Both converge to the kernel truth within the probe schedule;
  no permanent wrong state (the steady-state loop reconciles subsequent
  RTM_NEWNEIGH). Acceptable — and identical to master's existing dump-vs-worker
  interleaving (v6 does not change the dump's upsert-into-live behavior, only adds
  the seq=0 staged replay).
- staged seq=0 DEL X then worker-insert X: the replay (after NLMSG_DONE) applies
  the DEL, removing a live worker-learned entry. **This is a theoretical concern**
  but matches kernel reality: a seq=0 DELNEIGH means the kernel removed X; if a
  worker re-learns X afterward via a live frame, that worker insert happens AFTER
  the replay (replay is at NLMSG_DONE, the dump window is short) and wins. If the
  worker insert happened BEFORE the replay, the DEL removes it — but then X really
  was deleted in the kernel, and the next frame re-probes (~5ms). No permanent
  blackhole. Flag for /engineer: confirm the replay-then-steady-state ordering so a
  legitimately-live X is re-learned promptly; this is a transient, not a blocker.

## 4. 5.E resync per-key-diff purge — correctly scoped
v6 §5.E now distinguishes the bringup dump (empty map, pure seed) from the 5.E
resync (live populated map after ENOBUFS, may hold stale entries). For the resync,
a per-key diff (remove keys in the map but absent from the fresh dump and not
worker-owned) is the right shape, NOT a blanket clear. "Worker-owned" is fuzzy at
the data-structure level (there is no ownership tag on a `NeighborEntry`), so
/engineer should treat this as: build the fresh dump set, remove map keys absent
from it, accept that a just-learned worker entry could be transiently removed and
re-learned in ~5ms. Gated on ENOBUFS being observed (H-D.1) — may never be built.
Acceptable as a plan-level direction.

## 5. Everything else from r5 still holds
Both-signal kill bar, target-B verified-absent, Window-3 BINDING-reconcile
narrowing, R3 matrix ENOBUFS=0-escalate cell, 5.F respawn-on-panic, 5.E.1
bounded-re-dump fallback — all unchanged from v5 and still sound.

## 6. Things I tried to break and could not
- A worker-write erased by the staged *replay* (not the rejected clear): only a
  staged seq=0 DEL can remove a key, and only if the DEL reflects a real kernel
  deletion — see §3, transient not permanent.
- A 4th window: re-confirmed exhaustive.
- The dump's existing upsert behavior changing semantics: v6 keeps it; the only
  add is the seq=0 staging + replay. Minimal blast radius.

## Forward
v6 is PLAN-READY for Gate-R. The /engineer notes (replay-vs-steady-state ordering,
5.E per-key-diff "worker-owned" fuzziness) are implementation details, not plan
blockers. Awaiting Codex r6 + AGY r6 confirmation of convergence.
