# Claude SMR plan-review — round 2 (v2 @ 31c4be70a)

**Verdict: PLAN-NEEDS-MINOR** (overall), with **one MAJOR on §2.1 that
must be fixed before Phase 4 is built** — but because Path B defers and
gates §2.1, the plan can proceed to PLAN-READY for Phases 1–3 with the
§2.1 fix folded into the doc.

I wrote v2, so I forced myself to attack it rather than confirm it. Two
real residual holes survived the round-1 fixes.

## MAJOR — §2.1 reintroduces a stale-MAC resurrection window via tombstone GC

The co-located epoch closes the round-1 absent-key-DELNEIGH race **while
the slot exists**. But v2 also made the epoch **GC-able** (tombstone TTL
60 s) and specified the confirmed-insert as *"insert only if
`slot.epoch == epoch_before`, creating the slot if absent with
`epoch = epoch_before`."* That "creating the slot if absent" clause is a
hole:

1. GET for key K snapshots `epoch_before = 5` (K had a tombstone, epoch 5).
2. Tombstone GC fires (60 s elapsed) → slot for K is **removed entirely**;
   the per-key epoch is now absent (reads as 0).
3. The in-flight GET returns REACHABLE and calls
   `insert_confirmed_if_unchanged(K, mac, epoch_before=5)`. Slot is absent
   → the "create if absent with epoch=epoch_before" branch inserts the MAC
   unconditionally. **Stale-MAC resurrection after GC** — the same class of
   bug round-1 killed, just triggered by GC instead of DELNEIGH-of-absent.

This is only reachable if a GET can stay in flight ~60 s, which is
unlikely given the GET timeout — but "unlikely timing" is exactly what
sank #1774, and the firewall-posture rule (immediate revocation, no
resurrection) means we don't get to hand-wave it.

**Fix (fold into v3):** draw epoch values from a **process-global
monotonic counter**, not a per-key `0,1,2…`. Every bump (NEWNEIGH,
DELNEIGH, re-dump eviction) does `epoch = GLOBAL_EPOCH.fetch_add(1)` and
stores it in the slot. Then:
- A snapshot of `5` can never equal any *future* slot's epoch (future
  bumps draw 6,7,8…), so GC-then-recreate cannot collide with an old
  snapshot.
- Confirmed-insert on an **absent slot must REJECT** (you cannot prove the
  MAC is unchanged against a slot that no longer exists). Drop the
  "create if absent" branch entirely for the confirmed path.

This keeps the per-key false-reject reduction (unrelated keys draw
unrelated epochs) while restoring the never-resurrect guarantee the global
atomic gave for free. It also means the tombstone is only a *cardinality*
device, not a *correctness* device — safe to GC at any TTL.

## MEDIUM — §2.5 reconcile can spuriously evict entries learned during the dump

§2.5 says "snapshot the dump into a set, then under `with_all_shards`
remove any key not present." Correct that netlink I/O is outside the lock
(it must be — `with_all_shards` holds all 64 shard mutexes; blocking
netlink recv under it would freeze every neighbor lookup in the
dataplane). But there is a TOCTOU: a NEWNEIGH that lands *after* the dump
snapshot but *before* the all-shard lock is a valid entry absent from the
stale snapshot — the reconcile would evict it.

**Fix:** stamp `dump_start_ns` before issuing the dump; in the reconcile,
only evict a key whose `slot.last_change_ns < dump_start_ns` (i.e. don't
touch anything learned after the snapshot began). The co-located
`last_change_ns` (§2.1) already carries this; for the Path-B case where
§2.1 isn't built yet, Phase 2 needs a lightweight per-entry timestamp or
must accept that the reconcile only runs when §2.1 has landed. **This
couples Phase 2 to Phase 4** — flag it: either Phase 2's re-dump is
upsert-only (no eviction, doesn't self-heal lost DELNEIGH) until §2.1
lands, or Phase 2 carries its own timestamp. The plan currently implies
Phase 2 evicts without §2.1's `last_change_ns` available — that's an
ordering inconsistency vs Path B.

## MINOR — Path B's measurement gate needs the counter to mean what we think

Path B gates §2.1 on `epoch_rejects`. Verify the counter distinguishes a
*false* reject (unrelated-key churn — the thing per-key fixes) from a
*true* reject (the MAC genuinely changed — per-key would reject too). If
`epoch_rejects` conflates both, it overstates the per-key benefit and the
gate reads high for the wrong reason. If it can't distinguish, the gate
should be "epoch_rejects AND a follow-up GET that then succeeds unchanged"
— or add a `epoch_rejects_unrelated` sub-counter in Phase 3 so the gate is
honest.

## What v2 got right (verified against master)

- Co-location genuinely dissolves round-1 #2 (TOCTOU) and #4 (lock order):
  one shard mutex, epoch read in the same critical section as
  `insert_confirmed_if_unchanged` (`sharded_neighbor.rs:120`).
- The UMEM correction is right: `PendingNeighPacket` pins a frame
  (`pkt.addr`, recycled to `pending_fill_frames`), bounded by
  `PENDING_NEIGH_TIMEOUT_NS` = 2000 ms (`forwarding_build/mod.rs:422,459`),
  **not** 5 min. Per-key bound reduces peak pinning. Round-1 AGY-C
  "dataplane lockup" was triggered by the v1 wording bug, now fixed.
- The two-clock separation is real: `PROBE_SCHEDULE_NS` drives kernel ARP
  (`neighbor_dispatch.rs:33`), `last_resolved` drives userspace GET — they
  don't share a syscall. `saturating_add` is already the idiom in
  `neighbor_dispatch.rs:177`.
- Path B is the right call: §2.1 is the highest-risk, lowest-evidence item
  and `epoch_rejects` already exists to measure it. Shipping §2.2/§2.5/§2.6
  first is the correct sequencing.

## Recommendation

PLAN-NEEDS-MINOR. Fold the global-monotonic-epoch + reject-on-absent fix
into §2.1, the `dump_start_ns`/`last_change_ns` eviction guard into §2.5
(and resolve the Phase 2↔4 ordering coupling), and the `epoch_rejects`
semantics caveat into §2a. With those, Phases 1–3 are PLAN-READY and §2.1
(Phase 4) is PLAN-READY-IF-MEASURED. None of these is a reason to kill the
campaign — Path B's two clear wins (§2.2, §2.5) are unaffected by the §2.1
refinement.
