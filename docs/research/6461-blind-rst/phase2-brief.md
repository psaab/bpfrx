# Phase-2 design brief — HA-wire anchor carriage (separate research track)

> This brief is the accumulated design state for the Phase-2 HA-wire
> anchor protocol, split out of the #6461 plan at v9. Phase 2 restores
> the 2 s fast-reap for synced flows after failover by carrying a trusted
> TCP sequence anchor from the RG owner to the standby. It is NOT part of
> the #6461 gate; it is an optimization for the bounded absorbing-state
> residual (imported entries refuse closes until churn). Nothing here is
> approved for implementation — it is the starting brief for a dedicated
> `/research` effort.

## What the Phase-1 gate already gives (so Phase 2 is optional)

- A blind close can never mark an entry → never produces a Close delta →
  the cluster-kill channel (#6461's HA teeth) is dead with no wire change.
- Imported entries are zero-trust absorbing: their closes refuse until
  churn (bounded; delivery unaffected; endpoints tear down normally).
- Cleanup of stranded shared state: the family-clock TTL sweep
  (Part B §5.2/§7) plus the reservation-purge hook.

## The design as it stood at split (v8.4)

- **Payload (two per-direction bundles, additive, presence-gated):**
  `{incarnation {origin_process_nonce, flow_incarnation_id}, established,
  open_ack_lo/hi ×2, bulk_epoch, dir[2] {seq_hi, ack_hi, wnd, coord_seqno,
  observed_ns, writer_node, writer_worker, present, valid, trusted}}`
  (~92 B packed) plus a `closing: u8` wire mark for peer-validated closes.
- **Emission:** per-direction writer ownership (the D-observing worker
  owns `seq_hi(D)`/`ack_hi(D)`/`wnd(D)`); per-worker bounded dirty ring
  (retain-on-rebaseline, drop-oldest with watermark); ≤1 update/entry/s;
  quiet-flow filter (re-baseline silently when over one slack);
  observation-gated staggered heartbeats (~60 s); batched messages
  (~256 records) under a node-global floor ≥ 3k records/s (split
  steering doubles bundle volume).
- **Merge:** lexicographic `(bulk_epoch, coord_seqno)` per bundle;
  coordinator as the single sequencer (writers submit bundles with
  `observed_ns`; stale submissions dropped at the coordinator).
- **Freshness:** receiver-computed from `observed_ns` (< T_anchor =
  240 s); leases evaluated lazily at validation; only the current
  owner's updates renew (never remote apply/import/materialize/stale
  bulk).
- **Ordering:** `AnchorStreamStart` on EVERY connection (primary or
  secondary fabric) carrying the sender's process nonce + current
  epoch; incrementals accepted only after the marker; epoch activation
  atomic with the `BulkStart` write; typed records in the Go queue
  (never pre-serialized bytes); `BulkStart(E)` floor discards older.
- **Trust posture:** a wire-carried side lands valid+trusted only when
  incarnation matches, the lexicographic version exceeds, the owner
  gate passes, and it arrives fresh; untrusted state never confers
  trust; decay on unrefreshed lease → Phase-1 refuse-biased posture
  (every loss mode safe).

## Open protocol questions (rounds 6-12 findings, unresolved at split)

1. **Cross-node clock normalization** (r12-3): `observed_ns` compares
   monotonic clocks with different origins across hosts/boots
   (`screen/mod.rs:786` notes the same in-tree). Either carry
   sender-computed age at actual write, or establish a process-nonce-
   bound clock offset (the existing sync offset exchange,
   `sync_protocol.go:18`, `sync_conn_read.go:475`, is the precedent)
   and reject anchor traffic until the offset is ready.
2. **Owner authority during overlap** (r12-9): `current_owner(rg)` is
   not unique during the masterDownInterval/election window
   (`group_state.go:218`, `election.go:213`). The fail-closed rule
   drafted at split: while the election is unresolved/dual, apply
   updates from NEITHER (lease decays to the Phase-1 posture); apply
   from the resolved winner only.
3. **Version namespacing** (r12-5): `bulk_epoch`/`coord_seqno` are
   sender-process-local; a former owner or pre-restart process with a
   high version can block a new owner's updates indefinitely. Versions
   must be namespaced by (accepted owner, sender process nonce), or
   atomically reset on authority/process transition.
4. **Wire-mark emission trigger** (r12-4): closing packets never move
   anchors, and the mark rides the anchor pipeline (dirty ring + 60 s
   heartbeat) — but a reset-marked entry reaps in 2 s, so the mark
   ordinarily never emits. Needs an incarnation-bound monotone record
   and an immediate/retried emission trigger independent of anchor
   movement, with current-owner admission and defined trust semantics.
5. **Secondary-fabric readiness race** (r12-12): the connection is
   published (`installConn`) before `ClockSync` completes
   (`sync_conn.go:125`); an incremental can reach the secondary before
   its `AnchorStreamStart` and be discarded with no later repair for a
   quiet flow. Gate active selection (for anchor traffic) on
   marker/clock readiness.
6. **Owner-ID adoption on full import** (r12-8): Phase-1 ids are
   node-local and Phase-2 AnchorUpdates apply only on the owner-id
   match — full Open/import must explicitly adopt the owner's
   `flow_incarnation_id` before sidecar updates can match (imports
   mint locally today).
7. **Capacity/payload accounting** (r12-13): payload is ~92 B packed
   (not ~80); the Go→Rust flush floor must match the split-steering
   steady state (~2.1-3k bundle records/s → 12 × 256-record batches/s);
   the sidecar bound is `2 × worker_count × max_sessions`
   (`protocol_status.go:259`), not one worker cap.
8. **Stale-sidecar merge semantics** (r12-4/6): merged full installs
   must reapply sidecar state only when incarnation matches AND the
   bundles arrive fresh; remote application must never re-emit or
   upgrade untrusted bundles (the Phase-1 provenance matrix holds end
   to end).

## Bottom line for the next research effort

Phase 2 is a genuinely separable wire protocol. The #6461 gate does not
depend on it. The next `/research` should either converge the eight
questions above or recommend a smaller Phase-2 (e.g., owner-side
validation only, with post-failover closes forwarded to the owner for
validation instead of importing anchors — a design that trades a
redirect hop for the entire trust-transport problem).
