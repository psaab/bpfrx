# Claude SMR hostile plan review — round 7 — #6461 blind-RST demote gate

Reviewer: Claude (SMR pass, adversarial). Scope: plan v7.2 (@ 747aa7075)
+ v7.3 interim (@ ff6c28a36), Codex r7 verdict (PLAN NO, 6B/2H/2M/1L),
AGY r7 scoped run (2 UNSOUND, 1 SOUND). Codex's blockers were re-traced;
the r6-round trust model (unchanged since v6) was not attacked again —
the round is entirely about authority identity and Phase-2 protocol
completeness.

**Verdict: PLAN NO for v7.2/v7.3 (v7.4 required).** Two of my v7.2/v7.3
folds were themselves wrong (the every-import-class ticket — Codex 1;
the alias-as-ticket without incarnation — Codex 2), and Phase 2 was a
schema sketch, not a protocol (Codex 5/6). v7.4 folds everything; the
authority design survives only after being NARROWED twice in one round.

## Adjudication of Codex r7

1. **BLOCKER — stale WorkerLocalImport sibling kills a live owner
   session: CONFIRMED, and it falsifies my v7.3 fold.** An owner-born
   flow is published and replicated to siblings as `WorkerLocalImport`
   (peer-synced). Siblings never observe traffic (queue steering); the
   unobserving sibling ages out; on the active RG it could win v7.2's
   ticket and emit Close → `session_delta.rs:436, :453` →
   `delete_synced.rs:16` → deletes the live canonical entry and releases
   the NAT allocation. v7.3 (folding AGY Q1) had ADDED WorkerLocalImport
   to the race — exactly backwards. v7.4 narrows the race to the true
   HA-import origins (`SyncImport`/`SharedMaterialize`); siblings and
   fabric replicas stay peer-synced-silent as master; the owner worker's
   direct emission is unchanged. Verified `worker_replica_origin()`
   (`entry.rs:257-262`) makes the classes disjoint: locally-born →
   WorkerLocalImport replicas; HA wire → SyncImport.

2. **BLOCKER — alias presence is not an incarnation-safe ticket:
   CONFIRMED (ABA).** `shared_ops.rs:960` removes key-only and
   unconditional; an E1-stale worker reaping after E2 republished the
   key deletes E2's alias and emits E1's stale Close. v7.4: the ticket
   is a `session_id` compare-and-delete (HA-imported entries carry the
   wire id via the #5212 inheritance; E1 vs E2 always distinct). The
   canonical alias is the ticket; the NAT/forward-wire family is cleaned
   by the winning Close's downstream processing (documented non-atomic
   residue, covered by `session_delta.rs:436`).

3. **BLOCKER — demotion/generation fencing: PARTIALLY CONFIRMED.** (a)
   The publish-before-command demotion ordering (`state.rs:72` vs
   `loop_body/mod.rs:682`) can emit an old-owner Close in the retag
   window — verified pre-existing (master has it); documented, not
   widened. (b) My "winning Close carries the stored generation" was
   fictional — generation exists only on `SyncedSessionEntry`
   (`worker/mod.rs:375`); `SessionInstall`/`SessionDelta`/the close
   event carry none (`ctx.rs:31`, `entry.rs:283`,
   `session_sync.rs:210`), and Go gen-zero deletes apply unconditionally
   (`sync_conn_gen.go:176, :263`). v7.4's actual fence is the
   session_id CAS at the ticket (Rust-side): a stale worker can no
   longer win, so the gen-zero downstream path only ever fires for the
   current incarnation. The flap-vs-reseed residual (E2 reaps on node1
   while E3 re-seeds on node0) is fenced by the live gate (node1's RG
   inactive → no emission) except in the VRRP overlap milliseconds —
   documented.

4. **BLOCKER — final admission still precedes XSK/TUN commit: CONFIRMED
   as far as it goes; adjudicated to a documented tail.** The true
   commit is descriptor insertion + `writer.commit()` (`write.rs:21`);
   between final admission and it sit stage/rewrite/verify/alloc
   failures and CoS cross-worker handoff (`cos.rs:101`). Codex wants a
   mutation token on every async path with a callback to the source
   worker — but per-packet cross-worker mutation traffic is a worse
   problem than the residual it closes: the classes between admission
   and XSK commit are capacity/allocation (UMEM slice, frame alloc),
   not sequence-targeted steering; a volumetric attacker driving them
   is out of threat model. v7.4 keeps final-admission apply and
   documents the tail honestly. The pending-neigh token DOES need the
   one addition Codex proves: on incarnation mismatch, re-resolve or
   drop (Codex 8 — a stale buffered decision can transmit on a
   released/reassigned SNAT port).

5. **BLOCKER — Phase-2 identity/writer/phase: CONFIRMED on all three.**
   (a) `session_id` is `(worker_id<<48)|counter`, restarts at 1, no
   node discriminator (`session/mod.rs:682, :753`) → incarnation =
   `(node_id, session_id)` + the sync generation for restart fencing.
   (b) The shim steers by PHYSICAL RX QUEUE, not parsed flow
   (`userspace-xdp/lib.rs:1460`) — split RSS lands directions on
   different workers → v7.2's single-writer claim false. v7.4's
   per-side writer ownership (the D-observing worker owns `seq_hi(D)`
   and `ack_hi(D)`; the O-observing worker owns the other two) gives
   every side exactly one writer under any steering; per-side interval
   seqnos + field-wise merge. The dataplane residual (a close on a
   replica worker soft-refuses in Phase 1) is documented in §7.
   (c) Synced imports force ESTABLISHED (`install.rs:359`,
   `daemon_ha_userspace_convert.go:183`) → the payload now carries the
   phase byte; a failover during the handshake validates under OPENING
   rules.

6. **BLOCKER — Phase-2 not an end-to-end protocol: CONFIRMED.** The
   Go↔Go hop had no message type (cluster types are full
   installs/deletes, `sync.go:38`, `sync_conn_read.go:96`), and the Go
   store delegates to the anchorless BPF ABI (`session_store.go:94`,
   `bpf_session_value.go:31`). v7.4 §10.5 specifies: sidecar anchor
   store with Open/Anchor/Delete lifecycle + snapshot locking;
   `MsgAnchorUpdate` cluster type with field-wise merge; reconnect-bulk-
   supersedes ordering; Go→peer-Rust `anchor_update` op flushed at
   1–4 batched messages/s deferred under install load (256-record
   batches; node-global ~16 msgs/s cap).

7. **HIGH — decay mechanics: CONFIRMED.** Decay is now a stored
   `wire_anchor_lease_ns` evaluated LAZILY at validation (the wheel
   never visits a 300 s entry at 4 s, `expire.rs:38, :166`); only the
   current owner's updates renew (never remote apply/import/
   materialization/stale bulk); retain-on-rebaseline kills the terminal
   no-emit case; decay is framed as defense-in-depth (during a loss
   window the standby is exactly as blind-guessable as the owner
   normally is; after decay, harder). The 60 s heartbeat /
   240 s lease recalibration stands (AGY r7 Q3's idle-flow point:
   without heartbeats, decay invalidated PERFECTLY ACCURATE idle
   anchors — Phase 2's whole target class).

8. **HIGH — pending-neigh stale decision: CONFIRMED (folded with 4).**

9. **MEDIUM — leg-3 during an unresolved hole: CONFIRMED.** Wording
   fixed: legs 1/3 recover AFTER repair; during the hole the ack lag can
   exceed the raw-wnd bound → abort-during-hole soft-refuses (table
   retention only).

10. **MEDIUM — stale §5.4 number + per-leg asserts: CONFIRMED (fixed).**

11. **LOW — tests: CONFIRMED (the enumerated race cases added to §9).**

## AGY r7 (scoped run): dispositions

- Q1 (ticket coverage): UNSOUND on v7.2's text — but its proposed fix
  (alias for every import class) was itself wrong (Codex 1); the correct
  fold is the v7.4 narrowing. The alias-delete atomicity (Q2) verified
  (`lock_shared_recover`).
- Q3 (idle decay): UNSOUND, valid — heartbeats added (v7.3), then
  recalibrated (60 s/240 s) in v7.4.

## Bottom line

The design has now survived seven rounds; the finding profile is fully
in the integration/identity layer (who may delete, which incarnation,
whose write, which message type) with zero trust-model changes since
v6. v7.4's authority rule is the third and narrowest form: live-ownership
gate + import-origin-narrowed incarnation-CAS ticket. Phase 2 is now a
complete protocol sketch (identity, writers, phase, transport, store
lifecycle, ordering, budget, lease). My verdict on v7.4:
implementation-ready modulo round-8 verification of the seven §11
questions.
