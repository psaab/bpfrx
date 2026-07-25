# Claude SMR hostile plan-review — round 35 (v9.9.19 @ fb7a059d2)

Reviewer: Claude SMR (in-conversation). Posture: HOSTILE — I wrote the
v9.9.19 folds; this pass attacks them. Verdict: **PLAN NO for
v9.9.19-as-committed** — one self-found MEDIUM (the allocator critical
section and the canonical-lock publish must be stated as never-nesting, or
the single reservation point introduces a lock-inversion deadlock class) and
two LOWs. The design direction of every v9.9.19 fold verifies sound.

## Finding 1 (MEDIUM — lock-order: allocator critical section must never nest with the canonical publish)

The single-reservation-point fold puts the coordinator's
reserve-with-receipt BEFORE `publish_shared_session`
(`ha/session_import.rs:113-118`). The canonical lock hierarchy is
`synced → nat → forward_wire → indexes` (`session_manager.rs:12-18`); the
allocator's `shared.live` mutex sits OUTSIDE that hierarchy. If the
reservation's critical section is allowed to SPAN the canonical publish,
the order allocator-live → synced exists — while the delete/TTL-sweep path
takes canonical locks and then releases NAT ownership (release →
allocator-live), giving synced → allocator-live: a textbook two-lock
inversion (coordinator import holds allocator-live awaiting `synced`;
concurrent delete holds `synced` awaiting allocator-live). The fold must
state: the reserve-with-receipt critical section COMPLETES AND RELEASES the
allocator lock before the canonical publish begins (reserve → unlock →
publish; the RAII guard re-acquires the allocator lock for a post-publish
undo), so no thread ever holds both, and the receipt commit point is
well-defined (the transaction commits at publish; the guard is armed
between reserve and publish-commit only). No nesting, no inversion.

## Finding 2 (LOW — retarget/close ordering and the drain-then-snapshot invariant)

The slot linearization fold should state the two facts that make it
provably correct: (a) the migration's snapshot runs AFTER the gate-WRITE
drain, so any release that observed `slot == A` under A's READ permit
completes into A BEFORE the snapshot (and is thereby included in B's copied
state — refcount continuity); (b) the retarget-then-close order (or the
equivalent bounded spin: a `with_current()` loader that lands in the
close-then-retarget window spins CPU-only until the retarget publishes —
bounded because the retarget is the very next step). Without (a) written
down, an implementer can snapshot before draining and lose the in-flight
release from B's copy.

## Finding 3 (LOW — §9 composition scenario)

The §9 bullets cover each mechanism in isolation but not the composition:
epoch park + single reservation point + slot indirection interacting across
an in-place-refresh migration during a config-apply lag during an RG
failover. One scenario bullet (the loss-cluster smoke shape: config change
→ apply lag on standby → park → failover mid-park → in-place refresh on
the survivor → drain, resync, retarget) closes it.

## Verified sound this round (my own re-trace)

- r34-B1 fold: the reconnect re-drive is a FULL bulk (OnPeerConnected →
  bulk, `sync_conn.go:130-194`), so consumed-then-dropped deltas are
  reconstructed; lossy-bulk suppression (no reconcile, no ACK) is the
  correct composition with the selective park (the dropped buffer includes
  the bulk's BulkEnd, so no partial reconcile can run).
- r34-B2 fold: with the reservation at the coordinator entry point, a
  worker cannot materialize an entry whose reservation failed — the
  canonical entry never publishes, and the materialize path
  (`session_glue/mod.rs:1157`) only reads published shared entries.
- r34-B3 fold: the slot-WRITE → allocator-WRITE order has no reverse
  (ownership operations never take slot-WRITE), so no inversion; the
  revalidation under the READ permit catches both the retarget and the
  closed gate; the retry loop is CPU-only and converges.
- r34-H4 fold: high-water advancing from observed INSTALL stamps is bounded
  by the same authentication as installs themselves (the #6284 namespace);
  a partition-era peer's stamps sort under the reunion adoption rule.

## Verdict

**PLAN NO for v9.9.19** — fold Findings 1-3 as v9.9.20 (precision clauses;
no design change). Part A remains converged and untouched.
