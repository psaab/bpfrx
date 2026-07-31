# Claude SMR hostile plan-review — round 92 (v10.8.0)

Reviewer: Claude SMR (in-conversation). Posture: HOSTILE — twelfth pass;
I authored the v10.8.0 fold of Codex r91's 2B/1H/2L, so this review
attacks my own fold first. Verdict: **PLAN YES**.

## 1. Fold verification (each Codex r91 finding, code-traced)

**r91-1 (B — forward-with-P2 after freeing P2).** Verified the mechanism
at the base: rollback removes `live_by_flow` ownership
(`allocator.rs:1392` region); the arm's existing rollback sites pair
release with drop + buffering suppression because replay would use "an
unreserved NAT tuple with no session" (`poll_descriptor/mod.rs:4670`,
`:4891`, `:4974`); a buffered `PendingNeighPacket` NAT-rewrites on
dispatch (`:5057` → `neighbor_dispatch.rs:272`/`:344`); the collision
class is documented at `allocator.rs:1617`. The v10.8.0 fold removes
the shape entirely: a closing packet never derives P2 — the
transient-purge gate is close-aware, so the close takes the
shared-backed `ExistingResolved` outcome (buffer with the resolver's
stored decision = the victim's own P1). No allocation, no rollback, no
freed-tuple transmit. The buffered-transmit path is master's
byte-identical machinery (the round-85-accepted pending-neighbor
retreat), and the stored decision is the victim's live translation, so
delivery is correct-by-construction. §4's never-drop promise survives
(Codex had noted the DROP variant would retract it; the purge-aware
shape does not drop).

**r91-2 (B — one-shot provenance destruction).** Verified: the purge
call chain (`session_glue/mod.rs:1178-1188` → `purge_translated_synced_hit`,
`promote.rs:167-207`) destroys the shared entry/BPF row/P1 reservation/
aliases (`shared_ops.rs:960`), and a second SYN|close would then find a
clean miss, pass #4400 (`session_admission.rs:83`), and FreshPrimary-
install with closing seeded + Open (`install.rs:179`/`:234`), the Open
overwriting the peer's family (`sync_conn_gen.go:435`,
`session_store.go:257`). The close-aware gate kills this at the root:
close #1 never purges, so close #2 (and #N) sees the same shared backing
and takes the same inert `ExistingResolved` branch. Non-close packets
purge + re-enter exactly as v10.4.1 (round-87-accepted). Residual check:
the purge-by-nonclose-then-close window leaves a locally installed P2 —
the close then hits P2 at site 1 and is validated against P2's own
anchor (no baseline on a just-seeded entry → refuse-demote). The
cold-neighbor interleave (purge by non-close, close arrives before the
install) lands at the MissingNeighbor arm as a transient
`MissingNeighborSeed` — master's exact behavior, `is_transient_local_seed`
→ silent at reap. No HA kill chain remains.

**r91-3 (H — matched probation row unprotected).** Verified: the
validator reads the family's anchor (canonical forward entry), so a
close hitting a reverse-key probation row directly (`lookup.rs:62`) can
validate against live F and would enter the accepted-mark rule, which
restamps the matched entry. The fold gates the matched-entry
mark/refresh/recompute/re-queue on `!probation` (§5.5 accept rule);
propagation to live F proceeds and marks F. Combined with the r90
propagation-target skip, a probation entry is now never marked or
restamped from either direction — the §7 invariant says so explicitly
and §9 tests both directions ((d) and the new (e)).

**r91-4 (L — adopt-S2 extension).** Verified: S2's candidate timeout
derives from `metadata.inactivity_timeout_ns` (`install.rs:382` via
`session_timeout_ns`). The fold preserves the MINIMUM absolute deadline
(`min(K's remaining, S2's own candidate)`), keeping the
shorter-timeout-never-extended promise in both directions; the wheel
re-queue uses the preserved absolute deadline.

**r91-5 (L — impossible counter test).** Folded: with the close-aware
purge, a closing packet never reaches the allocator at all — the §9(a)
test now asserts counters AND live gauges bit-identical, which is
possible precisely because no allocate/rollback pair runs.

**r91's confirmed-sound note** (`ReplacedSyncedLocal`: branch before
`take_synced_local`, `local_delivery.rs:75`; declined caching still
delivers, `:60`; no SNAT allocation consumed,
`poll_descriptor/mod.rs:1967`) is preserved verbatim in the fold.

## 2. Full-plan consistency sweep

- Every v10.7.0 rollback/skip-install mention rewritten or qualified as
  retraction narrative: §5.6 site-3 supplement (rewritten), §3 site-3
  row + site-9 row, §5.8 two bullets + the typed-outcomes RWoLB clause
  (paren balance re-read), §7 invariant, §9 tests (a)-(e), §11(e),
  header history. Grep-verified no stale "rolls back"/"SKIPS the
  install" live references remain (the survivors are site-2b's refuse
  precedent and the round-88 capacity-rollback, both still live design).
- The gate (§5.1–§5.4, §5.7) untouched for the eighth consecutive round.
- The v10.8.0 shape is again strictly smaller than its predecessor: the
  close-aware purge gate adds ONE predicate to an existing branch and
  deletes the entire rollback/skip-install apparatus from the design.

## 3. Bottom line

Three consecutive Codex rounds attacked the Part-B constructor shapes I
folded; each fold got strictly simpler (alive-probation-install →
skip-install+rollback → never-create-anything). v10.8.0's close-aware
purge is the simplest shape yet and removes the entire class: closing
packets are fully inert on every peer-synced-provenance path. PLAN YES
for v10.8.0.
