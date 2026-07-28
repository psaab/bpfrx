# Claude SMR hostile plan-review — round 86 (v10.3.0 fold verification)

Reviewer: Claude SMR (in-conversation). Posture: HOSTILE — I authored the
v10.3.0 folds of Codex r85's four BLOCKERs; this pass attacks them.
Verdict: **PLAN NO for v10.3.0-as-first-written** — one precision nit
(folded in-revision); no LOW or above. Codex r85's findings are
individually verified against the code.

## Codex r85 finding verification (against this branch's code)

- **r85-1 (outcome exhaustiveness) — CONFIRMED.** The purge path
  (`session_glue/mod.rs:1178-1193` → `promote.rs:181-207`) deletes
  local/shared state and releases NAT, then returns
  `Some(created=false)` at `:1254-1261`. `keep_transient=true` implies
  `poison_key.is_some()` (the `.or_else` always yields Some for a hit),
  so the purge flag is a complete discriminator for the third outcome.
  The v10.3.0 fold treats `ResolvedWithoutLocalBacking` as a genuine
  miss end-to-end — #4400 for a bare close (consistent with the shipped
  miss posture; the backing was authoritatively torn down), full seed
  transaction for SYN/data (restoring master's reverse-backing behavior
  incl. the `allocator.rs:1265` reacquire). Mechanically the resolve
  layer threads the purge flag into the arm's provenance — feasible:
  `keep_transient` is in scope at `:1194`.
- **r85-2 (flip accounting) — CONFIRMED and the precedent exists.**
  `install.rs:226`: `counted = !is_reverse &&
  !is_transient_local_seed()` — seeds are uncounted AND emit no Open
  (the `counted && !is_peer_synced()` gate at `:234`).
  `session/mod.rs:1817` decrements every non-transient forward at
  removal — a bare flip would dec without inc (cap corruption) and
  emit Close without Open. Crucially, `install.rs:555-562` already
  contains the exact class-transition pattern (snapshot pre-flip class,
  flip, increment iff added to the counted class) for the seed→SyncImport
  case — the v10.3.0 fold mirrors it, and the Open fires AT the flip
  (install emits none). The accepted-close case's Open→Close stream
  order is stated.
- **r85-3 (identity substrate) — CONFIRMED, with the right id choice.**
  `ExpiredSession` (`entry.rs:337-340`) carries key/decision, no
  generation; seed publication writes zero ids
  (`poll_descriptor/mod.rs:4811`); shared/DNAT deletion is key-only
  (`shared_ops.rs:960`, `checksum.rs:246`). The fold uses the #4915
  node-unique `session_id` (allocated at every fresh install,
  `install.rs:143-148`) — NOT the per-table `install_epoch`, which
  collides across workers (the stale-cleanup-vs-newer-generation trace
  is a cross-worker race; per-table epochs cannot discriminate it).
- **r85-4 (reverse-hit reciprocity) — CONFIRMED.** The propagation
  derives the companion by key (`session/mod.rs:1241`) with no
  generation agreement; forward/reverse halves are separable (HA import
  creates both; `purge_translated_synced_hit` removes only the
  forward). The fold's reciprocal `(key, nat)` check uses the SAME
  `reverse_session_key` derivation the propagation uses
  (`expire.rs:476-496`), so reciprocity and propagation can never
  disagree about the family. `NAT1 ≠ NAT2` fails reciprocity → refuse;
  exact tuple+NAT reuse is packet-indistinguishable (no token needed).
  The forward-hit path needs no check (matched IS the anchor's entry).

## Finding 1 (nit — the drain guard needs a zero-id fallback)

The v10.3.0 text requires `session_id` agreement at the alias cleanup
AND the flipped seed's Close drain, but pre-upgrade nodes (and
pre-upgrade publications on this node) wrote zero ids. An unqualified
guard would either refuse cleanup for all legacy records (leak) or be
silently dropped by the implementer. Folded in-revision: legacy zero-id
records fall back to master's key-based cleanup — the guard only ever
ADDS protection where a real `session_id` exists on both sides.

## Bottom line

Four rounds into the terminal cut, the findings have converged onto one
small, fully-mapped corner (the MissingNeighbor/seed state machine), and
every fold is local: typed outcomes, the in-tree class-transition
precedent, the existing node-unique id, one reciprocal derivation. The
gate itself has now been confirmed sound five times (r12, r83, r84, r85
Codex core-gate rechecks + AGY r83-r85). One nit folded. If Codex r86
verifies and finds nothing new at LOW+, this plan is at convergence.
