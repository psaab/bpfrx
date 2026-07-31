# Claude SMR hostile plan-review — round 94 (v10.10.0)

Reviewer: Claude SMR (in-conversation). Posture: HOSTILE — fourteenth
pass; I authored the v10.10.0 fold of Codex r93's 2B/1H/2M/1L. The
r93-1 finding is the arc's most important catch since the terminal cut,
so this review attacks my fold of it hardest. Verdict: **PLAN YES**.

## 1. Fold verification

**r93-1 (B — same-dispatch re-entry collapsed #6599 from 2 packets to
1).** Verified the master mechanics at the base: post-purge,
`session_glue/mod.rs:1194-1196` sets `resolved = hit.lookup.clone()`
and returns `Some(...)` — the caller stays in the HIT branch and
forwards with the retained (victim's own) decision; the install/Open
requires a later packet's clean miss. Master's #6599 sequence is two
packets; v10.4.1's same-dispatch re-entry made it one. The fold makes
the re-entry INSTALL-FREE: fresh derivation (r87's correctness
requirement — the stored decision may reference deleted config) serves
only this packet's forward/buffer; install/publication/Open/seed/cache
all defer to the next packet's clean-miss dispatch. Self-attack:
(i) upstream-equivalence — master: packet 1 purge+forward (retained
lookup), packet 2 clean-miss install+Open; v10.10.0: packet 1
purge+re-derive+forward (fresh decision), packet 2 clean-miss
install+Open. Same packet count, same state transitions; the only
difference is fresh-derive vs retained-lookup for packet 1's
forwarding — the r87-required correctness direction (current config,
not stale stored state). (ii) Does install-free break a legitimate
flow? The flow's session establishes one packet later than v10.4.1 —
identical to master; delivery is never blocked. (iii) Does anything
else consume the re-entry's derived decision expecting an install?
The v10.10.0 §9(c) asserts the full no-install/no-publication/no-
Open/no-seed/no-cache-mutation set; the reinjection epilogue transmits
the buffered fresh decision without re-running the pipeline (the
round-88 consumer checks were re-scoped to the clean-miss dispatch).
(iv) The close-aware purge is unchanged — closes still never reach the
re-entry.

**r93-3 (B — overdue-K pin).** Verified the algebra:
`now.saturating_add(D.saturating_sub(now))` = `max(D, now)`; expiry is
strict and wheel-driven (`expire.rs:130-168`, `wheel.rs:39-50`); the
upsert remove/recreates and re-queues (`install.rs:312-322`,
`:345-401`, `:427-433`). The fold: D ≤ now → skip the upsert wholesale
(no remove/recreate, no restamp, no re-queue); K keeps its existing
wheel slot and the GC reaps it on schedule; the packet forwards with
S2's decision (K is already due — its residual state is irrelevant).
Self-attack: (i) the pin required the re-queue — skipping removes the
mechanism, not the timing; (ii) the split-brain concern (K serves S1,
packet used S2) is bounded by K's imminent reap and exists only for an
already-overdue zombie — stated; (iii) the phase-shifted GC regression
test is in §9; (iv) the "immutable/never-restamped" wording conflict
is resolved by the shorten-only + encoding-vehicle clarification.

**r93-2 (H — close-aware retention amplifies #6600).** Verified:
master's purge predicate is flag-agnostic (`promote.rs:48-59`), so a
conflicted-P1 row is self-cleaned by ANY packet on master; the
reservation refusal is silent today (`allocator.rs:1682-1689`,
`nat/source.rs:945-953`). The fold: the upsert records the reservation
outcome on the entry (dataplane-local — no wire, no #6600 dependency),
and close-aware retention applies ONLY to reservation-succeeded rows;
reservation-failed rows take master's flag-agnostic purge even for
closes. Self-attack: (i) does the purge of a reservation-failed row
re-open r91-2's one-shot destruction? That trace needed a
FreshPrimary install+Open to overwrite the peer — for a
reservation-failed row the state is already broken (the local node
never owned P1); purging it restores master's exact behavior for a
state the import race corrupted; the peer's authoritative family is
unaffected by the local purge (the purge is local/shared-map only).
(ii) The recording point (`upsert_synced.rs:80`'s refusal) is
observable at the worker — no propagation needed for the gate.

**r93-4/5/6 (M/M/L).** §9(c-defense-in-depth) relabels the unreachable
bare-close-RWoLB oracle; §7's emission invariant is scoped to the
prompt marked producer with the SharedPromote caveat referenced; the
#4400 cites are now the statement span (`poll_descriptor/mod.rs:
1642-1650`, expression `:1646`) and the predicate body
(`session_admission.rs:82-87`); the fabric-seed provenance row is
scoped branch-base-only (#6478). All verified at the base.

## 2. Consistency sweep

- §5.8 typed-outcomes clause, §5.6 site-3 supplement + site-2c adopt
  rule, site-9 row, §7 invariant + residuals, §9 tests (a)-(e) +
  close-inertness + materialize-preservation bullets, §11(e), and the
  header history all carry the v10.10.0 shapes with the same names.
- The gate (§5.1–§5.4, §5.7) untouched for the ninth consecutive
  round.
- The v10.10.0 shapes are again strictly smaller: install-free
  re-entry REMOVES the last state mutation from the RWoLB path (the
  re-entry is now a pure forwarding construct), and the overdue-K skip
  removes a re-queue instead of adding a fence.

## 3. Bottom line

The fresh-thread r93 review was the most productive in twenty rounds —
it caught a real upstream-equivalence regression (2→1 packets) that
the shared-context thread had accepted since r87. The fold removes the
regression by removing the install, which is also the simplest shape
the RWoLB path has had. PLAN YES for v10.10.0.
