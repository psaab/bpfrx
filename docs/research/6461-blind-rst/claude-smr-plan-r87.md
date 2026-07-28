# Claude SMR hostile plan-review — round 87 (v10.4.0 second retreat + fold verification)

Reviewer: Claude SMR (in-conversation). Posture: HOSTILE — I authored the
v10.4.0 second retreat and the two kept folds; this pass attacks them.
Verdict: **PLAN NO for v10.4.0-as-first-written** — two precision nits
(both folded in-revision); no LOW or above. Codex r86's findings are
individually verified against the code, and the second retreat is
adjudicated below.

## The second retreat adjudication (round-86 Codex 2/3/4/6)

The v10.2.0/v10.3.0 seed-lifecycle completion was my attempt to close
two traces (transient-seed zero-producer; stale install-published
aliases). Round 86 verified the closure mechanisms unfold: flip-time
`session_limit_inc` bypasses the configured per-IP admission cap
(`session_admission.rs:29` is miss-only; `session_limit_inc` performs no
check, `session/mod.rs:909`); flip publication is an unconditional
replace (`shared_ops.rs:897`) that can overwrite a newer generation or
undo an HA demotion (`ha/state.rs:72` + `loop_body/mod.rs:682` window);
`session_id` is NOT collision-free cross-node (`session/mod.rs:766`
worker/counter namespacing, `install.rs:324` import-adopted ids,
`ha/export.rs:143` bulk-export zero ids) and check/delete has no
linearization point (`shared_ops.rs:960`, `checksum.rs:246`,
`xpf_maps.h:508`); the flipped seed keeps stub metadata
(`neighbor_dispatch.rs:606`). Each is fixable — Codex's own
prescriptions are recorded in §10.6.2 — but every fix is another
identity-substrate layer in a class where (i) every gap is PRE-EXISTING
on master, and (ii) the flagship gap (zero-producer) is HA-safe by
construction: seeds emit no Open, so no HA peer copy exists to orphan.
That is the exact shape of the pending-neighbor retreat Codex accepted
at round 85. The retraction is correct; the carve-out text (§7 emission
invariant + races e-g) bounds the class honestly.

## Kept-fold verification (against this branch's code)

- **Clean pre-SNAT baseline (r86-1) — CONFIRMED necessary and correct.**
  The purge releases `P1` (`promote.rs:194-200`) while the resolve
  returns the stored decision (`session_glue/mod.rs:1194`);
  `NatDecision::merge` is left-biased (`nat/mod.rs:123`), so the
  purged-class miss transaction would install with unowned `P1` and
  leak `P2`. Discarding the purged decision's NAT before derivation is
  the minimal correct baseline; the deterministic persistent reacquire
  (`allocator.rs:1265`) still works through the allocator (the owned
  path). Policy/metadata handling for this class is the same miss-arm
  re-evaluation master runs (`poll_descriptor/mod.rs:4190-4262`).
- **Propagation-target reciprocity (r86-5) — CONFIRMED necessary; the
  first fold text was direction-broken (finding 1 below).** The blind
  mutate at `session/mod.rs:1241` on the derived key (`lookup.rs:204`)
  is a real pre-existing wrong-mark: an unrelated forward B at
  `reverse_session_key(K, NAT_A)` with no companion (`expire.rs:508`'s
  supported state) gets A's close semantics on master today.
- **§5.8/`account_packet` wording (r86-7) — folded:** counters stay in
  `account_packet`; the anchor rides the distinct post-admission hook
  (the slow-path accounting call at `poll_descriptor/mod.rs:3497`
  precedes build/output-filter/CoS failures and cannot host the
  anchor).

## Finding 1 (nit — the propagation gate as first written broke the reverse-hit direction)

My first v10.4.0 text required the propagation target to `is_reverse`
unconditionally — but the reverse-hit propagation target is the FORWARD
companion (not `is_reverse`); the gate as written would have skipped
every legitimate reverse-hit companion mark (a silent teardown-delivery
regression on the #4109 mirror). Folded: the gate is direction-aware —
the target must reciprocate the matched entry's family, and
ADDITIONALLY `is_reverse` only when the matched entry is a forward
(the reverse-hit forward target's reciprocity was already established
at validation in the same post-borrow phase).

## Finding 2 (nit — the carve-out must name the 2b mark site too)

The emission carve-out as first written covered "an accepted close
whose matched entry is a transient `MissingNeighborSeed`" — the
reverse-synth accept's mark lands on the FORWARD FAMILY, which can also
be a seed (the same transient class, the same HA-safe-by-construction
argument). Folded: the carve-out names both mark sites.

## Bottom line

The second retreat leaves the plan at its smallest coherent shape: the
gate (confirmed sound six times now: r12, r83-r86 Codex core-gate
rechecks, AGY r83-r86), the constructor/probation rules, the
typed-outcome dispatch gate with the clean baseline, and the two
family-identity checks — every remaining gap documented as pre-existing
with a designed follow-up. Two nits folded. If Codex r87 verifies and
finds nothing new at LOW+, this plan is at convergence.
