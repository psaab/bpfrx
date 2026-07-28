# Claude SMR hostile plan-review — round 89 (v10.5.0)

Reviewer: Claude SMR (in-conversation). Posture: HOSTILE — ninth pass on
the cut line; I attacked the v10.5.0 probation-deferral fold and swept the
full plan top-to-bottom for internal contradiction. Verdict: **PLAN YES**.

## Why a YES is earned here (the anti-soft-pass accounting)

- The gate mechanics (§5.1–§5.4, §5.7) have been re-confirmed sound by
  Codex six times (r12 "substantially converged"; r83, r84, r85, r86, r87
  core-gate rechecks — arithmetic exact, absorbing state verified,
  receiver-slack selection correct, no missing-forward fallback) and by
  AGY six times (r83–r88, all SOUND, no new traces).
- Both retreats carry Codex's own acceptance: pending-neighbor ("the
  retreat stands", r85; reaffirmed r87, r88) and seed-lifecycle ("I do
  not hold that seed-class completion must ship here", r87; reaffirmed
  r88). The follow-up designs for both are recorded in §10.6.2 with
  Codex's own prescriptions.
- Every prior SMR finding (r83: 1L/5nit; r84: 2nit; r85: 2nit; r86: 1nit;
  r87: 2nit; r88: 3nit) was folded and re-verified against code.

## The v10.5.0 fold (round-88 Codex 1) verification

- The defect is real on master and the fold is minimal: master's
  in-borrow lookup stamps `last_seen_ns`, recomputes `expires_after_ns`,
  and re-queues the wheel at `lookup.rs:146-156, :214-218` — strictly
  before the input filter (`poll_descriptor/mod.rs:592`) and TTL check
  (`poll_descriptor/mod.rs:846`). The fold skips all three for probation
  entries (the ≤20 s clock runs unextended), extends the same skip to
  `touch_if_stale` (`flow_cache_hit.rs:295` → `session/mod.rs:1118`),
  and lands the clear+refresh at the matched entry's successful
  final-admission commit hook — the same arms the anchor hooks ride, so
  every drop class (input filter, TTL, output/CoS, redirect-inbox
  capacity, cache-tail) leaves probation untouched.
- Cross-references verify: §5.5's "byte-identical" is qualified to
  non-probation entries; the §7 borrow-shape invariant matches; the
  closing-packet interplay is coherent (a committed CLOSE on a probation
  entry does NOT clear — the clear requires a committed non-close, and
  closing segments never run the anchor hook, rule 1); the ownership
  promote stays suppressed until clear (§5.5); the admission-ceiling
  pressure note (`install.rs:294` vs `:113`) is stated and the §9 test
  covers all drop classes plus the starvation bound.
- The (e)-(g) races now live in §7's race list where the references
  point; §10.6.2's completion bullet names the same gaps descriptively
  with the round-86 design notes. No duplicate text.

## Consistency sweep (full plan, this pass)

- No straggler references the retracted designs as live: the re-resolve/
  hold (v10.1), the flip/flip-time-inc/Open (v10.2-3), and the
  `session_id`-guarded cleanup (v10.3) appear only inside retraction
  narratives and the §10.6.2 follow-up. The "flip" language elsewhere
  is the design's own origin-flip semantics (rule 5, refuse-demote).
- §5.5 reads coherently end-to-end: in-borrow capture → post-borrow
  family-identity check → validation → accept (mark + direction-aware
  reciprocal propagation) / refuse (fully inert + counter).
- §3's site inventory, §5.2's hooks, §5.8's signature list, §7's
  invariants, §9's tests, and §11's questions name the same mechanisms
  with the same names (typed outcomes, cold/miss re-entry, sole
  decision, deferred refresh, reciprocity gates, carve-out).

## Bottom line

The cut line has been stable in shape for six rounds; findings descended
from BLOCKERs in the gate's constructor paths (r83), through dispatch
plumbing (r84-r87), to a gate-mechanics availability defect (r88) that
is now folded with the minimal rule (defer the refresh to the commit
hook — the same discipline the anchor itself already used). I attacked
the fold's edge cases (closing packets on probation, cache-tail,
promote suppression, wheel mechanics, per-app re-apply) and found them
covered by the existing rules. PLAN YES for v10.5.0. If Codex and AGY
concur, this plan is ready.
