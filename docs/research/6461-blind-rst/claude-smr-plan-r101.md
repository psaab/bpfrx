# Claude SMR hostile plan-review — round 101 (v10.17.0)

Reviewer: Claude SMR (in-conversation). Posture: HOSTILE — twenty-first
pass; I authored the v10.17.0 fold of Codex r100's 4B/1H/1M. Verdict:
**PLAN YES**.

## 1. Fold verification

**r100-1 (B — suppression/clean-miss stragglers).** Five spots
carried the retracted suppression or the overclaimed "next packet
clean-misses" sequence: §9 test (c), the §5.6 supplement tail, the
§5.8 bullet, the §9 purged-class bullet, and a re-spliced "(d) a
genuine top-level(d)..." duplication. All now say: master-split with
FULL cache parity (a purged pure-ACK is cache-eligible and inserted
normally, `flow_cache.rs:352-394`, `poll_descriptor/mod.rs:3900-3959`;
a follow-up cache-eligible packet cache-hits before session
resolution, `:298-327`), and the ForwardFlow install happens on the
next cache-MISSING packet's genuine clean miss — master's sequence
exactly. Grep-verified no live "suppressed"/"clean-misses" claims
remain outside retraction narratives.

**r100-2 (B — OverdueSkipped producer/transport).** The field is now
defined: `materialize_shared_session_hit` gains an OUT result (it
returns only `SessionLookup` today, `session_glue/mod.rs:1092-1121`);
`ResolvedFlowSessionDecision` gains `materialization:
MaterializeOutcome` initialized `None` on every other path
(`shared_ops.rs:563-578`). The promote-rationale error is corrected:
K REMAINS installed, so "cannot engage because no local entry exists"
was wrong — the guard is the §5.5 probation flag on K.

**r100-3 (B — composition not carried through the poller).**
Verified the mechanical claim: only `install_failed` is hoisted at
`poll_descriptor/mod.rs:509` and the result reduces to
`resolved.decision` at `:883`. The fold specifies the carriage: the
field is hoisted alongside `install_failed` and rides the dispatch
context to the cache-insert point (`:3900-3959`), the arm (`:4034`),
and the commit hooks. The composition rule is now IN the §5.8 outcome
list (OverdueSkipped + MissingNeighbor → the live-backed
ExistingResolved buffer-only arm; never the seed block,
`:4662-4829`); the three teardown sites carry explicit guards
(`:698-714`, `:768-784`, `:824-840`); §9 tests the propagation and
the accounting-allowed carve-out; the "K bit-identical" assertion is
scoped to timing/probation/flag fields (accounting may advance).

**r100-4 (B — alias lifecycle/execution).** Verified: adoption runs
where only `SessionTable` is available (`session_glue/mod.rs:
1092-1121`); caches are per-binding and exact-key
(`flow_cache.rs:203-218`, `:1105-1120`); the reap path iterates all
bindings (`worker/loop_body/mod.rs:1467-1520`); descriptor processing
batches (`poll_descriptor/mod.rs:110-131`). The fold specifies the
lifecycle: EVERY site-2c state transition (initial probation
construction — including the fabric-placeholder substitution corner,
`shared_ops.rs:594-628`, `session_glue/tests.rs:704-759`; an S1→S2
adoption; any successful replacement of a non-probation predecessor —
the upsert guard protects only locally-owned rows,
`install.rs:310-322`) invalidates the PRIOR identity's full alias set
in the current binding IMMEDIATELY (before the cache-insert point and
before the next descriptor) AND fans out to sibling bindings via the
reap path's iteration.

**r100-5 (H — parity contradictions).** The "NO delta at all /
byte-parity" (§5.2), "changes NOTHING" (§7), and "cannot engage"
(§10.6.2) phrasings are corrected: the gate DOES engage on the first
close's pre-purge lookup (the deliberate delta), and §9 gains the
companion-state assertion (the surviving reverse replica keeps its
ordinary peer-synced trajectory, not the 2 s/30 s closing window).

**r100-6 (M — inertness over-scoped).** §5.7 now scopes the
refused-close inertness to mark/refresh/re-queue effects; master's
flag-agnostic purge of the entry is explicitly not the gate's effect.

## 2. Consistency sweep

Re-read every mutated paragraph in place; the mechanism names match
across §5.2/§5.6/§5.8/§7/§9/§11; the gate (§5.1–§5.4, §5.7) is
untouched for the sixteenth consecutive round.

## 3. Bottom line

Round 100's BLOCKERs were specification-completeness and text-fidelity
findings, each with a concrete prescription now folded. The design has
been stable for four rounds. PLAN YES for v10.17.0.
