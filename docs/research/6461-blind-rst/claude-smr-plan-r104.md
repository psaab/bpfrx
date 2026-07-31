# Claude SMR hostile plan-review — round 104 (v10.20.0)

Reviewer: Claude SMR (in-conversation). Posture: HOSTILE — twenty-fourth
pass; I authored the v10.20.0 fold of Codex r103's 4B/2H/1M. Verdict:
**PLAN YES**.

## 1. Fold verification

**r103-1/4 (set carrier + storage split).** The fold separates the two
storage roles Codex distinguished: `displaced: DisplacedSet` is a
small INLINE fixed-capacity array (≤3 families, no allocation) on
`ResolvedFlowSessionDecision` — initialized EMPTY at both constructors
(`session_glue/mod.rs:1254-1261`, `:1330-1344`) — feeding the
current-binding drain (the poller drains exactly the current
descriptor's set, so descriptor 2 never re-invalidates descriptor 1's
fresh S2 alias); a SEPARATE preallocated `WorkerScratch` batch
accumulator (`with_capacity`, `worker/scratch.rs:19-32`; 3 families ×
64 descriptors, `afxdp/mod.rs:278-281`) carries the union for the
once-per-batch sibling fan-out at the `poll_binding` level over
`left + right` (`worker/lifecycle.rs:53-55`, `:209-225`), explicitly
NOT via the reap routine. The producers gain OUT parameters (the
upsert's `_previous` at `install.rs:295-322`; the placeholder
substitution at `shared_ops.rs:602-628`; the promote's displacement).

**r103-2 (refusal outcomes).** The enum is now six variants with the
code-correct definitions: `ValidatorRefused` (the site-2c
refuse-install — the alive probation entry IS installed and can
displace a canonical predecessor; the set carries that family);
`UpsertRefused` — the synced upsert's NON-PEER-predecessor refusal
(`install.rs:310-315`; my v10.19.0 "capacity" parenthetical was wrong
— capacity refusal belongs to the fresh-install path,
`install.rs:123-125`; verified) — gates the SAME authority consumers
as `OverdueSkipped` (teardown/cache/commit), because the table state
(the surviving non-peer predecessor) and the dispatch's S2 identity
diverge, and a teardown under S2's identity would delete the
predecessor's family (`session_glue/mod.rs:477-581`). The
currently-implicit behavior (the materializer ignores the upsert's
false and returns S2, `:1098-1119`) is what the outcome makes
explicit.

**r103-3 (OverdueSkipped non-empty).** Verified the trace: the lookup
shadows a differently-keyed fabric placeholder P with shared S2
(`shared_ops.rs:602-610`, `:614-626`; fixture
`session_glue/tests.rs:704-759`); FIN/RST bypasses the cache, so an
overdue close reaches the lookup; an empty set would leave P's cache
aliases refreshable indefinitely (`flow_cache_hit.rs:295-317`). The
fold: the shadowed-placeholder identity rides the set even on
`OverdueSkipped` (only an overdue skip with NO shadowed placeholder
or a no-predecessor refusal carries EMPTY).

**r103-5 (§9).** The categorical EMPTY assertion is corrected; the
new tests (vii)-(x) cover validator-refused-with-predecessor,
upsert-refused survival + gating, upsert-refused→promotion capture,
and overdue-plus-shadowed-placeholder; the transient-purge parity
test carries the warm/lapsed-seed qualification.

**r103-6/7 (overclaims).** §5.6's "FULL MASTER PARITY" is replaced by
the exact scope (purge DECISION + dispatch only; the lookup runs
before the purge decision, `shared_ops.rs:594-635` /
`session_glue/mod.rs:1157-1196`, so the gate's pre-purge refusal is a
deliberate documented delta); the §5.5 "pre-attack trajectory",
Option A's "idles out", and §10.6.1's "refuse closes until churn" all
carry the gate-effects/purge-exemption scope.

## 2. Consistency sweep

All folds this round used assertion-checked replacements (every
target verified present before substitution — the r102 process fix);
each mutated paragraph re-read in place. The gate (§5.1–§5.4, §5.7)
is untouched for the nineteenth consecutive round.

## 3. Bottom line

PLAN YES for v10.20.0.
