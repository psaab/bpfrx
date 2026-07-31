# Claude SMR hostile plan-review — round 102 (v10.18.0)

Reviewer: Claude SMR (in-conversation). Posture: HOSTILE — twenty-second
pass; I authored the v10.18.0 fold of Codex r101's 5B/1H/1M. Verdict:
**PLAN YES**.

## 1. Fold verification

**r101-1 (B — producer/transport contract).** The contract is now
normative in §5.8: `MaterializeOutcome ::= None | Installed |
AdoptedPreservingDeadline | OverdueSkipped`;
`materialize_shared_session_hit` returns `(SessionLookup,
MaterializeOutcome)` computed AT the materialize site — available
BEFORE the promotion attempt (`session_glue/mod.rs:1235-1261`,
`promote.rs:99-139`), which was Codex's ordering point;
`ResolvedFlowSessionDecision.materialization` is initialized `None`
at every construction site (`shared_ops.rs:563-578`); the poller
reads it at the `:509` hoist and stores it on the per-descriptor
dispatch context that survives the `:883` reduction, with the
consumer read points named (`:3900-3959`, `:4034`, the three teardown
sites, the commit hooks). The promote-guard rationale is corrected
(K remains installed; the §5.5 probation flag is the guard).

**r101-2 (B — guards as executable design).** The composition
(OverdueSkipped + MissingNeighbor → live-backed ExistingResolved
buffer-only, never the seed block) and the three teardown guards are
now in the normative §5.8 outcome list rather than §9 prose; the
buffer/replay soundness note (`poll_descriptor/mod.rs:5057-5068`,
`neighbor_dispatch.rs:272-405`) is recorded.

**r101-3 (B — displaced-identity set).** Verified the three discard
points (`shared_ops.rs:522-560` no shadowed-local identity;
`:602-628` placeholder substitution discards; `install.rs:295-322`
upsert discards `_previous`). The fold: every site-2c transition
result carries the bounded displaced-identity SET (new S2 family +
any removed canonical predecessor's old family + any shadowed
placeholder's key family; EMPTY for refusal/OverdueSkipped).

**r101-4 (B — mechanically realizable timing).** Verified the
ownership constraints (materialization has no cache handle,
`session_glue/mod.rs:1092-1143`; the poller owns the binding/batch,
`poll_descriptor/mod.rs:110-131`; siblings are outer-lifecycle,
`worker/lifecycle.rs:53-56`). The fold: current-binding invalidation
runs at the POLLER immediately after resolution and before every
early exit / the cache insert / the next descriptor; transitions
accumulate per batch; the sibling fan-out runs once per batch via the
reap path's iteration EXCLUDING the current binding (avoiding both
the same-batch miss and the new-S2 eviction on alias overlap). §9
gains the six lifecycle cases (initial-placeholder, simultaneous
two-predecessor, same-batch, sibling, multi-transition,
new-current-S2-survives).

**r101-5 (B — cold-seed artifact).** Verified: with the retraction,
both versions run the same seed transaction on the current packet's
raw flags (`poll_descriptor/mod.rs:4787-4795`,
`install.rs:179-180`), and the follow-up ACK hits the local seed
(`shared_ops.rs:594-613`). The 300 s-vs-2 s/30 s delta text is
removed; the §9 cold-corner now asserts NO delta.

**r101-6 (H — companion-delta contradictions).** §10.6.2 and §11 now
say the gate engages on the pre-purge lookup (the deliberate
documented delta, with the lengthened-exposure cost stated) but
cannot prevent the constructor-side Open; the warm/lapsed-seed
qualification rides the chain statement in §7.

**r101-7 (M — inertness phrasing).** Both surviving copies (§5.7 and
§9) are scoped to the gate's own effects.

## 2. Consistency sweep

Every r101-cited line was rewritten and re-read in place; the
specification now names types, construction sites, carriers, and read
points for every mechanism added since v10.14. The gate (§5.1–§5.4,
§5.7) is untouched for the seventeenth consecutive round.

## 3. Bottom line

The last three rounds were specification-rigor rounds, not design
rounds: the same stable end-state, stated with increasing mechanical
precision. v10.18.0 completes the producer/transport/consumer
contracts. PLAN YES for v10.18.0.
