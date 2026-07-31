# Claude SMR hostile plan-review — round 106 (v10.22.0)

Reviewer: Claude SMR (in-conversation). Posture: HOSTILE — twenty-sixth
pass; I authored the v10.22.0 fold of Codex r105's 2B/4M/1L. Verdict:
**PLAN YES**.

## 1. Fold verification

**r105-1 (B — split not propagated).** The producer now returns
`(SessionLookup, Option<CloseValidation>, TransitionResult)`; the
resolved result carries BOTH fields, initialized `(None, None)` at
both constructors (`session_glue/mod.rs:1254-1261`, `:1330-1344`);
the carriage reads both at the `:509` hoist onto the dispatch context.
The legal Phase-1 product is stated normatively — `(None, None)` /
`(None, T)` / `(Refused, T)` with `T ∈ {Installed,
AdoptedPreservingDeadline, UpsertRefused, OverdueSkipped}` — with
`Accepted` having no Phase-1 producer (every site-2c close refuses;
site 2b reports via `reverse_installed`/`install_failed`,
`session_glue/mod.rs:1264-1284`/`:1330-1344`), and a fail-closed
default (any out-of-product combination is treated as
`OverdueSkipped`).

**r105-2 (B — second outcome list).** The MissingNeighbor outcome
list's composition line now names both `OverdueSkipped` and
`UpsertRefused` → live-backed `ExistingResolved` buffer-only.
Verified there are exactly two composition statements in the document
(the §5.8 contract bullet and the outcome list) and they now agree.

**r105-3 (H — capacity contradiction).** Codex's own uniqueness proof
is folded: P + K + S2 are the only unique families per dispatch
because the promote preimage dedups (after a successful upsert the
preimage IS S2; after a refused upsert it is K — promotion changes
resolution/owner/fabric state but not (key, NAT, orientation),
`session_glue/mod.rs:1200-1234`, `promote.rs:92-107`,
`session/mod.rs:1344-1378`). Capacity 3 inline / 3×64 batch. The
preimage capture point is named: inside `update_session` immediately
before the overwrite (`session/mod.rs:1344-1348`, `:1393-1396`),
threaded outward through the boolean-returning outer promote.

**r105-4/5/6/7 (M/M/M/L).** The UpsertRefused "forwarding-only"
phrasing is scoped (the decision is forwarding-only; the surviving
state may still change via the recorded promotion attempt and the
allowed accounting; §9 asserts the resulting promoted state); the
pre-hoist policy-counter fallback (`poll_descriptor/mod.rs:487-509`,
`lookup.rs:345-354`) is explicitly ACCEPTED as master's own fallback
semantics for divergent transitions (telemetry-only; the surviving
entry is the table's notion of the flow); the §10.6.1 reap-rate
claim, the §5.6 superseded summary, and both "FULL MASTER PARITY"
remnants (:762, :2099) are scoped.

## 2. Consistency sweep

Assertion-checked replacements throughout; the two-field outcome is
named identically in the producer, fields, carriage, consumers,
composition, §9 tests, and §11. The gate (§5.1–§5.4, §5.7) is
untouched for the twenty-first consecutive round.

## 3. Bottom line

PLAN YES for v10.22.0.
