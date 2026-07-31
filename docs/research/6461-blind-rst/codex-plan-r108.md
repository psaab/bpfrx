# Codex hostile plan-review — round 108 (v10.24.0)

Reviewer: Codex (fresh thread, job task-ms9dbr41-r3y8ei, 2026-07-31). Verdict: PLAN NO (1B/2H/2M) — every finding was a contradiction BETWEEN my own partial-edit generations (the second drain paragraph vs the first; the unscoped fallback in the legal-product paragraph and composition clauses; the consumer list's guards vs the new explicit gate; terminology my v10.24 fold reintroduced). r107-4 RESOLVED. The v10.25.0 answer: the contract block is rewritten wholesale as one coherent specification.

## Verbatim review

PLAN NO 1. **BLOCKER — The two-drain contradiction survived.** The corrected storage paragrap...

[2026-07-31T20:07:29.422Z] Assistant message
PLAN NO

1. **BLOCKER — The two-drain contradiction survived.** The corrected storage paragraph says current-binding invalidation consumes only the current descriptor’s `report.displaced`, while `WorkerScratch` is union-only for sibling fan-out (`docs/research/6461-blind-rst/plan.md:1901-1919`). The next normative paragraph still says the displaced set accumulates on `WorkerScratch` and current invalidates “the set” after every descriptor (`:1925-1936`). Following that wording lets descriptor 2 re-invalidate descriptor 1’s freshly cached S2. Descriptor processing owns only current (`userspace-dp/src/afxdp/poll_descriptor/mod.rs:110-131`); sibling ownership exists at `userspace-dp/src/afxdp/worker/lifecycle.rs:53-55`, `:209-225`. The single report carrier itself is now correct.

2. **HIGH — The SSOT still both scopes and unscopes invalid-report fallback.** The producer paragraph correctly restricts invalid→`OverdueSkipped` handling to `Some(Site2c)` and sends `site=None` through master dispatch (`plan.md:1753-1760`). The legal-product paragraph then says any invalid combination becomes `OverdueSkipped` (`:1793-1803`), while both MissingNeighbor composition clauses remain site-unqualified (`:1840-1849`, `:1980-1986`). On a purged retained lookup, purge has removed state and released NAT (`userspace-dp/src/afxdp/session_glue/promote.rs:181-207`) but dispatch retains its decision (`userspace-dp/src/afxdp/session_glue/mod.rs:1194-1196`); the broad interpretation again buffers and replays the released tuple (`userspace-dp/src/afxdp/poll_descriptor/mod.rs:5057-5068`; `userspace-dp/src/afxdp/neighbor_dispatch.rs:272-292`).

3. **HIGH — Pre-upsert construction is sound, but its promotion/refresh consumers remain contradictory.** Computing validation and probation overdue status before mutation is mechanically valid: synced upsert checks its only refusal before mutation (`userspace-dp/src/session/install.rs:310-315`), with removal/install beginning at `:322-400`. Mapping the resulting boolean to `Installed` or `UpsertRefused` preserves the legal product.

   The new paragraph also requires an explicit `report.transition == OverdueSkipped` promotion/refresh gate (`plan.md:1760-1775`), but the normative consumer list still says promotion is guarded only by K’s probation flag and refresh only by an “overdue entry” check (`:1820-1832`). Current promotion checks only origin and disposition (`userspace-dp/src/afxdp/session_glue/promote.rs:86-107`), so the consumer-side invalid-Site2c fallback remains ungated when no probation K exists. Section 9 also still tests producer normalization rather than valid-by-construction ordering (`plan.md:2526-2529`) and omits the `site=None` master-dispatch regression.

   The legal runtime combinations are otherwise coherent: Installed/Adopted are table-backed; UpsertRefused gates teardown/cache/anchor but may promote on a non-close ForwardCandidate; OverdueSkipped additionally gates refresh/promotion; accounting and S2 delivery/buffering remain allowed.

4. **MEDIUM — Removed terminology was reintroduced in the new fold.** The gate names a site-2c `ValidatorRefused` class and a “normalized-invalid” report (`plan.md:1769-1775`), but the declared fields are `validation == Some(Refused)` and `transition == OverdueSkipped`; no `ValidatorRefused` variant exists (`:1701-1710`). This leaves unclear whether the predicate means every refused close, only `(Refused, Installed)`, or the retired enum. Raw closing flags already provide the broader rule-5 gate.

5. **MEDIUM — Site 2b remains falsely described as reporting validation.** The legal-product paragraph still says acceptance/refusal rides `reverse_installed`/`install_failed` (`plan.md:1797-1800`). Those booleans report installation success only: validator refusal and accepted-but-capacity-refused both yield false/failed (`userspace-dp/src/afxdp/shared_ops.rs:824-895`; `userspace-dp/src/afxdp/session_glue/mod.rs:1264-1284`, `:1330-1344`).

Round-107 dispositions: r107-1 **UNRESOLVED**; r107-2 **UNRESOLVED**; r107-3 **UNRESOLVED**; r107-4 **RESOLVED**; r107-5 **UNRESOLVED**; r107-6 **UNRESOLVED**.