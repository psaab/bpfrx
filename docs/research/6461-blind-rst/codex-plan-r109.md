# Codex hostile plan-review — round 109 (v10.25.0)

Reviewer: Codex (fresh thread, job task-ms9e0462-lkx3l9, 2026-07-31). Verdict: PLAN NO (1B/2H/1M). r108-1/3/4/5 RESOLVED (the wholesale rewrite landed); the residuals: the producer list omitted the post-state S2 family; the Some(Site2c) fallback was not applied before promotion/refresh; the later MissingNeighbor clause remained site-unqualified; unconditional clear/install claims outside the SSOT contradicted the overdue exceptions.

## Verbatim review

PLAN NO 1. **BLOCKER — The rewritten exhaustive producer list omits the post-state S2 family....

[2026-07-31T20:26:23.640Z] Assistant message
PLAN NO

1. **BLOCKER — The rewritten exhaustive producer list omits the post-state S2 family.** The set definition includes P, predecessor K, and newly installed/resulting S2 (`docs/research/6461-blind-rst/plan.md:1828-1842`), but its exhaustive producers are only staged P, upsert `_previous`, and promotion’s preimage (`:1843-1859`). Nothing adds:

   - S2 after successful install/adopt; or
   - resulting S2 after `UpsertRefused → promotion`.

   A no-P/no-predecessor `(Refused, Installed)` therefore produces an empty set: `_previous` is absent and rule 5 suppresses promotion, contradicting §9’s requirement that S2 be present (`plan.md:2431-2443`). The materializer has S2 at `userspace-dp/src/afxdp/session_glue/mod.rs:1098-1119`; `_previous` represents only the removed old entry (`userspace-dp/src/session/install.rs:295-322`).

   This is observable: FIN/RST skips cache lookup because only pure ACKs are cache-eligible (`userspace-dp/src/afxdp/flow_cache.rs:352-358`), so it can materialize S2 while an older cache entry survives; the following ACK consults that cache before session resolution (`userspace-dp/src/afxdp/poll_descriptor/mod.rs:298-327`). Invalidation is exact-key (`userspace-dp/src/afxdp/flow_cache.rs:1105-1120`). Add the post-state family after successful materialization and successful promotion; the latter can contribute both preimage K and resulting S2 while total capacity remains three.

2. **HIGH — The `Some(Site2c)` defensive fallback is not applied before promotion/refresh.** An invalid site-2c combination is promised effective `OverdueSkipped` behavior (`plan.md:1771-1779`), but the pre-poller gates inspect only the raw fields `transition == OverdueSkipped` and `validation == Some(Refused)` (`:1740-1747`, `:1803-1809`). An invalid `(Some(Site2c), Accepted, Installed)` therefore satisfies neither gate and can reach promotion, whose current checks are only origin/disposition before overwrite, publication, and replication (`userspace-dp/src/afxdp/session_glue/promote.rs:86-139`).

   Legal products are valid by construction and their consumer matrix is otherwise sound. If the defensive fallback remains, derive one validated/effective transition before every consumer—including the pre-resolved-result promotion—not merely at later poller consumers.

3. **HIGH — The later MissingNeighbor clause remains site-unqualified.** The rewritten SSOT correctly restricts `OverdueSkipped`/`UpsertRefused` composition to `Some(Site2c)` (`plan.md:1817-1827`). The later normative outcome clause again says any such transition becomes live-backed `ExistingResolved` (`:1921-1927`). That contradicts the rule that an impossible `site=None` report follows master.

   On a purge path, state and NAT are removed (`userspace-dp/src/afxdp/session_glue/promote.rs:181-207`) while the retained decision still drives dispatch (`userspace-dp/src/afxdp/session_glue/mod.rs:1194-1196`). The broad wording again permits buffer/replay of the released tuple (`userspace-dp/src/afxdp/poll_descriptor/mod.rs:5057-5068`). Scope this second clause explicitly to `report.site == Some(Site2c)`.

4. **MEDIUM — Overdue exceptions remain contradicted outside the SSOT.** Section 5.6 correctly says overdue probation skips the upsert and never clears/refreshes at commit (`plan.md:1352-1380`), but immediately afterward says the first committed non-close always clears probation and that site-2c installation “cannot be skipped” (`:1394-1408`). Section 5.5 and §9 repeat the unconditional committed-non-close clear (`:1225-1230`, `:2517-2538`), while §9’s Overdue test requires no clear (`:2483-2495`). This is reachable because expiry is strict and wheel-driven, so a due entry can be observed before GC removes it (`userspace-dp/src/session/expire.rs:130-168`). Qualify every unconditional clear/install statement with `transition != OverdueSkipped`.

Round-108 dispositions: r108-1 **RESOLVED**; r108-2 **UNRESOLVED**; r108-3 **RESOLVED**; r108-4 **RESOLVED**; r108-5 **RESOLVED**.