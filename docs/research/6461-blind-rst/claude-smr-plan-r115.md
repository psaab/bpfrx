# Claude SMR hostile plan-review — round 115 (v10.30.0)

Reviewer: Claude SMR (in-conversation). Posture: HOSTILE — thirty-fifth
pass; I authored the v10.30.0 fold of Codex r114's 3B/3M. Verdict:
**PLAN YES**.

## 1. Fold verification

**r114-1 (B — sixth consumer ordered before its producer).** Verified
the mutual exclusion at the code: `is_fabric_wire_placeholder`
requires `!is_reverse` (`shared_ops.rs:583-590`), the establishment
candidate requires `entry.metadata.is_reverse`
(`lookup.rs:129-149`), and a live local non-placeholder hit wins over
the shared map (no materialize runs). So no dispatch ever has both an
establishment candidate and an `OverdueSkipped`/`UpsertRefused`
report — the establishment promote is REMOVED from the report
consumers (back to five), its own gates (the §5.5 proof gate, rule 5,
the probation flag) all available at its lookup-phase fire point, and
§9 tests the exclusion. The compute-at-lookup/apply-at-resolve-end
split from v10.29.1 is retained for the deferral mechanics but no
longer carries a report dependency.

**r114-2/3 (B/B — the matched token's shape and binding).** Verified
all three constraints: `FlowCacheEntry.key` must stay the query key
(`flow_cache.rs:578-581`, `:962-989`, `:1046-1065`); same-key synced
upserts replace with a new epoch (`install.rs:310-351`) and worker
`UpsertSynced` does so WITHOUT cache invalidation
(`session_glue/commands/upsert_synced.rs:64-120`), while cache
validation checks config/FIB/RG stamps, not session identity
(`flow_cache.rs:991-1021`). The fold: a DISTINCT optional
identity-bound token `Option<(canonical key, NatDecision, is_reverse,
install_epoch)>` rides the lookup return, the resolution result, and
the cache entry (additive; §6's claim corrected); the commit hook and
the cache-hit re-probe verify full identity agreement and suppress
every authority mutation on mismatch; purged/sessionless resolves
carry `None`.

**r114-4 (H — the full promote transaction).** Verified against
master's ordering (`lookup.rs:146-171` sets the flag before selecting
the timeout and pushes the wheel at `:214-218`): the apply now sets
`established`, recomputes the established/per-app timeout,
`last_seen_ns = now_ns`, and re-queues the canonical wheel key,
atomically — a flag-only move would have stranded the entry on its
freshly computed OPENING deadline. The forward companion stays
flag-only with its absolute opening deadline unchanged
(`session/mod.rs:1243-1252`).

**r114-5/6/7 (M/M/M).** The pre-filter split is stated (proof may
change established/timing only; anchor samples adopt only at a
successful commit hook); §9's consumer count was fixed at v10.29.1
and the missing alias/replacement cases are now in the test list;
the pending-path wording is exact ("next successfully committed
unbuffered non-close whose effective transition is neither outcome").

## 2. Consistency sweep

Assertion-checked replacements throughout; the consumer list is five
again with the exclusion proof referenced from both the SSOT and §9.
The gate (§5.1–§5.4, §5.7) is untouched for the thirtieth consecutive
round.

## 3. Bottom line

PLAN YES for v10.30.0.
