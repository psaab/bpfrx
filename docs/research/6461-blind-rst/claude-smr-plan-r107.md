# Claude SMR hostile plan-review — round 107 (v10.23.0)

Reviewer: Claude SMR (in-conversation). Posture: HOSTILE — twenty-
seventh pass; I authored the v10.23.0 fold of Codex r106's 1B/2H/4M/1L.
Verdict: **PLAN YES**.

## 1. Fold verification

**r106-1 (B — DisplacedSet transport).** The producer now returns ONE
typed `MaterializeReport { site, validation, transition, displaced }`
— the four-member report covers P (placeholder substitution OUT),
refusal-K (the surviving predecessor, recorded only when a later
promote actually overwrites it — an upsert refusal with a no-op
promote displaces nothing and K's aliases stay valid), `_previous`
(the upsert's OUT), installed S2, and the promotion preimage
(captured inside `update_session` immediately before the overwrite,
`session/mod.rs:1344-1348`/`:1393-1396`, threaded outward through
`promote_synced_with_origin`, `:1673-1675`, and
`maybe_promote_synced_session`, `promote.rs:99-140` — replacing the
bool → bool → metadata chain). The resolved result carries the whole
report, initialized `MaterializeReport::NONE` at both constructors.

**r106-2 (H — fail-closed not enforceable).** Two mechanisms, both
now specified: (a) the `site` discriminator
(`Some(Site2c)` only from the materialize) lets consumers distinguish
an erroneous site-2c `(None, None)` from a valid local hit; (b) the
producer NORMALIZES the product while the branch is known — any
out-of-product combination is mapped to OverdueSkipped semantics AT
the materialize site, BEFORE the promotion attempt — so no
post-hoc downstream interpretation is ever asked to undo mutations.

**r106-3 (M — proof precision).** The v10.22.0 proof text said
promotion cannot change NAT/orientation — false
(`update_session` detects/reindexes/overwrites those fields,
`session/mod.rs:1344-1348`, `:1373-1381`, `:1393-1396`). The
corrected statement: K's preimage family and the resulting S2 family
are two separately recorded members of the ≤3-family set (P +
K-preimage + S2); capacity 3 inline / 3×64 batch stands.

**r106-4 (H — §9).** The two-field terminology is used throughout;
the three new tests are present: (ix-a) producer-side normalization +
consumer-side fail-closed read; (ix-b) `UpsertRefused +
MissingNeighbor` never enters the seed block (`install.rs:139`
would replace K); (ix-c) the P+K+S2 maximum-cardinality case and the
full 64-descriptor/192-family batch. The predecessor-survival
assertion is scoped to the failed-upsert instant with the resulting
promoted/accounted state asserted.

**r106-5/6/7 (M/M/L).** Site 2b is correctly described as outside the
report (its install-outcome booleans conflate validator refusal and
capacity refusal — `shared_ops.rs:824-895`); the §5.6 fan-out text
now names the `poll_binding` level over `left + right`
(`worker/lifecycle.rs:53-55`, `:209-225`) and explicitly excludes the
reap routine; §10.6.1's reap-rate claim carries the purge exemption;
the policy-counter fallback is scoped exactly
(`bound_policy_counter_for` does not mirror forward-wire matching,
`lookup.rs:335-354` — it can miss the survivor and use S2's
positional counter; telemetry-only).

## 2. Consistency sweep

Assertion-checked replacements; the report's field names are
identical across the producer/fields/carriage/consumers/composition
bullets, §9, and §11. The gate (§5.1–§5.4, §5.7) is untouched for the
twenty-second consecutive round.

## 3. Bottom line

PLAN YES for v10.23.0.
