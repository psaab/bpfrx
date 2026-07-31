# Codex hostile plan-review — round 106 (v10.22.0)

Reviewer: Codex (fresh thread, job task-ms9bm6e2-0m987v, 2026-07-31). Verdict: PLAN NO (1B/2H/4M/1L). Headline: DisplacedSet still lacked complete producer-to-result transport (the refusal case has no _previous at all), and the out-of-product fail-closed rule was not mechanically enforceable downstream — the fold answers both with the single typed MaterializeReport carrying producer-side normalization. r105-5 RESOLVED; the rest UNRESOLVED at v10.22.0.

## Verbatim review

PLAN NO 1. **BLOCKER — `DisplacedSet` still has no complete producer-to-result transport.** T...

[2026-07-31T19:24:37.970Z] Assistant message
PLAN NO

1. **BLOCKER — `DisplacedSet` still has no complete producer-to-result transport.** The materializer’s exact return is only `(SessionLookup, Option<CloseValidation>, TransitionResult)`, while `displaced` appears later as a separate resolved field (`docs/research/6461-blind-rst/plan.md:1730-1743`, `:1843-1847`). The nested upsert alone sees `_previous` (`userspace-dp/src/afxdp/session_glue/mod.rs:1092-1119`; `userspace-dp/src/session/install.rs:295-322`), but neither a fourth return member nor a caller-owned `&mut DisplacedSet` is specified.

   The refusal case is worse: `upsert_synced_with_origin` returns before `_previous` exists (`install.rs:310-322`). If promotion no-ops—as it does for MissingNeighbor (`userspace-dp/src/afxdp/session_glue/promote.rs:86-90`)—neither `_previous` nor a promotion preimage records surviving K. Thus K’s aliases have no declared route into invalidation. Promotion capture is correctly placed inside `update_session`, but its outward API remains unnamed: the current chain returns bool → bool → metadata (`userspace-dp/src/session/mod.rs:1299`, `:1673-1675`; `session_glue/promote.rs:99-140`). Define one typed materialization result/local accumulator covering P, refusal-K, `_previous`, installed S2, and promotion preimage.

2. **HIGH — The advertised out-of-product fail-closed rule is not mechanically enforceable.** `(None,None)` is valid for non-materializing paths, but the same bits are illegal only when produced by a materializing path; consumers receive no materialization discriminator (`plan.md:1744-1760`). The code knows `shared_entry: Some` versus `None` only inside `materialize_shared_session_hit`, after which both paths converge on the same resolved constructor (`userspace-dp/src/afxdp/session_glue/mod.rs:1092-1121`, `:1194-1198`, `:1254-1261`). Consumers therefore cannot distinguish an erroneous site-2c `(None,None)` from a valid local hit.

   Moreover, detectable invalid pairs are interpreted only downstream, after the upsert/install and possible promotion have already mutated authority (`session_glue/mod.rs:1098-1119`, `:1235-1253`). Mapping them to `OverdueSkipped` then cannot undo those mutations. Normalize/assert the product while the producer still knows the branch, before promotion, and carry an already-normalized transition or explicit provenance. Otherwise, the legal pairs are covered: `(None,None)`, `(None,T)`, and `(Refused,T)` have defined behavior for all four `T` variants.

3. **MEDIUM — Capacity three is correct, but part of its proof is false.** No fourth unique family exists: successful-upsert promotion’s preimage is S2; refused-upsert promotion’s preimage is K; together with P, at most three unique `(key,NAT,orientation)` families occur. The capture point at `update_session` is also correct.

   However, the plan says refused-upsert promotion changes neither NAT nor orientation (`plan.md:1800-1819`). It can replace K with an S2 having different NAT or `is_reverse`; `update_session` explicitly detects, reindexes, and overwrites those fields (`userspace-dp/src/session/mod.rs:1344-1348`, `:1373-1381`, `:1393-1396`). The sound proof is that K and resulting S2 are two separately recorded families—not that they are identity-equal.

4. **HIGH — Section 9 still contradicts the two-field contract and omits load-bearing regressions.** It retains removed `ValidatorRefused` terminology (`plan.md:2434-2453`), says a singular outcome is `None` except for overdue despite three other non-`None` transitions (`:2461-2471`), and still expects an `UpsertRefused` predecessor to survive unmodified (`:2453-2457`) despite permitted same-resolve promotion and accounting (`userspace-dp/src/afxdp/session_glue/promote.rs:99-139`; `userspace-dp/src/session/mod.rs:1177-1210`).

   It also lacks tests for:

   - legal-product normalization and invalid-product fail-closed handling;
   - `UpsertRefused + MissingNeighbor` avoiding the seed block that can replace K (`userspace-dp/src/afxdp/poll_descriptor/mod.rs:4662-4829`; `userspace-dp/src/session/install.rs:139`);
   - P+K+S2 maximum cardinality and a full 64-descriptor/192-family batch.

   The second normative MissingNeighbor list itself is repaired at `plan.md:1921-1927`; its regression is not.

5. **MEDIUM — Site 2b is incorrectly described as reporting validation through install booleans.** The product paragraph says site 2b reports acceptance/refusal via `reverse_installed/install_failed` (`plan.md:1748-1751`). It actually reports installation success only: validator refusal and accepted-but-capacity-refused both become `reverse_installed=false` and `install_failed=true` (`userspace-dp/src/afxdp/shared_ops.rs:824-895`; `userspace-dp/src/afxdp/session_glue/mod.rs:1264-1284`, `:1330-1344`). State simply that site 2b is outside the two new fields and retains its existing install-outcome boolean.

6. **MEDIUM — The claimed straggler sweep still missed normative-looking text.** Section 5.6 still names removed `ValidatorRefused` and routes sibling fan-out through the reap iteration (`plan.md:1441-1458`), contrary to the SSOT’s `poll_binding`/not-reap contract (`:1853-1877`; `userspace-dp/src/afxdp/worker/lifecycle.rs:53-55`, `:209-225`). Section 10.6.1 still locally says refused closes never reap early (`plan.md:2775-2780`), although the flag-agnostic purge can immediately delete the row (`userspace-dp/src/afxdp/session_glue/promote.rs:48-59`, `:167-207`). The purge-parity wording elsewhere is now correctly scoped.

7. **LOW — The accepted policy-counter description remains overbroad.** It says the pre-hoist fallback attributes divergent packets to the surviving entry’s rule, while later saying telemetry consumes S2 (`plan.md:1760-1765`, `:1781`). `bound_policy_counter_for` deliberately does not mirror forward-wire matching (`userspace-dp/src/session/lookup.rs:335-354`); on a forward-wire placeholder substitution (`userspace-dp/src/afxdp/shared_ops.rs:614-626`) it can miss the survivor and use S2’s positional counter instead. This is telemetry-only and does not alter authority.

Round-105 dispositions: r105-1 **UNRESOLVED**; r105-2 **UNRESOLVED**; r105-3 **UNRESOLVED**; r105-4 **UNRESOLVED**; r105-5 **RESOLVED**; r105-6 **UNRESOLVED**; r105-7 **UNRESOLVED**.