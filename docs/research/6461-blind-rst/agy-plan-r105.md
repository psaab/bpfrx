# AGY hostile plan-review — round 105 (v10.22.0)

Reviewer: AGY (direct binary). Verdict: SOUND — full propagation verification, legal-product walk, uniqueness proof and capture point verified.

## Verbatim review

SOUND

### Routine Design-Document Consistency Review: `docs/research/6461-blind-rst/plan.md` (v10.22.0)

**Commit Base:** `940219b1135f` (`research/6461-blind-rst`)  
**Scope:** Round-105 folds verification, legal Phase-1 product enumeration walk, displaced-set capacity-3 uniqueness proof & capture point verification, surviving surface stress test, and full-document consistency sweep.

---

### 1. Verification of Round-105 Folds Against Code & Design

1. **Two-field contract split propagation:**
   - **Plan:** `materialize_shared_session_hit` (`userspace-dp/src/afxdp/session_glue/mod.rs:1092-1121`) produces `(SessionLookup, Option<CloseValidation>, TransitionResult)` at the materialize site. `ResolvedFlowSessionDecision` (`userspace-dp/src/afxdp/shared_ops.rs:563-578`) gains both `validation: Option<CloseValidation>` and `transition: TransitionResult`, initialized `(None, None)` at both constructors (`userspace-dp/src/afxdp/session_glue/mod.rs:1254-1261` and `:1330-1344`).
   - **Code Verification:** Line 1254–1261 (HIT path return) and Line 1330–1344 (reverse-NAT match return) in `session_glue/mod.rs` are the exact constructor locations for `ResolvedFlowSessionDecision`. Initializing `(None, None)` at these two sites covers all non-site-2c dispatches. `materialize_shared_session_hit` is called prior to `maybe_promote_synced_session` (line 1197 vs line 1238), ensuring the outcome fields are computed and available before promotion.

2. **Legal Phase-1 Product Enumeration:**
   - **Plan:** Defines the legal product as `(None, None)` (non-materializing), `(None, T)` (non-close site-2c materialization), and `(Refused, T)` (closing site-2c materialization), with $T \in \{\text{Installed}, \text{AdoptedPreservingDeadline}, \text{UpsertRefused}, \text{OverdueSkipped}\}$. `Accepted` has no Phase-1 producer.
   - **Code/Logic Verification:** Checked across the full $3 \times 5 = 15$ product space of `Option<CloseValidation> \times TransitionResult`:
     - Legal (9 variants): `(None, None)`, `(None, Installed)`, `(None, AdoptedPreservingDeadline)`, `(None, UpsertRefused)`, `(None, OverdueSkipped)`, `(Refused, Installed)`, `(Refused, AdoptedPreservingDeadline)`, `(Refused, UpsertRefused)`, `(Refused, OverdueSkipped)`.
     - Unreachable Out-of-Product (6 variants): `(Accepted, None)`, `(Accepted, Installed)`, `(Accepted, AdoptedPreservingDeadline)`, `(Accepted, UpsertRefused)`, `(Accepted, OverdueSkipped)`, and `(Refused, None)`.
     - The fail-closed rule specifies that any consumer reading an out-of-product combination treats it as `OverdueSkipped`. This safely suppresses terminal teardown, anchor commit write, flow-cache insertion, probation clear, and ownership promotion.

3. **Second `MissingNeighbor` Outcome List Composition:**
   - **Plan:** Names both `OverdueSkipped` and `UpsertRefused` in §5.6 contract (lines 1786–1795) and the `MissingNeighbor` outcome list (lines 1920–1927).
   - **Code/Logic Verification:** On `UpsertRefused`, promotion no-ops for a non-ForwardCandidate (`userspace-dp/src/afxdp/session_glue/promote.rs:86-90`), leaving the non-peer predecessor installed in `sessions`. Routing `UpsertRefused` to the live-backed `ExistingResolved` buffer-only arm prevents the common seed block (`poll_descriptor/mod.rs:4662-4829`) from replacing the predecessor via `install.rs:139`. Both lists are identical and consistent.

4. **Capacity-3 Displaced-Set Uniqueness Proof & Capture Point:**
   - **Plan:** Inline capacity of 3 families for `DisplacedSet` (lines 1800–1825). Capture point placed inside `update_session` immediately before overwrite (`userspace-dp/src/session/mod.rs:1344-1348`, `:1393-1396`).
   - **Mathematical Uniqueness Proof:** In a single site-2c dispatch, the set of potential identity families $(k, \text{NAT}, \text{orientation})$ is bounded by:
     1. $P$: Shadowed placeholder family (if present).
     2. $K$: Canonical predecessor family (if present in local table).
     3. $S_2$: Materialized shared session family.
     - *Promote step deduplication:* `maybe_promote_synced_session` invokes `update_session`. Promotion updates `resolution`, `owner_rg_id`, or `fabric_ingress` (`promote.rs:92-107`), but **never** mutates $(k, \text{NAT}, \text{orientation})$.
     - If upsert succeeded ($S_2$ installed/adopted), the table entry at key $k$ is $S_2$, so the promote preimage captured inside `update_session` is $S_2$ itself.
     - If upsert was refused (`UpsertRefused`), $K$ remains installed in `sessions`, so any promote attempt on $k$ captures $K$ as its preimage.
     - Thus, the promote preimage is always in $\{S_2, K\}$ and never introduces a 4th distinct family. Max capacity = 3 $\{P, K, S_2\}$, proven exact.
   - **Capture Point Verification:** Lines 1344–1348 of `session/mod.rs` snapshot `old_nat`, `old_is_reverse`, `old_owner_rg`, and `old_origin` immediately before lines 1393–1396 overwrite `record.entry.decision`, `metadata`, and `origin`. Threading the OUT parameter directly from `update_session` captures the exact preimage before mutation.

5. **Pre-hoist Policy-Counter Fallback:**
   - **Plan:** Explicitly accepts fallback to the surviving entry's rule (`poll_descriptor/mod.rs:487-509`, `lookup.rs:345-354`) when $S_2$ lacks a bound counter (lines 1760–1765).
   - **Code Verification:** Matches upstream master fallback semantics for divergent transitions (telemetry attribution only).

6. **Straggler & Scope Corrections:**
   - **Plan:** Scopes §10.6.1 reap-rate / "reduces reap rate" claims to imported entries refusing closes until churn or flag-agnostic purge; corrects "FULL MASTER PARITY" phrasing across §5.6 summary, §7, and §10.6.1 to exact transient-purge master parity.
   - **Verification:** All references aligned across document sections.

---

### 2. Detailed Checklist Findings

#### Findings: None (Plan is Sound)

1. **`userspace-dp/src/afxdp/session_glue/mod.rs:1254-1261`, `:1330-1344`** — Verified constructors initialized `(None, None)` for non-materializing paths.
2. **`userspace-dp/src/afxdp/shared_ops.rs:563-578`** — Verified `ResolvedFlowSessionDecision` field placement and line citations.
3. **`userspace-dp/src/session/mod.rs:1344-1348`, `:1393-1396`** — Verified exact capture point for promote preimage inside `update_session`.
4. **`userspace-dp/src/afxdp/session_glue/promote.rs:92-107`** — Verified promotion mutation bounds preserving key, NAT decision, and orientation.

---

### Summary of Work Done

- Verified all 7 round-105 folds against codebase line numbers (`023f17a606d8` / `fff7a4ab5`) and structural semantics.
- Walked the legal Phase-1 product matrix ($3 \times 5 = 15$ combinations), confirming complete coverage and fail-closed handling (`OverdueSkipped`) for all out-of-product states.
- Verified the capacity-3 uniqueness proof algebraically and confirmed the preimage capture point placement in `userspace-dp/src/session/mod.rs`.
- Audited surviving surfaces, consumers, and pre-existing race documentation (§7, §8, §10.6) for cross-section consistency.
