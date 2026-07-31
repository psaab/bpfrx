# AGY hostile plan-review — round 108 (v10.25.0)

Reviewer: AGY (direct binary). Verdict: SOUND — implementer-perspective line-by-line read of the rewritten contract block confirms all accumulated partial-edit contradictions resolved; no findings.

## Verbatim review

SOUND

### Round-108 Design Document Consistency Review (v10.25.0)

This routine staff design-document consistency review evaluates `docs/research/6461-blind-rst/plan.md` at **v10.25.0 (Status: DRAFT v10.25.0 — THE TERMINAL CUT, round-108 folds)** against the codebase at worktree commit `a68d5ea9aded` (base `023f17a606d8` with origin/master deltas at `fff7a4ab5`).

---

### 1. Verification of Section 5.8 Rewrite (§5.8 Normative Contract Sweep)

An implementer-perspective line-by-line read of the rewritten Section 5.8 (`MaterializeReport` / `OverdueSkipped` contract block, lines 1693–1888) confirms that all accumulated partial-edit contradictions from prior rounds have been completely resolved:

1. **Two-Field Outcome Model (Lines 1696–1725):**
   - The specification cleanly decouples `validation: Option<CloseValidation>` (`None | Accepted | Refused`) from `transition: TransitionResult` (`None | Installed | AdoptedPreservingDeadline | UpsertRefused | OverdueSkipped`).
   - The contract explicitly justifies `(Refused, Installed)` as the site-2c refuse-install state (installing an alive probation copy that can displace a canonical predecessor).
   - `UpsertRefused` correctly cites `install.rs:310-315` (the non-peer predecessor refusal in `upsert_synced_with_origin`) and distinguishes it from the fresh-install capacity check (`install.rs:123-125`).

2. **Valid-by-Construction Producer (Lines 1726–1751):**
   - `materialize_shared_session_hit` (`session_glue/mod.rs:1092-1121`) computes `validation` and the overdue check *before* executing the state-changing upsert (`install.rs:310-322`, `:345-400`).
   - Out-of-product combinations are unreachable by construction because selection occurs prior to table mutation.
   - The promotion path (`promote.rs:86-107`) receives the report before attempting promotion (`session_glue/mod.rs:1235-1253`) and explicitly checks `report.transition == OverdueSkipped` and `validation == Some(Refused)`.

3. **Resolved Result Carriage (Lines 1752–1758):**
   - `ResolvedFlowSessionDecision` (`shared_ops.rs:563-578`) carries `report: MaterializeReport`, initialized to `MaterializeReport::NONE` (site `None`, validation `None`, transition `None`, displaced empty) at both constructor sites (`session_glue/mod.rs:1254-1261` and `:1330-1344`). No redundant `displaced` field exists.

4. **Legal Phase-1 Product & Fail-Closed Scoping (Lines 1759–1779):**
   - Product definitions: `(None, None)` for non-materializing paths (`site == None`); `(None, T)` for non-close site-2c materializations; `(Refused, T)` for closing site-2c materializations (`T ∈ {Installed, AdoptedPreservingDeadline, UpsertRefused, OverdueSkipped}`).
   - `Accepted` has no Phase-1 producer for site-2c.
   - The consumer fail-closed fallback is strictly scoped to `Some(Site2c)` reports (`site == None` follows master's own dispatch to prevent replaying released tuples on purged retained lookups at `poll_descriptor/mod.rs:5057-5068` and `neighbor_dispatch.rs:272-292`).

5. **Carriage and Consumer Alignment (Lines 1780–1830):**
   - Poller hoists `resolved.report` at `poll_descriptor/mod.rs:509` onto the descriptor dispatch context before `resolved.decision` reduction at `:883`.
   - All five consumers (Teardown, Anchor commit hook, Flow-cache insert, Probation clear+refresh, Ownership promote) explicitly consume `OverdueSkipped` and `UpsertRefused`.

6. **MissingNeighbor Composition (Lines 1831–1840):**
   - `OverdueSkipped` or `UpsertRefused` + `MissingNeighbor` disposition routes to the live-backed `ExistingResolved` buffer-only arm, bypassing the common seed block (`poll_descriptor/mod.rs:4662-4829`) and preventing raw-flags replacement of non-peer predecessors via `install.rs:139`.

7. **Displaced Set Uniqueness & Producers (Lines 1841–1864):**
   - Inline array capacity of 3 identity families (`DisplacedSet`) is mathematically proven: shadowed placeholder $P$, canonical predecessor $K$, and newly installed $S_2$.
   - Preimage capture inside `update_session` (`session/mod.rs:1344-1348`, `:1393-1396`) deduplicates into this set. Placeholder substitution in `shared_ops.rs:602-628` is staged and committed to the set only on the site-2c materialization branch.

8. **Single Drain Description & Invalidation Timing (Lines 1865–1877):**
   - Current-binding drain invalidates `report.displaced` in the current binding's cache immediately after descriptor resolution (`poll_descriptor/mod.rs:110-131`).
   - `WorkerScratch` batch accumulator (`worker/scratch.rs:19-32`) feeds sibling fan-out once per batch at `poll_binding` (`worker/lifecycle.rs:53-55`, `:209-225`) over `left + right` before the next RX batch (never per-descriptor, never via the reap routine at `worker/loop_body/mod.rs:1481-1521`).

9. **Probation Reap Alias Set (Lines 1878–1883):**
   - Invalidates flow cache for the complete alias set of the final identity (`lookup.rs:62-100`, `:222-250`, `:253-315`, `key.rs:19-26`), with prior identities already invalidated at adopt/replace time.

---

### 2. Codebase Site Verification

Every named site cited across Section 5.8 and related sections was re-verified against the codebase:

| Plan Citation | Codebase Path & Location | Verification Status |
|---|---|---|
| `install.rs:310-315` | `userspace-dp/src/session/install.rs:310-315` | **EXACT MATCH**: Non-peer predecessor refusal (`!existing.origin.is_peer_synced()`). |
| `install.rs:123-125` | `userspace-dp/src/session/install.rs:123-125` | **EXACT MATCH**: Fresh install capacity check (`self.len() >= self.max_sessions`). |
| `promote.rs:86-107`, `:99-139` | `userspace-dp/src/afxdp/session_glue/promote.rs:86-107`, `:99-139` | **EXACT MATCH**: Promotion eligibility gate and `promote_synced_with_origin`. |
| `session/mod.rs:1177-1210` | `userspace-dp/src/session/mod.rs:1177-1210` | **EXACT MATCH**: `account_packet` counter accounting and TCP flag OR-folding. |
| `session_glue/mod.rs:477-581` | `userspace-dp/src/afxdp/session_glue/mod.rs:477-581` | **EXACT MATCH**: `delete_terminal_half` companion derivation and state deletion. |
| `session_glue/mod.rs:1092-1121` | `userspace-dp/src/afxdp/session_glue/mod.rs:1092-1121` | **EXACT MATCH**: `materialize_shared_session_hit`. |
| `poll_descriptor/mod.rs:509` | `userspace-dp/src/afxdp/poll_descriptor/mod.rs:509` | **EXACT MATCH**: `flow_cache_install_failed = resolved.install_failed;`. |
| `poll_descriptor/mod.rs:883` | `userspace-dp/src/afxdp/poll_descriptor/mod.rs:883` | **EXACT MATCH**: `resolved.decision` extraction. |
| `poll_descriptor/mod.rs:698-714` | `userspace-dp/src/afxdp/poll_descriptor/mod.rs:698-714` | **EXACT MATCH**: Terminal filtered session delete site #1 (host-inbound). |
| `poll_descriptor/mod.rs:768-784` | `userspace-dp/src/afxdp/poll_descriptor/mod.rs:768-784` | **EXACT MATCH**: Terminal filtered session delete site #2 (lo0 policy deny). |
| `poll_descriptor/mod.rs:824-840` | `userspace-dp/src/afxdp/poll_descriptor/mod.rs:824-840` | **EXACT MATCH**: Terminal filtered session delete site #3 (junos-host local policy deny). |
| `poll_descriptor/mod.rs:3900-3959` | `userspace-dp/src/afxdp/poll_descriptor/mod.rs:3900-3959` | **EXACT MATCH**: Flow-cache insertion logic. |
| `poll_descriptor/mod.rs:4662-4829` | `userspace-dp/src/afxdp/poll_descriptor/mod.rs:4662-4829` | **EXACT MATCH**: Common seed block for `MissingNeighbor`. |
| `shared_ops.rs:602-628` | `userspace-dp/src/afxdp/session_glue/shared_ops.rs:602-628` | **EXACT MATCH**: Forward-wire placeholder match and substitution. |
| `session/mod.rs:1344-1348`, `:1393-1396` | `userspace-dp/src/session/mod.rs:1344-1348`, `:1393-1396` | **EXACT MATCH**: `update_session` head and overwrite points. |
| `worker/scratch.rs:19-32` | `userspace-dp/src/afxdp/worker/scratch.rs:19-32` | **EXACT MATCH**: `WorkerScratch` structure. |
| `worker/lifecycle.rs:53-55`, `:209-225` | `userspace-dp/src/afxdp/worker/lifecycle.rs:53-55`, `:209-225` | **EXACT MATCH**: `poll_binding` sibling cache invalidation fan-out. |
| `worker/loop_body/mod.rs:1481-1521` | `userspace-dp/src/afxdp/worker/loop_body/mod.rs:1481-1521` | **EXACT MATCH**: Table reap loop and NAT/BPF teardown. |

---

### 3. Full Consumer & Legal Product Verification

- **Legal Phase-1 Product Set:**
  $$\text{Product} = \{(None, None)\} \cup \{(None, T) \mid T \in \mathcal{T}\} \cup \{(Refused, T) \mid T \in \mathcal{T}\}$$
  where $\mathcal{T} = \{\text{Installed}, \text{AdoptedPreservingDeadline}, \text{UpsertRefused}, \text{OverdueSkipped}\}$.
  - All legal product cases map unambiguously.
  - Fail-closed fallback is strictly guarded by `site == Some(Site2c)`.
- **Consumer Behavior:**
  1. *Teardown (3 sites):* Skipped on `OverdueSkipped` or `UpsertRefused`.
  2. *Anchor Commit Hook:* Suppressed on `OverdueSkipped` or `UpsertRefused`.
  3. *Flow-Cache Insert:* Suppressed on `OverdueSkipped` or `UpsertRefused`.
  4. *Probation Clear/Refresh:* Suppressed on `OverdueSkipped`.
  5. *Ownership Promote:* Suppressed on `OverdueSkipped` or `validation == Some(Refused)`.

---

### 4. Surviving Surface Stress Analysis

The surviving attack surface and residuals remain strictly bounded as specified:
- **HA-imported / Materialized Entries:** In Phase 1, imported entries carry no wire anchor and soft-refuse closes until local observation or churn. Retention is bounded by entry inactivity timeout (300 s default).
- **Split-Direction Steering:** Master-parity; B's imported replica anchor is untrusted, so reverse closes soft-refuse without corrupting A's authoritative entry.
- **Both-Direction Path-Switch:** Frozen anchors cause soft-refuses; entries idle out naturally without blocking packet delivery.
- **Pre-existing Races / Issues (#6522, #6599, #6600):** Correctly isolated to their respective tracks; Part A changes no HA wire formats and creates no new delta classes.

---

### 5. Full-Document Consistency Sweep

- **Cross-Section References:** Section 5.6 summary notes, Section 9 test plan, and Section 10 open questions are fully aligned with the Section 5.8 contract SSOT.
- **Terminology:** All deprecated terms from early iterations remain purged.
- **Master Drift Table (§3.1):** Accurately accounts for master commits up to `fff7a4ab5` (including #6478 removal of the fabric return fast path).

---

### Final Verdict

**SOUND**

The plan document `docs/research/6461-blind-rst/plan.md` (v10.25.0) is coherent, rigorous, fully verified against the codebase, and ready for implementation approval via `/engineer 6461`.
